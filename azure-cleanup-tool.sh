#!/bin/bash

#====================================================================================================
# Azure Resource Cleanup Tool: Comprehensive discovery and deletion across all Azure scopes
# 
# 🎯 PURPOSE: Streamline Tenant/Management Group off-boarding and re-onboarding
# 
# 🔍 DISCOVERS: Resources, Resource Groups, Policies, Enterprise Apps, Service Principals,
#               Custom Roles, Role Assignments, Diagnostic Settings, Managed Identities
# 
# 🛡️  FEATURES: Dependency-aware deletion, dry-run mode, scope mismatch handling,
#               case-insensitive pattern matching, cross-scope coverage
# 
# ⚡ HANDLES: 'Unknown' role assignments, orphaned resources, multi-subscription cleanup
#====================================================================================================

# Exit on critical errors but allow graceful handling for individual resource operations
set -u
trap 'echo "❌ Script interrupted."; exit 1' INT

# --- Style Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# --- Logging Functions ---
log_info() { echo -e "${BLUE}ℹ️  $*${NC}"; }
log_success() { echo -e "${GREEN}✅ $*${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $*${NC}"; }
log_error() { echo -e "${RED}❌ $*${NC}"; }
log_debug() { echo -e "${CYAN}ℹ️  $*${NC}"; }
log_special() { echo -e "${PURPLE}🔐 $*${NC}"; }

# --- Usage Function ---
usage() {

    echo -e "${YELLOW}Description:${NC}"
    echo "  Comprehensive Azure resource discovery and cleanup tool that searches across all scopes"
    echo "  for resources matching the specified name pattern (case-insensitive)."
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 <resource-name> [--dry-run] [--delete] [--subscription SUB_ID] [--help]"
    echo
    echo -e "${YELLOW}Options:${NC}"
    echo "  --dry-run          Only show what would be deleted (default)"
    echo "  --delete           Actually delete resources (default: dry-run)"
    echo "  --subscription ID  Limit search to specific subscription"
    echo "  --help             Show this help message"
    echo
    echo -e "${YELLOW}Examples:${NC}"
    echo "  ./$0 cortex"
    echo "  ./$0 cortex --dry-run"
    echo "  ./$0 cortex --subscription 12345-67890 --dry-run"
    echo "  ./$0 cortex --delete"
    exit 1
}

# --- Argument Parsing ---
DELETE_MODE=false
DRY_RUN=true
SUBSCRIPTION_ID=""
NAME_PATTERN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --delete)
            DELETE_MODE=true
            DRY_RUN=false
            shift
            ;;
        --dry-run)
            DELETE_MODE=false
            DRY_RUN=true
            shift
            ;;
        --subscription)
            SUBSCRIPTION_ID="$2"
            shift 2
            ;;
        --help)
            usage
            ;;
        -*)
            log_error "Unknown option $1"
            usage
            ;;
        *)
            NAME_PATTERN="$1"
            shift
            ;;
    esac
done

# --- Validation ---
if [[ -z "$NAME_PATTERN" ]]; then
    log_error "Name pattern is required"
    usage
fi

# Sanitize name pattern for JSON queries
SANITIZED_PATTERN=$(printf '%s' "$NAME_PATTERN" | sed "s/'/''/g")

# --- Pre-flight Checks ---
check_dependency() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "$1 not found. Please install it."
        exit 1
    fi
}

check_dependency az
check_dependency jq

if ! az account show >/dev/null 2>&1; then
    log_error "Not logged into Azure. Please run 'az login' first."
    exit 1
fi

log_success "Azure login confirmed"

# --- Initialize Arrays ---
declare -a ALL_IDS
declare -a SUMMARY_ROWS
declare -A RESOURCE_TYPES
declare -A RG_SUBSCRIPTION
declare -A RESOURCE_DETAILS

# Track if we found any resources
RESOURCES_FOUND=false

# --- Helper Functions ---
normalize() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

# Clean display name for output (handles edge cases where role names contain literal color codes)
clean_display_name() {
    local text="$1"
    # Just return the text as-is - don't try to highlight if it contains what looks like color codes
    echo "$text"
}

# Simple highlight function that only highlights if no suspicious sequences are found
safe_highlight() {
    local text="$1"
    local pattern="$2"
    
    # If the text contains what looks like color codes or escape sequences, don't attempt highlighting
    if [[ "$text" =~ [\x00-\x1F] ]] || [[ "$text" =~ 033\[ ]]; then
        echo "$text"
    else
        if [[ "${text,,}" == *"${pattern,,}"* ]]; then
            local esc_pattern=$(echo "$pattern" | sed 's/[]\/$*.^|[]/\\&/g')
            echo "$text" | sed -E "s/($esc_pattern)/${YELLOW}\1${NC}/Ig"
        else
            echo "$text"
        fi
    fi
}

# --- Subscription Handling ---
get_subscriptions() {
    if [[ -n "$SUBSCRIPTION_ID" ]]; then
        log_info "Limiting search to subscription: $SUBSCRIPTION_ID"
        echo "$SUBSCRIPTION_ID"
    else
        log_info "Getting all enabled subscriptions..."
        local subs
        subs=$(az account list --query '[?state==`Enabled`].id' -o tsv 2>/dev/null || echo "")
        if [[ -z "$subs" ]]; then
            log_error "No enabled subscriptions found or unable to list subscriptions"
            exit 1
        fi
        echo "$subs"
    fi
}

# --- Resource Discovery Functions ---
discover_resources() {
    local sub="$1"
    local sub_name="$2"
    
    log_info "Searching resources in subscription: $sub_name"
    
    # Resources in resource groups
    local resources
    resources=$(az resource list --subscription "$sub" -o json 2>/dev/null || echo '[]')
    
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue
        
        local name type id tags
        name=$(jq -r '.name // ""' <<< "$row")
        type=$(jq -r '.type // ""' <<< "$row")
        id=$(jq -r '.id // ""' <<< "$row")
        tags=$(jq -r '.tags // {} | to_entries | map("\(.key)=\(.value)") | join(", ")' <<< "$row")
        
        # Skip role definitions (handled separately)
        [[ "$type" == *"Microsoft.Authorization/roleDefinitions"* ]] && continue
        
        if [[ "${name,,}" == *"${NAME_PATTERN,,}"* ]]; then
            echo "  → Found Resource: $(safe_highlight "$name" "$NAME_PATTERN") ($type)"
            SUMMARY_ROWS+=("$name|$type|$sub_name|$tags")
            ALL_IDS+=("$id")
            RESOURCE_TYPES["$id"]="$type"
            RESOURCE_DETAILS["$id"]="$name|$type|$sub_name"
            RESOURCES_FOUND=true
        fi
    done < <(jq -c '.[]' <<< "$resources")
    
    # Resource Groups
    local rgs
    rgs=$(az group list --subscription "$sub" -o json 2>/dev/null || echo '[]')
    
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue
        
        local name id tags
        name=$(jq -r '.name // ""' <<< "$row")
        id=$(jq -r '.id // ""' <<< "$row")
        tags=$(jq -r '.tags // {} | to_entries | map("\(.key)=\(.value)") | join(", ")' <<< "$row")
        
        if [[ "${name,,}" == *"${NAME_PATTERN,,}"* ]]; then
            echo "  → Found Resource Group: $(safe_highlight "$name" "$NAME_PATTERN")"
            SUMMARY_ROWS+=("$name|ResourceGroup|$sub_name|$tags")
            ALL_IDS+=("$id")
            RESOURCE_TYPES["$id"]="ResourceGroup"
            RG_SUBSCRIPTION["$id"]="$sub"
            RESOURCE_DETAILS["$id"]="$name|ResourceGroup|$sub_name"
            RESOURCES_FOUND=true
        fi
    done < <(jq -c '.[]' <<< "$rgs")
}

discover_management_group_role_assignments() {
    log_info "Searching for management group role assignments..."
    
    # Get all management groups
    local mgs
    mgs=$(az account management-group list --query '[].name' -o tsv 2>/dev/null || echo "")
    
    if [[ -z "$mgs" ]]; then
        log_debug "No management groups found or access denied"
        return
    fi
    
    for mg in $mgs; do
        log_debug "Checking management group: $mg"
        local assignments
        assignments=$(az role assignment list --scope "/providers/Microsoft.Management/managementGroups/$mg" -o json 2>/dev/null || echo '[]')
        
        while IFS= read -r assignment; do
            [[ -z "$assignment" ]] && continue
            
            local principal_name principal_id assignment_id principal_type scope
            principal_name=$(jq -r '.principalName // ""' <<< "$assignment")
            principal_id=$(jq -r '.principalId // ""' <<< "$assignment")
            assignment_id=$(jq -r '.id // ""' <<< "$assignment")
            principal_type=$(jq -r '.principalType // ""' <<< "$assignment")
            scope=$(jq -r '.scope // ""' <<< "$assignment")
            
            # Check if principal name matches our pattern
            if [[ "${principal_name,,}" == *"${NAME_PATTERN,,}"* ]]; then
                echo "  → Found Management Group Role Assignment: $(safe_highlight "$principal_name" "$NAME_PATTERN") ($principal_type on $mg)"
                SUMMARY_ROWS+=("$principal_name|ManagementGroupRoleAssignment|$mg|Scope: $scope")
                ALL_IDS+=("$assignment_id")
                RESOURCE_TYPES["$assignment_id"]="ManagementGroupRoleAssignment"
                RESOURCE_DETAILS["$assignment_id"]="$principal_name|ManagementGroupRoleAssignment|$mg"
                RESOURCES_FOUND=true
            fi
        done < <(jq -c '.[]' <<< "$assignments")
    done
}

discover_diagnostic_settings() {
    log_info "Searching for diagnostic settings..."
    
    local subscriptions
    subscriptions=$(get_subscriptions)
    
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        
        local sub_name
        sub_name=$(az account show --subscription "$sub" --query 'name' -o tsv 2>/dev/null || echo "Unknown")
        
        log_debug "Checking diagnostic settings in subscription: $sub_name"
        
        # Get all resources in the subscription that might have diagnostic settings
        local resources
        resources=$(az resource list --subscription "$sub" --query '[].id' -o tsv 2>/dev/null || echo "")
        
        for resource_id in $resources; do
            [[ -z "$resource_id" ]] && continue
            
            local diagnostic_settings
            diagnostic_settings=$(az monitor diagnostic-settings list --resource "$resource_id" -o json 2>/dev/null || echo '[]')
            
            while IFS= read -r setting; do
                [[ -z "$setting" ]] && continue
                
                local name id target_resource
                name=$(jq -r '.name // ""' <<< "$setting")
                id=$(jq -r '.id // ""' <<< "$setting")
                target_resource=$(jq -r '.resourceId // ""' <<< "$setting")
                
                # Check if diagnostic setting name matches our pattern
                if [[ "${name,,}" == *"${NAME_PATTERN,,}"* ]]; then
                    echo "  → Found Diagnostic Setting: $(safe_highlight "$name" "$NAME_PATTERN") (Resource: $(basename "$target_resource"))"
                    SUMMARY_ROWS+=("$name|DiagnosticSetting|$sub_name|Target: $(basename "$target_resource")")
                    ALL_IDS+=("$id")
                    RESOURCE_TYPES["$id"]="DiagnosticSetting"
                    RESOURCE_DETAILS["$id"]="$name|DiagnosticSetting|$sub_name|$target_resource"
                    RESOURCES_FOUND=true
                fi
            done < <(jq -c '.[]' <<< "$diagnostic_settings")
        done
    done <<< "$subscriptions"
    
    # Also check for diagnostic settings at subscription scope
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        
        local sub_name
        sub_name=$(az account show --subscription "$sub" --query 'name' -o tsv 2>/dev/null || echo "Unknown")
        
        log_debug "Checking subscription-level diagnostic settings: $sub_name"
        
        local subscription_diagnostics
        subscription_diagnostics=$(az monitor diagnostic-settings subscription list --subscription "$sub" -o json 2>/dev/null || echo '[]')
        
        while IFS= read -r setting; do
            [[ -z "$setting" ]] && continue
            
            local name id
            name=$(jq -r '.name // ""' <<< "$setting")
            id=$(jq -r '.id // ""' <<< "$setting")
            
            # Check if diagnostic setting name matches our pattern
            if [[ "${name,,}" == *"${NAME_PATTERN,,}"* ]]; then
                echo "  → Found Subscription Diagnostic Setting: $(safe_highlight "$name" "$NAME_PATTERN")"
                SUMMARY_ROWS+=("$name|SubscriptionDiagnosticSetting|$sub_name|")
                ALL_IDS+=("$id")
                RESOURCE_TYPES["$id"]="SubscriptionDiagnosticSetting"
                RESOURCE_DETAILS["$id"]="$name|SubscriptionDiagnosticSetting|$sub_name"
                RESOURCES_FOUND=true
            fi
        done < <(jq -c '.[]' <<< "$subscription_diagnostics")
    done <<< "$subscriptions"
}

# --- Diagnostic Settings Deletion ---

discover_directory_diagnostic_settings() {
    log_info "Discovering AAD tenant-level diagnostic settings..."
    
    local SETTINGS
    SETTINGS=$(az rest --method get \
        --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" \
        -o json 2>/dev/null || echo '{"value": []}')

    # Filter the resources using your working approach
    local FILTERED
    FILTERED=$(echo "$SETTINGS" | jq --arg kw "$NAME_PATTERN" -r '.value[] | select(.name | test($kw; "i")) | "\(.name)\t\(.id)"')

    if [[ -z "$FILTERED" ]]; then
        log_debug "No AAD tenant-level diagnostic settings found for pattern: $NAME_PATTERN"
        return
    fi



    # Process for cleanup
    while IFS=$'\t' read -r name id; do
        [[ -z "$name" ]] && continue
        
        echo "  → Found Azure AD Diagnostic Setting: $(safe_highlight "$name" "$NAME_PATTERN") (Default Directory)"
        SUMMARY_ROWS+=("$name|DirectoryDiagnosticSetting|Tenant|AAD Diagnostic")
        ALL_IDS+=("$id")
        
        # Use compatible array storage for older Bash versions
        if [[ "$BASH_VERSINFO" -ge 4 ]]; then
            # Bash 4.0+ with associative arrays
            RESOURCE_TYPES["$id"]="DirectoryDiagnosticSetting"
            RESOURCE_DETAILS["$id"]="$name|DirectoryDiagnosticSetting|Tenant|$id"
        else
            # Older Bash compatibility
            RESOURCE_TYPES+=("$id|DirectoryDiagnosticSetting")
            RESOURCE_DETAILS+=("$id|$name|DirectoryDiagnosticSetting|Tenant|$id")
        fi
        
        RESOURCES_FOUND=true
    done <<< "$FILTERED"
}

discover_subscription_role_assignments() {
    local sub="$1"
    local sub_name="$2"
    
    log_debug "Checking role assignments in subscription: $sub_name"
    
    local assignments
    assignments=$(az role assignment list --subscription "$sub" -o json 2>/dev/null || echo '[]')
    
    while IFS= read -r assignment; do
        [[ -z "$assignment" ]] && continue
        
        local principal_name principal_id assignment_id principal_type scope
        principal_name=$(jq -r '.principalName // ""' <<< "$assignment")
        principal_id=$(jq -r '.principalId // ""' <<< "$assignment")
        assignment_id=$(jq -r '.id // ""' <<< "$assignment")
        principal_type=$(jq -r '.principalType // ""' <<< "$assignment")
        scope=$(jq -r '.scope // ""' <<< "$assignment")
        
        # Check if principal name matches our pattern
        if [[ "${principal_name,,}" == *"${NAME_PATTERN,,}"* ]]; then
            echo "  → Found Subscription Role Assignment: $(safe_highlight "$principal_name" "$NAME_PATTERN") ($principal_type in $sub_name)"
            SUMMARY_ROWS+=("$principal_name|SubscriptionRoleAssignment|$sub_name|Scope: $scope")
            ALL_IDS+=("$assignment_id")
            RESOURCE_TYPES["$assignment_id"]="SubscriptionRoleAssignment"
            RESOURCE_DETAILS["$assignment_id"]="$principal_name|SubscriptionRoleAssignment|$sub_name"
            RESOURCES_FOUND=true
        fi
    done < <(jq -c '.[]' <<< "$assignments")
}

discover_policy_assignments() {
    log_info "Searching for policy assignments..."
    
    # Search at different scopes: management groups, subscriptions, and resource groups
    
    # 1. Management Group scope policy assignments
    local mgs
    mgs=$(az account management-group list --query '[].name' -o tsv 2>/dev/null || echo "")
    
    for mg in $mgs; do
        log_debug "Checking policy assignments in management group: $mg"
        local mg_assignments
        mg_assignments=$(az policy assignment list --scope "/providers/Microsoft.Management/managementGroups/$mg" -o json 2>/dev/null || echo '[]')
        
        while IFS= read -r assignment; do
            [[ -z "$assignment" ]] && continue
            
            local displayName name scope id
            displayName=$(jq -r '.displayName // ""' <<< "$assignment")
            name=$(jq -r '.name // ""' <<< "$assignment")
            scope=$(jq -r '.scope // ""' <<< "$assignment")
            id=$(jq -r '.id // ""' <<< "$assignment")
            
            # Check if display name or name matches our pattern
            if [[ "${displayName,,}" == *"${NAME_PATTERN,,}"* ]] || [[ "${name,,}" == *"${NAME_PATTERN,,}"* ]]; then
                echo "  → Found Management Group Policy Assignment: $(safe_highlight "$displayName" "$NAME_PATTERN") (Scope: $scope)"
                SUMMARY_ROWS+=("$displayName|PolicyAssignment|$scope|Name: $name")
                ALL_IDS+=("$id")
                RESOURCE_TYPES["$id"]="PolicyAssignment"
                RESOURCE_DETAILS["$id"]="$displayName|PolicyAssignment|$scope|$name"
                RESOURCES_FOUND=true
            fi
        done < <(jq -c '.[]' <<< "$mg_assignments")
    done
    
    # 2. Subscription scope policy assignments
    local subscriptions
    subscriptions=$(get_subscriptions)
    
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        
        local sub_name
        # Try to get subscription name with better error handling
        sub_name=$(az account show --subscription "$sub" --query 'name' -o tsv 2>/dev/null)
        if [[ $? -ne 0 ]] || [[ -z "$sub_name" ]]; then
            # If that fails, try to get it from the account list
            sub_name=$(az account list --query "[?id=='$sub'].name | [0]" -o tsv 2>/dev/null)
            if [[ $? -ne 0 ]] || [[ -z "$sub_name" ]]; then
                # Last resort: show the subscription ID
                sub_name="Subscription ($sub)"
            fi
        fi
        
        log_debug "Checking policy assignments in subscription: $sub_name"
        local sub_assignments
        sub_assignments=$(az policy assignment list --subscription "$sub" -o json 2>/dev/null || echo '[]')
        
        while IFS= read -r assignment; do
            [[ -z "$assignment" ]] && continue
            
            local displayName name scope id
            displayName=$(jq -r '.displayName // ""' <<< "$assignment")
            name=$(jq -r '.name // ""' <<< "$assignment")
            scope=$(jq -r '.scope // ""' <<< "$assignment")
            id=$(jq -r '.id // ""' <<< "$assignment")
            
            # Check if display name or name matches our pattern
            if [[ "${displayName,,}" == *"${NAME_PATTERN,,}"* ]] || [[ "${name,,}" == *"${NAME_PATTERN,,}"* ]]; then
                echo "  → Found Subscription Policy Assignment: $(safe_highlight "$displayName" "$NAME_PATTERN") (Scope: $scope)"
                SUMMARY_ROWS+=("$displayName|PolicyAssignment|$sub_name|Name: $name")
                ALL_IDS+=("$id")
                RESOURCE_TYPES["$id"]="PolicyAssignment"
                RESOURCE_DETAILS["$id"]="$displayName|PolicyAssignment|$scope|$name"
                RESOURCES_FOUND=true
            fi
        done < <(jq -c '.[]' <<< "$sub_assignments")
    done <<< "$subscriptions"
}

discover_policy_remediations() {
    log_info "Searching for policy remediations..."
    
    # Get all subscriptions for remediation search
    local subscriptions
    subscriptions=$(get_subscriptions)
    
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        
        local sub_name
        sub_name=$(az account show --subscription "$sub" --query 'name' -o tsv 2>/dev/null || echo "Unknown")
        
        local remediations
        remediations=$(az policy remediation list --subscription "$sub" -o json 2>/dev/null || echo '[]')
        
        while IFS= read -r remediation; do
            [[ -z "$remediation" ]] && continue
            
            local name id
            name=$(jq -r '.name // ""' <<< "$remediation")
            id=$(jq -r '.id // ""' <<< "$remediation")
            
            if [[ "${name,,}" == *"${NAME_PATTERN,,}"* ]]; then
                echo "  → Found Policy Remediation: $(safe_highlight "$name" "$NAME_PATTERN") ($sub_name)"
                SUMMARY_ROWS+=("$name|PolicyRemediation|$sub_name|")
                ALL_IDS+=("$id")
                RESOURCE_TYPES["$id"]="PolicyRemediation"
                RESOURCE_DETAILS["$id"]="$name|PolicyRemediation|$sub_name"
                RESOURCES_FOUND=true
            fi
        done < <(jq -c '.[]' <<< "$remediations")
    done <<< "$subscriptions"
}



discover_management_group_deployments() {
    log_info "Searching for management group deployments..."
    
    local mgs
    mgs=$(az account management-group list --query '[].name' -o tsv 2>/dev/null || echo "")
    
    if [[ -z "$mgs" ]]; then
        log_debug "No management groups found or access denied"
        return
    fi
    
    for mg in $mgs; do
        local deployments
        deployments=$(az deployment mg list --management-group-id "$mg" -o json 2>/dev/null || echo '[]')
        
        while IFS= read -r deployment; do
            [[ -z "$deployment" ]] && continue
            
            local name id
            name=$(jq -r '.name // ""' <<< "$deployment")
            id=$(jq -r '.id // ""' <<< "$deployment")
            
            if [[ "${name,,}" == *"${NAME_PATTERN,,}"* ]]; then
                echo "  → Found Management Group Deployment: $(safe_highlight "$name" "$NAME_PATTERN") (MG: $mg)"
                SUMMARY_ROWS+=("$name|ManagementGroupDeployment|$mg|")
                ALL_IDS+=("$id")
                RESOURCE_TYPES["$id"]="ManagementGroupDeployment"
                RESOURCE_DETAILS["$id"]="$name|ManagementGroupDeployment|$mg"
                RESOURCES_FOUND=true
            fi
        done < <(jq -c '.[]' <<< "$deployments")
    done
}

# discover_enterprise_apps() {
#     log_info "Searching for enterprise applications..."
    
#     # Use multiple query approaches to find enterprise apps
#     local apps
#     apps=$(az ad app list --query "[?contains(displayName, '$SANITIZED_PATTERN') || contains(appId, '$SANITIZED_PATTERN')].[displayName,appId]" -o tsv 2>/dev/null || true)
    
#     if [[ -z "$apps" ]]; then
#         # Also try searching by alternative names and identifiers
#         apps=$(az ad app list --query "[].{displayName:displayName, appId:appId}" -o json 2>/dev/null | jq -r ".[] | select(.displayName | test(\"$NAME_PATTERN\"; \"i\")) | [.displayName, .appId] | @tsv" || true)
#     fi
    
#     if [[ -z "$apps" ]]; then
#         log_debug "No enterprise applications found matching pattern: $NAME_PATTERN"
#         return
#     fi
    
#     while IFS=$'\t' read -r appName appId; do
#         [[ -z "$appName" ]] && continue
#         echo "  → Found Enterprise Application: $(safe_highlight "$appName" "$NAME_PATTERN") ($appId)"
#         SUMMARY_ROWS+=("$appName|EnterpriseApplication|Tenant|AppID: $appId")
#         ALL_IDS+=("$appId")
#         RESOURCE_TYPES["$appId"]="EnterpriseApplication"
#         RESOURCE_DETAILS["$appId"]="$appName|EnterpriseApplication|Tenant|$appId"
#         RESOURCES_FOUND=true
#     done <<< "$apps"
# }

# discover_service_principals() {
#     log_info "Searching for service principals..."
    
#     local sps
#     sps=$(az ad sp list --query "[?contains(displayName, '$SANITIZED_PATTERN') || contains(appId, '$SANITIZED_PATTERN')].[displayName,id,appId]" -o tsv 2>/dev/null || true)
    
#     if [[ -z "$sps" ]]; then
#         log_debug "No service principals found matching pattern: $NAME_PATTERN"
#         return
#     fi
    
#     while IFS=$'\t' read -r spName spId appId; do
#         [[ -z "$spName" ]] && continue
        
#         local details=""
#         if [[ -n "$appId" && "$appId" != "null" ]]; then
#             details="AppID: $appId"
#         fi
        
#         echo "  → Found Service Principal: $(safe_highlight "$spName" "$NAME_PATTERN") ($spId)"
#         SUMMARY_ROWS+=("$spName|ServicePrincipal|Tenant|$details")
#         ALL_IDS+=("$spId")
#         RESOURCE_TYPES["$spId"]="ServicePrincipal"
#         RESOURCE_DETAILS["$spId"]="$spName|ServicePrincipal|Tenant|$spId"
#         RESOURCES_FOUND=true
        
#         # Also add the associated Enterprise App if we found the App ID
#         # if [[ -n "$appId" && "$appId" != "null" ]]; then
#         #     # Check if we already have this Enterprise App
#         #     if [[ ! " ${ALL_IDS[@]} " =~ " ${appId} " ]]; then
#         #         echo "  → Found associated Enterprise Application: $(safe_highlight "$spName" "$NAME_PATTERN") ($appId)"
#         #         SUMMARY_ROWS+=("$spName|EnterpriseApplication|Tenant|AppID: $appId")
#         #         ALL_IDS+=("$appId")
#         #         RESOURCE_TYPES["$appId"]="EnterpriseApplication"
#         #         RESOURCE_DETAILS["$appId"]="$spName|EnterpriseApplication|Tenant|$appId"
#         #     fi
#         # fi
#     done <<< "$sps"
# }

# --- Enhanced Custom Role Discovery (from second script) ---
discover_custom_roles_enhanced() {
    log_info "Searching for custom roles..."
    
    local roles
    roles=$(az role definition list --custom-role-only true -o json | jq -r ".[] | select((.roleName|test(\"$NAME_PATTERN\";\"i\"))) | [.roleName,.name,(.assignableScopes|length)] | @tsv")
    
    if [[ -z "$roles" ]]; then
        log_debug "No custom roles found matching pattern: $NAME_PATTERN"
        return
    fi

    
    while IFS=$'\t' read -r roleName roleId scope_count; do
        [[ -z "$roleName" ]] && continue
        
        # Clean the role name of any actual color codes before processing
        local clean_roleName=$(echo "$roleName" | sed -E 's/\x1B\[[0-9;]*[mGK]//g')
        
        # Use safe highlighting that won't break on weird role names
        local displayed_name
        displayed_name=$(safe_highlight "$clean_roleName" "$NAME_PATTERN")
        
        echo "  → Found Custom Role: $displayed_name ($roleId)"
        
        SUMMARY_ROWS+=("$clean_roleName|CustomRole|Tenant|Scopes: $scope_count")
        ALL_IDS+=("$roleId")
        RESOURCE_TYPES["$roleId"]="CustomRole"
        RESOURCE_DETAILS["$roleId"]="$clean_roleName|CustomRole|Tenant|$roleId"
        RESOURCES_FOUND=true
    done <<< "$roles"
}

# --- Enhanced Role Assignment Handling (from second script) ---
discover_role_assignments_for_custom_roles() {
    log_info "Discovering role assignments for custom roles..."
    
    # Get all custom roles matching our pattern first
    local custom_roles
    custom_roles=$(az role definition list --custom-role-only true --query "[?contains(roleName, '$SANITIZED_PATTERN')].name" -o tsv 2>/dev/null || echo "")
    
    if [[ -z "$custom_roles" ]]; then
        log_debug "No custom roles found for pattern: $NAME_PATTERN"
        return
    fi
    
    for role_id in $custom_roles; do
        [[ -z "$role_id" ]] && continue
        
        # Get role details
        local role_info
        role_info=$(az role definition show --name "$role_id" -o json 2>/dev/null || echo "{}")
        local role_name
        role_name=$(echo "$role_info" | jq -r '.roleName // ""')
        
        if [[ -z "$role_name" ]]; then
            continue
        fi
        
        log_debug "Checking assignments for role: $role_name"
        
        # Find role assignments for this custom role
        local assignments
        assignments=$(az role assignment list --all --query "[?contains(roleDefinitionId, '$role_id')]" -o json 2>/dev/null || echo '[]')
        
        while IFS= read -r assignment; do
            [[ -z "$assignment" ]] && continue
            
            local principal_name assignment_id scope principal_type
            principal_name=$(jq -r '.principalName // "Unknown"' <<< "$assignment")
            assignment_id=$(jq -r '.id // ""' <<< "$assignment")
            scope=$(jq -r '.scope // ""' <<< "$assignment")
            principal_type=$(jq -r '.principalType // ""' <<< "$assignment")
            
            # Skip if we already have this assignment
            if [[ ! " ${ALL_IDS[@]} " =~ " ${assignment_id} " ]]; then
                echo "  → Found Role Assignment: $(safe_highlight "$principal_name" "$NAME_PATTERN") ($principal_type for $role_name)"
                SUMMARY_ROWS+=("$principal_name|RoleAssignment|$scope|Role: $role_name")
                ALL_IDS+=("$assignment_id")
                RESOURCE_TYPES["$assignment_id"]="RoleAssignment"
                RESOURCE_DETAILS["$assignment_id"]="$principal_name|RoleAssignment|$scope|$role_name"
                RESOURCES_FOUND=true
            fi
        done < <(jq -c '.[]' <<< "$assignments")
        
        # Also check for "Unknown" type assignments (edge case)
        local unknown_assignments
        unknown_assignments=$(az role assignment list --all -o json 2>/dev/null | jq -r ".[] | select(.roleDefinitionName==\"Unknown\" and (.roleDefinitionId|contains(\"$role_id\"))) | .id" 2>/dev/null || echo "")
        
        for assignment_id in $unknown_assignments; do
            [[ -z "$assignment_id" ]] && continue
            
            if [[ ! " ${ALL_IDS[@]} " =~ " ${assignment_id} " ]]; then
                echo "  → Found Unknown Role Assignment: $role_name (Orphaned)"
                SUMMARY_ROWS+=("$role_name|UnknownRoleAssignment|Orphaned|Role: $role_name")
                ALL_IDS+=("$assignment_id")
                RESOURCE_TYPES["$assignment_id"]="UnknownRoleAssignment"
                RESOURCE_DETAILS["$assignment_id"]="$role_name|UnknownRoleAssignment|Orphaned|$role_name"
                RESOURCES_FOUND=true
            fi
        done
    done
}



# --- Enhanced Role Assignment Deletion ---
delete_role_assignment_enhanced() {
    local ROLE_ID="$1"
    local ROLE_NAME="$2"

    log_info "Checking for role assignments linked to role: ${ROLE_NAME} (${ROLE_ID})"

    local ASSIGNMENTS
    ASSIGNMENTS=$(az role assignment list --all --query "[?contains(roleDefinitionId,'${ROLE_ID}')]" -o json | jq -r '.[]?.id // empty')

    if [[ -z "$ASSIGNMENTS" ]]; then
        log_info "No direct matches found. Checking for Unknown-type role assignments..."
        ASSIGNMENTS=$(az role assignment list --all -o json | jq -r ".[] | select(.roleDefinitionName==\"Unknown\" and (.roleDefinitionId|contains(\"${ROLE_ID}\"))) | .id")
    fi

    if [[ -z "$ASSIGNMENTS" ]]; then
        log_info "No role assignments existed for ${ROLE_NAME}."
        return
    fi

    log_info "Found assignments:"
    echo "$ASSIGNMENTS"

    while read -r ASSIGN_ID; do
        [[ -z "$ASSIGN_ID" ]] && continue
        log_info "Deleting role assignment: ${ASSIGN_ID}"
        az role assignment delete --ids "$ASSIGN_ID" || log_warning "Failed to delete $ASSIGN_ID (might be orphaned)"
    done <<< "$ASSIGNMENTS"

    local REMAINING
    REMAINING=$(az role assignment list --all --query "[?contains(roleDefinitionId,'${ROLE_ID}')]" -o tsv)
    if [[ -z "$REMAINING" ]]; then
        log_success "All role assignments for ${ROLE_NAME} deleted successfully"
    else
        log_error "Some role assignments still remain for ${ROLE_NAME}"
    fi
}


delete_directory_diagnostic_setting() {
    local setting_id="$1"
    local setting_name="$2"
    
    log_special "Deleting Azure AD Diagnostic Setting: $setting_name (Default Directory)"
    
    # Use your working API pattern
    local result
    result=$(az rest --method delete \
        --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/${setting_name}?api-version=2017-04-01-preview" \
        2>&1)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "Successfully deleted Azure AD Diagnostic Setting: $setting_name"
        return 0
    else
        log_error "❌ Failed to delete Azure AD Diagnostic Setting: $setting_name"
        log_error "Error: $result"
        
        if [[ "$result" == *"Permission"* ]] || [[ "$result" == *"authorized"* ]]; then
            log_error "🔐 Insufficient permissions to delete Azure AD diagnostic settings."
            log_error "Required permission: microsoft.aadiam/diagnosticSettings/delete"
            log_error "Contact your Azure administrator for the required permissions."
        elif [[ "$result" == *"not found"* ]]; then
            log_warning "⚠️  Azure AD diagnostic setting not found (may have been deleted already)"
            return 0
        fi
        
        return 1
    fi
}


# --- Enhanced Custom Role Deletion (edge case) ---
delete_custom_role_enhanced() {
    local role_id="$1"
    local role_name="$2"
    
    log_info "Attempting to delete Custom Role: $role_name (ID: $role_id)"
    
    local role_info
    role_info=$(az role definition list --custom-role-only true --query "[?name=='$role_id'] | [0]" -o json 2>/dev/null || echo "{}")
    
    if [[ "$role_info" == "{}" || "$role_info" == "null" ]]; then
        log_warning "Custom Role not found: $role_name (ID: $role_id)"
        return 1
    fi
    
    local actual_role_name
    actual_role_name=$(echo "$role_info" | jq -r '.roleName // ""')
    local role_scope
    role_scope=$(echo "$role_info" | jq -r '.assignableScopes[0] // ""')
    
    if [[ -z "$actual_role_name" ]]; then
        log_error "Could not retrieve role information for ID: $role_id"
        return 1
    fi
    
    log_info "Found Custom Role: $actual_role_name (Scope: $role_scope)"
    
    local result
    local exit_code
    
    if [[ -n "$role_scope" && "$role_scope" != "null" ]]; then
        log_info "Deleting role using scope: $role_scope"
        result=$(az role definition delete --name "$role_id" --scope "$role_scope" 2>&1)
        exit_code=$?
    else
        result=$(az role definition delete --name "$role_id" 2>&1) || true
        exit_code=$?
        if [[ $exit_code -ne 0 ]]; then
            local current_sub
            current_sub=$(az account show --query id -o tsv)
            role_scope="/subscriptions/$current_sub"
            log_info "Retrying with subscription scope: $role_scope"
            result=$(az role definition delete --name "$role_id" --scope "$role_scope" 2>&1)
            exit_code=$?
        fi
    fi
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "Successfully deleted Custom Role: $actual_role_name"
        return 0
    else
        log_error "Failed to delete Custom Role: $actual_role_name"
        log_warning "Error: $result"
        
        if [[ "$result" == *"scope"* ]]; then
            log_info "Trying alternative role deletion approach..."
            try_alternative_role_deletion "$role_id" "$role_name"
        fi
    fi
}

# --- Alternative Role Deletion Helper ---
try_alternative_role_deletion() {
    local role_id="$1"
    local role_name="$2"
    
    log_info "Trying alternative method to delete role: $role_name"
    
    local all_custom_roles
    all_custom_roles=$(az role definition list --custom-role-only true -o json 2>/dev/null || echo "[]")
    
    local role_info
    role_info=$(echo "$all_custom_roles" | jq -r ".[] | select(.name == \"$role_id\")")
    
    if [[ -z "$role_info" || "$role_info" == "null" ]]; then
        log_warning "Role not found in custom roles list: $role_name"
        return 1
    fi
    
    local scopes
    scopes=$(echo "$role_info" | jq -r '.assignableScopes[]?')
    
    if [[ -z "$scopes" ]]; then
        log_error "No assignable scopes found for role: $role_name"
        return 1
    fi
    
    local deleted=false
    while IFS= read -r scope; do
        [[ -z "$scope" ]] && continue
        log_info "Trying to delete with scope: $scope"
        local result
        result=$(az role definition delete --name "$role_id" --scope "$scope" 2>&1)
        
        if [[ $? -eq 0 ]]; then
            log_success "Successfully deleted Custom Role: $role_name using scope: $scope"
            deleted=true
            break
        else
            log_warning "Failed to delete with scope $scope: $result"
        fi
    done <<< "$scopes"
    
    if [[ "$deleted" == true ]]; then
        return 0
    else
        log_error "All deletion attempts failed for role: $role_name"
        return 1
    fi
}

# --- Deletion Functions ---
delete_with_retry() {
    local id="$1"
    local type="$2"
    local max_retries=3
    local retry_delay=10
    
    for ((retry=1; retry<=max_retries; retry++)); do
        if az resource delete --ids "$id" --no-wait 2>/dev/null; then
            log_success "Delete command issued for $type: $(basename "$id")"
            return 0
        else
            log_warning "Attempt $retry failed for $type: $(basename "$id")"
            if [[ $retry -eq $max_retries ]]; then
                log_error "Failed to delete $type after $max_retries attempts: $(basename "$id")"
                return 1
            fi
            sleep $retry_delay
        fi
    done
}

delete_management_group_role_assignment() {
    local assignment_id="$1"
    local assignment_name="$2"
    
    log_special "Deleting Management Group Role Assignment: $assignment_name"
    
    if az role assignment delete --ids "$assignment_id" 2>/dev/null; then
        log_success "Deleted Management Group Role Assignment: $assignment_name"
        return 0
    else
        log_error "Failed to delete Management Group Role Assignment: $assignment_name"
        return 1
    fi
}

delete_subscription_role_assignment() {
    local assignment_id="$1"
    local assignment_name="$2"
    
    log_special "Deleting Subscription Role Assignment: $assignment_name"
    
    if az role assignment delete --ids "$assignment_id" 2>/dev/null; then
        log_success "Deleted Subscription Role Assignment: $assignment_name"
        return 0
    else
        log_error "Failed to delete Subscription Role Assignment: $assignment_name"
        return 1
    fi
}

delete_policy_assignment() {
    local assignment_id="$1"
    local assignment_name="$2"
    local assignment_scope="$3"
    
    log_special "Deleting Policy Assignment: $assignment_name (Scope: $assignment_scope)"
    
    local result
    result=$(az policy assignment delete --name "$(basename "$assignment_id")" --scope "$assignment_scope" 2>&1)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "Successfully deleted Policy Assignment: $assignment_name"
        return 0
    else
        log_error "❌ Failed to delete Policy Assignment: $assignment_name"
        log_error "Exit code: $exit_code"
        log_error "Error output: $result"
        
        if [[ "$result" == *"Permission"* ]] || [[ "$result" == *"authorized"* ]] || [[ "$result" == *"access"* ]]; then
            log_error "🔐 Insufficient permissions to delete policy assignment."
            log_error "Required permission: Microsoft.Authorization/policyAssignments/delete"
            log_error "Contact your Azure administrator for the required permissions."
        elif [[ "$result" == *"not found"* ]]; then
            log_warning "⚠️  Policy assignment not found (may have been deleted by another process)"
            return 0
        else
            log_error "💥 Unknown error occurred. Please check the error message above."
        fi
        
        return 1
    fi
}

delete_policy_remediation() {
    local remediation_id="$1"
    local remediation_name="$2"
    
    log_special "Deleting Policy Remediation: $remediation_name"
    
    if az policy remediation delete --ids "$remediation_id" 2>/dev/null; then
        log_success "Deleted Policy Remediation: $remediation_name"
        return 0
    else
        log_error "Failed to delete Policy Remediation: $remediation_name"
        return 1
    fi
}

delete_management_group_deployment() {
    local deployment_id="$1"
    local deployment_name="$2"
    local mg_id="$3"
    
    log_special "Deleting Management Group Deployment: $deployment_name"
    
    if az deployment mg delete --name "$deployment_name" --management-group-id "$mg_id" 2>/dev/null; then
        log_success "Deleted Management Group Deployment: $deployment_name"
        return 0
    else
        log_error "Failed to delete Management Group Deployment: $deployment_name"
        return 1
    fi
}

delete_service_principal() {
    local sp_id="$1"
    local sp_name="$2"
    
    log_info "Processing Service Principal: $sp_name"
    
    # Check if SP still exists
    if ! az ad sp show --id "$sp_id" &>/dev/null; then
        log_success "Service Principal already deleted: $sp_name"
        return 0
    fi
    
    # Remove role assignments
    local assignment_count=0
    while IFS= read -r assignment_id; do
        [[ -z "$assignment_id" ]] && continue
        ((assignment_count++))
        log_debug "Removing role assignment: $assignment_id"
        az role assignment delete --ids "$assignment_id" 2>/dev/null || true
    done < <(az role assignment list --assignee "$sp_id" --query "[].id" -o tsv 2>/dev/null)
    
    if [[ $assignment_count -gt 0 ]]; then
        log_success "Removed $assignment_count role assignments from $sp_name"
    fi
    
    # Try to delete associated application first
    local app_id
    app_id=$(az ad sp show --id "$sp_id" --query "appId" -o tsv 2>/dev/null || echo "")
    if [[ -n "$app_id" ]]; then
        log_debug "Attempting to delete associated application: $app_id"
        if az ad app delete --id "$app_id" 2>/dev/null; then
            log_success "Deleted associated application: $app_id"
            sleep 5  # Wait for propagation
        fi
    fi
    
    # Delete service principal
    if az ad sp delete --id "$sp_id" 2>/dev/null; then
        log_success "Deleted Service Principal: $sp_name"
    else
        log_error "Failed to delete Service Principal: $sp_name"
        return 1
    fi
}

delete_resource_group() {
    local rg_id="$1"
    local rg_name="$2"
    local sub_id="$3"
    
    log_warning "Resource Group detected: $rg_name (contains ALL resources within it)"
    
    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would delete resource group: $rg_name"
        return 0
    fi
    
    # Confirm deletion for resource groups
    if [[ "$DELETE_MODE" == true ]]; then
        read -p "Delete this resource group and ALL its contents? (yes/no): " rg_confirm
        if [[ "$rg_confirm" != "yes" ]]; then
            log_warning "Skipped deletion of Resource Group: $rg_name"
            return 0
        fi
    fi
    
    if az group delete --name "$rg_name" --subscription "$sub_id" --yes --no-wait 2>/dev/null; then
        log_success "Delete command issued for Resource Group: $rg_name"
        return 0  # Signal success
    else
        log_error "Failed to delete Resource Group: $rg_name"
        return 1  # Signal failure
    fi
}

# --- Confirmation Function ---
confirm_delete() {
    echo
    log_error "WARNING: You are about to DELETE ${#ALL_IDS[@]} resource(s)"
    log_error "This operation cannot be undone!"
    echo
    
    read -p "Are you absolutely sure you want to proceed? (type 'DELETE' to confirm): " confirmation
    if [[ "$confirmation" != "DELETE" ]]; then
        log_warning "Deletion aborted"
        exit 0
    fi
}

# --- Main Execution ---
main() {
    echo
    log_info "Searching for resources containing: ${YELLOW}${NAME_PATTERN}${NC}"
    echo "--------------------------------------------------------"
    
    # Get current subscription context
    CURRENT_SUB=$(az account show --query id -o tsv)
    
    # Get subscriptions
    local subscriptions
    subscriptions=$(get_subscriptions)
    if [[ -z "$subscriptions" ]]; then
        log_error "No subscriptions found"
        exit 1
    fi
    
    # Discover resources across subscriptions
    while IFS= read -r sub; do
        if [[ -z "$sub" ]]; then
            continue
        fi
        
        # Set subscription context
        if az account set --subscription "$sub" >/dev/null 2>&1; then
            local sub_name
            sub_name=$(az account show --subscription "$sub" --query 'name' -o tsv 2>/dev/null || echo "Unknown")
            discover_resources "$sub" "$sub_name"
            discover_subscription_role_assignments "$sub" "$sub_name"

        else

        log_info "Accessed subscription: $sub"

        fi
    done <<< "$subscriptions"
    
    # Switch back to original subscription
    az account set --subscription "$CURRENT_SUB" >/dev/null 2>&1
    
    # Discover tenant-level resources
    discover_management_group_role_assignments
    discover_management_group_deployments
    discover_policy_assignments
    discover_policy_remediations
    discover_directory_diagnostic_settings
    
    # --- Enhanced Custom Role Discovery ---
    discover_custom_roles_enhanced
    discover_role_assignments_for_custom_roles
    # discover_enterprise_apps
    #discover_service_principals
    
    echo ""
    echo "========================================================="
    
    # --- Summary Table ---
    if [[ "$RESOURCES_FOUND" == "false" ]]; then
        log_success "No matching resources found"
        echo "========================================================="
        echo ""
        exit 0
    fi
    echo "                      Summary Table                      "
    echo "========================================================="
    
    log_success "Found ${#ALL_IDS[@]} matching resource(s)"
    echo
    printf "%-60s %-50s %-25s %-40s\n" "NAME" "TYPE" "SCOPE" "DETAILS"
    printf "%-60s %-50s %-25s %-40s\n" "------------------------------------------------------------" "--------------------------------------------------" "-------------------------" "----------------------------------------"
    
    for row in "${SUMMARY_ROWS[@]}"; do
        IFS="|" read -r name type scope details <<< "$row"
        # Clean names for summary table
        clean_name=$(echo "$name" | sed -E 's/\x1B\[[0-9;]*[mGK]//g')
        printf "%-60s %-50s %-25s %-40s\n" "$clean_name" "$type" "$scope" "$details"
    done
    
    # --- Deletion Logic ---
    if [[ "$DRY_RUN" == true ]]; then
        echo
        log_info "IT'S DRY RUN MODE: No resources have been deleted"
        log_info "To delete these resources, run with: --delete"
        exit 0
    fi
    
    confirm_delete
    log_info "Starting ordered deletion process..."
    
    # Ordered deletion by dependency
    local deleted_count=0
    local failed_count=0
    
    # Phase 1: Management Group Deployments
    for id in "${ALL_IDS[@]}"; do
        if [[ "${RESOURCE_TYPES[$id]}" == "ManagementGroupDeployment" ]]; then
            IFS="|" read -r name type scope <<< "${RESOURCE_DETAILS[$id]}"
            if delete_management_group_deployment "$id" "$name" "$scope"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    
    # Phase 2: Policy Remediations
    for id in "${ALL_IDS[@]}"; do
        if [[ "${RESOURCE_TYPES[$id]}" == "PolicyRemediation" ]]; then
            IFS="|" read -r name type scope <<< "${RESOURCE_DETAILS[$id]}"
            if delete_policy_remediation "$id" "$name"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    
    # Phase 3: Policy Assignments
    for id in "${ALL_IDS[@]}"; do
        if [[ "${RESOURCE_TYPES[$id]}" == "PolicyAssignment" ]]; then
            IFS="|" read -r name type scope assignment_name <<< "${RESOURCE_DETAILS[$id]}"
            if delete_policy_assignment "$id" "$name" "$scope"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    
    # Phase 4: Management Group Role Assignments
    for id in "${ALL_IDS[@]}"; do
        if [[ "${RESOURCE_TYPES[$id]}" == "ManagementGroupRoleAssignment" ]]; then
            IFS="|" read -r name type scope <<< "${RESOURCE_DETAILS[$id]}"
            if delete_management_group_role_assignment "$id" "$name"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    

    # Phase 5: Azure AD (Default Directory) Diagnostic Settings
    for id in "${ALL_IDS[@]}"; do
        local resource_type
        if [[ "$BASH_VERSINFO" -ge 4 ]]; then
            resource_type="${RESOURCE_TYPES[$id]}"
        else
            resource_type=$(get_resource_type "$id")
        fi
        
        if [[ "$resource_type" == "DirectoryDiagnosticSetting" ]]; then
            local details
            if [[ "$BASH_VERSINFO" -ge 4 ]]; then
                details="${RESOURCE_DETAILS[$id]}"
            else
                details=$(get_resource_details "$id")
            fi
            
            IFS="|" read -r name type scope <<< "$details"
            if delete_directory_diagnostic_setting "$id" "$name"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done


    # Phase 6: Subscription Role Assignments
    for id in "${ALL_IDS[@]}"; do
        if [[ "${RESOURCE_TYPES[$id]}" == "SubscriptionRoleAssignment" ]]; then
            IFS="|" read -r name type scope <<< "${RESOURCE_DETAILS[$id]}"
            if delete_subscription_role_assignment "$id" "$name"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    
    # Phase 7: Role Assignments (from custom roles - enhanced)
    for id in "${ALL_IDS[@]}"; do
        if [[ "${RESOURCE_TYPES[$id]}" == "RoleAssignment" || "${RESOURCE_TYPES[$id]}" == "UnknownRoleAssignment" ]]; then
            IFS="|" read -r name type scope role_name <<< "${RESOURCE_DETAILS[$id]}"
            log_special "Deleting Role Assignment: $name for role $role_name"
            if az role assignment delete --ids "$id" 2>/dev/null; then
                log_success "Deleted Role Assignment: $name"
                ((deleted_count++))
            else
                log_error "Failed to delete Role Assignment: $name"
                ((failed_count++))
            fi
        fi
    done
    
    # Phase 8: Enterprise Applications
    for id in "${ALL_IDS[@]}"; do
        if [[ "${RESOURCE_TYPES[$id]}" == "EnterpriseApplication" ]]; then
            IFS="|" read -r name type scope <<< "${RESOURCE_DETAILS[$id]}"
            log_info "Deleting Enterprise Application: $name"
            if az ad app delete --id "$id" 2>/dev/null; then
                log_success "Deleted Enterprise Application: $name"
                ((deleted_count++))
            else
                log_error "Failed to delete Enterprise Application: $name"
                ((failed_count++))
            fi
        fi
    done
    
    # Phase 9: Regular Resources (EXCLUDE DirectoryDiagnosticSetting)
    for id in "${ALL_IDS[@]}"; do
        local resource_type
        if [[ "$BASH_VERSINFO" -ge 4 ]]; then
            resource_type="${RESOURCE_TYPES[$id]}"
        else
            resource_type=$(get_resource_type "$id")
        fi
        
        # EXCLUDE these resource types from regular resource processing
        if [[ "$resource_type" != "ResourceGroup" && \
              "$resource_type" != "CustomRole" && \
              "$resource_type" != "EnterpriseApplication" && \
              "$resource_type" != "ServicePrincipal" && \
              "$resource_type" != "ManagementGroupRoleAssignment" && \
              "$resource_type" != "SubscriptionRoleAssignment" && \
              "$resource_type" != "RoleAssignment" && \
              "$resource_type" != "UnknownRoleAssignment" && \
              "$resource_type" != "PolicyAssignment" && \
              "$resource_type" != "PolicyRemediation" && \
              "$resource_type" != "ManagementGroupDeployment" && \
              "$resource_type" != "DirectoryDiagnosticSetting" && \          
              "$resource_type" != "DiagnosticSetting" && \                    
              "$resource_type" != "SubscriptionDiagnosticSetting" ]]; then    
            IFS="|" read -r name type sub <<< "${RESOURCE_DETAILS[$id]}"
            log_info "Deleting Resource: $name ($type)"
            if delete_with_retry "$id" "$type"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    
    # Phase 10: Regular Resources (excluding resource groups and already handled types)
    for id in "${ALL_IDS[@]}"; do
        local type="${RESOURCE_TYPES[$id]}"
        if [[ "$type" != "ResourceGroup" && \
              "$type" != "CustomRole" && \
              "$type" != "EnterpriseApplication" && \
              "$type" != "ServicePrincipal" && \
              "$type" != "ManagementGroupRoleAssignment" && \
              "$type" != "SubscriptionRoleAssignment" && \
              "$type" != "RoleAssignment" && \
              "$type" != "UnknownRoleAssignment" && \
              "$type" != "PolicyAssignment" && \
              "$type" != "PolicyRemediation" && \
              "$type" != "ManagementGroupDeployment" ]]; then
            IFS="|" read -r name type sub <<< "${RESOURCE_DETAILS[$id]}"
            log_info "Deleting Resource: $name ($type)"
            if delete_with_retry "$id" "$type"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    
    # Phase 11: Service Principals 
    for id in "${ALL_IDS[@]}"; do
        if [[ "${RESOURCE_TYPES[$id]}" == "ServicePrincipal" ]]; then
            IFS="|" read -r name type scope <<< "${RESOURCE_DETAILS[$id]}"
            if delete_service_principal "$id" "$name"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    
    # Phase 12: Resource Groups (last - contains other resources)
    for id in "${ALL_IDS[@]}"; do
        if [[ "${RESOURCE_TYPES[$id]}" == "ResourceGroup" ]]; then
            local rg_name sub_id
            rg_name=$(echo "$id" | awk -F/ '{print $NF}')
            sub_id="${RG_SUBSCRIPTION[$id]}"
            if delete_resource_group "$id" "$rg_name" "$sub_id"; then
                ((deleted_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    
    # Final summary
    echo
    if [[ $failed_count -eq 0 ]]; then
        echo "========================================================="
        log_success "Deletion commands issued for $deleted_count resource(s)"
        echo "========================================================="
    else
        log_warning "Deletion completed with $failed_count failure(s)"
        log_success "Successfully processed $deleted_count resource(s)"
    fi
    log_warning "Note: Some deletions may run asynchronously. Check Azure Portal for final status."
    echo ""
}

# Run main function
main "$@"
