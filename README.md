# Azure Resource Cleanup Tool

A comprehensive Bash script for discovering and cleaning up Azure resources across all scopes (Resource, Subscription, Management Group, and Tenant levels). Perfect for Tenant/Management Group/Subscription off-boarding and re-onboarding scenarios.

## 🚀 Features

- **🔍 Comprehensive Discovery**: Searches across all Azure scopes for resources matching name patterns
- **🛡️ Safety First**: Dry-run mode by default with explicit confirmation prompts
- **🗑️ Safe Deletion**: Dependency-aware deletion order to prevent conflicts
- **🎯 Multi-Resource Support**: Handles 15+ Azure resource types
- **⚡ Edge Case Handling**: Manages 'Unknown' role assignments, scope mismatches, and orphaned resources

## 📋 Supported Resource Types

| Resource Type | Discovery | Deletion |
|---------------|-----------|----------|
| Resources & Resource Groups | ✅ | ✅ |
| Custom Roles & Role Assignments | ✅ | ✅ |
| Policy Assignments & Definitions | ✅ | ✅ |
| Policy Remediations | ✅ | ✅ |
| Enterprise Applications | ✅ | ✅ |
| Service Principals | ✅ | ✅ |
| Managed Identities | ✅ | ✅ |
| Diagnostic Settings (All levels) | ✅ | ✅ |
| Management Group Deployments | ✅ | ✅ |
| Management Group Role Assignments | ✅ | ✅ |

## 🛠️ Prerequisites

### System Requirements
- **Bash**: Version 4.0 or higher (5.0+ recommended)
- **Azure CLI**: Version 2.0 or higher
- **jq**: JSON processor
- **column**: Table formatting utility (usually pre-installed)

### Installation Commands

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y jq bash
```

#### macOS
```bash
brew install jq
# Bash 5+ comes with modern macOS
```

#### RHEL/CentOS
```bash
sudo yum install -y jq
# Or for newer versions:
sudo dnf install -y jq
```

### Azure Permissions

#### Required Azure Roles
- **Owner** role is required on the Root Level

#### Azure Entra Permissions
- **Application Administrator** or **Global Administrator** (for Service Principals & Enterprise Apps)

## 📥 Installation

1. **Download the script**:
```bash
curl -fsSLo https://raw.githubusercontent.com/Cortex-Cloud/azure-cleanup-tool/main/azure-cleanup-tool.sh && chmod +x azure-cleanup-tool.sh
```

2. **Verify prerequisites**:
```bash
# Check Bash version (If your Bash version is old, scroll down to "Troubleshooting" for installation instructions.)
bash --version
# Should show: GNU bash, version 4.x or 5.x

# Check Azure CLI
az version
# Should show Azure CLI version 2.x+

# Check jq
jq --version
# Should show: jq-1.6 or similar

# Check column utility on MAC (different methods for different systems)
echo "test1 test2" | column -t 2>/dev/null && echo "✅ column is working" || echo "❌ column not functioning"

# Verify Azure login
az account show
```

3. **Login to Azure**:
```bash
az login

# If using specific tenant:
az login --tenant <your-tenant-id>
```

## 🎯 Usage

### Basic Usage
```bash
# Dry-run (recommended first step)
./azure-cleanup-tool.sh <resource-name> --dry-run
or
./azure-cleanup-tool.sh <resource-name>

# Actual deletion (with confirmation)
./azure-cleanup-tool.sh <resource-name> --delete
```

### Examples
```bash
# Discover all resources containing "cortex" and provide summary table.
./azure-cleanup-tool.sh cortex --dry-run

# Discover and lists all resources containing "cortex." As a safety feature, you will be prompted to type 'DELETE' to confirm before the resources are deleted.
./azure-cleanup-tool.sh cortex --delete

# Delete all resources containing "test" in specific subscription
./azure-cleanup-tool.sh test --subscription 12345-67890 --delete

# Show help message
./azure-cleanup-tool.sh --help
```

### Command Line Options
| Option | Description | Default |
|--------|-------------|---------|
| `<resource-name>` | Name pattern to search for (case-insensitive) | Required |
| `--delete` | Actually delete resources with confirmation (otherwise dry-run) | Dry-run |
| `--dry-run` | Only show what would be deleted | Enabled |
| `--subscription` | Limit search to specific subscription | All subscriptions |
| `--help` | Show help message | N/A |

## 🔧 How It Works

### Discovery Process
1. **Subscription Enumeration**: Discovers all accessible subscriptions
2. **Multi-Scope Search**: Searches resources at Resource, Subscription, Management Group, and Tenant levels
3. **Pattern Matching**: Case-insensitive search across all resource types
4. **Dependency Mapping**: Identifies relationships between resources

### Deletion Order
The script deletes resources in dependency order to prevent failures:
1. 🎯 Management Group Deployments
2. 🔧 Policy Remediations
3. 📋 Policy Assignments
4. 👥 Role Assignments
5. 🏷️ Custom Roles
6. 📊 Diagnostic Settings
7. 🔑 Enterprise Applications
8. ⚙️ Service Principals
9. 🗂️ Regular Resources
10. 📦 Resource Groups (last)

## 🛡️ Safety Features

- **Dry-run by default**: No accidental deletions
- **Explicit confirmation**: Required for destructive operations
- **Color-coded output**: Easy to understand status
- **Formatted tables**: Clear resource summaries
- **Error handling**: Comprehensive error messages with guidance
- **Retry logic**: Automatic retries for transient failures

## 🐛 Troubleshooting

### Common Issues

**Permission Errors**:
```bash
az login --tenant <tenant-id>
az account set --subscription <subscription-id>
```

**Missing jq**:
```bash
# Ubuntu/Debian
sudo apt-get install jq

# macOS
brew install jq

# Windows (WSL)
choco install jq
```

**Missing column**:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y bsdmainutils

# macOS
# column should be pre-installed, but if missing:
brew install util-linux

# RHEL/CentOS
sudo yum install -y util-linux-ng
```

**Bash Version Too Old**:
```bash
# macOS
brew install bash
echo '/usr/local/bin/bash' >> /etc/shells
```

### Debug Mode
For detailed debugging, run with:
```bash
bash -x azure-cleanup-tool.sh <resource-name> --dry-run
```

## 🤝 Contributing

We welcome contributions! Please feel free to submit issues, feature requests, or pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool performs destructive operations. Always:
1. Run with `--dry-run` first
2. Review the discovered resources
3. Ensure you have appropriate backups
4. Test in non-production environments first

The authors are not responsible for any data loss or unintended deletions.

---

**Happy Cleaning! 🧹**
