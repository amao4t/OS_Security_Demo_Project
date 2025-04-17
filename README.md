# OS Security Demo Project

This project provides a set of scripts for demonstrating OS security concepts for a group presentation.

## Components

1. **User Authentication and Access Control** (Duong Vu)
   - `user_auth.sh`: Script for user account management and access control demonstration
   
2. **File and Directory Permissions** (Cameron Tran)
   - `file_permissions.sh`: Script for demonstrating file permissions concepts
   - `permission_visualizer.sh`: Custom tool to visualize file and directory permissions
   
3. **Firewall Configuration and Security Auditing** (Adonis Jimenez)
   - `firewall_config.sh`: Script for firewall configuration demonstration
   - `security_audit.sh`: Script for running security audits and analysis

## Requirements

- Ubuntu 22.04 or compatible Linux distribution
- Root/sudo access for system configuration
- Required packages: ufw, lynis, chkrootkit

## Installation

```bash
# Clone the repository
git clone https://github.com/DuongVu/os-security-demo.git
cd os-security-demo

# Make all scripts executable
chmod +x *.sh
```

## Usage

1. Run the main demo script:
   ```bash
   sudo ./demo.sh
   ```
   
2. Or run individual components:
   ```bash
   sudo ./user_auth.sh
   sudo ./file_permissions.sh
   sudo ./firewall_config.sh
   sudo ./security_audit.sh
   ```

## Notes

- These scripts are designed for educational purposes only
- Always run security-related commands with caution in production environments
- Some features require root/sudo privileges 