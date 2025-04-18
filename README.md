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
git clone https://github.com/amao4t/OS_Security_Demo_Project.git
cd OS_Security_Demo_Project

# Make all scripts executable
chmod +x demo.sh user_auth.sh file_permissions.sh firewall_config.sh security_audit.sh

# install sudo required
sudo apt update
sudo apt install -y ufw acl
sudo apt install -y lynis chkrootkit
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

1. Always use sudo when running these scripts as they require root privileges
2. After the demo, use the "Cleanup" option in the main menu to remove all demo users and files
3. In the User Authentication section, the commands that create users and groups may require logging out and back in to apply some changes
4. The Firewall Configuration section will change actual firewall settings, so be careful when running in a production environment

- These scripts are designed for educational purposes only
- Always run security-related commands with caution in production environments
- Some features require root/sudo privileges 
