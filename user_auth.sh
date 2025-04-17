#!/bin/bash

# User Authentication and Access Control Demo Script
# Author: Duong Vu

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo"
  exit 1
fi

# Colors for better visualization
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Display header
clear
echo -e "${BLUE}==========================================================${NC}"
echo -e "${BLUE}      USER AUTHENTICATION AND ACCESS CONTROL DEMO         ${NC}"
echo -e "${BLUE}==========================================================${NC}"
echo -e "${YELLOW}Presenter: Duong Vu${NC}"
echo

# Function to display a section header
section() {
  echo
  echo -e "${GREEN}==== $1 ====${NC}"
  echo
}

# Function to demonstrate and explain a command
demo_cmd() {
  echo -e "${YELLOW}Command:${NC} $1"
  echo -e "${YELLOW}Explanation:${NC} $2"
  echo -e "${PURPLE}Executing...${NC}"
  eval "$1"
  echo
}

# Main menu for this component
show_auth_menu() {
  section "User Authentication and Access Control Menu"
  echo "1) Create demo users and groups"
  echo "2) Demonstrate password policies"
  echo "3) Demonstrate group-based access control"
  echo "4) Verify user permissions and group membership"
  echo "5) Interactive user privilege test"
  echo "6) Return to main menu"
  
  read -p "Select an option: " option
  echo
  
  case $option in
    1) create_users ;;
    2) password_policies ;;
    3) group_access_control ;;
    4) verify_permissions ;;
    5) interactive_test ;;
    6) return 0 ;;
    *) 
      echo "Invalid option"
      show_auth_menu
      ;;
  esac
  
  # Return to this menu after completing an action
  read -p "Press Enter to return to the User Auth menu..."
  show_auth_menu
}

# 1. Create users with different privilege levels
create_users() {
  section "Creating Demo Users and Groups"
  
  # Create groups
  demo_cmd "groupadd demo_admins" "Creating 'demo_admins' group for administrative users"
  demo_cmd "groupadd demo_users" "Creating 'demo_users' group for standard users"
  demo_cmd "groupadd demo_guests" "Creating 'demo_guests' group for restricted users"
  
  # Create admin user
  demo_cmd "useradd -m -c 'Demo Administrator' -s /bin/bash -G sudo,demo_admins demo_admin" "Creating administrator user with sudo privileges"
  demo_cmd "echo 'demo_admin:Admin123!' | chpasswd" "Setting password for admin user"
  
  # Create standard user
  demo_cmd "useradd -m -c 'Demo Standard User' -s /bin/bash -G demo_users demo_user" "Creating standard user"
  demo_cmd "echo 'demo_user:User123!' | chpasswd" "Setting password for standard user"
  
  # Create guest user with restricted shell
  demo_cmd "useradd -m -c 'Demo Guest User' -s /bin/rbash -G demo_guests demo_guest" "Creating guest user with restricted bash shell"
  demo_cmd "echo 'demo_guest:Guest123!' | chpasswd" "Setting password for guest user"
  
  echo -e "${GREEN}Successfully created demo users and groups!${NC}"
}

# 2. Demonstrate password policies
password_policies() {
  section "Password Policies and Security"
  
  # Show current password policy settings
  demo_cmd "grep -E '(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs" "Current password aging policy"
  
  # Demonstrate PAM password quality settings
  if [ -f /etc/pam.d/common-password ]; then
    demo_cmd "grep 'pam_pwquality.so' /etc/pam.d/common-password" "PAM password quality settings"
  else
    echo "PAM password quality module configuration not found"
  fi
  
  # Demonstrate setting password expiration for a user
  demo_cmd "chage -l demo_user" "Current password expiration settings for demo_user"
  demo_cmd "chage -M 90 -m 7 -W 14 demo_user" "Setting password to expire in 90 days with 14 days warning"
  demo_cmd "chage -l demo_user" "Updated password expiration settings for demo_user"
  
  # Demonstrate password complexity requirements
  echo -e "${YELLOW}Password Complexity Guidelines:${NC}"
  echo "1. Minimum 8 characters"
  echo "2. Must include uppercase, lowercase, numbers, and symbols"
  echo "3. Cannot contain username or easy-to-guess patterns"
  echo "4. Must not be a commonly used password"
  
  echo -e "${GREEN}Note: In a production environment, you would use PAM modules like pam_pwquality.so to enforce these policies.${NC}"
}

# 3. Group-based access control
group_access_control() {
  section "Group-Based Access Control"
  
  # Create test directories with different permissions
  demo_cmd "mkdir -p /opt/demo_files/{admin,user,shared}" "Creating test directories for access control demo"
  
  # Set ownership and permissions
  demo_cmd "chown -R root:demo_admins /opt/demo_files/admin" "Setting admin directory ownership"
  demo_cmd "chmod 770 /opt/demo_files/admin" "Setting admin directory permissions to 770 (rwxrwx---)"
  
  demo_cmd "chown -R root:demo_users /opt/demo_files/user" "Setting user directory ownership"
  demo_cmd "chmod 770 /opt/demo_files/user" "Setting user directory permissions to 770 (rwxrwx---)"
  
  demo_cmd "chown -R root:root /opt/demo_files/shared" "Setting shared directory ownership"
  demo_cmd "chmod 775 /opt/demo_files/shared" "Setting shared directory permissions to 775 (rwxrwxr-x)"
  
  # Create test files in each directory
  demo_cmd "echo 'Admin-only content' > /opt/demo_files/admin/admin_file.txt" "Creating admin test file"
  demo_cmd "echo 'User-level content' > /opt/demo_files/user/user_file.txt" "Creating user test file"
  demo_cmd "echo 'Shared content' > /opt/demo_files/shared/shared_file.txt" "Creating shared test file"
  
  # Add shared access for demo_users to shared directory
  demo_cmd "setfacl -m g:demo_users:rx /opt/demo_files/shared" "Adding ACL for demo_users to access shared directory"
  
  echo -e "${GREEN}Group-based access control has been configured.${NC}"
}

# 4. Verify user permissions and group membership
verify_permissions() {
  section "Verifying User Permissions and Group Membership"
  
  # Show group membership
  demo_cmd "groups demo_admin" "Groups for demo_admin user"
  demo_cmd "groups demo_user" "Groups for demo_user user"
  demo_cmd "groups demo_guest" "Groups for demo_guest user"
  
  # Show directory permissions
  demo_cmd "ls -la /opt/demo_files/" "Directory permissions for demo files"
  
  # Test access as different users
  echo -e "${YELLOW}Testing access as demo_admin:${NC}"
  demo_cmd "sudo -u demo_admin ls -la /opt/demo_files/admin" "Admin should have access to admin directory"
  demo_cmd "sudo -u demo_admin ls -la /opt/demo_files/shared" "Admin should have access to shared directory"
  
  echo -e "${YELLOW}Testing access as demo_user:${NC}"
  demo_cmd "sudo -u demo_user ls -la /opt/demo_files/user 2>&1 || echo 'Access denied as expected'" "User should have access to user directory"
  demo_cmd "sudo -u demo_user ls -la /opt/demo_files/admin 2>&1 || echo 'Access denied as expected'" "User should NOT have access to admin directory"
  
  echo -e "${YELLOW}Testing access as demo_guest:${NC}"
  demo_cmd "sudo -u demo_guest ls -la /opt/demo_files/shared 2>&1 || echo 'Access denied as expected'" "Guest should have limited access"
  
  # Show sudo capabilities
  demo_cmd "sudo -l -U demo_admin" "Sudo privileges for demo_admin"
  demo_cmd "sudo -l -U demo_user" "Sudo privileges for demo_user (should be none)"
}

# 5. Interactive user privilege test
interactive_test() {
  section "Interactive User Privilege Test"
  
  echo -e "${YELLOW}This test demonstrates how different users have different privileges.${NC}"
  echo "We'll create a test file and attempt to access it as different users."
  
  # Create a test file with root permissions
  echo "This is a root-owned file" > /tmp/root_test.txt
  chmod 600 /tmp/root_test.txt
  
  # Try to access as different users
  echo -e "${BLUE}Attempting to read file as root:${NC}"
  cat /tmp/root_test.txt
  
  echo -e "${BLUE}Attempting to read file as demo_admin:${NC}"
  sudo -u demo_admin cat /tmp/root_test.txt 2>&1 || echo "Access denied as expected"
  
  echo -e "${BLUE}Attempting to read file as demo_user:${NC}"
  sudo -u demo_user cat /tmp/root_test.txt 2>&1 || echo "Access denied as expected"
  
  # Change permissions to allow group read
  chmod 640 /tmp/root_test.txt
  chown root:demo_admins /tmp/root_test.txt
  
  echo -e "${GREEN}Changed file permissions to allow demo_admins group to read it${NC}"
  
  echo -e "${BLUE}Attempting to read file as demo_admin again:${NC}"
  sudo -u demo_admin cat /tmp/root_test.txt 2>&1 || echo "Access denied"
  
  echo -e "${BLUE}Attempting to read file as demo_user again:${NC}"
  sudo -u demo_user cat /tmp/root_test.txt 2>&1 || echo "Access denied as expected"
  
  # Cleanup
  rm /tmp/root_test.txt
}

# Start the component menu
show_auth_menu 