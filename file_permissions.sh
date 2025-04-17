#!/bin/bash

# File and Directory Permissions Demo Script
# Author: Cameron Tran (Demo created by Duong Vu)

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
echo -e "${BLUE}          FILE AND DIRECTORY PERMISSIONS DEMO             ${NC}"
echo -e "${BLUE}==========================================================${NC}"
echo -e "${YELLOW}Presenter: Cameron Tran${NC}"
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

# Function to explain file permissions
explain_permissions() {
  local perms=$1
  local type=${perms:0:1}
  local user=${perms:1:3}
  local group=${perms:4:3}
  local others=${perms:7:3}
  
  echo -e "${YELLOW}Permission explained:${NC} $perms"
  
  # File type
  case $type in
    d) echo -e "File type: ${GREEN}Directory${NC}" ;;
    -) echo -e "File type: ${GREEN}Regular file${NC}" ;;
    l) echo -e "File type: ${GREEN}Symbolic link${NC}" ;;
    *) echo -e "File type: ${GREEN}Special file${NC}" ;;
  esac
  
  # User permissions
  echo -ne "Owner permissions: "
  [[ ${user:0:1} == "r" ]] && echo -ne "${GREEN}read ${NC}" || echo -ne "${RED}no read ${NC}"
  [[ ${user:1:1} == "w" ]] && echo -ne "${GREEN}write ${NC}" || echo -ne "${RED}no write ${NC}"
  [[ ${user:2:1} == "x" ]] && echo -e "${GREEN}execute${NC}" || echo -e "${RED}no execute${NC}"
  
  # Group permissions
  echo -ne "Group permissions: "
  [[ ${group:0:1} == "r" ]] && echo -ne "${GREEN}read ${NC}" || echo -ne "${RED}no read ${NC}"
  [[ ${group:1:1} == "w" ]] && echo -ne "${GREEN}write ${NC}" || echo -ne "${RED}no write ${NC}"
  [[ ${group:2:1} == "x" ]] && echo -e "${GREEN}execute${NC}" || echo -e "${RED}no execute${NC}"
  
  # Others permissions
  echo -ne "Others permissions: "
  [[ ${others:0:1} == "r" ]] && echo -ne "${GREEN}read ${NC}" || echo -ne "${RED}no read ${NC}"
  [[ ${others:1:1} == "w" ]] && echo -ne "${GREEN}write ${NC}" || echo -ne "${RED}no write ${NC}"
  [[ ${others:2:1} == "x" ]] && echo -e "${GREEN}execute${NC}" || echo -e "${RED}no execute${NC}"
}

# Function to convert symbolic to numeric permissions
symbolic_to_numeric() {
  local symbolic=$1
  local numeric=0
  
  # Owner
  [[ ${symbolic:1:1} == "r" ]] && numeric=$((numeric+400))
  [[ ${symbolic:2:1} == "w" ]] && numeric=$((numeric+200))
  [[ ${symbolic:3:1} == "x" ]] && numeric=$((numeric+100))
  
  # Group
  [[ ${symbolic:4:1} == "r" ]] && numeric=$((numeric+40))
  [[ ${symbolic:5:1} == "w" ]] && numeric=$((numeric+20))
  [[ ${symbolic:6:1} == "x" ]] && numeric=$((numeric+10))
  
  # Others
  [[ ${symbolic:7:1} == "r" ]] && numeric=$((numeric+4))
  [[ ${symbolic:8:1} == "w" ]] && numeric=$((numeric+2))
  [[ ${symbolic:9:1} == "x" ]] && numeric=$((numeric+1))
  
  echo "$numeric"
}

# Main menu for this component
show_perm_menu() {
  section "File and Directory Permissions Menu"
  echo "1) Create demonstration directory structure"
  echo "2) Basic permissions overview (chmod, chown)"
  echo "3) Special permissions demonstration (SUID, SGID, sticky bit)"
  echo "4) ACL (Access Control Lists) demonstration"
  echo "5) Permission visualizer tool"
  echo "6) Interactive permission challenge"
  echo "7) Return to main menu"
  
  read -p "Select an option: " option
  echo
  
  case $option in
    1) create_demo_structure ;;
    2) basic_permissions ;;
    3) special_permissions ;;
    4) acl_demonstration ;;
    5) permission_visualizer ;;
    6) interactive_challenge ;;
    7) return 0 ;;
    *) 
      echo "Invalid option"
      show_perm_menu
      ;;
  esac
  
  # Return to this menu after completing an action
  read -p "Press Enter to return to the File Permissions menu..."
  show_perm_menu
}

# 1. Create demonstration directory structure
create_demo_structure() {
  section "Creating Demo Directory Structure"
  
  # Create base directories if they don't exist
  demo_cmd "mkdir -p /opt/demo_files/permissions/{public,protected,private,special}" "Creating base directory structure"
  
  # Create test files for demonstrations
  demo_cmd "echo 'Public content for everyone' > /opt/demo_files/permissions/public/public_file.txt" "Creating public test file"
  demo_cmd "echo 'Protected content for group members' > /opt/demo_files/permissions/protected/group_file.txt" "Creating group test file"
  demo_cmd "echo 'Private content for owner only' > /opt/demo_files/permissions/private/private_file.txt" "Creating private test file"
  
  # Create a test script for SUID demonstration
  cat > /opt/demo_files/permissions/special/test_script.sh << 'EOF'
#!/bin/bash
echo "This script is running as: $(whoami)"
echo "The real user is: $SUDO_USER"
EOF
  chmod +x /opt/demo_files/permissions/special/test_script.sh
  
  # Set initial permissions
  demo_cmd "chmod 777 /opt/demo_files/permissions/public" "Setting public directory to rwxrwxrwx (777)"
  demo_cmd "chmod 770 /opt/demo_files/permissions/protected" "Setting protected directory to rwxrwx--- (770)"
  demo_cmd "chmod 700 /opt/demo_files/permissions/private" "Setting private directory to rwx------ (700)"
  
  # Set ownership
  if getent group demo_users >/dev/null; then
    demo_cmd "chown -R root:demo_users /opt/demo_files/permissions/protected" "Setting group ownership of protected directory to demo_users"
  else
    echo "Group demo_users not found. Please run the User Authentication demo first to create this group."
  fi
  
  echo -e "${GREEN}Demo directory structure created successfully!${NC}"
}

# 2. Basic permissions overview
basic_permissions() {
  section "Basic File Permissions"
  
  # Explanation of permission notations
  echo -e "${YELLOW}Understanding Permission Notations:${NC}"
  echo "1. Symbolic notation: rwxrwxrwx (user, group, others)"
  echo "   r = read, w = write, x = execute"
  echo "2. Numeric notation: 777 (user, group, others)"
  echo "   4 = read, 2 = write, 1 = execute"
  echo
  
  # Demonstrate ls output
  demo_cmd "ls -la /opt/demo_files/permissions/" "Viewing directory permissions with ls -la"
  
  # Extract and explain the permissions of one file
  perms=$(ls -la /opt/demo_files/permissions/public | grep -v "total" | head -2 | tail -1 | awk '{print $1}')
  explain_permissions "$perms"
  echo "Numeric equivalent: $(symbolic_to_numeric "$perms")"
  
  # Demonstrate chmod with numeric notation
  demo_cmd "chmod 644 /opt/demo_files/permissions/public/public_file.txt" "Setting permissions to 644 (rw-r--r--) using numeric notation"
  demo_cmd "ls -l /opt/demo_files/permissions/public/public_file.txt" "Verifying permissions change"
  
  # Demonstrate chmod with symbolic notation
  demo_cmd "chmod u+x,g-r,o-r /opt/demo_files/permissions/public/public_file.txt" "Modifying permissions using symbolic notation: add execute to user, remove read from group and others"
  demo_cmd "ls -l /opt/demo_files/permissions/public/public_file.txt" "Verifying permissions change"
  
  # Restore permissions
  chmod 644 /opt/demo_files/permissions/public/public_file.txt
  
  # Demonstrate chown
  if id demo_user >/dev/null 2>&1; then
    demo_cmd "chown demo_user:demo_users /opt/demo_files/permissions/protected/group_file.txt" "Changing file ownership to demo_user:demo_users"
    demo_cmd "ls -l /opt/demo_files/permissions/protected/group_file.txt" "Verifying ownership change"
  else
    echo "User demo_user not found. Please run the User Authentication demo first to create this user."
  fi
  
  # Permission inheritance explanation
  echo -e "${YELLOW}Permission Inheritance:${NC}"
  echo "1. New files inherit the group of their parent directory"
  echo "2. New files do NOT inherit directory permissions by default"
  echo "3. The umask determines default permissions for new files (typically 022 or 002)"
  
  # Demonstrate umask
  demo_cmd "umask" "Current umask setting"
  echo "Default file permissions = 666 - umask"
  echo "Default directory permissions = 777 - umask"
}

# 3. Special permissions demonstration
special_permissions() {
  section "Special Permissions (SUID, SGID, Sticky Bit)"
  
  echo -e "${YELLOW}Special Permission Bits:${NC}"
  echo "1. SUID (Set User ID): Allows a file to be executed with the permissions of the file owner"
  echo "2. SGID (Set Group ID): Allows a file to be executed with the permissions of the file group"
  echo "   On directories: New files inherit the directory's group"
  echo "3. Sticky Bit: Only the owner can delete files in a directory (common on /tmp)"
  echo
  
  # SUID demonstration
  demo_cmd "ls -l /usr/bin/passwd" "Example of SUID bit on passwd command"
  explain_permissions "$(ls -l /usr/bin/passwd | awk '{print $1}')"
  
  # Set SUID on our test script
  demo_cmd "chmod u+s /opt/demo_files/permissions/special/test_script.sh" "Setting SUID bit on our test script"
  demo_cmd "ls -l /opt/demo_files/permissions/special/test_script.sh" "Verifying SUID was set"
  
  # SGID demonstration
  demo_cmd "chmod g+s /opt/demo_files/permissions/protected/" "Setting SGID bit on protected directory"
  demo_cmd "ls -ld /opt/demo_files/permissions/protected/" "Verifying SGID was set"
  demo_cmd "touch /opt/demo_files/permissions/protected/test_sgid.txt" "Creating a new file in SGID directory"
  demo_cmd "ls -l /opt/demo_files/permissions/protected/test_sgid.txt" "Verifying group inheritance"
  
  # Sticky bit demonstration
  demo_cmd "chmod +t /opt/demo_files/permissions/public/" "Setting sticky bit on public directory"
  demo_cmd "ls -ld /opt/demo_files/permissions/public/" "Verifying sticky bit was set"
  
  echo -e "${YELLOW}Explanation of ls output with special permissions:${NC}"
  echo "1. SUID appears as 's' in place of 'x' in the user permissions (position 3)"
  echo "2. SGID appears as 's' in place of 'x' in the group permissions (position 6)"
  echo "3. Sticky bit appears as 't' in place of 'x' in the others permissions (position 9)"
  
  echo -e "${YELLOW}Numeric representation of special permissions:${NC}"
  echo "4000 = SUID, 2000 = SGID, 1000 = sticky bit"
  echo "Examples:"
  echo "chmod 4755 file   # SUID + rwxr-xr-x"
  echo "chmod 2755 file   # SGID + rwxr-xr-x"
  echo "chmod 1777 dir    # Sticky bit + rwxrwxrwx"
}

# 4. ACL (Access Control Lists) demonstration
acl_demonstration() {
  section "Access Control Lists (ACLs)"
  
  echo -e "${YELLOW}Access Control Lists (ACLs):${NC}"
  echo "1. ACLs provide more fine-grained access control than standard permissions"
  echo "2. Allow you to set permissions for specific users or groups beyond owner/group/others"
  echo "3. Useful when standard permission model is not flexible enough"
  echo
  
  # Check if ACL tools are installed
  if ! command -v getfacl >/dev/null || ! command -v setfacl >/dev/null; then
    echo -e "${RED}ACL tools (acl package) not installed. Please install with:${NC}"
    echo "apt-get install acl"
    return
  fi
  
  # Demo file for ACL
  demo_cmd "echo 'This file has custom ACL permissions' > /opt/demo_files/permissions/acl_test.txt" "Creating test file for ACL demonstration"
  demo_cmd "chmod 640 /opt/demo_files/permissions/acl_test.txt" "Setting base permissions (rw-r-----)"
  
  if id demo_user >/dev/null 2>&1 && id demo_guest >/dev/null 2>&1; then
    # Set an ACL for specific user
    demo_cmd "setfacl -m u:demo_guest:r /opt/demo_files/permissions/acl_test.txt" "Setting ACL to give read permission to demo_guest"
    
    # View the ACL
    demo_cmd "getfacl /opt/demo_files/permissions/acl_test.txt" "Viewing ACLs on the file"
    
    # Notice the "+" in the ls output indicating ACL presence
    demo_cmd "ls -l /opt/demo_files/permissions/acl_test.txt" "Note the '+' at the end of permissions indicating ACL presence"
    
    # Modify ACLs
    demo_cmd "setfacl -m g:demo_guests:r /opt/demo_files/permissions/acl_test.txt" "Adding ACL for demo_guests group"
    demo_cmd "getfacl /opt/demo_files/permissions/acl_test.txt" "Viewing updated ACLs"
    
    # Remove an ACL
    demo_cmd "setfacl -x u:demo_guest /opt/demo_files/permissions/acl_test.txt" "Removing ACL for demo_guest user"
    demo_cmd "getfacl /opt/demo_files/permissions/acl_test.txt" "Verifying ACL removal"
    
    # Default ACLs for directories (inheritance)
    demo_cmd "mkdir -p /opt/demo_files/permissions/acl_dir" "Creating directory for ACL inheritance demo"
    demo_cmd "setfacl -d -m g:demo_users:rwx /opt/demo_files/permissions/acl_dir" "Setting default ACL for new files in directory"
    demo_cmd "getfacl /opt/demo_files/permissions/acl_dir" "Viewing directory ACLs with default settings"
    
    # Create a file in the directory to demonstrate ACL inheritance
    demo_cmd "touch /opt/demo_files/permissions/acl_dir/inherited_acl.txt" "Creating file in directory with default ACLs"
    demo_cmd "getfacl /opt/demo_files/permissions/acl_dir/inherited_acl.txt" "Verifying inherited ACLs"
  else
    echo "Demo users not found. Please run the User Authentication demo first to create these users."
  fi
}

# 5. Permission visualizer tool
permission_visualizer() {
  section "Permission Visualizer Tool"
  
  # Create permission visualizer script if it doesn't exist
  if [ ! -f "./permission_visualizer.sh" ]; then
    create_visualizer_script
  fi
  
  # Execute the visualizer
  echo -e "${YELLOW}Running Permission Visualizer Tool:${NC}"
  
  # Check if any demo directory exists
  if [ -d "/opt/demo_files/permissions" ]; then
    bash ./permission_visualizer.sh "/opt/demo_files/permissions"
  else
    echo "Demo directory not found. Please run 'Create demonstration directory structure' first."
  fi
}

# Create permission visualizer script
create_visualizer_script() {
  cat > permission_visualizer.sh << 'EOF'
#!/bin/bash

# Permission Visualizer Script
# Displays a visual representation of file permissions

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if a target directory was provided
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <directory>"
  exit 1
fi

TARGET_DIR="$1"

# Check if target directory exists
if [ ! -d "$TARGET_DIR" ]; then
  echo "Error: Directory $TARGET_DIR does not exist!"
  exit 1
fi

# Header
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}       PERMISSION VISUALIZATION TOOL        ${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "Target directory: ${YELLOW}$TARGET_DIR${NC}"
echo

# Function to render a single permission block
render_permission() {
  local perm=$1
  local label=$2

  if [ "$perm" == "r" ]; then
    echo -ne "${GREEN}■ $label-Read${NC}  "
  elif [ "$perm" == "w" ]; then
    echo -ne "${RED}■ $label-Write${NC}  "
  elif [ "$perm" == "x" ]; then
    echo -ne "${YELLOW}■ $label-Execute${NC}  "
  elif [ "$perm" == "s" ] && [ "$label" == "U" ]; then
    echo -ne "${CYAN}■ SUID${NC}  "
  elif [ "$perm" == "s" ] && [ "$label" == "G" ]; then
    echo -ne "${CYAN}■ SGID${NC}  "
  elif [ "$perm" == "t" ]; then
    echo -ne "${CYAN}■ Sticky${NC}  "
  else
    echo -ne "□ $label-${perm}  "
  fi
}

# Get the files in the target directory
find "$TARGET_DIR" -type f -o -type d | sort | while read -r file; do
  # Get file information
  perms=$(ls -la "$file" | awk '{print $1}' | head -1)
  owner=$(ls -la "$file" | awk '{print $3}' | head -1)
  group=$(ls -la "$file" | awk '{print $4}' | head -1)
  filename=$(basename "$file")
  
  # Determine file type
  if [ -d "$file" ]; then
    filetype="Directory"
  elif [ -L "$file" ]; then
    filetype="Symlink"
  elif [ -f "$file" ]; then
    filetype="File"
  else
    filetype="Special"
  fi
  
  # Output file information
  echo -e "${YELLOW}$filename${NC} ($filetype, Owner: $owner, Group: $group)"
  
  # Extract and visualize permissions
  # User permissions
  echo -ne "User:  "
  render_permission "${perms:1:1}" "U"
  render_permission "${perms:2:1}" "U"
  render_permission "${perms:3:1}" "U"
  echo ""
  
  # Group permissions
  echo -ne "Group: "
  render_permission "${perms:4:1}" "G"
  render_permission "${perms:5:1}" "G"
  render_permission "${perms:6:1}" "G"
  echo ""
  
  # Others permissions
  echo -ne "Other: "
  render_permission "${perms:7:1}" "O"
  render_permission "${perms:8:1}" "O"
  render_permission "${perms:9:1}" "O"
  echo -e "\n"
done

echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}■${NC} = Permission granted  □ = Permission denied"
echo -e "${GREEN}■ Read${NC} ${RED}■ Write${NC} ${YELLOW}■ Execute${NC} ${CYAN}■ Special${NC}"
EOF

  # Make it executable
  chmod +x permission_visualizer.sh
  
  echo "Created permission visualizer script"
}

# 6. Interactive permission challenge
interactive_challenge() {
  section "Interactive Permission Challenge"
  
  echo -e "${YELLOW}Permission Prediction Challenge:${NC}"
  echo "This activity tests your understanding of Linux permissions."
  echo "I'll create a file with specific permissions, and you have to predict the outcome of access attempts."
  echo
  
  # Create challenge directory
  mkdir -p /opt/demo_files/permissions/challenge
  
  # Create a test file with specific permissions
  echo "This is a challenge file." > /opt/demo_files/permissions/challenge/secret.txt
  
  # Set specific permissions
  chmod 640 /opt/demo_files/permissions/challenge/secret.txt
  if getent group demo_users >/dev/null; then
    chown root:demo_users /opt/demo_files/permissions/challenge/secret.txt
  fi
  
  # Display the permissions
  echo -e "${GREEN}Challenge File:${NC}"
  ls -l /opt/demo_files/permissions/challenge/secret.txt
  
  # Ask for predictions
  echo
  echo -e "${YELLOW}Predict the outcome of these access attempts:${NC}"
  echo "1. Can root read this file? (yes/no)"
  read -p "Your answer: " answer1
  echo "2. Can a member of the demo_users group modify this file? (yes/no)"
  read -p "Your answer: " answer2
  echo "3. Can a user not in the demo_users group read this file? (yes/no)"
  read -p "Your answer: " answer3
  
  # Verify answers
  echo
  echo -e "${BLUE}Checking your answers...${NC}"
  echo
  
  # Answer 1 verification
  echo -e "${GREEN}1. Can root read this file?${NC}"
  echo -ne "Your answer: $answer1, Correct answer: yes - "
  if [[ "$answer1" == "yes" ]]; then
    echo -e "${GREEN}Correct!${NC}"
  else
    echo -e "${RED}Incorrect.${NC}"
  fi
  echo "Explanation: root can read, write, and execute any file regardless of permissions."
  
  # Answer 2 verification
  echo -e "${GREEN}2. Can a member of the demo_users group modify this file?${NC}"
  echo -ne "Your answer: $answer2, Correct answer: no - "
  if [[ "$answer2" == "no" ]]; then
    echo -e "${GREEN}Correct!${NC}"
  else
    echo -e "${RED}Incorrect.${NC}"
  fi
  echo "Explanation: The group permission is r-- (4), which only allows reading, not writing or executing."
  
  # Answer 3 verification
  echo -e "${GREEN}3. Can a user not in the demo_users group read this file?${NC}"
  echo -ne "Your answer: $answer3, Correct answer: no - "
  if [[ "$answer3" == "no" ]]; then
    echo -e "${GREEN}Correct!${NC}"
  else
    echo -e "${RED}Incorrect.${NC}"
  fi
  echo "Explanation: The 'others' permission is --- (0), which denies all access."
  
  # Demonstration of the actual outcomes
  echo
  echo -e "${YELLOW}Demonstrating actual outcomes:${NC}"
  
  echo "1. Reading as root:"
  cat /opt/demo_files/permissions/challenge/secret.txt
  
  if id demo_user >/dev/null 2>&1; then
    echo
    echo "2. Attempting to modify as demo_user (group member):"
    sudo -u demo_user bash -c "echo 'Modified content' >> /opt/demo_files/permissions/challenge/secret.txt 2>&1 || echo 'Permission denied as expected'"
    
    echo
    echo "3. Attempting to read as demo_guest (not in group):"
    sudo -u demo_guest bash -c "cat /opt/demo_files/permissions/challenge/secret.txt 2>&1 || echo 'Permission denied as expected'"
  else
    echo "Demo users not available. Please run the User Authentication demo to create users."
  fi
}

# Start the component menu
show_perm_menu 