#!/bin/bash

# OS Security Demo Main Script
# This script serves as the main controller for the OS security demonstration

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo"
  exit 1
fi

# Display banner
clear
echo "====================================================="
echo "      OS SECURITY CONCEPTS DEMONSTRATION TOOL        "
echo "====================================================="
echo "Group Members:"
echo "  - Javier Cruz: Introduction to OS Security Concepts"
echo "  - Duong Vu: User Authentication and Access Control"
echo "  - Cameron Tran: File and Directory Permissions"
echo "  - Adonis Jimenez: Firewall Config & Security Auditing"
echo "====================================================="
echo ""

# Function to check if a script exists
check_script() {
  if [ ! -f "$1" ]; then
    echo "Error: Required script $1 not found!"
    echo "Please make sure all required scripts are in the current directory."
    exit 1
  fi
}

# Check if all required scripts exist
check_script "./user_auth.sh"
check_script "./file_permissions.sh"
check_script "./firewall_config.sh"
check_script "./security_audit.sh"

# Main menu
show_menu() {
  echo ""
  echo "Select a demonstration component:"
  echo "1) User Authentication and Access Control"
  echo "2) File and Directory Permissions"
  echo "3) Firewall Configuration and Security Auditing"
  echo "4) Run Complete Demo (All Components)"
  echo "5) Cleanup (Remove Demo Users and Files)"
  echo "q) Quit"
  echo ""
  read -p "Enter your choice: " choice
  
  case $choice in
    1) bash ./user_auth.sh ;;
    2) bash ./file_permissions.sh ;;
    3) 
      echo "Select a component:"
      echo "a) Firewall Configuration"
      echo "b) Security Auditing"
      read -p "Enter your choice: " fw_choice
      case $fw_choice in
        a) bash ./firewall_config.sh ;;
        b) bash ./security_audit.sh ;;
        *) echo "Invalid choice" ;;
      esac
      ;;
    4) 
      echo "Running complete demo sequence..."
      bash ./user_auth.sh
      bash ./file_permissions.sh
      bash ./firewall_config.sh
      bash ./security_audit.sh
      ;;
    5)
      echo "Cleaning up demo environment..."
      # Remove demo users
      for user in demo_admin demo_user demo_guest; do
        if id "$user" &>/dev/null; then
          deluser --remove-home $user
          echo "Removed user: $user"
        fi
      done
      # Remove demo groups
      for group in demo_admins demo_users demo_guests; do
        if getent group "$group" &>/dev/null; then
          delgroup $group
          echo "Removed group: $group"
        fi
      done
      # Remove demo directories
      if [ -d "/opt/demo_files" ]; then
        rm -rf /opt/demo_files
        echo "Removed directory: /opt/demo_files"
      fi
      echo "Cleanup complete!"
      ;;
    q|Q) exit 0 ;;
    *) echo "Invalid choice" ;;
  esac
  
  # Return to menu after completion
  read -p "Press Enter to return to the main menu..."
  show_menu
}

# Display the menu
show_menu 