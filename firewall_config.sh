#!/bin/bash

# Firewall Configuration Demo Script
# Author: Adonis Jimenez (Demo created by Duong Vu)

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
echo -e "${BLUE}            FIREWALL CONFIGURATION DEMO                   ${NC}"
echo -e "${BLUE}==========================================================${NC}"
echo -e "${YELLOW}Presenter: Adonis Jimenez${NC}"
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

# Check if UFW is installed
check_ufw() {
  if ! command -v ufw &> /dev/null; then
    echo -e "${RED}UFW (Uncomplicated Firewall) is not installed.${NC}"
    echo "Would you like to install it now? (y/n)"
    read -r install_ufw
    if [[ "$install_ufw" =~ ^[Yy]$ ]]; then
      demo_cmd "apt-get update" "Updating package lists"
      demo_cmd "apt-get install -y ufw" "Installing UFW"
    else
      echo "UFW is required for this demo. Exiting."
      return 1
    fi
  fi
  return 0
}

# Main menu for this component
show_fw_menu() {
  section "Firewall Configuration Menu"
  echo "1) Introduction to firewalls and network security"
  echo "2) Basic UFW status and configuration"
  echo "3) Managing firewall rules"
  echo "4) Allow/deny specific services"
  echo "5) Allow/deny specific IP addresses"
  echo "6) Logging and monitoring"
  echo "7) Advanced rule configuration"
  echo "8) Interactive firewall challenge"
  echo "9) Return to main menu"
  
  read -p "Select an option: " option
  echo
  
  case $option in
    1) fw_introduction ;;
    2) basic_ufw_config ;;
    3) manage_rules ;;
    4) service_rules ;;
    5) ip_rules ;;
    6) logging_monitoring ;;
    7) advanced_rules ;;
    8) interactive_challenge ;;
    9) return 0 ;;
    *) 
      echo "Invalid option"
      show_fw_menu
      ;;
  esac
  
  # Return to this menu after completing an action
  read -p "Press Enter to return to the Firewall menu..."
  show_fw_menu
}

# 1. Introduction to firewalls and network security
fw_introduction() {
  section "Introduction to Firewalls and Network Security"
  
  echo -e "${YELLOW}What is a Firewall?${NC}"
  echo "A firewall is a network security device that monitors and filters incoming and outgoing"
  echo "network traffic based on an organization's previously established security policies."
  echo
  
  echo -e "${YELLOW}Types of Firewalls:${NC}"
  echo "1. Packet Filtering Firewalls: Examine packets and permit or deny them based on rules"
  echo "2. Stateful Inspection Firewalls: Keep track of the state of active connections"
  echo "3. Application-Level Gateways (Proxy Firewalls): Filter at the application layer"
  echo "4. Next-Generation Firewalls (NGFW): Combine traditional firewall with advanced filtering"
  echo
  
  echo -e "${YELLOW}UFW (Uncomplicated Firewall):${NC}"
  echo "UFW is a frontend for iptables, designed to simplify the process of configuring a firewall."
  echo "It provides a user-friendly way to create an IPv4 or IPv6 host-based firewall."
  echo
  
  echo -e "${YELLOW}Key Firewall Concepts:${NC}"
  echo "1. Default Policies: Define default behavior for incoming/outgoing traffic"
  echo "2. Rules: Specific instructions to allow or deny traffic based on criteria"
  echo "3. Services: Common applications or protocols (HTTP, SSH, etc.)"
  echo "4. Ports: Numeric identifiers for network services (HTTP=80, SSH=22, etc.)"
  echo "5. IP Addresses: Unique identifiers for network devices"
  echo
  
  echo -e "${YELLOW}Firewall Security Best Practices:${NC}"
  echo "1. Default Deny: Block all traffic by default, then allow only what's necessary"
  echo "2. Least Privilege: Grant only the access that's required and nothing more"
  echo "3. Regular Audits: Regularly review and update firewall rules"
  echo "4. Logging: Enable logging to monitor and analyze firewall activity"
  echo "5. Testing: Verify firewall configurations work as expected"
}

# 2. Basic UFW status and configuration
basic_ufw_config() {
  section "Basic UFW Status and Configuration"
  
  # Check if UFW is installed
  check_ufw || return
  
  # Check current UFW status
  demo_cmd "ufw status verbose" "Checking current firewall status and rules"
  
  # Check if UFW is enabled
  if ! ufw status | grep -q "Status: active"; then
    echo -e "${YELLOW}UFW is currently disabled. Would you like to enable it? (y/n)${NC}"
    read -r enable_ufw
    if [[ "$enable_ufw" =~ ^[Yy]$ ]]; then
      # First, ensure SSH is allowed to prevent lockout
      echo -e "${GREEN}First, allowing SSH connections to prevent remote access lockout${NC}"
      demo_cmd "ufw allow ssh" "Allowing SSH connections before enabling firewall"
      
      # Enable UFW
      demo_cmd "ufw --force enable" "Enabling UFW firewall with force option to bypass confirmation"
    else
      echo "Continuing with UFW disabled for demonstration purposes."
    fi
  fi
  
  # Show default policies
  demo_cmd "ufw default" "Showing default policies"
  
  # Explain default policies
  echo -e "${YELLOW}Default Policies:${NC}"
  echo "1. incoming: How to handle incoming connections (usually 'deny')"
  echo "2. outgoing: How to handle outgoing connections (usually 'allow')"
  echo "3. routed: How to handle routed/forwarded connections"
  echo
  
  # Set default policies for demonstration
  demo_cmd "ufw default deny incoming" "Setting default policy to deny all incoming connections"
  demo_cmd "ufw default allow outgoing" "Setting default policy to allow all outgoing connections"
  
  # Show UFW application profiles
  demo_cmd "ufw app list" "Listing available application profiles"
  
  # Show available applications
  if [[ -d /etc/ufw/applications.d ]]; then
    echo -e "${YELLOW}Application Profiles:${NC}"
    echo "UFW includes profiles for common applications that define the ports they use."
    echo "These profiles make it easier to create rules for specific applications."
  fi
}

# 3. Managing firewall rules
manage_rules() {
  section "Managing Firewall Rules"
  
  # Check if UFW is installed
  check_ufw || return
  
  # Show current rules
  demo_cmd "ufw status numbered" "Showing current rules with numbers for easy reference"
  
  # Basic rule syntax explanation
  echo -e "${YELLOW}Basic Rule Syntax:${NC}"
  echo "ufw [--dry-run] [delete] [insert NUM] [prepend] [allow|deny|reject|limit] [in|out] [log|log-all] [proto PROTOCOL] [from ADDRESS [port PORT]] [to ADDRESS [port PORT]]"
  echo
  
  # Add a simple rule for demonstration
  demo_cmd "ufw allow 80/tcp" "Creating a rule to allow incoming HTTP traffic (port 80)"
  
  # Add a rule with more options
  demo_cmd "ufw allow from 192.168.1.0/24 to any port 22" "Allowing SSH access only from local network 192.168.1.0/24"
  
  # Delete a rule
  echo -e "${YELLOW}Deleting rules:${NC}"
  echo "Rules can be deleted by number or by reversing the allow/deny command:"
  
  # Show rules with numbers
  demo_cmd "ufw status numbered" "Show rules with numbers for deletion"
  
  # Get the number of the first rule (assuming there's at least one)
  rule_count=$(ufw status numbered | grep -c '^\[')
  if [ "$rule_count" -gt 0 ]; then
    # Delete the HTTP rule we just added
    demo_cmd "ufw delete allow 80/tcp" "Deleting the HTTP rule by repeating the rule with 'delete'"
    
    # Alternative method by number
    echo -e "${YELLOW}Alternative deletion method by rule number:${NC}"
    echo "ufw delete [rule number]"
  else
    echo "No rules available to delete"
  fi
  
  # Reset all rules (be careful with this!)
  echo -e "${YELLOW}Would you like to reset all firewall rules? (y/n)${NC}"
  read -r reset_rules
  if [[ "$reset_rules" =~ ^[Yy]$ ]]; then
    demo_cmd "ufw --force reset" "Resetting all firewall rules (restores defaults)"
    
    # Make sure SSH is allowed again if UFW is active
    if ufw status | grep -q "Status: active"; then
      demo_cmd "ufw allow ssh" "Re-allowing SSH connections after reset"
    fi
  fi
}

# 4. Allow/deny specific services
service_rules() {
  section "Configuring Rules for Services"
  
  # Check if UFW is installed
  check_ufw || return
  
  echo -e "${YELLOW}Common Services and Their Ports:${NC}"
  echo "SSH (22) - Secure Shell for remote access"
  echo "HTTP (80) - Web server (unencrypted)"
  echo "HTTPS (443) - Web server (encrypted)"
  echo "FTP (21) - File Transfer Protocol"
  echo "SMTP (25) - Email sending"
  echo "POP3 (110) - Email receiving"
  echo "IMAP (143) - Email receiving (alternative)"
  echo "DNS (53) - Domain name resolution"
  echo "MySQL/MariaDB (3306) - Database server"
  echo "PostgreSQL (5432) - Database server"
  echo
  
  # Using application profiles
  demo_cmd "ufw app list" "Listing available application profiles"
  demo_cmd "ufw app info OpenSSH" "Showing details of the OpenSSH application profile"
  
  # Allow services by name
  demo_cmd "ufw allow ssh" "Allowing SSH connections (same as 'ufw allow 22/tcp')"
  demo_cmd "ufw allow http" "Allowing HTTP connections (same as 'ufw allow 80/tcp')"
  demo_cmd "ufw allow https" "Allowing HTTPS connections (same as 'ufw allow 443/tcp')"
  
  # Denying a service
  demo_cmd "ufw deny telnet" "Denying Telnet connections (port 23) - insecure protocol"
  
  # Allowing a custom port
  demo_cmd "ufw allow 8080/tcp" "Allowing custom web server on port 8080"
  
  # Allowing a port range
  demo_cmd "ufw allow 6000:6100/tcp" "Allowing TCP ports from 6000 to 6100"
  
  # Allowing multiple ports
  demo_cmd "ufw allow 80,443/tcp" "Allowing both HTTP and HTTPS in a single rule"
  
  # Show current rules
  demo_cmd "ufw status" "Displaying current firewall rules"
  
  # Clean up demo rules
  echo -e "${YELLOW}Would you like to remove the demo service rules? (y/n)${NC}"
  read -r remove_rules
  if [[ "$remove_rules" =~ ^[Yy]$ ]]; then
    demo_cmd "ufw delete allow http" "Removing HTTP rule"
    demo_cmd "ufw delete allow https" "Removing HTTPS rule"
    demo_cmd "ufw delete deny telnet" "Removing Telnet rule"
    demo_cmd "ufw delete allow 8080/tcp" "Removing custom port rule"
    demo_cmd "ufw delete allow 6000:6100/tcp" "Removing port range rule"
    demo_cmd "ufw delete allow 80,443/tcp" "Removing multiple port rule"
    
    # Keep SSH rule to prevent lockout
    echo -e "${GREEN}Keeping SSH rule to prevent remote access lockout${NC}"
  fi
}

# 5. Allow/deny specific IP addresses
ip_rules() {
  section "Configuring Rules for IP Addresses"
  
  # Check if UFW is installed
  check_ufw || return
  
  echo -e "${YELLOW}IP Address Filtering:${NC}"
  echo "You can allow or deny traffic based on source or destination IP addresses"
  echo "This is useful for creating allow-lists or block-lists of IPs"
  echo
  
  # Get our IP address for demonstration
  our_ip=$(hostname -I | awk '{print $1}')
  
  echo -e "${YELLOW}Our IP address:${NC} $our_ip"
  echo
  
  # Allow specific IP
  demo_cmd "ufw allow from 192.168.1.100" "Allowing all traffic from IP 192.168.1.100"
  
  # Allow specific IP to specific port
  demo_cmd "ufw allow from 192.168.1.100 to any port 22" "Allowing only SSH from IP 192.168.1.100"
  
  # Allow subnet
  demo_cmd "ufw allow from 192.168.1.0/24" "Allowing all traffic from subnet 192.168.1.0/24 (IPs 192.168.1.1-192.168.1.254)"
  
  # Denying an IP
  demo_cmd "ufw deny from 10.0.0.5" "Blocking all traffic from IP 10.0.0.5"
  
  # Allow to specific destination
  demo_cmd "ufw allow from any to $our_ip port 80" "Allowing HTTP to our specific IP address"
  
  # Show current rules
  demo_cmd "ufw status" "Displaying current firewall rules"
  
  # Clean up demo rules
  echo -e "${YELLOW}Would you like to remove the demo IP rules? (y/n)${NC}"
  read -r remove_rules
  if [[ "$remove_rules" =~ ^[Yy]$ ]]; then
    demo_cmd "ufw delete allow from 192.168.1.100" "Removing allow rule for IP 192.168.1.100"
    demo_cmd "ufw delete allow from 192.168.1.100 to any port 22" "Removing specific port rule for IP 192.168.1.100"
    demo_cmd "ufw delete allow from 192.168.1.0/24" "Removing subnet rule"
    demo_cmd "ufw delete deny from 10.0.0.5" "Removing deny rule for IP 10.0.0.5"
    demo_cmd "ufw delete allow from any to $our_ip port 80" "Removing destination IP rule"
  fi
}

# 6. Logging and monitoring
logging_monitoring() {
  section "Firewall Logging and Monitoring"
  
  # Check if UFW is installed
  check_ufw || return
  
  echo -e "${YELLOW}Firewall Logging:${NC}"
  echo "Logging helps monitor firewall activity, troubleshoot issues, and detect potential threats"
  echo "UFW logs are stored in /var/log/ufw.log"
  echo
  
  # Enable logging
  demo_cmd "ufw logging on" "Enabling UFW logging"
  
  # Logging levels
  echo -e "${YELLOW}Logging Levels:${NC}"
  echo "low - Basic logging (default)"
  echo "medium - More details, including packet types"
  echo "high - Very verbose, includes all connection information"
  echo "full - Maximum logging detail"
  echo
  
  # Set logging level
  demo_cmd "ufw logging medium" "Setting logging level to medium"
  
  # View UFW log
  if [ -f /var/log/ufw.log ]; then
    demo_cmd "tail -n 10 /var/log/ufw.log" "Viewing the last 10 lines of the UFW log"
  else
    echo -e "${RED}UFW log file not found at /var/log/ufw.log${NC}"
  fi
  
  # Search for blocked connections
  if [ -f /var/log/ufw.log ]; then
    demo_cmd "grep 'BLOCK' /var/log/ufw.log | tail -n 5" "Finding the most recent blocked connections"
  fi
  
  # Alternative logging with iptables
  echo -e "${YELLOW}Alternative Logging Options:${NC}"
  echo "1. Enable logging for specific rules using 'ufw allow log ...'"
  echo "2. Use 'ufw allow log-all ...' to log all matching connections"
  echo
  
  # Example of rule with logging
  demo_cmd "ufw allow log 80/tcp" "Allowing HTTP with logging"
  
  # Monitor connections in real-time (briefly)
  echo -e "${YELLOW}Monitoring Connections in Real-Time:${NC}"
  echo "Press Ctrl+C after a few seconds to stop monitoring"
  demo_cmd "timeout 5 watch -n 1 'netstat -tunap | grep ESTABLISHED'" "Watching established connections for 5 seconds"
  
  # Clean up logging demo
  echo -e "${YELLOW}Would you like to reset logging to default? (y/n)${NC}"
  read -r reset_logging
  if [[ "$reset_logging" =~ ^[Yy]$ ]]; then
    demo_cmd "ufw logging low" "Resetting logging level to low (default)"
    demo_cmd "ufw delete allow log 80/tcp" "Removing HTTP rule with logging"
    demo_cmd "ufw allow 80/tcp" "Re-adding HTTP rule without logging"
  fi
}

# 7. Advanced rule configuration
advanced_rules() {
  section "Advanced Firewall Configuration"
  
  # Check if UFW is installed
  check_ufw || return
  
  echo -e "${YELLOW}Advanced UFW Configuration Options:${NC}"
  echo "1. Rate limiting: Prevent brute force attacks"
  echo "2. Direction-specific rules: Control incoming vs outgoing traffic"
  echo "3. Protocol-specific rules: Target UDP, TCP, or other protocols"
  echo "4. Custom chains and routing"
  echo
  
  # Rate limiting example
  echo -e "${YELLOW}Rate Limiting:${NC}"
  echo "Rate limiting allows a connection if it's not excessive, otherwise drops it."
  demo_cmd "ufw limit ssh" "Limiting SSH connections to prevent brute force attacks"
  demo_cmd "ufw status | grep ssh" "Verifying SSH limit rule"
  
  # Direction-specific rules
  echo -e "${YELLOW}Direction-Specific Rules:${NC}"
  demo_cmd "ufw allow in to any port 80" "Explicitly allowing incoming traffic to port 80"
  demo_cmd "ufw allow out from any to any port 53" "Explicitly allowing outgoing DNS queries"
  
  # Protocol-specific rules
  echo -e "${YELLOW}Protocol-Specific Rules:${NC}"
  demo_cmd "ufw allow proto tcp to any port 25" "Allowing TCP traffic to port 25 (SMTP)"
  demo_cmd "ufw allow proto udp to any port 53" "Allowing UDP traffic to port 53 (DNS)"
  demo_cmd "ufw allow proto tcp from 192.168.1.0/24 to any port 3306" "Allowing MySQL connections from specific subnet"
  
  # Show more advanced options in config file
  if [ -f /etc/ufw/ufw.conf ]; then
    demo_cmd "cat /etc/ufw/ufw.conf" "Viewing main UFW configuration file"
  fi
  
  # Clean up advanced rules
  echo -e "${YELLOW}Would you like to remove the advanced demo rules? (y/n)${NC}"
  read -r remove_rules
  if [[ "$remove_rules" =~ ^[Yy]$ ]]; then
    demo_cmd "ufw delete limit ssh" "Removing SSH rate limit"
    demo_cmd "ufw allow ssh" "Re-adding normal SSH rule"
    demo_cmd "ufw delete allow in to any port 80" "Removing directional HTTP rule"
    demo_cmd "ufw delete allow out from any to any port 53" "Removing outgoing DNS rule"
    demo_cmd "ufw delete allow proto tcp to any port 25" "Removing SMTP protocol rule"
    demo_cmd "ufw delete allow proto udp to any port 53" "Removing UDP DNS protocol rule"
    demo_cmd "ufw delete allow proto tcp from 192.168.1.0/24 to any port 3306" "Removing specific MySQL rule"
  fi
}

# 8. Interactive firewall challenge
interactive_challenge() {
  section "Interactive Firewall Challenge"
  
  # Check if UFW is installed
  check_ufw || return
  
  echo -e "${YELLOW}Firewall Configuration Challenge:${NC}"
  echo "This activity tests your understanding of firewall rules."
  echo
  
  echo -e "${YELLOW}Scenario:${NC}"
  echo "You are configuring the firewall for a web server that needs:"
  echo "1. Allow HTTP (port 80) and HTTPS (port 443) from anywhere"
  echo "2. Allow SSH (port 22) only from internal network 192.168.1.0/24"
  echo "3. Allow MySQL (port 3306) only from the application server at 192.168.1.100"
  echo "4. Block all incoming traffic from a known malicious IP 203.0.113.5"
  echo "5. Enable rate limiting for SSH to prevent brute force attacks"
  echo "6. Allow all outgoing traffic"
  echo "7. Block incoming traffic by default"
  echo
  
  echo -e "${YELLOW}Create these rules one by one:${NC}"
  echo
  
  # Check if user already entered commands
  challenge_complete=0
  
  # Rule 1: HTTP and HTTPS
  echo -e "1. Command to allow HTTP and HTTPS from anywhere:"
  read -p "> " http_rule
  if [[ "$http_rule" == "ufw allow http" || "$http_rule" == "ufw allow 80/tcp" || 
        "$http_rule" == "ufw allow 80" || "$http_rule" == "ufw allow http,https" || 
        "$http_rule" == "ufw allow 80,443/tcp" ]]; then
    echo -e "${GREEN}Correct approach!${NC}"
    # We won't execute user input directly for safety
  else
    echo -e "${RED}Not quite right.${NC} A good solution would be: ufw allow http"
  fi
  
  # Rule 2: Restricted SSH
  echo -e "\n2. Command to allow SSH only from internal network 192.168.1.0/24:"
  read -p "> " ssh_rule
  if [[ "$ssh_rule" == "ufw allow from 192.168.1.0/24 to any port 22" || 
        "$ssh_rule" == "ufw allow from 192.168.1.0/24 to any port ssh" ]]; then
    echo -e "${GREEN}Correct approach!${NC}"
  else
    echo -e "${RED}Not quite right.${NC} A good solution would be: ufw allow from 192.168.1.0/24 to any port 22"
  fi
  
  # Rule 3: Restricted MySQL
  echo -e "\n3. Command to allow MySQL only from 192.168.1.100:"
  read -p "> " mysql_rule
  if [[ "$mysql_rule" == "ufw allow from 192.168.1.100 to any port 3306" || 
        "$mysql_rule" == "ufw allow from 192.168.1.100 to any port mysql" ]]; then
    echo -e "${GREEN}Correct approach!${NC}"
  else
    echo -e "${RED}Not quite right.${NC} A good solution would be: ufw allow from 192.168.1.100 to any port 3306"
  fi
  
  # Rule 4: Block malicious IP
  echo -e "\n4. Command to block all traffic from malicious IP 203.0.113.5:"
  read -p "> " block_rule
  if [[ "$block_rule" == "ufw deny from 203.0.113.5" || 
        "$block_rule" == "ufw reject from 203.0.113.5" ]]; then
    echo -e "${GREEN}Correct approach!${NC}"
  else
    echo -e "${RED}Not quite right.${NC} A good solution would be: ufw deny from 203.0.113.5"
  fi
  
  # Rule 5: Rate limiting SSH
  echo -e "\n5. Command to enable rate limiting for SSH:"
  read -p "> " limit_rule
  if [[ "$limit_rule" == "ufw limit ssh" || 
        "$limit_rule" == "ufw limit 22/tcp" || 
        "$limit_rule" == "ufw limit 22" ]]; then
    echo -e "${GREEN}Correct approach!${NC}"
  else
    echo -e "${RED}Not quite right.${NC} A good solution would be: ufw limit ssh"
  fi
  
  # Rule 6 & 7: Default policies
  echo -e "\n6 & 7. Commands to set default policies (allow outgoing, deny incoming):"
  read -p "> " policy_rule
  if [[ "$policy_rule" == "ufw default deny incoming; ufw default allow outgoing" || 
        "$policy_rule" == "ufw default allow outgoing; ufw default deny incoming" ]]; then
    echo -e "${GREEN}Correct approach!${NC}"
    challenge_complete=1
  else
    echo -e "${RED}Not quite right.${NC} A good solution would be: ufw default deny incoming; ufw default allow outgoing"
  fi
  
  echo
  if [ $challenge_complete -eq 1 ]; then
    echo -e "${GREEN}Great job! You've completed the firewall challenge.${NC}"
  else
    echo -e "${YELLOW}You've completed the firewall challenge. Keep practicing!${NC}"
  fi
  
  echo
  echo -e "${YELLOW}Would you like to see the correct implementation? (y/n)${NC}"
  read -r show_solution
  if [[ "$show_solution" =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Here's how to implement the solution:${NC}"
    echo "ufw default deny incoming"
    echo "ufw default allow outgoing"
    echo "ufw allow http"
    echo "ufw allow https"
    echo "ufw allow from 192.168.1.0/24 to any port 22"
    echo "ufw allow from 192.168.1.100 to any port 3306"
    echo "ufw deny from 203.0.113.5"
    echo "ufw limit ssh"
    echo "ufw enable"
  fi
}

# Start the component menu
check_ufw && show_fw_menu 