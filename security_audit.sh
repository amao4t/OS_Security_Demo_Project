#!/bin/bash

# Security Auditing Demo Script
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
echo -e "${BLUE}              SECURITY AUDITING DEMO                      ${NC}"
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

# Check if a tool is installed
check_tool() {
  if ! command -v "$1" &> /dev/null; then
    echo -e "${RED}$1 is not installed.${NC}"
    echo "Would you like to install it now? (y/n)"
    read -r install_tool
    if [[ "$install_tool" =~ ^[Yy]$ ]]; then
      demo_cmd "apt-get update" "Updating package lists"
      demo_cmd "apt-get install -y $1" "Installing $1"
      return $?
    else
      echo "$1 is required for this demo section. Skipping."
      return 1
    fi
  fi
  return 0
}

# Main menu for this component
show_audit_menu() {
  section "Security Auditing Menu"
  echo "1) Introduction to security auditing"
  echo "2) Basic system security checks"
  echo "3) User and access auditing"
  echo "4) File system security analysis"
  echo "5) Network security scanning"
  echo "6) Log analysis and monitoring"
  echo "7) Automated security scanning with Lynis"
  echo "8) Rootkit detection with chkrootkit"
  echo "9) Interactive security challenge"
  echo "10) Return to main menu"
  
  read -p "Select an option: " option
  echo
  
  case $option in
    1) audit_introduction ;;
    2) basic_system_checks ;;
    3) user_access_audit ;;
    4) filesystem_security ;;
    5) network_security ;;
    6) log_analysis ;;
    7) lynis_scan ;;
    8) rootkit_detection ;;
    9) interactive_challenge ;;
    10) return 0 ;;
    *) 
      echo "Invalid option"
      show_audit_menu
      ;;
  esac
  
  # Return to this menu after completing an action
  read -p "Press Enter to return to the Security Auditing menu..."
  show_audit_menu
}

# 1. Introduction to security auditing
audit_introduction() {
  section "Introduction to Security Auditing"
  
  echo -e "${YELLOW}What is Security Auditing?${NC}"
  echo "Security auditing is the systematic evaluation of an organization's information system"
  echo "security by measuring how well it conforms to established criteria."
  echo
  
  echo -e "${YELLOW}Goals of Security Auditing:${NC}"
  echo "1. Identify vulnerabilities and security gaps"
  echo "2. Ensure compliance with security policies and regulations"
  echo "3. Verify effectiveness of security controls"
  echo "4. Detect unauthorized access or changes to the system"
  echo "5. Provide evidence for security incident investigations"
  echo
  
  echo -e "${YELLOW}Types of Security Audits:${NC}"
  echo "1. Vulnerability Assessment: Identifying and quantifying security vulnerabilities"
  echo "2. Penetration Testing: Simulating attacks to identify exploitable vulnerabilities"
  echo "3. Compliance Audit: Ensuring adherence to security standards"
  echo "4. Risk Assessment: Evaluating potential threats and their impact"
  echo "5. System Audit: Examining configurations and settings"
  echo
  
  echo -e "${YELLOW}Security Auditing Tools:${NC}"
  echo "1. Lynis: Open-source security auditing tool for Unix/Linux systems"
  echo "2. Chkrootkit: Tool to check for rootkits on Linux systems"
  echo "3. AIDE: Advanced Intrusion Detection Environment"
  echo "4. OpenSCAP: Security compliance and vulnerability scanning"
  echo "5. Auditd: Linux Audit Daemon for system call auditing"
  echo
  
  echo -e "${YELLOW}Auditing Best Practices:${NC}"
  echo "1. Regular and Scheduled Audits: Conduct audits at regular intervals"
  echo "2. Comprehensive Coverage: Audit all aspects of the system"
  echo "3. Least Privilege: Review access rights to enforce least privilege principle"
  echo "4. Documentation: Maintain detailed audit logs and reports"
  echo "5. Follow-up: Address identified issues and verify fixes"
}

# 2. Basic system security checks
basic_system_checks() {
  section "Basic System Security Checks"
  
  echo -e "${YELLOW}Performing basic system security checks...${NC}"
  
  # System information
  demo_cmd "uname -a" "Displaying system information (kernel version, architecture)"
  
  # System update status
  if command -v apt &> /dev/null; then
    demo_cmd "apt list --upgradable | head -10" "Checking for available system updates (shows first 10)"
  elif command -v yum &> /dev/null; then
    demo_cmd "yum check-update | head -10" "Checking for available system updates (shows first 10)"
  fi
  
  # Check running services
  demo_cmd "systemctl list-units --type=service --state=running | grep -v systemd | head -10" "Listing currently running services (shows first 10)"
  
  # Check listening ports
  demo_cmd "ss -tulpn | head -10" "Checking network ports and associated processes (shows first 10)"
  
  # Check for failed login attempts
  demo_cmd "lastb | head -10 || echo 'No failed login attempts found'" "Checking failed login attempts (shows first 10)"
  
  # Check system disk usage
  demo_cmd "df -h" "Checking disk usage (full disks can cause security issues)"
  
  # Check system load
  demo_cmd "uptime" "Checking system load and uptime (unusual load could indicate compromise)"
  
  # Check kernel parameters
  demo_cmd "sysctl -a | grep -E 'kernel.(randomize|kptr|dmesg|exec|sysrq)' | head -10" "Checking important kernel security parameters (shows first 10)"
  
  # Check open files
  demo_cmd "lsof | head -10" "Listing open files and processes (shows first 10)"
  
  echo -e "${YELLOW}Security Recommendation:${NC}"
  echo "1. Keep the system updated with latest security patches"
  echo "2. Disable unnecessary services"
  echo "3. Close unused network ports"
  echo "4. Monitor for suspicious login attempts"
  echo "5. Configure kernel parameters for enhanced security"
  echo "6. Monitor system resource usage for anomalies"
}

# 3. User and access auditing
user_access_audit() {
  section "User and Access Auditing"
  
  echo -e "${YELLOW}Auditing user accounts and access controls...${NC}"
  
  # Check users with login shells
  demo_cmd "cat /etc/passwd | grep -v '/nologin' | grep -v '/false'" "Listing all users with valid login shells"
  
  # Check users with sudo access
  demo_cmd "grep -Po '^sudo.+:\K.*$' /etc/group || grep -Po '^wheel.+:\K.*$' /etc/group || echo 'No sudo/wheel group found'" "Listing users with sudo access"
  
  # Check for users with UID 0 (root)
  demo_cmd "cat /etc/passwd | awk -F: '\$3 == 0 {print \$1}'" "Finding all users with root privileges (UID 0)"
  
  # Check password policies
  demo_cmd "grep -E '(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs" "Checking password aging policies"
  
  # Check sudo configuration
  demo_cmd "cat /etc/sudoers | grep -v '^#' | grep -v '^$' | head -10" "Checking sudo configuration (shows first 10 lines)"
  
  # Check groups and memberships
  demo_cmd "cat /etc/group | head -10" "Listing system groups (shows first 10)"
  
  # Check for passwordless accounts
  demo_cmd "cat /etc/shadow | awk -F: '\$2 == \"\" {print \$1}'" "Checking for accounts without passwords"
  
  # Check for users who haven't logged in recently
  demo_cmd "lastlog | grep 'Never logged in' | head -5" "Finding users who have never logged in (shows first 5)"
  
  # Check SSH configuration
  if [ -f /etc/ssh/sshd_config ]; then
    demo_cmd "grep -v '^#' /etc/ssh/sshd_config | grep -v '^$'" "Checking SSH server configuration"
  fi
  
  echo -e "${YELLOW}Security Recommendations:${NC}"
  echo "1. Remove or disable unused accounts"
  echo "2. Implement strong password policies"
  echo "3. Restrict sudo access to only necessary users"
  echo "4. Regularly audit user accounts and privileges"
  echo "5. Disable direct root login via SSH"
  echo "6. Use SSH key authentication instead of passwords"
}

# 4. File system security analysis
filesystem_security() {
  section "File System Security Analysis"
  
  echo -e "${YELLOW}Analyzing file system security...${NC}"
  
  # Check world-writable files
  demo_cmd "find /etc -type f -perm -o+w -ls 2>/dev/null | head -5" "Finding world-writable files in /etc (shows first 5)"
  
  # Check files with no owner
  demo_cmd "find / -type f -nouser 2>/dev/null | head -5" "Finding files with no owner (shows first 5)"
  
  # Check SUID/SGID files
  demo_cmd "find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -10" "Finding SUID/SGID files (shows first 10)"
  
  # Check important file permissions
  demo_cmd "ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow" "Checking permissions on critical system files"
  
  # Check for unowned files in home directories
  demo_cmd "find /home -type f -not -user root 2>/dev/null | head -5" "Finding non-root owned files in home directories (shows first 5)"
  
  # Check for hidden files in home directories
  demo_cmd "find /home -name '.*' -type f 2>/dev/null | head -5" "Finding hidden files in home directories (shows first 5)"
  
  # Check for large files
  demo_cmd "find / -type f -size +100M 2>/dev/null | head -5" "Finding unusually large files (shows first 5)"
  
  # Check for recently modified files
  demo_cmd "find / -type f -mtime -1 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -5" "Finding files modified in the last 24 hours (shows first 5)"
  
  # Check temporary directories permissions
  demo_cmd "ls -la /tmp /var/tmp" "Checking permissions on temporary directories"
  
  echo -e "${YELLOW}Security Recommendations:${NC}"
  echo "1. Remove unnecessary world-writable permissions"
  echo "2. Review SUID/SGID files and remove if not needed"
  echo "3. Ensure critical files have correct permissions"
  echo "4. Monitor unusual file changes or large files"
  echo "5. Secure temporary directories to prevent misuse"
}

# 5. Network security scanning
network_security() {
  section "Network Security Scanning"
  
  echo -e "${YELLOW}Analyzing network security...${NC}"
  
  # Check open ports
  demo_cmd "ss -tulpn" "Checking all open TCP and UDP ports"
  
  # Check active connections
  demo_cmd "ss -ta | head -10" "Checking active TCP connections (shows first 10)"
  
  # Check routing table
  demo_cmd "ip route" "Checking network routing table"
  
  # Check firewall rules (using UFW if available)
  if command -v ufw &> /dev/null; then
    demo_cmd "ufw status verbose" "Checking firewall rules with UFW"
  elif command -v iptables &> /dev/null; then
    demo_cmd "iptables -L -v -n" "Checking firewall rules with iptables"
  fi
  
  # Check network interfaces
  demo_cmd "ip addr" "Checking network interfaces and IP addresses"
  
  # Check ARP table
  demo_cmd "arp -a" "Checking ARP table for known hosts"
  
  # Check for suspicious ports
  demo_cmd "ss -tulpn | grep -E ':25|:23|:21|:3389|:5900'" "Checking for potentially risky open ports (SMTP, Telnet, FTP, RDP, VNC)"
  
  # Check DNS resolvers
  demo_cmd "cat /etc/resolv.conf" "Checking DNS resolvers"
  
  # Check hosts file
  demo_cmd "cat /etc/hosts" "Checking hosts file for suspicious entries"
  
  echo -e "${YELLOW}Security Recommendations:${NC}"
  echo "1. Close unnecessary network ports"
  echo "2. Use a properly configured firewall"
  echo "3. Monitor active network connections"
  echo "4. Use secure protocols (HTTPS, SSH, SFTP) instead of insecure ones"
  echo "5. Regularly scan for open ports and vulnerabilities"
  echo "6. Check for suspicious network traffic patterns"
}

# 6. Log analysis and monitoring
log_analysis() {
  section "Log Analysis and Monitoring"
  
  echo -e "${YELLOW}Analyzing system logs for security issues...${NC}"
  
  # Check authentication logs
  if [ -f /var/log/auth.log ]; then
    demo_cmd "grep -i 'failed password' /var/log/auth.log | tail -5" "Checking for failed login attempts (shows last 5)"
    demo_cmd "grep -i 'session opened for user root' /var/log/auth.log | tail -5" "Checking for root logins (shows last 5)"
  elif [ -f /var/log/secure ]; then
    demo_cmd "grep -i 'failed password' /var/log/secure | tail -5" "Checking for failed login attempts (shows last 5)"
    demo_cmd "grep -i 'session opened for user root' /var/log/secure | tail -5" "Checking for root logins (shows last 5)"
  fi
  
  # Check system logs
  if [ -f /var/log/syslog ]; then
    demo_cmd "grep -i 'error' /var/log/syslog | tail -5" "Checking for system errors (shows last 5)"
  elif [ -f /var/log/messages ]; then
    demo_cmd "grep -i 'error' /var/log/messages | tail -5" "Checking for system errors (shows last 5)"
  fi
  
  # Check kernel logs
  demo_cmd "dmesg | grep -i 'error' | tail -5" "Checking for kernel errors (shows last 5)"
  
  # Check for login anomalies
  demo_cmd "last | head -10" "Checking recent logins (shows last 10)"
  
  # Check for sudo usage
  if [ -f /var/log/auth.log ]; then
    demo_cmd "grep -i 'sudo' /var/log/auth.log | tail -5" "Checking sudo usage (shows last 5)"
  elif [ -f /var/log/secure ]; then
    demo_cmd "grep -i 'sudo' /var/log/secure | tail -5" "Checking sudo usage (shows last 5)"
  fi
  
  # Check for network-related logs
  if [ -d /var/log/ufw ]; then
    demo_cmd "ls -la /var/log/ufw" "Checking firewall logs"
  fi
  
  # Check for package management logs
  if [ -f /var/log/apt/history.log ]; then
    demo_cmd "grep -i 'install' /var/log/apt/history.log | tail -5" "Checking package installation logs (shows last 5)"
  elif [ -f /var/log/yum.log ]; then
    demo_cmd "grep -i 'install' /var/log/yum.log | tail -5" "Checking package installation logs (shows last 5)"
  fi
  
  echo -e "${YELLOW}Log Monitoring Recommendations:${NC}"
  echo "1. Regularly review authentication logs for unauthorized access attempts"
  echo "2. Monitor system logs for unusual errors or activities"
  echo "3. Track all privileged command executions (sudo usage)"
  echo "4. Set up log rotation to prevent logs from filling disk space"
  echo "5. Consider using a centralized log management system"
  echo "6. Set up automated alerts for suspicious log entries"
}

# 7. Automated security scanning with Lynis
lynis_scan() {
  section "Automated Security Scanning with Lynis"
  
  # Check if Lynis is installed
  if ! check_tool "lynis"; then
    return
  fi
  
  echo -e "${YELLOW}About Lynis:${NC}"
  echo "Lynis is an open-source security auditing tool for Unix/Linux systems."
  echo "It performs hundreds of automated security checks in categories including:"
  echo "- System tools verification"
  echo "- Boot and services"
  echo "- Kernel security features"
  echo "- User accounts and authentication"
  echo "- File systems and permissions"
  echo "- Networking, firewalls, and SSH"
  echo "- Software and patch management"
  echo
  
  echo -e "${YELLOW}Running a basic Lynis audit...${NC}"
  echo "This might take a few minutes. Only showing summary results."
  echo
  
  # Create a temporary directory for Lynis output
  LYNIS_OUTPUT=$(mktemp)
  
  # Run Lynis in non-interactive mode and capture output
  lynis audit system --quiet > $LYNIS_OUTPUT 2>&1
  
  # Extract and display relevant parts of the report
  echo -e "${GREEN}Lynis Audit Results:${NC}"
  echo
  
  # Display warning count
  warnings=$(grep "Warnings:" $LYNIS_OUTPUT | awk '{print $2}')
  echo -e "${YELLOW}Warnings found: $warnings${NC}"
  
  # Display suggestions count
  suggestions=$(grep "Suggestions:" $LYNIS_OUTPUT | awk '{print $2}')
  echo -e "${YELLOW}Suggestions: $suggestions${NC}"
  
  # Display hardening index
  hardening=$(grep "Hardening index:" $LYNIS_OUTPUT | awk '{print $3}')
  echo -e "${YELLOW}Hardening index: $hardening${NC}"
  
  # Display some warnings and suggestions
  echo
  echo -e "${YELLOW}Sample warnings:${NC}"
  grep "Warning:" $LYNIS_OUTPUT | head -5
  
  echo
  echo -e "${YELLOW}Sample suggestions:${NC}"
  grep "Suggestion:" $LYNIS_OUTPUT | head -5
  
  # Clean up
  rm -f $LYNIS_OUTPUT
  
  echo
  echo -e "${YELLOW}Would you like to see the full Lynis report? (y/n)${NC}"
  read -r full_report
  if [[ "$full_report" =~ ^[Yy]$ ]]; then
    lynis audit system --no-colors | less
  fi
  
  echo -e "${YELLOW}Lynis Security Recommendations:${NC}"
  echo "1. Address any warnings identified by the scan"
  echo "2. Implement suggested security controls"
  echo "3. Run Lynis regularly as part of your security maintenance"
  echo "4. Use the detailed report to create a security improvement plan"
  echo "5. Compare reports over time to track security improvements"
}

# 8. Rootkit detection with chkrootkit
rootkit_detection() {
  section "Rootkit Detection with chkrootkit"
  
  # Check if chkrootkit is installed
  if ! check_tool "chkrootkit"; then
    return
  fi
  
  echo -e "${YELLOW}About chkrootkit:${NC}"
  echo "chkrootkit is a tool to locally check for signs of a rootkit infection."
  echo "It checks system binaries for rootkit modification and looks for known"
  echo "rootkit signatures."
  echo
  
  echo -e "${YELLOW}Running chkrootkit scan...${NC}"
  echo "This might take a few minutes. Only showing summary results."
  echo
  
  # Create a temporary file for output
  CHKROOTKIT_OUTPUT=$(mktemp)
  
  # Run chkrootkit and capture output
  chkrootkit -q > $CHKROOTKIT_OUTPUT 2>&1
  
  # Count suspicious items
  suspicious=$(grep -c "INFECTED" $CHKROOTKIT_OUTPUT)
  
  echo -e "${GREEN}chkrootkit Scan Results:${NC}"
  echo
  
  if [ "$suspicious" -gt 0 ]; then
    echo -e "${RED}Potentially infected items found: $suspicious${NC}"
    grep "INFECTED" $CHKROOTKIT_OUTPUT
  else
    echo -e "${GREEN}No obvious rootkit infections found.${NC}"
  fi
  
  # Show suspicious findings or common false positives
  warning_count=$(grep -c -E '(suspicious|Searching|wrong)' $CHKROOTKIT_OUTPUT)
  if [ "$warning_count" -gt 0 ]; then
    echo
    echo -e "${YELLOW}Warnings or possible false positives:${NC}"
    grep -E '(suspicious|Searching|wrong)' $CHKROOTKIT_OUTPUT | head -10
  fi
  
  # Clean up
  rm -f $CHKROOTKIT_OUTPUT
  
  echo
  echo -e "${YELLOW}Would you like to see the full chkrootkit report? (y/n)${NC}"
  read -r full_report
  if [[ "$full_report" =~ ^[Yy]$ ]]; then
    chkrootkit | less
  fi
  
  echo -e "${YELLOW}Rootkit Detection Recommendations:${NC}"
  echo "1. Run rootkit scans regularly (weekly or after system changes)"
  echo "2. Investigate any 'INFECTED' results carefully (some may be false positives)"
  echo "3. If infection is confirmed, isolated the affected system immediately"
  echo "4. Consider using multiple tools for rootkit detection (rkhunter, AIDE, etc.)"
  echo "5. Keep security tools updated for the latest rootkit signatures"
}

# 9. Interactive security challenge
interactive_challenge() {
  section "Interactive Security Challenge"
  
  echo -e "${YELLOW}Security Assessment Challenge:${NC}"
  echo "This activity tests your understanding of security auditing."
  echo "Let's evaluate some common security issues and decide on remediation steps."
  echo
  
  # Challenge 1: World-writable file
  echo -e "${BLUE}Scenario 1:${NC} You find a world-writable configuration file:"
  echo "$ ls -la /etc/important_config.conf"
  echo "-rw-rw-rw- 1 root root 2048 Jan 10 10:00 /etc/important_config.conf"
  echo
  echo "What is the security risk, and how would you fix it?"
  echo "1) No risk since it's owned by root"
  echo "2) Risk of unauthorized modification, change permissions to 644"
  echo "3) Risk of unauthorized access, encrypt the file"
  echo "4) Risk of file deletion, change permissions to 444"
  read -p "Your answer (1-4): " answer1
  
  if [ "$answer1" == "2" ]; then
    echo -e "${GREEN}Correct!${NC} World-writable configuration files allow any user to modify settings,"
    echo "potentially leading to system compromise or misconfiguration."
    echo "Proper permissions would be 644 (rw-r--r--) for most config files."
  else
    echo -e "${RED}Incorrect.${NC} The correct answer is 2."
    echo "World-writable files can be modified by any user on the system, creating a security risk."
  fi
  
  echo
  
  # Challenge 2: SSH Configuration
  echo -e "${BLUE}Scenario 2:${NC} You find this in your SSH server configuration:"
  echo "PermitRootLogin yes"
  echo "PasswordAuthentication yes"
  echo
  echo "What security concerns do these settings raise?"
  echo "1) None, these are default secure settings"
  echo "2) Allowing root login increases risk of unauthorized access"
  echo "3) Password authentication is less secure than key-based"
  echo "4) Both 2 and 3 are security concerns"
  read -p "Your answer (1-4): " answer2
  
  if [ "$answer2" == "4" ]; then
    echo -e "${GREEN}Correct!${NC} Both settings reduce security:"
    echo "- PermitRootLogin yes: Allows attackers to target the known root account directly"
    echo "- PasswordAuthentication yes: Passwords can be brute-forced, unlike SSH keys"
    echo "Recommended settings are 'PermitRootLogin no' and 'PasswordAuthentication no'"
  else
    echo -e "${RED}Incorrect.${NC} The correct answer is 4."
    echo "Both settings create significant security risks and should be changed."
  fi
  
  echo
  
  # Challenge 3: Open ports
  echo -e "${BLUE}Scenario 3:${NC} A port scan reveals these open ports on your server:"
  echo "22/tcp open ssh"
  echo "25/tcp open smtp"
  echo "80/tcp open http"
  echo "445/tcp open microsoft-ds"
  echo "3389/tcp open ms-wts"
  echo
  echo "Which services might be unnecessary and create security risks on a Linux web server?"
  echo "1) SSH (22/tcp)"
  echo "2) Microsoft-DS/SMB (445/tcp) and RDP (3389/tcp)"
  echo "3) HTTP (80/tcp)"
  echo "4) SMTP (25/tcp)"
  read -p "Your answer (1-4): " answer3
  
  if [ "$answer3" == "2" ]; then
    echo -e "${GREEN}Correct!${NC} Microsoft-DS (SMB) and RDP are typically Windows services."
    echo "On a Linux web server, these are likely unnecessary and create potential attack vectors."
    echo "They should be disabled unless specifically required."
  else
    echo -e "${RED}Incorrect.${NC} The correct answer is 2."
    echo "SSH, HTTP, and possibly SMTP might be needed on a web server, but SMB and RDP are"
    echo "typically Windows services that represent unnecessary security risks on Linux."
  fi
  
  echo
  
  # Final score
  correct=0
  [ "$answer1" == "2" ] && ((correct++))
  [ "$answer2" == "4" ] && ((correct++))
  [ "$answer3" == "2" ] && ((correct++))
  
  echo -e "${YELLOW}Challenge complete!${NC}"
  echo "You got $correct out of 3 correct."
  
  if [ "$correct" -eq 3 ]; then
    echo -e "${GREEN}Excellent! You have a strong understanding of security auditing concepts.${NC}"
  elif [ "$correct" -eq 2 ]; then
    echo -e "${YELLOW}Good job! You have a solid understanding, but there's still room to learn.${NC}"
  else
    echo -e "${RED}You might need more practice with security auditing concepts.${NC}"
  fi
  
  echo
  echo -e "${YELLOW}Security Auditing Key Takeaways:${NC}"
  echo "1. Regularly check file permissions, especially for configuration files"
  echo "2. Secure SSH and other remote access services"
  echo "3. Disable unnecessary services and close unused ports"
  echo "4. Monitor logs for suspicious activities"
  echo "5. Use automated tools like Lynis for comprehensive scanning"
}

# Start the component menu
show_audit_menu 