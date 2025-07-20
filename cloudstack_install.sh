#!/bin/bash

# CloudStack 4.20.0 Installation Script
# Author: ParrotXray
# Date: $(date)
# Support OS: Ubuntu 24.04

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
LIGHT_CYAN='\033[1;36m'
NC='\033[0m' # No Color

# Global variables for architecture
SCRIPT_NAME="cloudstack_install.sh"
OS_VERSION="22.04"
ARCH=""
SYSTEMVM_URL=""
IS_UEFI=false
BOOT_TYPE=""

# Installation state tracking
INSTALL_STATE_DIR="/var/lib/cloudstack-install"
INSTALL_LOG_FILE="/var/log/cloudstack-install.log"
INSTALL_CONFIG_FILE="$INSTALL_STATE_DIR/config.env"

# Installation steps
STEPS=(
    "check_system_requirements"
    "collect_configuration"
    "install_requirements"
    "install_ssh"
    "configure_network"
    "install_nfs"
    "install_mysql"
    "secure_mysql"
    "install_cloudstack_management"
    "install_systemvm"
    "install_cloudstack_agent"
    "launch_cloudstack"
)

# Logging function
log() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}$message${NC}"
    echo "$message" >> "$INSTALL_LOG_FILE"
}

error() {
    local message="[ERROR] $1"
    echo -e "${RED}$message${NC}" >&2
    echo "$message" >> "$INSTALL_LOG_FILE"
}

warning() {
    local message="[WARNING] $1"
    echo -e "${YELLOW}$message${NC}"
    echo "$message" >> "$INSTALL_LOG_FILE"
}

info() {
    local message="[INFO] $1"
    echo -e "${BLUE}$message${NC}"
    echo "$message" >> "$INSTALL_LOG_FILE"
}

# Initialize installation state directory
init_install_state() {
    if [[ ! -d "$INSTALL_STATE_DIR" ]]; then
        mkdir -p "$INSTALL_STATE_DIR"
        chmod 755 "$INSTALL_STATE_DIR"
        log "Created installation state directory: $INSTALL_STATE_DIR"
    fi
    
    # Create log file if it doesn't exist
    if [[ ! -f "$INSTALL_LOG_FILE" ]]; then
        touch "$INSTALL_LOG_FILE"
        chmod 644 "$INSTALL_LOG_FILE"
        log "Created installation log file: $INSTALL_LOG_FILE"
    fi
}

# Mark step as completed
mark_step_completed() {
    local step="$1"
    touch "$INSTALL_STATE_DIR/${step}_completed"
    log "Step '$step' completed and marked"
}

# Check if step is completed
is_step_completed() {
    local step="$1"
    [[ -f "$INSTALL_STATE_DIR/${step}_completed" ]]
}

# Save configuration to file
save_config() {
    cat > "$INSTALL_CONFIG_FILE" << EOF
# CloudStack Installation Configuration
# Generated on: $(date)

# Network Configuration
NATNIC="$NATNIC"
LANIP="$LANIP"
CIDR="$CIDR"
GATEWAY="$GATEWAY"
DNS1="$DNS1"
DNS2="$DNS2"
NETWORK_MODE="$NETWORK_MODE"

# MySQL Configuration
MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASSWORD"
MYSQL_CLOUD_PASSWORD="$MYSQL_CLOUD_PASSWORD"
MANAGEMENT_SERVER_KEY="$MANAGEMENT_SERVER_KEY"
DATABASE_KEY="$DATABASE_KEY"

# System Configuration
ARCH="$ARCH"
SYSTEMVM_URL="$SYSTEMVM_URL"
IS_UEFI="$IS_UEFI"
BOOT_TYPE="$BOOT_TYPE"
EOF
    chmod 600 "$INSTALL_CONFIG_FILE"
    log "Configuration saved to $INSTALL_CONFIG_FILE"
}

# Load configuration from file
load_config() {
    if [[ -f "$INSTALL_CONFIG_FILE" ]]; then
        source "$INSTALL_CONFIG_FILE"
        log "Configuration loaded from $INSTALL_CONFIG_FILE"
        return 0
    else
        return 1
    fi
}

# Show installation progress
show_progress() {
    echo -e "\n${BLUE}=== Installation Progress ===${NC}"
    local completed_count=0
    local total_count=${#STEPS[@]}
    
    for step in "${STEPS[@]}"; do
        if is_step_completed "$step"; then
            echo -e "${GREEN}✓${NC} $step"
            ((completed_count++))
        else
            echo -e "${YELLOW}○${NC} $step"
        fi
    done
    
    echo -e "\nProgress: $completed_count/$total_count steps completed"
    
    if [[ $completed_count -eq $total_count ]]; then
        echo -e "${GREEN}Installation is complete!${NC}"
        return 0
    else
        echo -e "${YELLOW}Installation is incomplete. Use --resume to continue.${NC}"
        return 1
    fi
}

# Clean up installation state
cleanup_install() {
    log "Cleaning up previous installation state..."
    
    # Stop services
    systemctl stop cloudstack-management 2>/dev/null || true
    systemctl stop cloudstack-usage 2>/dev/null || true
    systemctl stop cloudstack-agent 2>/dev/null || true
    systemctl stop mysql 2>/dev/null || true
    systemctl stop nfs-kernel-server 2>/dev/null || true
    
    # Remove CloudStack packages
    apt-get remove --purge -y cloudstack-management cloudstack-usage cloudstack-agent 2>/dev/null || true
    
    # Remove MySQL (optional - ask user)
    read -p "Remove MySQL server and data? (y/N): " remove_mysql
    if [[ "$remove_mysql" =~ ^[Yy]$ ]]; then
        apt-get remove --purge -y mysql-server mysql-common mysql-client-core-* 2>/dev/null || true
        rm -rf /var/lib/mysql
        rm -rf /etc/mysql
    fi
    
    # Remove NFS exports
    sed -i '/\/export/d' /etc/exports 2>/dev/null || true
    exportfs -ra 2>/dev/null || true
    
    # Remove created directories
    rm -rf /export
    rm -rf /mnt/primary
    rm -rf /mnt/secondary
    
    # Remove netplan configuration
    rm -f /etc/netplan/01-network-manager-all.yaml
    
    # Restore original netplan if backup exists
    if ls /etc/netplan/*.yaml.backup.* 1> /dev/null 2>&1; then
        latest_backup=$(ls -t /etc/netplan/*.yaml.backup.* | head -1)
        original_file=$(echo "$latest_backup" | sed 's/\.backup\..*$//')
        cp "$latest_backup" "$original_file"
        log "Restored original netplan configuration"
    fi
    
    # Remove installation state
    rm -rf "$INSTALL_STATE_DIR"
    
    # Remove keys file
    rm -f /root/cloudstack_keys.txt
    
    log "Cleanup completed. You can now run a fresh installation."
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Wait for apt lock to be released
wait_for_apt_lock() {
    local max_attempts=30
    local attempt=0
    local current_pid=$$
    local script_name=$(basename "$0" 2>/dev/null || echo "$SCRIPT_NAME")
    
    while true; do
        # Check if any APT locks exist
        if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && ! fuser /var/lib/apt/lists/lock >/dev/null 2>&1 && ! fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
            if [ $attempt -gt 0 ]; then
                log "APT lock released after $((attempt * 2)) seconds"
            fi
            return 0
        fi
        
        if [ $attempt -ge $max_attempts ]; then
            error "APT is locked by another process for too long. Attempting automatic fix..."
            
            # Show what's using the lock
            warning "Processes using APT locks:"
            lsof /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null | head -10 || true
            
            # Try to fix automatically
            warning "Attempting to resolve APT lock automatically..."
            
            # Check for and handle suspended processes first
            local apt_pids=$(pgrep -f "apt-get|apt |dpkg|unattended-upgrade" | grep -v "^${current_pid}$" | tr '\n' ' ')
            
            # Filter out our own script more carefully
            local filtered_pids=""
            for pid in $apt_pids; do
                if [ -n "$pid" ] && [ -d "/proc/$pid" ] && [ "$pid" != "$current_pid" ]; then
                    local cmdline=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
                    # Skip if it's our script
                    if [[ "$cmdline" != *"$script_name"* ]]; then
                        filtered_pids="$filtered_pids $pid"
                    fi
                fi
            done
            apt_pids="$filtered_pids"
            
            local suspended_pids=""
            
            if [ -n "$apt_pids" ]; then
                for pid in $apt_pids; do
                    if [ -d "/proc/$pid" ]; then
                        local stat=$(ps -p $pid -o stat= 2>/dev/null | tr -d ' ')
                        if [[ "$stat" =~ T ]]; then
                            suspended_pids="$suspended_pids $pid"
                        fi
                    fi
                done
                
                if [ -n "$suspended_pids" ]; then
                    warning "Found suspended APT processes: $suspended_pids"
                    warning "Resuming suspended processes first..."
                    for pid in $suspended_pids; do
                        if [ -d "/proc/$pid" ] && [ "$pid" != "$current_pid" ]; then
                            log "Resuming process $pid..."
                            kill -CONT "$pid" 2>/dev/null || true
                        fi
                    done
                    sleep 2
                fi
            fi
            
            # Kill processes by specific PID to avoid killing our own script
            log "Terminating APT processes..."
            for pid in $apt_pids; do
                if [ -d "/proc/$pid" ] && [ "$pid" != "$current_pid" ]; then
                    # Double-check this isn't our script
                    local cmdline=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
                    if [[ "$cmdline" != *"$script_name"* ]]; then
                        kill -TERM "$pid" 2>/dev/null || true
                    fi
                fi
            done
            sleep 3
            
            # Force kill any remaining processes
            for pid in $apt_pids; do
                if [ -d "/proc/$pid" ] && [ "$pid" != "$current_pid" ]; then
                    # Double-check this isn't our script
                    local cmdline=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
                    if [[ "$cmdline" != *"$script_name"* ]]; then
                        kill -KILL "$pid" 2>/dev/null || true
                    fi
                fi
            done
            sleep 2
            
            # Remove lock files
            rm -f /var/lib/dpkg/lock-frontend
            rm -f /var/lib/apt/lists/lock
            rm -f /var/cache/apt/archives/lock
            rm -f /var/lib/dpkg/lock
            
            # Fix interrupted dpkg
            dpkg --configure -a 2>/dev/null || true
            
            # Wait a bit for system to settle
            sleep 2
            
            # Check if fix worked
            if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && ! fuser /var/lib/apt/lists/lock >/dev/null 2>&1 && ! fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
                log "APT lock resolved automatically, continuing installation..."
                return 0
            else
                error "Unable to resolve APT lock automatically"
                warning "Manual intervention required. Please run:"
                echo "  sudo bash -c \"$(curl -fsSL https://raw.githubusercontent.com/ParrotXray/CloudStack-4.20.0-Installation-Guide/refs/heads/feat/resume-capability/cloudstack_install.sh)\" -- --fix-apt-lock"
                echo "  Then run: $0 --resume"
                return 1
            fi
        fi
        
        if [ $attempt -eq 0 ]; then
            warning "APT is locked by another process. Waiting for it to finish..."
            info "This usually happens when system updates are running in background"
            
            # Show what's using the lock
            if command -v lsof >/dev/null 2>&1; then
                info "Processes using APT:"
                lsof /var/lib/dpkg/lock-frontend 2>/dev/null | tail -n +2 || true
            fi
            
            # Check for suspended processes
            local suspended_pids=$(ps aux | grep -E "(apt|dpkg|unattended-upgrade)" | grep -v grep | grep -v "$script_name" | awk '$8 ~ /T/ {print $2}' | tr '\n' ' ')
            if [ -n "$suspended_pids" ]; then
                warning "Detected suspended APT processes: $suspended_pids"
                warning "These may be from interrupted SSH sessions or Ctrl+Z"
            fi
        fi
        
        sleep 2
        ((attempt++))
        
        if [ $((attempt % 10)) -eq 0 ]; then
            info "Still waiting for APT lock... (attempt $attempt/$max_attempts)"
            
            # Check if the process is still alive and show its status
            if command -v lsof >/dev/null 2>&1; then
                local lock_pids=$(lsof -t /var/lib/dpkg/lock-frontend 2>/dev/null || true)
                if [ -n "$lock_pids" ]; then
                    info "Lock held by PIDs: $lock_pids"
                    for pid in $lock_pids; do
                        if [ -d "/proc/$pid" ]; then
                            local cmd=$(ps -p $pid -o comm= 2>/dev/null || echo 'unknown')
                            local stat=$(ps -p $pid -o stat= 2>/dev/null || echo 'unknown')
                            info "PID $pid ($stat): $cmd"
                            if [[ "$stat" =~ T ]]; then
                                warning "Process $pid is suspended (status: $stat)"
                            fi
                        else
                            warning "PID $pid no longer exists, but lock remains"
                        fi
                    done
                fi
            fi
        fi
    done
}

# General package installation function with state checking
ensure_packages() {
    local packages_needed=()
    local all_packages=("$@")
    
    if [ ${#all_packages[@]} -eq 0 ]; then
        warning "No packages specified for installation check"
        return 1
    fi
    
    log "Checking packages: ${all_packages[*]}"
    
    for package in "${all_packages[@]}"; do
        if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
            packages_needed+=("$package")
            info "Package '$package' needs to be installed"
        else
            info "Package '$package' already installed"
        fi
    done
    
    if [ ${#packages_needed[@]} -gt 0 ]; then
        log "Installing missing packages: ${packages_needed[*]}"
        
        # Wait for apt lock to be released
        if ! wait_for_apt_lock; then
            error "Cannot proceed with package installation due to APT lock"
            return 1
        fi
        
        if ! apt update; then
            error "Failed to update package list"
            return 1
        fi
        
        # Wait again in case update triggered another lock
        if ! wait_for_apt_lock; then
            error "Cannot proceed with package installation due to APT lock"
            return 1
        fi
        
        if apt install "${packages_needed[@]}" -y; then
            log "Packages installed successfully: ${packages_needed[*]}"
            
            local failed_packages=()
            for package in "${packages_needed[@]}"; do
                if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
                    failed_packages+=("$package")
                fi
            done
            
            if [ ${#failed_packages[@]} -gt 0 ]; then
                error "Installation verification failed for: ${failed_packages[*]}"
                warning "This may be due to APT lock issues. Try: $0 --fix-apt-lock"
                return 1
            fi
        else
            error "Failed to install packages: ${packages_needed[*]}"
            warning "APT may be locked. Try: $0 --fix-apt-lock && $0 --resume"
            return 1
        fi
    else
        log "All requested packages are already installed, skipping..."
    fi
    
    return 0
}

# Function to prompt for user input
prompt_input() {
    local prompt="$1"
    local var_name="$2"
    local default="$3"
    
    if [ -n "$default" ]; then
        read -p "${prompt} (default: ${default}): " input
        if [ -z "$input" ]; then
            input="$default"
        fi
    else
        read -p "${prompt}: " input
        while [ -z "$input" ]; do
            read -p "This field is required. ${prompt}: " input
        done
    fi
    
    eval "$var_name='$input'"
}

# Check UEFI/BIOS/U-Boot boot mode
check_boot_mode() {
    if is_step_completed "check_boot_mode"; then
        info "Boot mode already detected: $BOOT_TYPE"
        return 0
    fi
    
    log "Detecting boot mode (BIOS/UEFI/U-Boot)..."

    # Check for U-Boot first (ARM devices often use U-Boot)
    if [ -f "/proc/device-tree/chosen/bootargs" ] || [ -d "/proc/device-tree" ]; then
        IS_UEFI=false
        BOOT_TYPE="U-Boot"
        log "U-Boot boot mode detected (Device Tree found)"
    # Check /sys/firmware/efi directory for UEFI
    elif [ -d "/sys/firmware/efi" ]; then
        IS_UEFI=true
        BOOT_TYPE="UEFI"
        log "UEFI boot mode detected"
    else
        IS_UEFI=false
        BOOT_TYPE="Legacy BIOS"
        log "Legacy BIOS boot mode detected"
    fi

    info "Boot Type: $BOOT_TYPE"
    mark_step_completed "check_boot_mode"
}

check_system_requirements() {
    # Initialize state directory first if not exists
    init_install_state
    
    if is_step_completed "check_system_requirements"; then
        log "System requirements already checked"
        return 0
    fi
    
    log "Checking system requirements..."

    # OS Check
    if [ -f /etc/debian_version ]; then
        ensure_packages lsb-release
        
        local distro=$(lsb_release -i -s)
        local version=$(lsb_release -r -s)
        local codename=$(lsb_release -c -s)
        
        if [[ "$distro" != "Ubuntu" ]]; then
            error "Distribution '$distro' is not supported"
            echo "Required: Ubuntu $OS_VERSION"
            exit 1
        fi
        
        if [[ "$version" != "$OS_VERSION" ]]; then
            error "Ubuntu $version is not supported"
            echo "Required: Ubuntu $OS_VERSION"
            echo "Current:  Ubuntu $version ($codename)"
            exit 1
        fi
        
        log "Ubuntu $version ($codename) - supported"
        
    elif [ -f /etc/redhat-release ]; then
        local redhat_version=$(cat /etc/redhat-release)
        error "Red Hat-based system detected: $redhat_version"
        echo "This script requires Ubuntu $OS_VERSION"
        exit 1
        
    else
        error "Unsupported operating system"
        echo "This script requires Ubuntu $OS_VERSION"
        exit 1
    fi

    log "System requirements check passed"
    mark_step_completed "check_system_requirements"
}

# Check CPU architecture and set appropriate variables
check_architecture() {
    if is_step_completed "check_architecture"; then
        log "Architecture already detected: $ARCH"
        return 0
    fi
    
    log "Detecting CPU architecture..."
    
    arch_output=$(uname -m)
    os_arch=$(dpkg --print-architecture)
    
    info "System architecture: $arch_output"
    info "OS architecture: $os_arch"
    
    case "$arch_output" in
        x86_64|amd64)
            ARCH="amd64"
            SYSTEMVM_URL="https://download.cloudstack.org/systemvm/4.20/systemvmtemplate-4.20.1-x86_64-kvm.qcow2.bz2"
            log "Detected AMD64/x86_64 architecture"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            SYSTEMVM_URL="https://download.cloudstack.org/systemvm/4.20/systemvmtemplate-4.20.1-aarch64-kvm.qcow2.bz2"
            log "Detected AArch64/ARM64 architecture"
            ;;
        armv7l|armhf)
            error "ARM 32-bit (ARMv7) is not supported by CloudStack 4.20"
            echo "Supported architectures: AMD64/x86_64, AArch64/ARM64"
            exit 1
            ;;
        *)
            error "Unsupported architecture: $arch_output"
            echo "Supported architectures: AMD64/x86_64, AArch64/ARM64"
            echo "Current architecture: $arch_output"
            exit 1
            ;;
    esac
    
    # Verify architecture compatibility with OS
    case "$os_arch" in
        amd64)
            if [ "$ARCH" != "amd64" ]; then
                error "Architecture mismatch detected. OS: $os_arch, Hardware: $arch_output"
                exit 1
            fi
            ;;
        arm64)
            if [ "$ARCH" != "aarch64" ]; then
                error "Architecture mismatch detected. OS: $os_arch, Hardware: $arch_output"
                exit 1
            fi
            ;;
    esac
    
    info "Using SystemVM template: $SYSTEMVM_URL"
    mark_step_completed "check_architecture"
}

# Check network interface exists
check_network_interface() {
    if ! ip link show "$NATNIC" >/dev/null 2>&1; then
        error "Network interface '$NATNIC' does not exist!"
        echo -e "\nAvailable interfaces:"
        ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://' | grep -v lo
        return 1
    fi
    return 0
}

select_interface() {
    echo -e "\n${BLUE}Available network interfaces:${NC}"
    ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://' | grep -v lo
    
    while true; do
        prompt_input "Enter your network interface name (e.g., eth0, ens33)" "NATNIC"
        if check_network_interface; then
            break
        fi
    done
}

collect_network_ip_info() {
    # Show current IP configuration
    echo -e "\n${BLUE}Current configuration of $NATNIC:${NC}"
    ip addr show $NATNIC
    
    prompt_input "Enter your desired IP address (e.g., 192.168.4.100)" "LANIP"
    prompt_input "Enter CIDR notation (e.g., /24, /21)" "CIDR"
    prompt_input "Enter gateway IP (e.g., 192.168.4.1)" "GATEWAY"
    prompt_input "Enter DNS1 (e.g., 8.8.8.8)" "DNS1"
    prompt_input "Enter DNS2 (e.g., 8.8.4.4)" "DNS2"
    
    # Validate IP addresses
    if ! [[ $LANIP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Invalid IP address format: $LANIP"
        exit 1
    fi
    
    if ! [[ $GATEWAY =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Invalid gateway IP format: $GATEWAY"
        exit 1
    fi
    
    if ! [[ $DNS1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Invalid DNS1 format: $DNS1"
        exit 1
    fi

    if ! [[ $DNS2 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Invalid DNS2 format: $DNS2"
        exit 1
    fi
    
    log "Network configuration collected:"
    info "Interface: $NATNIC"
    info "IP: $LANIP$CIDR"
    info "Gateway: $GATEWAY"
    info "DNS1: $DNS1"
    info "DNS2: $DNS2"
}

# Select network configuration mode
select_network_mode() {
    echo -e "${BLUE}"
    echo "======================================="
    echo "    NETWORK CONFIGURATION OPTIONS     "
    echo "======================================="
    echo -e "${NC}"
    echo ""
    echo "1) Static IP Configuration (Recommended)"
    echo "   - Best for production environments"
    echo ""
    echo "2) DHCP Bridge Configuration"
    echo "   - Good for testing/development"
    echo ""
    while true; do
        read -p "Select network configuration option (1-2): " choice
        
        case $choice in
            1)
                NETWORK_MODE="static"
                log "Selected: Static IP Configuration"
                break
                ;;
            2)
                NETWORK_MODE="dhcp"
                log "Selected: DHCP Bridge Configuration"
                break
                ;;
            *)
                error "Invalid choice. Please select 1-2."
                ;;
        esac
    done
}

# Collect network configuration
collect_network_config() {
    log "Collecting network configuration..."
    
    select_network_mode
    select_interface
    
    if [ "$NETWORK_MODE" = "static" ]; then
        collect_network_ip_info
    fi
}

# Generate secure key
generate_secure_key() {
    local prefix="$1"
    echo "${prefix}-$(date +%Y%m%d)-$(openssl rand -hex 8)"
}

# Collect MySQL passwords
collect_mysql_config() {
    log "Collecting MySQL configuration..."
    
    prompt_input "Enter MySQL root password" "MYSQL_ROOT_PASSWORD"
    prompt_input "Enter MySQL cloud user password" "MYSQL_CLOUD_PASSWORD"
    
    # Generate suggested keys
    SUGGESTED_MGT_KEY=$(generate_secure_key "CS-MGT")
    SUGGESTED_DB_KEY=$(generate_secure_key "CS-DB")
    
    echo -e "\n${YELLOW}Important: Management and Database keys are used for encryption and security.${NC}"
    echo -e "${YELLOW}Suggested secure keys have been generated for you.${NC}"
    
    prompt_input "Enter CloudStack management server key" "MANAGEMENT_SERVER_KEY" "$SUGGESTED_MGT_KEY"
    prompt_input "Enter CloudStack database key" "DATABASE_KEY" "$SUGGESTED_DB_KEY"
    
    # Save keys to file for reference
    cat > /root/cloudstack_keys.txt << EOF
CloudStack Installation Keys - $(date)
=====================================
Management Server Key: ${MANAGEMENT_SERVER_KEY}
Database Key: ${DATABASE_KEY}
MySQL Root Password: ${MYSQL_ROOT_PASSWORD}
MySQL Cloud Password: ${MYSQL_CLOUD_PASSWORD}

IMPORTANT: Keep this file secure and backed up!
These keys are required for CloudStack operation.
EOF
    
    chmod 600 /root/cloudstack_keys.txt
    warning "Keys saved to /root/cloudstack_keys.txt - Please backup this file!"
}

# Set root password
set_root_password() {
    log "Please set the system root password first..."
    
    while true; do
        prompt_input "Enter new root password" "NEW_ROOT_PASSWORD"
        prompt_input "Confirm root password" "CONFIRM_ROOT_PASSWORD"
        
        if [ "$NEW_ROOT_PASSWORD" == "$CONFIRM_ROOT_PASSWORD" ]; then
            echo "root:${NEW_ROOT_PASSWORD}" | chpasswd
            log "Root password updated successfully"
            break
        else
            warning "Passwords do not match. Please try again."
        fi
    done
}

# Collect all configuration
collect_configuration() {
    if is_step_completed "collect_configuration"; then
        log "Configuration already collected"
        return 0
    fi
    
    check_boot_mode
    check_architecture
    set_root_password
    collect_network_config
    collect_mysql_config
    
    # Save configuration
    save_config
    
    echo -e "\n${YELLOW}Starting installation with collected configuration...${NC}"
    read -p "Press Enter to continue or Ctrl+C to abort..."
    
    mark_step_completed "collect_configuration"
}

# Install basic requirements
install_requirements() {
    if is_step_completed "install_requirements"; then
        log "Basic requirements already installed"
        return 0
    fi
    
    log "Installing basic requirements..."
    
    apt update
    ensure_packages vim openntpd
    
    log "Basic requirements installed successfully"
    mark_step_completed "install_requirements"
}

# Install and configure SSH
install_ssh() {
    if is_step_completed "install_ssh"; then
        log "SSH already installed and configured"
        return 0
    fi
    
    log "Installing and configuring SSH..."
    
    ensure_packages openssh-server
    
    # Check if SSH is already configured
    if ! grep -q "CloudStack SSH Configuration" /etc/ssh/sshd_config; then
        # Backup original sshd_config
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        
        # Configure SSH
        cat >> /etc/ssh/sshd_config << EOF

# CloudStack SSH Configuration
PermitRootLogin yes
KexAlgorithms=+diffie-hellman-group-exchange-sha1
PubkeyAcceptedKeyTypes=+ssh-dss
HostKeyAlgorithms=+ssh-dss
KexAlgorithms=+diffie-hellman-group1-sha1
EOF
        
        systemctl restart ssh
        log "SSH configured successfully"
    else
        log "SSH already configured for CloudStack"
    fi
    
    mark_step_completed "install_ssh"
}

# Configure network
configure_network() {
    if is_step_completed "configure_network"; then
        log "Network already configured"
        return 0
    fi
    
    log "Configuring network..."
    
    ensure_packages net-tools bridge-utils
    
    # Get current netplan files
    NETPLAN_FILES=($(ls /etc/netplan/*.yaml 2>/dev/null || echo))
    
    # Backup existing netplan configurations
    for file in "${NETPLAN_FILES[@]}"; do
        if [ -f "$file" ]; then
            cp "$file" "${file}.backup.$(date +%Y%m%d_%H%M%S)"
            log "Backed up $file"
        fi
    done
    
    # Remove existing configurations to avoid conflicts
    rm -f /etc/netplan/*.yaml
    
    # Create new netplan configuration
    NETPLAN_CONFIG="/etc/netplan/01-network-manager-all.yaml"
    
    if [ "$NETWORK_MODE" = "static" ]; then
        cat > $NETPLAN_CONFIG << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${NATNIC}:
      dhcp4: false
      dhcp6: false
      optional: true
  bridges:
    cloudbr0:
      dhcp4: false
      dhcp6: false
      interfaces: [${NATNIC}]
      addresses: [${LANIP}${CIDR}]
      routes:
       - to: default
         via: ${GATEWAY}
      nameservers:
        addresses: [${DNS1}, ${DNS2}]
      parameters:
        stp: false
        forward-delay: 0
EOF
    else
        cat > $NETPLAN_CONFIG << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${NATNIC}:
      dhcp4: false
      dhcp6: false
      optional: true
  bridges:
    cloudbr0:
      dhcp4: true
      dhcp6: false
      interfaces: [${NATNIC}]
      parameters:
        stp: false
        forward-delay: 0
EOF
    fi
    
    # Set correct permissions
    chmod 600 $NETPLAN_CONFIG
    chown root:root $NETPLAN_CONFIG
    
    log "Network configuration created with correct permissions"
    
    # Validate configuration
    if ! netplan generate; then
        error "Network configuration validation failed"
        exit 1
    fi
    
    warning "Network configuration will be applied. This may temporarily disconnect your connection."
    warning "Make sure you have physical access to the server!"
    
    echo -e "\nCurrent network configuration:"
    cat $NETPLAN_CONFIG
    
    read -p "Press Enter to apply the configuration (Ctrl+C to abort)..."
    
    # Apply configuration directly (skip try as it may not work with bridges)
    if netplan apply; then
        log "Network configuration applied successfully"
        
        # Wait for network to stabilize
        sleep 5
        
        # Verify bridge is created
        if ip addr show cloudbr0 >/dev/null 2>&1; then
            log "Bridge cloudbr0 created successfully"
            ip addr show cloudbr0
        else
            error "Bridge cloudbr0 was not created properly"
            exit 1
        fi
        
        # Test connectivity
        if [ "$NETWORK_MODE" = "static" ]; then
            if ping -c 3 $GATEWAY >/dev/null 2>&1; then
                log "Network connectivity verified"
            else
                error "Cannot ping gateway. Please check network configuration."
                exit 1
            fi
        else
            if ping -c 3 "google.com" >/dev/null 2>&1; then
                log "Network connectivity verified"
            else
                error "Cannot reach internet. Please check network configuration."
                exit 1
            fi
        fi
    else
        error "Failed to apply network configuration"
        
        # Try to restore backup
        if [ ${#NETPLAN_FILES[@]} -gt 0 ]; then
            warning "Attempting to restore original configuration..."
            rm -f $NETPLAN_CONFIG
            for file in "${NETPLAN_FILES[@]}"; do
                backup_file="${file}.backup.$(date +%Y%m%d)_*"
                if ls $backup_file >/dev/null 2>&1; then
                    latest_backup=$(ls -t ${backup_file} | head -1)
                    cp "$latest_backup" "$file"
                fi
            done
            netplan apply
        fi
        exit 1
    fi
    
    mark_step_completed "configure_network"
}

# Install and configure NFS
install_nfs() {
    if is_step_completed "install_nfs"; then
        log "NFS already installed and configured"
        return 0
    fi
    
    log "Installing and configuring NFS..."
    
    ensure_packages nfs-kernel-server nfs-common
    
    # Create NFS directories
    mkdir -p /export
    mkdir -m 777 /export/primary
    mkdir -m 777 /export/secondary
    mkdir -m 777 /mnt/primary
    mkdir -m 777 /mnt/secondary
    
    # Configure NFS exports (check if already configured)
    if ! grep -q "/export/secondary" /etc/exports; then
        echo "/export/secondary *(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
    fi
    
    if ! grep -q "/export/primary" /etc/exports; then
        echo "/export/primary *(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
    fi
    
    # Configure NFS kernel server
    if ! grep -q "LOCKD_TCPPORT=32803" /etc/default/nfs-kernel-server; then
        cat >> /etc/default/nfs-kernel-server << EOF
LOCKD_TCPPORT=32803
LOCKD_UDPPORT=32769
MOUNTD_PORT=892
RQUOTAD_PORT=875
STATD_PORT=662
STATD_OUTGOING_PORT=2020
EOF
    fi
    
    systemctl enable nfs-kernel-server
    systemctl restart nfs-kernel-server
    exportfs -a
    
    # Get current IP for NFS mounts
    if [ "$NETWORK_MODE" = "static" ]; then
        CURRENT_IP="$LANIP"
    else
        CURRENT_IP=$(ip route get 1 | awk '{print $7}' | head -1)
    fi
    
    # Configure fstab for auto-mounting (check if already configured)
    if ! grep -q "/mnt/primary" /etc/fstab; then
        echo "${CURRENT_IP}:/export/primary    /mnt/primary   nfs defaults 0 0" >> /etc/fstab
    fi
    
    if ! grep -q "/mnt/secondary" /etc/fstab; then
        echo "${CURRENT_IP}:/export/secondary    /mnt/secondary   nfs defaults 0 0" >> /etc/fstab
    fi
    
    systemctl daemon-reload
    mount -a
    
    log "NFS configured successfully"
    mark_step_completed "install_nfs"
}

# Install and configure MySQL
install_mysql() {
    if is_step_completed "install_mysql"; then
        log "MySQL already installed and configured"
        return 0
    fi
    
    log "Installing and configuring MySQL..."
    
    ensure_packages mysql-server
    
    # Configure MySQL for CloudStack
    cat > /etc/mysql/mysql.conf.d/mysqld.cnf << EOF
[mysqld]
server-id=master-01
sql-mode="STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO,NO_ZERO_DATE,NO_ZERO_IN_DATE,NO_ENGINE_SUBSTITUTION"
innodb_rollback_on_timeout=1
innodb_lock_wait_timeout=600
max_connections=1000
log-bin=mysql-bin
binlog-format = 'ROW'
EOF
    
    systemctl enable mysql.service
    systemctl start mysql.service
    
    # Check if MySQL root password is already set
    if ! mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SELECT 1;" 2>/dev/null; then
        # Set MySQL root password
        mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password by '${MYSQL_ROOT_PASSWORD}';" 2>/dev/null || true
    fi
    
    log "MySQL configured successfully"
    mark_step_completed "install_mysql"
}

# Run MySQL secure installation
secure_mysql() {
    if is_step_completed "secure_mysql"; then
        log "MySQL already secured"
        return 0
    fi
    
    log "Running MySQL secure installation..."
    
    # Use expect to automate mysql_secure_installation
    ensure_packages expect
    
    expect -c "
    spawn mysql_secure_installation
    expect \"Enter password for user root:\"
    send \"${MYSQL_ROOT_PASSWORD}\r\"
    expect \"Press y|Y for Yes, any other key for No:\"
    send \"n\r\"
    expect \"Change the password for root ?\"
    send \"n\r\"
    expect \"Remove anonymous users?\"
    send \"n\r\"
    expect \"Disallow root login remotely?\"
    send \"y\r\"
    expect \"Remove test database and access to it?\"
    send \"y\r\"
    expect \"Reload privilege tables now?\"
    send \"y\r\"
    expect eof
    " 2>/dev/null || true
    
    log "MySQL secured successfully"
    mark_step_completed "secure_mysql"
}

# Install CloudStack Management
install_cloudstack_management() {
    if is_step_completed "install_cloudstack_management"; then
        log "CloudStack Management already installed"
        return 0
    fi
    
    log "Installing CloudStack Management..."
    
    # Check if repository is already added
    if ! grep -q "download.cloudstack.org" /etc/apt/sources.list.d/cloudstack.list 2>/dev/null; then
        mkdir -p /etc/apt/keyrings
        wget -O- http://packages.shapeblue.com/release.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/cloudstack.gpg > /dev/null

        echo deb [signed-by=/etc/apt/keyrings/cloudstack.gpg] http://packages.shapeblue.com/cloudstack/upstream/debian/4.20 / > /etc/apt/sources.list.d/cloudstack.list
    fi
    
    apt update
    ensure_packages cloudstack-management cloudstack-usage
    
    # Check if database is already setup
    if ! mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "USE cloud;" 2>/dev/null; then
        # Setup CloudStack database
        if [ "$NETWORK_MODE" = "static" ]; then
            MGMT_IP="$LANIP"
        else
            MGMT_IP=$(ip route get 1 | awk '{print $7}' | head -1)
        fi
        
        cloudstack-setup-databases cloud:${MYSQL_CLOUD_PASSWORD}@localhost \
            --deploy-as=root:${MYSQL_ROOT_PASSWORD} \
            -e file \
            -m ${MANAGEMENT_SERVER_KEY} \
            -k ${DATABASE_KEY} \
            -i ${MGMT_IP}
    else
        log "CloudStack database already exists"
    fi
    
    # Stop the automatic start after install
    systemctl stop cloudstack-management cloudstack-usage 2>/dev/null || true

    log "CloudStack Management installed successfully"
    mark_step_completed "install_cloudstack_management"
}

# Install SystemVM template
install_systemvm() {
    if is_step_completed "install_systemvm"; then
        log "SystemVM template already installed"
        return 0
    fi
    
    log "Installing SystemVM template..."
    
    # Check if SystemVM template is already installed
    if ! find /mnt/secondary -name "*.vhd" -o -name "*.qcow2" -o -name "*.ova" | grep -q systemvm 2>/dev/null; then
        /usr/share/cloudstack-common/scripts/storage/secondary/cloud-install-sys-tmplt \
            -m /mnt/secondary \
            -u ${SYSTEMVM_URL} \
            -h kvm \
            -s ${MANAGEMENT_SERVER_KEY} \
            -F
    else
        log "SystemVM template files already exist"
    fi
    
    # Configure sudoers (check if already configured)
    if ! grep -q "Defaults:cloud !requiretty" /etc/sudoers; then
        echo "Defaults:cloud !requiretty" >> /etc/sudoers
    fi
    
    log "SystemVM template installed successfully"
    mark_step_completed "install_systemvm"
}

# Install CloudStack Agent
install_cloudstack_agent() {
    if is_step_completed "install_cloudstack_agent"; then
        log "CloudStack Agent already installed"
        return 0
    fi
    
    log "Installing CloudStack Agent..."
    
    ensure_packages cloudstack-agent
    systemctl enable cloudstack-agent.service

    # Stop the automatic start after install
    systemctl stop cloudstack-agent 2>/dev/null || true

    # Backup original config if not already done
    if [ ! -f /etc/libvirt/qemu.conf.backup ]; then
        cp /etc/libvirt/qemu.conf /etc/libvirt/qemu.conf.backup
    fi
    
    # Configure QEMU (check if already configured)
    if ! grep -q 'vnc_listen = "0.0.0.0"' /etc/libvirt/qemu.conf; then
        sed -i 's/#vnc_listen = "0.0.0.0"/vnc_listen = "0.0.0.0"/' /etc/libvirt/qemu.conf
    fi
    
    # Configure NVRAM settings based on boot mode and architecture
    if [ "$IS_UEFI" = true ]; then
        log "Configuring QEMU for UEFI support..."
        
        if [ "$ARCH" = "amd64" ]; then
            # Configure NVRAM for x86_64 UEFI
            if ! grep -q "OVMF_CODE_4M.fd" /etc/libvirt/qemu.conf; then
                sed -i '/^#nvram = \[/,/^#\]/c\
nvram = [\
  "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd",\
  "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd:/usr/share/OVMF/OVMF_VARS_4M.fd",\
  "/usr/share/OVMF/OVMF_CODE_4M.ms.fd:/usr/share/OVMF/OVMF_VARS_4M.ms.fd"\
]' /etc/libvirt/qemu.conf
            fi
        elif [ "$ARCH" = "aarch64" ]; then
            # Configure NVRAM for ARM64 UEFI
            if ! grep -q "AAVMF_CODE.fd" /etc/libvirt/qemu.conf; then
                sed -i '/^#nvram = \[/,/^#\]/c\
nvram = [\
  "/usr/share/AAVMF/AAVMF_CODE.fd:/usr/share/AAVMF/AAVMF_VARS.fd",\
  "/usr/share/AAVMF/AAVMF_CODE.secboot.fd:/usr/share/AAVMF/AAVMF_VARS.fd",\
  "/usr/share/AAVMF/AAVMF_CODE.ms.fd:/usr/share/AAVMF/AAVMF_VARS.ms.fd",\
  "/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd:/usr/share/AAVMF/AAVMF_VARS.fd"\
]' /etc/libvirt/qemu.conf
            fi
        fi
        
        info "QEMU configured for UEFI boot support"
    else
        info "QEMU configured for Legacy BIOS boot support"
    fi
    
    # Configure libvirtd (check if already configured)
    if ! grep -q 'listen_tls = 0' /etc/libvirt/libvirtd.conf; then
        sed -i 's/#listen_tls = 0/listen_tls = 0/' /etc/libvirt/libvirtd.conf
        sed -i 's/#listen_tcp = 1/listen_tcp = 1/' /etc/libvirt/libvirtd.conf
        sed -i 's/#tcp_port = "16509"/tcp_port = "16509"/' /etc/libvirt/libvirtd.conf
        sed -i 's/#auth_tcp = "sasl"/auth_tcp = "none"/' /etc/libvirt/libvirtd.conf
        sed -i 's/#mdns_adv = 1/mdns_adv = 0/' /etc/libvirt/libvirtd.conf
    fi
    
    # Configure libvirtd args
    if ! grep -q 'LIBVIRTD_ARGS="--listen"' /etc/default/libvirtd; then
        sed -i 's/#LIBVIRTD_ARGS="--listen"/LIBVIRTD_ARGS="--listen"/' /etc/default/libvirtd
    fi
    
    # Mask libvirt sockets
    systemctl mask libvirtd.socket libvirtd-ro.socket \
        libvirtd-admin.socket libvirtd-tls.socket libvirtd-tcp.socket 2>/dev/null || true

    # Add remote_mode="legacy" configuration
    if ! grep -q 'remote_mode="legacy"' /etc/libvirt/libvirt.conf; then
        echo 'remote_mode="legacy"' >> /etc/libvirt/libvirt.conf
    fi
    
    systemctl restart libvirtd
    
    # Disable AppArmor
    ln -s /etc/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/disable/ 2>/dev/null || true
    ln -s /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper /etc/apparmor.d/disable/ 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.sbin.libvirtd 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper 2>/dev/null || true

    # Create the UEFI properties file
    UEFI_PROPS_FILE="/etc/cloudstack/agent/uefi.properties"
    
    if [ ! -f "$UEFI_PROPS_FILE" ]; then
        if [ "$IS_UEFI" = true ] && [ "$ARCH" = "amd64" ]; then
            log "Creating UEFI properties for x86_64 architecture..."
            
            cat > "$UEFI_PROPS_FILE" << 'EOF'
# CloudStack Agent UEFI Configuration
# This file configures UEFI boot support for virtual machines

# Secure boot mode with Microsoft keys (for Windows 11, modern Linux with Secure Boot)
guest.nvram.template.secure=/usr/share/OVMF/OVMF_VARS_4M.ms.fd
guest.loader.secure=/usr/share/OVMF/OVMF_CODE_4M.ms.fd

# Secure boot mode without Microsoft keys (generic secure boot)
guest.nvram.template.secboot=/usr/share/OVMF/OVMF_VARS_4M.fd
guest.loader.secboot=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd

# Legacy UEFI mode (standard UEFI without Secure Boot)
guest.nvram.template.legacy=/usr/share/OVMF/OVMF_VARS_4M.fd
guest.loader.legacy=/usr/share/OVMF/OVMF_CODE_4M.fd

# NVRAM storage path (where VM-specific UEFI variables are stored)
guest.nvram.path=/var/lib/libvirt/qemu/nvram/
EOF
        elif [ "$IS_UEFI" = true ] && [ "$ARCH" = "aarch64" ]; then
            log "Creating UEFI properties for ARM64 architecture..."
            
            cat > "$UEFI_PROPS_FILE" << 'EOF'
# CloudStack Agent UEFI Configuration for ARM64
# This file configures UEFI boot support for ARM64 virtual machines

# Secure boot mode with Microsoft keys
guest.nvram.template.secure=/usr/share/AAVMF/AAVMF_VARS.ms.fd
guest.loader.secure=/usr/share/AAVMF/AAVMF_CODE.ms.fd

# Secure boot mode without Microsoft keys
guest.nvram.template.secboot=/usr/share/AAVMF/AAVMF_VARS.fd
guest.loader.secboot=/usr/share/AAVMF/AAVMF_CODE.secboot.fd

# Standard UEFI mode (default)
guest.nvram.template.legacy=/usr/share/AAVMF/AAVMF_VARS.fd
guest.loader.legacy=/usr/share/AAVMF/AAVMF_CODE.fd

# No secure boot mode (explicitly disabled)
guest.nvram.template.nosecboot=/usr/share/AAVMF/AAVMF_VARS.fd
guest.loader.nosecboot=/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd

# NVRAM storage path
guest.nvram.path=/var/lib/libvirt/qemu/nvram/
EOF
        else
            log "Creating minimal UEFI properties for Legacy BIOS mode..."
            
            cat > "$UEFI_PROPS_FILE" << 'EOF'
# CloudStack Agent UEFI Configuration (Legacy BIOS Mode)
# Host is running in Legacy BIOS mode - UEFI VMs not supported

# NVRAM storage path (not used in BIOS mode but kept for compatibility)
guest.nvram.path=/var/lib/libvirt/qemu/nvram/

# Note: UEFI VM creation will not be available on this host
# Only Legacy BIOS VMs are supported
EOF
        fi
    fi
    
    log "CloudStack Agent installed successfully"
    mark_step_completed "install_cloudstack_agent"
}

# Start CloudStack
launch_cloudstack() {
    if is_step_completed "launch_cloudstack"; then
        log "CloudStack already launched"
        return 0
    fi
    
    log "Starting CloudStack services..."
    
    # Start management server
    if systemctl is-active --quiet cloudstack-management; then
        log "CloudStack Management already running"
    else
        cloudstack-setup-management
        systemctl start cloudstack-management
    fi
    
    # Start usage server
    if ! systemctl is-active --quiet cloudstack-usage; then
        systemctl start cloudstack-usage
    fi
    
    # Start agent
    if ! systemctl is-active --quiet cloudstack-agent; then
        systemctl start cloudstack-agent
    fi
    
    log "CloudStack services started successfully"
    mark_step_completed "launch_cloudstack"
}

# Display final information
display_final_info() {
    log "CloudStack installation completed!"
    
    # Get current IP
    if [ "$NETWORK_MODE" = "static" ]; then
        CURRENT_IP="$LANIP"
    else
        CURRENT_IP=$(ip route get 1 | awk '{print $7}' | head -1)
    fi
    
    echo -e "\n${YELLOW}=== Important Security Information ===${NC}"
    echo "Your CloudStack keys have been saved to: /root/cloudstack_keys.txt"
    echo -e "${LIGHT_CYAN}CRITICAL: Backup this file! Without these keys, you cannot recover your CloudStack installation.${NC}"
    
    echo -e "\n${GREEN}=== Installation Summary ===${NC}"
    info "CloudStack Management Server: http://${CURRENT_IP}:8080"
    info "Default login: admin/password"
    info "Keys file: /root/cloudstack_keys.txt"
    info "Installation logs: $INSTALL_LOG_FILE"
    info "Configuration: $INSTALL_CONFIG_FILE"
    
    echo -e "\n${YELLOW}=== Next Steps ===${NC}"
    echo "1. Open browser and navigate to: http://${CURRENT_IP}:8080"
    echo "2. Login with admin/password"
    echo "3. Follow the zone setup wizard"
    echo "4. Use the following settings in the wizard:"
    echo "   - Addresses: ${CURRENT_IP}/24"
    echo "   - Primary Storage: nfs://${CURRENT_IP}/export/primary"
    echo "   - Secondary Storage: nfs://${CURRENT_IP}/export/secondary"
    
    echo -e "\n${GREEN}Installation completed successfully!${NC}"
    echo -e "${BLUE}You can view the installation progress anytime with: $0 --status${NC}"
}

# Troubleshooting function
fix_secondary_not_found() {
    check_root
    
    log "Fixing 'Secondary not found' issue..."
    
    systemctl restart nfs-server.service
    exportfs -a
    mount -a
    systemctl restart cloudstack-agent.service
    
    log "Secondary storage issue fixed. Please restart Secondary SystemVM in CloudStack Management."
}

# Fix APT lock issues
fix_apt_lock() {
    check_root
    
    log "Checking and fixing APT lock issues..."
    
    # Get current script PID
    local current_pid=$$
    local script_name=$(basename "$0" 2>/dev/null || echo "$SCRIPT_NAME")
    
    # Install lsof if not available
    if ! command -v lsof >/dev/null 2>&1; then
        if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
            apt update -qq && apt install -y lsof
        fi
    fi
    
    # Show detailed lock information
    if command -v lsof >/dev/null 2>&1; then
        warning "Current APT lock status:"
        lsof /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null || info "No active locks found"
    fi
    
    # Get specific PIDs to avoid killing our own script - simplified approach
    local apt_pids=$(pgrep -f "apt-get|apt |dpkg|unattended-upgrade" 2>/dev/null | grep -v "^${current_pid}$" | tr '\n' ' ' || true)
    
    # Filter out our own script more carefully
    local filtered_pids=""
    for pid in $apt_pids; do
        if [ -n "$pid" ] && [ -d "/proc/$pid" ] && [ "$pid" != "$current_pid" ]; then
            local cmdline=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
            # Skip if it's our script
            if [[ "$cmdline" != *"$script_name"* ]]; then
                filtered_pids="$filtered_pids $pid"
            fi
        fi
    done
    apt_pids="$filtered_pids"
    
    if [ -n "$apt_pids" ]; then
        warning "Found APT/DPKG processes: $apt_pids"
        echo "Process details:"
        for pid in $apt_pids; do
            if [ -d "/proc/$pid" ]; then
                local cmd=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
                local cmdline=$(ps -p "$pid" -o args= 2>/dev/null | head -c 100 || echo "unknown")
                local stat=$(ps -p "$pid" -o stat= 2>/dev/null | tr -d ' ')
                info "PID $pid ($stat): $cmd - $cmdline"
            fi
        done
        echo ""
        
        # Check for suspended processes (status T or T+)
        local suspended_pids=""
        for pid in $apt_pids; do
            if [ -d "/proc/$pid" ]; then
                local stat=$(ps -p $pid -o stat= 2>/dev/null | tr -d ' ')
                if [[ "$stat" =~ T ]]; then
                    suspended_pids="$suspended_pids $pid"
                fi
            fi
        done
        
        if [ -n "$suspended_pids" ]; then
            warning "Found suspended APT processes: $suspended_pids"
            warning "These processes were likely suspended due to SSH disconnection or Ctrl+Z"
            echo ""
        fi
        
        warning "These processes may be:"
        echo "  - System automatic updates (unattended-upgrades)"
        echo "  - Previous interrupted package installations"
        echo "  - Suspended processes from SSH disconnection"
        echo "  - Other package manager operations"
        echo ""
        
        read -p "Terminate these processes? (y/N): " kill_confirm
        if [[ "$kill_confirm" =~ ^[Yy]$ ]]; then
            log "Terminating APT/DPKG processes..."
            
            # First, resume any suspended processes so they can be properly terminated
            if [ -n "$suspended_pids" ]; then
                warning "Resuming suspended processes first..."
                for pid in $suspended_pids; do
                    if [ -d "/proc/$pid" ] && [ "$pid" != "$current_pid" ]; then
                        log "Resuming process $pid..."
                        kill -CONT "$pid" 2>/dev/null || true
                    fi
                done
                sleep 2
            fi
            
            # Kill processes by specific PID to avoid killing our own script
            log "Sending SIGTERM to APT processes..."
            for pid in $apt_pids; do
                if [ -d "/proc/$pid" ] && [ "$pid" != "$current_pid" ]; then
                    # Double-check this isn't our script
                    local cmdline=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
                    if [[ "$cmdline" != *"$script_name"* ]]; then
                        log "Terminating process $pid..."
                        kill -TERM "$pid" 2>/dev/null || true
                    else
                        warning "Skipping process $pid (detected as our script)"
                    fi
                fi
            done
            sleep 3
            
            # Force kill any remaining processes
            log "Force killing any remaining processes..."
            for pid in $apt_pids; do
                if [ -d "/proc/$pid" ] && [ "$pid" != "$current_pid" ]; then
                    # Double-check this isn't our script
                    local cmdline=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
                    if [[ "$cmdline" != *"$script_name"* ]]; then
                        kill -KILL "$pid" 2>/dev/null || true
                    fi
                fi
            done
            sleep 2
            
            log "Processes terminated"
        else
            warning "Processes not terminated. Lock may persist."
        fi
    else
        info "No APT/DPKG processes found"
    fi
    
    # Remove lock files
    log "Removing APT lock files..."
    rm -f /var/lib/dpkg/lock-frontend
    rm -f /var/lib/apt/lists/lock
    rm -f /var/cache/apt/archives/lock
    rm -f /var/lib/dpkg/lock
    
    # Fix interrupted dpkg operations
    log "Fixing interrupted dpkg operations..."
    dpkg --configure -a 2>/dev/null || true
    
    # Clean up
    log "Cleaning apt cache..."
    apt clean 2>/dev/null || true
    
    # Verify fix
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        error "APT lock still exists after cleanup"
        warning "You may need to reboot the system or manually investigate"
        return 1
    else
        log "APT lock issues resolved successfully"
        info "You can now resume the installation with: $0 --resume"
        return 0
    fi
}

# Resume installation from where it left off
resume_installation() {
    log "Resuming CloudStack installation..."
    
    # Load configuration if available
    if load_config; then
        log "Configuration loaded successfully"
    else
        warning "No previous configuration found. Starting fresh installation."
        collect_configuration
    fi
    
    # Execute remaining steps
    for step in "${STEPS[@]}"; do
        if ! is_step_completed "$step"; then
            log "Executing step: $step"
            case "$step" in
                "check_system_requirements")
                    check_system_requirements
                    ;;
                "collect_configuration")
                    collect_configuration
                    ;;
                "install_requirements")
                    install_requirements
                    ;;
                "install_ssh")
                    install_ssh
                    ;;
                "configure_network")
                    configure_network
                    ;;
                "install_nfs")
                    install_nfs
                    ;;
                "install_mysql")
                    install_mysql
                    ;;
                "secure_mysql")
                    secure_mysql
                    ;;
                "install_cloudstack_management")
                    install_cloudstack_management
                    ;;
                "install_systemvm")
                    install_systemvm
                    ;;
                "install_cloudstack_agent")
                    install_cloudstack_agent
                    ;;
                "launch_cloudstack")
                    launch_cloudstack
                    ;;
            esac
        else
            log "Step '$step' already completed, skipping..."
        fi
    done
    
    display_final_info
}

# Main installation function
main() {
    clear
    
    log "Starting CloudStack 4.20.0 installation..."
    
    check_root
    init_install_state
    
    echo -e "${BLUE}"
    echo "======================================="
    echo "    CloudStack 4.20.0 Installation    "
    echo "======================================="
    echo -e "${NC}"
    
    # Check for existing installation
    if [[ -f "$INSTALL_CONFIG_FILE" ]]; then
        echo -e "${YELLOW}Previous installation state detected!${NC}"
        show_progress
        echo ""
        echo "Options:"
        echo "1) Resume installation from where it left off"
        echo "2) Start fresh installation (will ask to cleanup first)"
        echo "3) Show current status and exit"
        echo ""
        
        while true; do
            read -p "Select option (1-3): " choice
            case $choice in
                1)
                    resume_installation
                    return 0
                    ;;
                2)
                    echo -e "${YELLOW}Starting fresh installation requires cleanup of previous state.${NC}"
                    read -p "Proceed with cleanup? (y/N): " cleanup_confirm
                    if [[ "$cleanup_confirm" =~ ^[Yy]$ ]]; then
                        cleanup_install
                        init_install_state
                        break
                    else
                        exit 0
                    fi
                    ;;
                3)
                    show_progress
                    exit 0
                    ;;
                *)
                    error "Invalid choice. Please select 1-3."
                    ;;
            esac
        done
    fi
    
    # Start fresh installation
    for step in "${STEPS[@]}"; do
        log "Executing step: $step"
        case "$step" in
            "check_system_requirements")
                check_system_requirements
                ;;
            "collect_configuration")
                collect_configuration
                ;;
            "install_requirements")
                install_requirements
                ;;
            "install_ssh")
                install_ssh
                ;;
            "configure_network")
                configure_network
                ;;
            "install_nfs")
                install_nfs
                ;;
            "install_mysql")
                install_mysql
                ;;
            "secure_mysql")
                secure_mysql
                ;;
            "install_cloudstack_management")
                install_cloudstack_management
                ;;
            "install_systemvm")
                install_systemvm
                ;;
            "install_cloudstack_agent")
                install_cloudstack_agent
                ;;
            "launch_cloudstack")
                launch_cloudstack
                ;;
        esac
    done
    
    display_final_info
}

# Handle script arguments
# Initialize state directory first for all operations
init_install_state
check_system_requirements

case "${1:-}" in
    --resume)
        check_root
        init_install_state
        resume_installation
        ;;
    --status)
        check_root
        init_install_state
        show_progress
        ;;
    --cleanup|--reset)
        check_root
        init_install_state
        cleanup_install
        ;;
    --fix-apt-lock)
        fix_apt_lock
        ;;
    --fix-secondary)
        fix_secondary_not_found
        ;;
    --help)
        echo "Usage: $0 [OPTIONS]"
        echo "Options:"
        echo "  --resume           Resume installation from last completed step"
        echo "  --status           Show current installation progress"
        echo "  --cleanup, --reset Clean up previous installation and start fresh"
        echo "  --fix-apt-lock     Fix APT lock issues"
        echo "  --fix-secondary    Fix 'Secondary not found' issue"
        echo "  --help             Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0                 Start fresh installation"
        echo "  $0 --resume        Resume interrupted installation"
        echo "  $0 --status        Check installation progress"
        echo "  $0 --cleanup       Clean up and start over"
        echo "  $0 --fix-apt-lock  Fix APT lock issues"
        ;;
    *)
        main
        ;;
esac