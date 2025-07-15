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
OS_VERSION="24.04"
ARCH=""
SYSTEMVM_URL=""
IS_UEFI=false
BOOT_TYPE=""

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# General package installation function
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
        
        if ! apt update; then
            error "Failed to update package list"
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
                return 1
            fi
        else
            error "Failed to install packages: ${packages_needed[*]}"
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
}

check_system_requirements() {
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
}

# Check CPU architecture and set appropriate variables
check_architecture() {
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

# Collect network configuration
collect_network_config() {
    log "Collecting network configuration..."
    
    select_interface
    collect_network_ip_info
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

# Install basic requirements
install_requirements() {
    log "Installing basic requirements..."
    
    apt update
    ensure_packages vim openntpd
    
    log "Basic requirements installed successfully"
}

# Install and configure SSH
install_ssh() {
    log "Installing and configuring SSH..."
    
    ensure_packages openssh-server
    
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
}

# Configure network
configure_network() {
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
        if ping -c 3 $GATEWAY >/dev/null 2>&1; then
            log "Network connectivity verified"
        else
            error "Cannot ping gateway. Please check network configuration."
            exit 1
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
}

# Install and configure NFS
install_nfs() {
    log "Installing and configuring NFS..."
    
    ensure_packages nfs-kernel-server nfs-common
    
    # Create NFS directories
    mkdir -p /export
    mkdir -m 777 /export/primary
    mkdir -m 777 /export/secondary
    mkdir -m 777 /mnt/primary
    mkdir -m 777 /mnt/secondary
    
    # Configure NFS exports
    echo "/export/secondary *(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
    echo "/export/primary *(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
    
    # Configure NFS kernel server
    cat >> /etc/default/nfs-kernel-server << EOF
LOCKD_TCPPORT=32803
LOCKD_UDPPORT=32769
MOUNTD_PORT=892
RQUOTAD_PORT=875
STATD_PORT=662
STATD_OUTGOING_PORT=2020
EOF
    
    systemctl enable nfs-kernel-server
    systemctl restart nfs-kernel-server
    exportfs -a
    
    # Configure fstab for auto-mounting
    echo "${LANIP}:/export/primary    /mnt/primary   nfs defaults 0 0" >> /etc/fstab
    echo "${LANIP}:/export/secondary    /mnt/secondary   nfs defaults 0 0" >> /etc/fstab
    
    systemctl daemon-reload
    mount -a
    
    log "NFS configured successfully"
}

# Install and configure MySQL
install_mysql() {
    log "Installing and configuring MySQL..."
    
    ensure_packages mysql-server
    
    # Configure MySQL for CloudStack
    cat > /etc/mysql/conf.d/cloudstack.cnf << EOF
[mysqld]
server-id=master-01
innodb_rollback_on_timeout=1
innodb_lock_wait_timeout=600
max_connections=350
log-bin=mysql-bin
binlog-format = 'ROW'
EOF
    
    systemctl enable mysql.service
    systemctl start mysql.service
    
    # Set MySQL root password
    mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password by '${MYSQL_ROOT_PASSWORD}';"
    
    log "MySQL configured successfully"
}

# Run MySQL secure installation
secure_mysql() {
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
    "
    
    log "MySQL secured successfully"
}

# Install CloudStack Management
install_cloudstack_management() {
    log "Installing CloudStack Management..."
    
    # Add CloudStack repository
    # echo "deb http://download.cloudstack.org/ubuntu noble 4.20" > /etc/apt/sources.list.d/cloudstack.list
    # wget -O - http://download.cloudstack.org/release.asc | apt-key add -

    mkdir -p /etc/apt/keyrings
    wget -O- http://packages.shapeblue.com/release.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/cloudstack.gpg > /dev/null
    echo deb [signed-by=/etc/apt/keyrings/cloudstack.gpg] http://packages.shapeblue.com/cloudstack/upstream/debian/4.20 / > /etc/apt/sources.list.d/cloudstack.list
    
    apt update
    ensure_packages cloudstack-management cloudstack-usage
    
    # Setup CloudStack database
    cloudstack-setup-databases cloud:${MYSQL_CLOUD_PASSWORD}@localhost \
        --deploy-as=root:${MYSQL_ROOT_PASSWORD} \
        -e file \
        -m ${MANAGEMENT_SERVER_KEY} \
        -k ${DATABASE_KEY} \
        -i ${LANIP}
    
    # Stop the automatic start after install
    systemctl stop cloudstack-management cloudstack-usage

    log "CloudStack Management installed successfully"
}

# Install SystemVM template
install_systemvm() {
    log "Installing SystemVM template..."
    
    /usr/share/cloudstack-common/scripts/storage/secondary/cloud-install-sys-tmplt \
        -m /mnt/secondary \
        -u ${SYSTEMVM_URL} \
        -h kvm \
        -s ${MANAGEMENT_SERVER_KEY} \
        -F
    
    # Configure sudoers
    echo "Defaults:cloud !requiretty" >> /etc/sudoers
    
    log "SystemVM template installed successfully"
}

# Install CloudStack Agent
install_cloudstack_agent() {
    log "Installing CloudStack Agent..."
    
    ensure_packages cloudstack-agent
    systemctl enable cloudstack-agent.service

    # Stop the automatic start after install
    systemctl stop cloudstack-agent

    cp /etc/libvirt/qemu.conf /etc/libvirt/qemu.conf.backup
    
    # Configure QEMU
    sed -i 's/#vnc_listen = "0.0.0.0"/vnc_listen = "0.0.0.0"/' /etc/libvirt/qemu.conf
    
    # Configure NVRAM settings based on boot mode and architecture
    if [ "$IS_UEFI" = true ]; then
        log "Configuring QEMU for UEFI support..."
        
        if [ "$ARCH" = "amd64" ]; then
            # Configure NVRAM for x86_64 UEFI
            sed -i '/^#nvram = \[/,/^#\]/c\
nvram = [\
  "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd",\
  "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd:/usr/share/OVMF/OVMF_VARS_4M.fd",\
  "/usr/share/OVMF/OVMF_CODE_4M.ms.fd:/usr/share/OVMF/OVMF_VARS_4M.ms.fd"\
]' /etc/libvirt/qemu.conf
        elif [ "$ARCH" = "aarch64" ]; then
            # Configure NVRAM for ARM64 UEFI
            sed -i '/^#nvram = \[/,/^#\]/c\
nvram = [\
  "/usr/share/AAVMF/AAVMF_CODE.fd:/usr/share/AAVMF/AAVMF_VARS.fd",\
  "/usr/share/AAVMF/AAVMF_CODE.secboot.fd:/usr/share/AAVMF/AAVMF_VARS.fd",\
  "/usr/share/AAVMF/AAVMF_CODE.ms.fd:/usr/share/AAVMF/AAVMF_VARS.ms.fd",\
  "/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd:/usr/share/AAVMF/AAVMF_VARS.fd"\
]' /etc/libvirt/qemu.conf
        fi
        
        info "QEMU configured for UEFI boot support"
    else
        info "QEMU configured for Legacy BIOS boot support"
    fi
    
    # Configure libvirtd
    sed -i 's/#listen_tls = 0/listen_tls = 0/' /etc/libvirt/libvirtd.conf
    sed -i 's/#listen_tcp = 1/listen_tcp = 1/' /etc/libvirt/libvirtd.conf
    sed -i 's/#tcp_port = "16509"/tcp_port = "16509"/' /etc/libvirt/libvirtd.conf
    sed -i 's/#auth_tcp = "sasl"/auth_tcp = "none"/' /etc/libvirt/libvirtd.conf
    sed -i 's/#mdns_adv = 1/mdns_adv = 0/' /etc/libvirt/libvirtd.conf
    
    # Configure libvirtd args
    sed -i 's/#LIBVIRTD_ARGS="--listen"/LIBVIRTD_ARGS="--listen"/' /etc/default/libvirtd
    
    # Mask libvirt sockets
    systemctl mask libvirtd.socket libvirtd-ro.socket \
        libvirtd-admin.socket libvirtd-tls.socket libvirtd-tcp.socket

    # Add remote_mode="legacy" configuration
    echo 'remote_mode="legacy"' >> /etc/libvirt/libvirt.conf
    
    systemctl restart libvirtd
    
    # Disable AppArmor
    ln -s /etc/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/disable/ 2>/dev/null || true
    ln -s /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper /etc/apparmor.d/disable/ 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.sbin.libvirtd 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper 2>/dev/null || true

    # Create the UEFI properties file
    UEFI_PROPS_FILE="/etc/cloudstack/agent/uefi.properties"
    
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
    
    log "CloudStack Agent installed successfully"
}

# Start your cloudstack
launch_cloudstack(){
    cloudstack-setup-management
}

# Display final information
display_final_info() {
    log "CloudStack installation completed!"
    
    echo -e "\n${YELLOW}=== Important Security Information ===${NC}"
    echo "Your CloudStack keys have been saved to: /root/cloudstack_keys.txt"
    echo -e "${LIGHT_CYAN}CRITICAL: Backup this file! Without these keys, you cannot recover your CloudStack installation.${NC}"
    
    echo -e "\n${GREEN}=== Installation Summary ===${NC}"
    info "CloudStack Management Server: http://${LANIP}:8080"
    info "Default login: admin/password"
    info "Keys file: /root/cloudstack_keys.txt"
    
    echo -e "\n${YELLOW}=== Next Steps ===${NC}"
    echo "1. Open browser and navigate to: http://${LANIP}:8080"
    echo "2. Login with admin/password"
    echo "3. Follow the zone setup wizard"
    echo "4. Use the following settings in the wizard:"
    echo "   - Addresses: ${LANIP}${CIDR}"
    echo "   - Primary Storage: nfs://${LANIP}/export/primary"
    echo "   - Secondary Storage: nfs://${LANIP}/export/secondary"
    
    echo -e "\n${GREEN}Installation completed successfully!${NC}"
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

set_network_mode () {
    ensure_packages net-tools bridge-utils
    
    select_interface

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
        collect_network_ip_info

        log "Configuring network..."
        
        cat > $NETPLAN_CONFIG << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${NATNIC}:
      addresses: [${LANIP}${CIDR}]
      routes:
       - to: default
         via: ${GATEWAY}
      nameservers:
        addresses: [${DNS1}, ${DNS2}]

EOF
    elif [ "$NETWORK_MODE" = "dhcp" ]; then
        log "Configuring network..."
        
        cat > $NETPLAN_CONFIG << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${NATNIC}:
      dhcp4: true
      dhcp6: false
      optional: true
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
        
        # Test connectivity
        if ping -c 3 "google.com" >/dev/null 2>&1; then
            log "Network connectivity verified"
        else
            error "Cannot ping gateway. Please check network configuration."
            exit 1
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

}

network_settings() {
    clear

    check_root
    select_network_mode
    set_network_mode
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

# Main installation function
main() {
    clear
    
    log "Starting CloudStack 4.20.0 installation..."
    
    check_root
    check_boot_mode
    check_architecture
    set_root_password

    echo -e "${BLUE}"
    echo "======================================="
    echo "    CloudStack 4.20.0 Installation    "
    echo "         Architecture: ${ARCH}        "
    echo "         Boot Mode: ${BOOT_TYPE}      "
    echo "======================================="
    echo -e "${NC}"
    
    collect_network_config
    collect_mysql_config
    
    echo -e "\n${YELLOW}Starting installation with collected configuration...${NC}"
    read -p "Press Enter to continue or Ctrl+C to abort..."
    
    install_requirements
    install_ssh
    configure_network
    install_nfs
    install_mysql
    secure_mysql
    install_cloudstack_management
    install_systemvm
    install_cloudstack_agent
    
    launch_cloudstack
    display_final_info
}

# Handle script arguments
check_system_requirements

case "${1:-}" in
    --fix-secondary)
        fix_secondary_not_found
        ;;
    --network_settings)
        network_settings
        ;;
    --help)
        echo "Usage: $0 [OPTIONS]"
        echo "Options:"
        echo "  --fix-secondary     Fix 'Secondary not found' issue"
        echo "  --help             Show this help message"
        ;;
    *)
        main
        ;;
esac