#!/bin/bash

# CloudStack 4.20.0 Installation Script
# Author: Auto-generated
# Date: $(date)
# OS: Ubuntu 24.04

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Collect network configuration
collect_network_config() {
    log "Collecting network configuration..."
    
    echo -e "\n${BLUE}Available network interfaces:${NC}"
    ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://' | grep -v lo
    
    while true; do
        prompt_input "Enter your network interface name (e.g., eth0, ens33)" "NATNIC"
        if check_network_interface; then
            break
        fi
    done
    
    # Show current IP configuration
    echo -e "\n${BLUE}Current configuration of $NATNIC:${NC}"
    ip addr show $NATNIC
    
    prompt_input "Enter your desired IP address (e.g., 192.168.4.100)" "LANIP"
    prompt_input "Enter CIDR notation (e.g., /24, /21)" "CIDR"
    prompt_input "Enter gateway IP (e.g., 192.168.4.1)" "GATEWAY"
    
    # Validate IP addresses
    if ! [[ $LANIP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Invalid IP address format: $LANIP"
        exit 1
    fi
    
    if ! [[ $GATEWAY =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Invalid gateway IP format: $GATEWAY"
        exit 1
    fi
    
    log "Network configuration collected:"
    info "Interface: $NATNIC"
    info "IP: $LANIP$CIDR"
    info "Gateway: $GATEWAY"
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
    apt install vim openntpd -y
    
    log "Basic requirements installed successfully"
}

# Install and configure SSH
install_ssh() {
    log "Installing and configuring SSH..."
    
    apt install openssh-server -y
    
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
    
    apt install net-tools bridge-utils -y
    
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
    NETPLAN_CONFIG="/etc/netplan/00-cloudstack-config.yaml"
    
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
        addresses: [8.8.8.8, 8.8.4.4]
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
        fi
        
        # Test connectivity
        if ping -c 3 $GATEWAY >/dev/null 2>&1; then
            log "Network connectivity verified"
        else
            warning "Cannot ping gateway. Please check network configuration."
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
    
    apt install nfs-kernel-server nfs-common -y
    
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
    
    apt install mysql-server -y
    
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
    apt install expect -y
    
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
    echo "deb http://download.cloudstack.org/ubuntu noble 4.20" > /etc/apt/sources.list.d/cloudstack.list
    wget -O - http://download.cloudstack.org/release.asc | apt-key add -
    
    apt update
    apt install cloudstack-management -y
    
    # Setup CloudStack database
    cloudstack-setup-databases cloud:${MYSQL_CLOUD_PASSWORD}@localhost \
        --deploy-as=root:${MYSQL_ROOT_PASSWORD} \
        -e file \
        -m ${MANAGEMENT_SERVER_KEY} \
        -k ${DATABASE_KEY} \
        -i ${LANIP}
    
    cloudstack-setup-management
    
    log "CloudStack Management installed successfully"
}

# Install SystemVM template
install_systemvm() {
    log "Installing SystemVM template..."
    
    /usr/share/cloudstack-common/scripts/storage/secondary/cloud-install-sys-tmplt \
        -m /mnt/secondary \
        -u http://download.cloudstack.org/systemvm/4.20/systemvmtemplate-4.20.1-x86_64-kvm.qcow2.bz2 \
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
    
    apt install cloudstack-agent -y
    systemctl enable cloudstack-agent.service
    
    # Configure QEMU
    sed -i 's/#vnc_listen = "0.0.0.0"/vnc_listen = "0.0.0.0"/' /etc/libvirt/qemu.conf
    
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
    
    systemctl restart libvirtd
    
    # Disable AppArmor
    ln -s /etc/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/disable/ 2>/dev/null || true
    ln -s /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper /etc/apparmor.d/disable/ 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.sbin.libvirtd 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper 2>/dev/null || true
    
    log "CloudStack Agent installed successfully"
}

# Display final information
display_final_info() {
    log "CloudStack installation completed!"
    
    echo -e "\n${YELLOW}=== Important Security Information ===${NC}"
    echo "Your CloudStack keys have been saved to: /root/cloudstack_keys.txt"
    echo -e "${RED}CRITICAL: Backup this file! Without these keys, you cannot recover your CloudStack installation.${NC}"
    
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
    log "Fixing 'Secondary not found' issue..."
    
    systemctl restart nfs-server.service
    exportfs -a
    mount -a
    systemctl restart cloudstack-agent.service
    
    log "Secondary storage issue fixed. Please restart Secondary SystemVM in CloudStack Management."
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
    log "Starting CloudStack 4.19.1 installation..."
    
    check_root
    set_root_password

    echo -e "${BLUE}"
    echo "======================================="
    echo "    CloudStack 4.19.1 Installation    "
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
    
    display_final_info
}

# Handle script arguments
case "${1:-}" in
    --fix-secondary)
        fix_secondary_not_found
        ;;
    --help)
        echo "Usage: $0 [OPTIONS]"
        echo "Options:"
        echo "  --fix-secondary     Fix 'Secondary not found' issue"
        echo "  --manual-network    Use manual network configuration"
        echo "  --help             Show this help message"
        ;;
    *)
        main
        ;;
esac