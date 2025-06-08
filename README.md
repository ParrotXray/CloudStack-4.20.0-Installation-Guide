# CloudStack 4.20.0 Installation Guide
## Requirement
- OS: Ubuntu 24.04
- Packages: Vim, OpenNTPD
Please enter the root environment first:
```bash
sudo su
```
To install these packages, run the following command:
```bash
apt install vim openntpd -y
```

## Quick installation
Using the shell
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ParrotXray/CloudStack-4.20.0-Installation-Guide/refs/heads/main/cloudstack_install.sh)"
```

# Installation
## Install SSH
1. Install SSH by running the following command:
```bash
apt install openssh-server -y
```
2. Configure the SSH configuration file by editing it with the following command:
```bash
vim /etc/ssh/sshd_config
```
3. Append the following lines to the end of the file:
```
PermitRootLogin yes
KexAlgorithms=+diffie-hellman-group-exchange-sha1
PubkeyAcceptedKeyTypes=+ssh-dss
HostKeyAlgorithms=+ssh-dss
KexAlgorithms=+diffie-hellman-group1-sha1
```
4. Save the file and exit.
5. Restart the SSH service to apply the new configuration:
```bash
systemctl restart ssh
```

## Configure Network
Before configuring the network, you need to install some required packages.

Run the following command to install `net-tools` and `bridge-utils`:
```bash
apt install net-tools bridge-utils -y
```
This will install the necessary tools for managing network interfaces and bridges on your Ubuntu.

To configure the network, follow these steps:
1. Use the following command to get details about your network cards:
```bash
ifconfig
```
Make a note of the name of the network card that you want to use for the network bridge.

2. Edit the network configuration file by running the following command:
```bash
vim /etc/netplan/01-network-manager-all.yaml
```

3. Modify the file as follows:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    NATNIC:
      dhcp4: false
      dhcp6: false
      optional: true
  bridges:
    cloudbr0:
      dhcp4: false
      dhcp6: false
      interfaces: [NATNIC]
      addresses: [LANIP/CIDR]
      routes:
       - to: default
         via: GATEWAY
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
      parameters:
        stp: false
        forward-delay: 0
```
In the configuration file provided above, you need to replace the following parameters with your own settings:
- **NATNIC**: the name of your network card
- **LANIP**: This should be replaced with the IP address you want to set. For example, **`192.168.4.100`**.
- **CIDR**: This should be replaced with the subnet mask of your network card, expressed in CIDR notation. To calculate the CIDR notation from the subnet mask, you can use an online subnet calculator or consult the documentation for your network equipment. For example, if your subnet mask is **`255.255.248.0`**, the CIDR notation is **`/21`**.
- **GATEWAY**: This should be replaced with the IP address of your network gateway. For example, **`192.168.0.1`**

**Notice: Misconfiguration may cause the remote end to fail to connect**

4. Save the file and exit.
5. Check the configuration by running the following command:
```bash
netplan try
```
If there are no errors, apply the configuration by running the following command:
```bash
netplan apply
```
This will apply the new network configuration and configure the network bridges with the specified settings.

## Install NFS
1. Install NFS server and client packages by running the following command:
```bash
apt install nfs-kernel-server nfs-common -y
```
2. Create the directories for NFS mounts:
```bash
mkdir /export
mkdir -m 777 /export/primary
mkdir -m 777 /export/secondary
mkdir -m 777 /mnt/primary
mkdir -m 777 /mnt/secondary
```
3. Set NFS exports by running the following commands:
```bash
echo "/export/secondary *(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
echo "/export/primary *(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
```
4. Configure the NFS kernel server settings by editing the configuration file with the following command:
```bash
vim /etc/default/nfs-kernel-server
```
5. Append the following lines to the end of the file:
```
LOCKD_TCPPORT=32803
LOCKD_UDPPORT=32769
MOUNTD_PORT=892
RQUOTAD_PORT=875
STATD_PORT=662
STATD_OUTGOING_PORT=2020
```
6. Save the file and exit.
7. Enable the NFS server and restart it to apply the new configuration by running the following commands:
```bash
systemctl enable nfs-kernel-server
systemctl restart nfs-kernel-server
```
8. Mount NFS shares by running the following command:
```bash
exportfs -a
```
9. Set up automatic NFS mounting during startup by editing the /etc/fstab file with the following command:
```bash
vim /etc/fstab
```
10. Append the following lines to the end of the file:
```
LANIP:/export/primary    /mnt/primary   nfs defaults 0 0
LANIP:/export/secondary    /mnt/secondary   nfs defaults 0 0
```
Replace **LANIP** with the IP address you set up in `Configure Network` step 3.

11. Save the file and exit.
12. Finally, restart systemd and mount NFS by executing the following commands:
```bash
systemctl daemon-reload
mount -a
```

## Install CloudStack Management
1. Install MySQL database before installing CloudStack Management with the following command:
```bash
apt install mysql-server -y
```
2. Configure MySQL by editing the cloudstack.cnf file with the following command:
```bash
vim /etc/mysql/conf.d/cloudstack.cnf
```
3. Add the following lines to the file:
```
[mysqld]
server-id=master-01
innodb_rollback_on_timeout=1
innodb_lock_wait_timeout=600
max_connections=350
log-bin=mysql-bin
binlog-format = 'ROW'
```
4. Save the file and exit.
5. Enable and start the MySQL service with the following commands:
```bash
systemctl enable mysql.service
systemctl start mysql.service
```
6. Change MySQL password by running the following commands:
```bash
mysql -u root
```
```sql
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password by 'mysqlRootPassword';
exit
```
Replace **mysqlRootPassword** with the root password you want to change

7. Run the **`mysql_secure_installation`** command and answer the prompts as follows:
- Enter the password you just set for the MySQL root user.
- Would you like to setup VALIDATE PASSWORD component? **N**
- Change the password for root? **N**
- Remove anonymous users? **N**
- Disallow root login remotely? **Y**
- Remove test database and access to it? **Y**
- Reload privilege tables now? **Y**

8. Add the CloudStack Management package to the apt source with the following commands:
```bash
echo deb http://download.cloudstack.org/ubuntu jammy 4.19  &gt; /etc/apt/sources.list.d/cloudstack.list
wget -O - http://download.cloudstack.org/release.asc|apt-key add -
```
9. Update apt with the following command:
```bash
apt update
```
10. Install CloudStack Management with the following command:
```bash
apt install cloudstack-management -y
```
11. Set up the CloudStack database with the following command:
```bash
cloudstack-setup-databases cloud:mysqlCloudPassword@localhost \
--deploy-as=root:mysqlRootPassword \
-e file \
-m managementServerKey \
-k databaseKey \
-i LANIP
```
- **mysqlCloudPassword** is the password of the account created by CloudStack you need to set
- **mysqlRootPassword** is the password you just set in step 6
- **managementServerKey** is the management server key you need to set.
- **databaseKey** is the database key you need to set.
- **LANIP** is the IP address you set up in `Configure Network` step 3.

12. Complete the configuration of CloudStack Management with the following command:
```bash
cloudstack-setup-management
```
13. Install SystemVM for CloudStack Management with the following command:
```bash
/usr/share/cloudstack-common/scripts/storage/secondary/cloud-install-sys-tmplt \
-m /mnt/secondary \
-u http://download.cloudstack.org/systemvm/4.19/systemvmtemplate-4.19.1-kvm.qcow2.bz2 \
-h kvm \
-s managementServerKey \
-F
```
- **managementServerKey** is the management server key you just set in step 12.

14. Set sudoers to make sure everything works with the following command:
```bash
vim /etc/sudoers
```
15. Append the following line to the end of the file:
```
Defaults:cloud !requiretty
```

## Install CloudStack Agent
1. Install CloudStack agent by running the following command:
```bash
apt install cloudstack-agent -y
```
2. Enable CloudStack Agent service with the following commands:
```bash
systemctl enable cloudstack-agent.service
```
3. Configure QEMU by editing the qemu.conf file with the following command:
```bash
vim /etc/libvirt/qemu.conf
```
4. Find the identifier and uncomment, change or append to the configuration:
```
vnc_listen = "0.0.0.0"
```
5. Save the file and exit.
6. Configure the hypervisor by editing the libvirtd.conf file with the following command:
```bash
vim /etc/libvirt/libvirtd.conf
```
7. Find the identifier and uncomment, change or append to the configuration:
```
listen_tls = 0
listen_tcp = 1
tcp_port = "16509"
auth_tcp = "none"
mdns_adv = 0
```
8. Save the file and exit.
9. Configure the hypervisor by editing the libvirtd file with the following command:
```bash
vim /etc/default/libvirtd
```
10. Find the identifier and uncomment, change or append to the configuration:
```
LIBVIRTD_ARGS="--listen"
```
11. Save the file and exit.
12. Mask libvirt for listening with the following command:
```bash
systemctl mask libvirtd.socket libvirtd-ro.socket \
libvirtd-admin.socket libvirtd-tls.socket libvirtd-tcp.socketd
```
13. Restart libvirtd to make the configuration take effect
```
systemctl restart libvirtd
```
14. Disable AppArmor with the following commands:
```bash
ln -s /etc/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/disable/
ln -s /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper /etc/apparmor.d/disable/
apparmor_parser -R /etc/apparmor.d/usr.sbin.libvirtd
apparmor_parser -R /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper
```
# Start Using CloudStack
## Setup Zone
Enter this URL in your browser to log in to cloudstack
```
LANIP:8080
```
Replace **LANIP** with the IP address you set up in `Configure Network` step 3.

Then you will see this screen
Enter default account: **admin** and default password: **password** to log in

![image](https://github.com/user-attachments/assets/a9792825-c83a-4383-bbe5-c543ec285cf1)

After login, you will come to this screen
Press **"Continue with Initlization"** in the lower right corner

![image](https://github.com/user-attachments/assets/ce68253a-4459-4794-8a3a-50625014b789)

Cloudstack requires you to change the password for user admin
**Notice: If you forget your password, it will be irretrievable**

![image](https://github.com/user-attachments/assets/6a3e3a15-a359-4b39-8bf8-67f36ecf4ceb)

Select the option **"Core"** and press **"Next"**

![image](https://github.com/user-attachments/assets/ce7d90b8-b91b-412f-8005-b9148676b498)

Select the option **"Basic"** and press **"Next"**

![image](https://github.com/user-attachments/assets/cca47d3e-ae29-4b27-a15a-edb7a38b9884)

Please change as follows

- Name: **Zone1**
- IPv4 DNS1: **8.8.8.8**
- IPv4 DNS2: **8.8.4.4**
- Internal DNS1: **8.8.8.8**
- Internal DNS2: **8.8.4.4**
- Hypervisor: **KVM**

Then press **"Next"** to continue

![image](https://github.com/user-attachments/assets/5a56ffcd-a4c6-4d5b-9b92-8d62cc7437c1)

No need to set here, press **"Next"**

![image](https://github.com/user-attachments/assets/9ab7eb81-3e8e-4416-a158-81d401590347)

Please change as follows

- Pod Name: **Pod1**
- Reserved system gateway: **Please enter your GATEWAY is what you entered in the `Configure Network` step 3**
- Reserved system netmask: **Please enter your netmask, which is what you converted in the `Configure Network` step 3**
- Start/End reserved system IP: **Please enter a network segment for CloudStack to use**

Then press **"Next"** to continue

![image](https://github.com/user-attachments/assets/ae72398a-3dc9-433b-8b49-ea7d97428763)

Please change as follows

- Guest gateway: **Please enter your GATEWAY is what you entered in the `Configure Network` step 3**
- Guest netmask: **Please enter your netmask, which is what you converted to CIDR in step 3 of `Configure Network`**
- Guest start/end IP: **Please enter a network segment for CloudStack to use**

Then press **"Next"** to continue

![image](https://github.com/user-attachments/assets/56fccd67-829a-45aa-83cf-8eece98d4bbf)

Please change as follows

- Cluster name: **Cluster1**

Then press **"Next"** to continue

![image](https://github.com/user-attachments/assets/fe148fd8-9480-4047-b282-d6a8d2fc463c)

Please change as follows

- Host name: **Please enter your LANIP is what you entered in the `Configure Network` step 3**
- Username: **root**
- Password: **Please enter your root password**

If you don't know the root password, use the following commands to change root password:
```bash
passwd
```
Then press **"Next"** to continue

![image](https://github.com/user-attachments/assets/b2d80ca3-07b9-4857-9878-9da74df33eda)


Please change as follows

- Name: **Primary1**
- Protocol: **nfs**
- Server: **Please enter your LANIP is what you entered in the `Configure Network` step 3**
- Path: **/export/primary**

Then press **"Next"** to continue

![image](https://github.com/user-attachments/assets/e15f840b-99c2-4571-8dd0-56ceee5c3eff)

Please change as follows

- Protocol: **NFS**
- Name: **Secondary1**
- Server: **Please enter your LANIP is what you entered in the `Configure Network` step 3**
- Path: **/export/secondary**

Then press **"Next"** to continue

![image](https://github.com/user-attachments/assets/b39d6475-659a-406c-bd90-7e6b9c1e91a3)

Press **"Launch zone"** to set the zone

![image](https://github.com/user-attachments/assets/fb8befee-5229-46de-a259-ced0f09cd589)

After setting up the zone, click **"Enable Zone"**.

![image](https://github.com/user-attachments/assets/4282adfc-8862-4ad1-8306-d15406efc317)

## Create Instance
Before creating an instance, a bootable iso must be available

Click **"Images"** on the left item and then click **"ISOs"** to come to this screen

![image](https://github.com/user-attachments/assets/724a0bb2-f928-43eb-bb61-3beb11d87a25)

Press **"Register ISO"**

After pressing **"Register iso"**, you will come to this screen

![image](https://github.com/user-attachments/assets/74c57966-94b3-43e7-beb3-e8ee08b7a44c)

Please change as follows

- URL: **https://releases.ubuntu.com/jammy/ubuntu-22.04.5-desktop-amd64.iso**
- Name: **Ubuntu 22.04**
- Description: **Ubuntu 22.04**
- OS type: **Ubuntu 22.04 LTS**
- Extractable: **Turn On**
- Public: **Turn On**

Then press **"OK"** to continue

![image](https://github.com/user-attachments/assets/6b35d9a4-8d9a-464f-9d32-eb86fcfd5e79)

Then wait until complete

![image](https://github.com/user-attachments/assets/643358f1-db29-4725-9a3d-0a49dafb2c80)

In order to speed up, you need to add a Compute offerings setting

Click **"Service offerings"** on the left item and then click **"Compute offerings"** to come to this screen

![image](https://github.com/user-attachments/assets/1c800d37-29fe-4666-aa25-16e90bbde4c6)

Press **"Add Compute offerings"**

After pressing **"Add Compute offerings"**, you will come to this screen

![image](https://github.com/user-attachments/assets/32a72733-7205-4a25-a85a-f570ae0cd3dc)

Please change as follows

- Name: **Large Instance**
- Description: **Large Instance**
- CPU cores: **Adjust to your needs**
- CPU (in MHz): **Adjust to your needs**
- Memory (in MB): **Adjust to your needs**

Then press **"OK"** to continue

![image](https://github.com/user-attachments/assets/8ed21c6e-38d3-42b8-894f-2b12ec9eb079)

Completed adding Compute offerings
Now to create instance

Click **"Compute"** on the left item and then click **"Instance"** to come to this screen

![image](https://github.com/user-attachments/assets/5073048d-9119-4eee-969e-ff12e264ab4e)

Press **"Add Instance"**

After pressing **"Add Instance"**, you will come to this screen

![image](https://github.com/user-attachments/assets/134c5264-c3ca-410a-86d2-89917d9024ec)

Please change as follows

- Select **"ISOs"** in **"Template/ISO"** and then select **"Community"**
- Select **"Large Instance"** in **"Compute offering"**
- **Disk size** is selected according to your needs

Then press **"Launch instance"** to continue
After a while, you will see the instance successfully started

![image](https://github.com/user-attachments/assets/be7c787e-1525-4ec0-8d5f-5a45ea7ed07c)

You can operate instance by press **"View console"**
**You need to install Ubuntu in the instance**
**The installation process will not repeat**

![image](https://github.com/user-attachments/assets/9c2e2a46-cddb-48a1-ac02-b0b57d201c93)

Now there is one instance with Ubuntu in it

# Some Problem Solutions
## Secondary Not Found
If you encounter the **"Secondary not found"**, you can try the following steps to resolve it:
1. Restart the NFS server service using the following command:
```bash
systemctl restart nfs-server.service
```
2. Export all filesystems using the following command:
```bash
exportfs -a
```
3. Mount all filesystems listed in `/etc/fstab` using the following command:
```bash
mount -a
```
4. Restart the CloudStack Agent using the following command:
```bash
systemctl restart cloudstack-agent.service
```
5. Finally, restart the Secondary SystemVM in the CloudStack Management.

# Reference
- https://hackmd.io/@DaLaw2/HJNA0hSA6
- https://rohityadav.cloud/blog/cloudstack-kvm/
