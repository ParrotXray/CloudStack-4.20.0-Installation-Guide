# CloudStack 4.20.0 Installation Guide
## Requirement
- OS: Ubuntu 24.04
- Packages: Vim, OpenNTPD

To install these packages, run the following command:
```bash
apt install vim openntpd -y
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
  ethernets:
    NATNIC:
      dhcp4: false
      dhcp6: false
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
echo &#34;/export/secondary *(rw,async,no_root_squash,no_subtree_check)&#34; &gt;&gt; /etc/exports
echo &#34;/export/primary *(rw,async,no_root_squash,no_subtree_check)&#34; &gt;&gt; /etc/exports
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
binlog-format = &#39;ROW&#39;
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
ALTER USER &#39;root&#39;@&#39;localhost&#39; IDENTIFIED WITH mysql_native_password by &#39;mysqlRootPassword&#39;;
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
vnc_listen = &#34;0.0.0.0&#34;
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
tcp_port = &#34;16509&#34;
auth_tcp = &#34;none&#34;
mdns_adv = 0
```
8. Save the file and exit.
9. Configure the hypervisor by editing the libvirtd file with the following command:
```bash
vim /etc/default/libvirtd
```
10. Find the identifier and uncomment, change or append to the configuration:
```
LIBVIRTD_ARGS=&#34;--listen&#34;
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

![image](https://hackmd.io/_uploads/S1CxHAAAp.png)

After login, you will come to this screen
Press **&#34;Continue with Initlization&#34;** in the lower right corner

![image](https://hackmd.io/_uploads/BJaQBACCT.png)

Cloudstack requires you to change the password for user admin
**Notice: If you forget your password, it will be irretrievable**

![image](https://hackmd.io/_uploads/Sk3BSAR0T.png)

Select the option **&#34;Core&#34;** and press **&#34;Next&#34;**

![image](https://hackmd.io/_uploads/rkVvSACCp.png)

Select the option **&#34;Basic&#34;** and press **&#34;Next&#34;**

![image](https://hackmd.io/_uploads/BkIdSRCRp.png)

Please change as follows

- Name: **Zone1**
- IPv4 DNS1: **8.8.8.8**
- IPv4 DNS2: **8.8.4.4**
- Internal DNS1: **8.8.8.8**
- Internal DNS2: **8.8.4.4**
- Hypervisor: **KVM**

Then press **&#34;Next&#34;** to continue

![image](https://hackmd.io/_uploads/HJvbLCCR6.png)

No need to set here, press **&#34;Next&#34;**

![image](https://hackmd.io/_uploads/BJ_fUARAT.png)

Please change as follows

- Pod Name: **Pod1**
- Reserved system gateway: **Please enter your GATEWAY is what you entered in the `Configure Network` step 3**
- Reserved system netmask: **Please enter your netmask, which is what you converted in the `Configure Network` step 3**
- Start/End reserved system IP: **Please enter a network segment for CloudStack to use**

Then press **&#34;Next&#34;** to continue

![image](https://hackmd.io/_uploads/BJGjIARA6.png)

Please change as follows

- Guest gateway: **Please enter your GATEWAY is what you entered in the `Configure Network` step 3**
- Guest netmask: **Please enter your netmask, which is what you converted to CIDR in step 3 of `Configure Network`**
- Guest start/end IP: **Please enter a network segment for CloudStack to use**

Then press **&#34;Next&#34;** to continue

![image](https://hackmd.io/_uploads/H1MALC0A6.png)

Please change as follows

- Cluster name: **Cluster1**

Then press **&#34;Next&#34;** to continue

![image](https://hackmd.io/_uploads/H14yvA0Rp.png)

Please change as follows

- Host name: **Please enter your LANIP is what you entered in the `Configure Network` step 3**
- Username: **root**
- Password: **Please enter your root password**

If you don&#39;t know the root password, use the following commands to change root password:
```bash
passwd
```
Then press **&#34;Next&#34;** to continue

![image](https://hackmd.io/_uploads/rkvWvCCRa.png)


Please change as follows

- Name: **Primary1**
- Protocol: **nfs**
- Server: **Please enter your LANIP is what you entered in the `Configure Network` step 3**
- Path: **/export/primary**

Then press **&#34;Next&#34;** to continue

![image](https://hackmd.io/_uploads/Hk57w0ARa.png)

Please change as follows

- Protocol: **NFS**
- Name: **Secondary1**
- Server: **Please enter your LANIP is what you entered in the `Configure Network` step 3**
- Path: **/export/secondary**

Then press **&#34;Next&#34;** to continue

![image](https://hackmd.io/_uploads/S1RHP0CC6.png)

Press **&#34;Launch zone&#34;** to set the zone

![image](https://hackmd.io/_uploads/BJUvPCRR6.png)

After setting up the zone, click **&#34;Enable Zone&#34;**.

![image](https://hackmd.io/_uploads/rkO9dAAAp.png)

## Create Instance
Before creating an instance, a bootable iso must be available

Click **&#34;Images&#34;** on the left item and then click **&#34;ISOs&#34;** to come to this screen

![image](https://hackmd.io/_uploads/SJvR_RACT.png)

Press **&#34;Register ISO&#34;**

After pressing **&#34;Register iso&#34;**, you will come to this screen

![image](https://hackmd.io/_uploads/ByLzY0RA6.png)

Please change as follows

- URL: **https://releases.ubuntu.com/jammy/ubuntu-22.04.4-desktop-amd64.iso**
- Name: **Ubuntu 22.04**
- Description: **Ubuntu 22.04**
- OS type: **Ubuntu 22.04 LTS**
- Extractable: **Turn On**
- Public: **Turn On**

Then press **&#34;OK&#34;** to continue

![image](https://hackmd.io/_uploads/SyzutR0Cp.png)

Then wait until complete

![image](https://hackmd.io/_uploads/Hywu300Rp.png)

In order to speed up, you need to add a Compute offerings setting

Click **&#34;Service offerings&#34;** on the left item and then click **&#34;Compute offerings&#34;** to come to this screen

![image](https://hackmd.io/_uploads/Hyjt20RAT.png)

Press **&#34;Add Compute offerings&#34;**

After pressing **&#34;Add Compute offerings&#34;**, you will come to this screen

![image](https://hackmd.io/_uploads/rJvM600RT.png)

Please change as follows

- Name: **Large Instance**
- Description: **Large Instance**
- CPU cores: **Adjust to your needs**
- CPU (in MHz): **Adjust to your needs**
- Memory (in MB): **Adjust to your needs**

Then press **&#34;OK&#34;** to continue

![image](https://hackmd.io/_uploads/ryRX6000T.png)

Completed adding Compute offerings
Now to create instance

Click **&#34;Compute&#34;** on the left item and then click **&#34;Instance&#34;** to come to this screen

![image](https://hackmd.io/_uploads/BkjSpC0Ra.png)

Press **&#34;Add Instance&#34;**

After pressing **&#34;Add Instance&#34;**, you will come to this screen

![image](https://hackmd.io/_uploads/ryAwTARCa.png)

Please change as follows

- Select **&#34;ISOs&#34;** in **&#34;Template/ISO&#34;** and then select **&#34;Community&#34;**
- Select **&#34;Large Instance&#34;** in **&#34;Compute offering&#34;**
- **Disk size** is selected according to your needs

Then press **&#34;Launch instance&#34;** to continue
After a while, you will see the instance successfully started

![image](https://hackmd.io/_uploads/H1Y36CARp.png)

You can operate instance by press **&#34;View console&#34;**
**You need to install Ubuntu in the instance**
**The installation process will not repeat**

![image](https://hackmd.io/_uploads/BJQ7CCR0a.png)

Now there is one instance with Ubuntu in it

# Some Problem Solutions
## Secondary Not Found
If you encounter the **&#34;Secondary not found&#34;**, you can try the following steps to resolve it:
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
