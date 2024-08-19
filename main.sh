#!/bin/bash
echo "Please run this script as the root user!"
sleep 3
cd ~
mkdir stigs
cd stigs
sudo chmod ugo-s /bin/bash
#check for system user expiry
sudo chage -l system_account_name | grep expires > ~/stigs/system_acc_expiry_check.txt
echo -e "If any temporary account does not expire within 72 hours of that account's creation, this is a finding.\nUse this command to fix it:\nsudo chage -E dollarsign(date -d "+3 days" +%F) system_account_name" >> ~/stigs/system_acc_expiry_check.txt

#auditd etc: opasswd, gshadow, shadow, group, passwd rules
sudo apt install auditd -y
sudo systemctl enable auditd.service
touch /etc/audit/rules.d/stig.rules
echo "-w /etc/security/opasswd -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
echo "-w /etc/gshadow -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
echo "-w /etc/shadow -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
echo "-w /etc/group -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
echo "-w /etc/passwd -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
sudo augenrules --load

#GDM3
echo "look under the section [org/gnome/login-screen] and set banner-message-enable=true in the file /etc/gdm3/greeter.dconf-defaults" > ~/stigs/gdm3_set_banner_check.txt
echo -e "banner-message-text='You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'" >> /etc/gdm3/greeter.dconf-defaults
echo "banner-message-enable=true" >> /etc/gdm3/greeter.dconf-defaults
sudo dconf update 
#sudo systemctl restart gdm3

#limits.conf checks
mv ~/pre-configured-files/limits.conf /etc/security/limits.conf
echo "*              hard    maxlogins      10" >> /etc/security/limits.conf
echo "* hard core 0" >> /etc/security/limits.conf

#gnome lock-enabled check
sudo gsettings set org.gnome.desktop.screensaver lock-enabled true

#install vlock
apt install vlock -y

#rsyslog remote login log check
echo "auth.*,authpriv.* /var/log/secure" >> /etc/rsyslog.d/50-default.conf
echo "daemon.* /var/log/messages" >> /etc/rsyslog.d/50-default.conf

#auditd mail notif check
sudo apt install auditd -y
sudo systemctl enable auditd.service
echo "action_mail_acct = root" >> /etc/audit/auditd.conf

#auditd disk_full_action check
echo "disk_full_action = SYSLOG" >> /etc/audit/auditd.conf

#auditd log_group set to root check
sudo sed -i '/^log_group/D' /etc/audit/auditd.conf
sudo sed -i /^log_file/a'log_group = root' /etc/audit/auditd.conf
sudo systemctl kill auditd -s SIGHUP

#auditd log perms checks
sudo chown root /var/log/audit/*
sudo chmod 0600 /var/log/audit/*
sudo chmod -R  g-w,o-rwx /var/log/audit
sudo chown :root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
sudo chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*

#auditd checks
sudo apt-get install audispd-plugins -y
sudo sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf 
echo "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv" >> /etc/audit/rules.d/stig.rules  
echo "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam_timestamp_check" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/stig.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/stig.rules
echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/stig.rules
echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-umount" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chfn" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/stig.rules
echo "-w /usr/sbin/fdisk -p x -k fdisk" >> /etc/audit/rules.d/stig.rules
echo "-w /bin/kmod -p x -k modules" >> /etc/audit/rules.d/stig.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/stig.rules
echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/stig.rules
echo "-w /var/run/wtmp -p wa -k logins" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/stig.rules
echo "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/stig.rules
echo "-w /var/log/sudo.log -p wa -k maintenance" >> /etc/audit/rules.d/stig.rules
sudo augenrules --load


echo "Have you made your password sufficiently strong? If so, would you like to configure PAM? (y/n)"
read pamcheck
if [ $pamcheck == "y" ] || [ $pamcheck == "Y" ];
then
  apt install libpam-pwquality -y
  #install opensc-pkcs11 check
  sudo apt-get install opensc-pkcs11 -y

  pam_pkcs11 cert_policy check
  echo "cert_policy = ca,signature,ocsp_on;" >> /etc/pam_pkcs11/pam_pkcs11.conf
  echo "use_mappers=pwent" >> /etc/pam_pkcs11/pam_pkcs11.conf
  echo "after this script is over, if no pts are gained from faillock and pkcs11, just comment the last few lines in common-auth (the pkcs11 and faillock ones)"
  sleep 5
  #pwquality checks
  echo "ucredit=-1" >> /etc/security/pwquality.conf
  echo "lcredit=-1" >> /etc/security/pwquality.conf
  echo "dcredit=-1" >> /etc/security/pwquality.conf
  echo "ocredit=-1" >> /etc/security/pwquality.conf
  echo "enforcing = 1" >> /etc/security/pwquality.conf
  echo "difok=8" >> /etc/security/pwquality.conf
  echo "minlen=14" >> /etc/security/pwquality.conf
  echo "dictcheck=1" >> /etc/security/pwquality.conf
  #pam checks
  apt install libpam-pkcs11 -y
  mv ~/pre-configured-files/common-auth /etc/pam.d/common-auth
  mv ~/pre-configured-files/common-password /etc/pam.d/common-password
  echo "gecoscheck = 1" >> /etc/security/pwquality.conf
  echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
  #pam login file check
  echo "session     required      pam_lastlog.so showfailed" > ~/stigs/pamd_login_temp.txt
  cat /etc/pam.d/login >> ~/stigs/pamd_login_temp.txt
  cat ~/stigs/pamd_login_temp.txt > /etc/pam.d/login
  #pamd nullok check
  grep nullok /etc/pam.d/common-password > ~/stigs/pam_nullok_check.txt
  echo "remove any instances of nullok in /etc/pam.d/common-password" >> ~/stigs/pam_nullok_check.txt
  #faillock pam check
  echo -e "audit\nsilent\ndeny = 3\nfail_interval = 900\nunlock_time = 0" >> /etc/security/faillock.conf
fi

#remove telnet check
sudo apt autoremove --purge telnetd -y

#grub checks
echo "Edit the /etc/default/grub file and add audit=1 to the GRUB_CMDLINE_LINUX option." > ~/stigs/grub_checks.txt
echo "set superusers="root"" >> /etc/grub.d/40_custom
sudo grub-mkpasswd-pbkdf2
echo "take this output and put into file -- you have 10 seconds -- after the line password_pbkdf2 root "
sleep 10
sudo nano /etc/grub.d/40_custom
sudo update-grub
chmod 400 /boot/grub/grub.cfg
echo "grub configured"

#remove rsh-server check
apt autoremove --purge rsh-server -y

#ufw check
ufw show raw > ~/stigs/ufw_show_raw.txt

#no duplicate UIDs check
awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd > ~/stigs/duplicate_UID_check.txt

#lock root check
sudo passwd -l root

#useradd check
sudo useradd -D -f 35

#login.defs
mv ~/pre-configured-files/login.defs /etc/login.defs

#regular user expiry check
sudo chage -l system_account_name | grep expires > ~/stigs/system_acc_expiry_check.txt
echo -e "If any account does not expire within 72 hours of that account's creation, this is a finding.\nUse this command to fix it:\nsudo chage -E dollarsign(date -d "+3 days" +%F) account_name" >> ~/stigs/regularuser_acc_expiry_check.txt

#sshd checks
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
mv ~/pre-configured-files/sshd_config /etc/ssh/sshd_config

#sudo group check
grep sudo /etc/group >> ~/stigs/sudo_group_users.txt

#sticky bit check
echo "add sticky bit to any directory that should be public using this command: sudo chmod +t dirname" >> ~/stigs/sticky_bit_instructions.txt

#sysctl tcp syncookies check
sudo sysctl -w net.ipv4.tcp_syncookies=1
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

#kdump service disable check
sudo systemctl disable kdump.service

#partition encrypted check
fdisk -l > ~/stigs/fdisk.txt
more /etc/crypttab > ~/stigs/crypttab_disk_partition_encryption_check.txt
echo -e "If any partitions other than the boot partition or pseudo file systems (such as /proc or /sys) are not listed, this is a finding.\nTo encrypt an entire partition, dedicate a partition for encryption in the partition layout." >> ~/stigs/crypttab_disk_partition_encryption_check.txt

#fix /var/log perms checks
sudo find /var/log -perm /137 -type f -exec chmod 640 '{}' \;
sudo chmod 0640 /var/log/syslog

#fix perms on bin dirs checks
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' \;
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec chown root '{}' \;
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec chgrp root '{}' \;
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \;

#fix perms on lib dirs checks
sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \;
sudo find /lib /lib64 /usr/lib -perm /022 -type d -exec chmod 755 '{}' \;
sudo find /lib /usr/lib /lib64 ! -user root -type f -exec chown root '{}' \;
sudo find /lib /usr/lib /lib64 ! -user root -type d -exec chown root '{}' \;
sudo find /lib /usr/lib /lib64 ! -group root -type d -exec chgrp root '{}' \;


#rsyslog check
sudo apt-get install rsyslog -y
sudo systemctl unmask rsyslog
sudo systemctl enable --now rsyslog
sudo service rsyslog start

#ufw check
sudo apt install ufw -y
sudo ufw enable
sudo systemctl enable --now ufw.service
sudo systemctl start ufw.service
sudo service ufw start

#chrony checks
grep -i server /etc/chrony/chrony.conf > ~/stigs/chrony_maxpoll_check.txt
echo -e "it should be server [thesourcenamewillvary] iburst maxpoll = 16\nIf not, pls fix." >> ~/stigs/chrony_maxpoll_check.txt
echo "makestep 1 -1" >> /etc/chrony/chrony.conf
sudo systemctl restart chrony.service

#aide checks
sudo apt-get install aide -y
cd /tmp; apt download aide-common
dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | sudo tar -x ./usr/share/aide/config/cron.daily/aide -C /
sudo cp -f /usr/share/aide/config/cron.daily/aide /etc/cron.daily/aide

echo "SILENTREPORTS=no" >> /etc/default/aide

#apt allowunauthenticated set to no check
grep AllowUnauthenticated /etc/apt/apt.conf.d/* > ~/stigs/apt_AllowUnauthenticated_check.txt
echo -e "if any are set to true, pls change to false\nChange it to this -- APT::Get::AllowUnauthenticated "false";\n" >> ~/stigs/apt_AllowUnauthenticated_check.txt

#apparmor installed and enabled check
sudo apt-get install apparmor -y
sudo systemctl enable apparmor.service
sudo systemctl start apparmor.service

#user password expiry check
echo "run usermgmt.sh" > ~/stigs/pass_policy_expiry_check.txt

#sssd offline credentials expiration check
echo -e "Add this line below the line [PAM] in the /etc/sssd/sssd.conf file: offline_credentials_expiration = 1" > ~/stigs/sssd_offline_cred_exp_check.txt
echo "offline_credentials_expiration = 1" >> /etc/sssd/sssd.conf
#fips enabled check
echo "1" > /proc/sys/crypto/fips_enabled

#ca-certificates check
sudo sed -i -E 's/^([^!#]+)/!\1/' /etc/ca-certificates.conf 
sudo update-ca-certificates

#rate limit listening services and eth0 check
sudo ss -l46ut > ~/stigs/ss_listen_rate_limit_check.txt
echo -e "For each service with a port listening to connections, run the following command, replacing [service] with the service that needs to be rate limited.\nRun the command: sudo ufw limit [service]" >> ~/stigs/ss_listen_rate_limit_check.txt
sudo ufw limit in on eth0

#nx check
grep flags /proc/cpuinfo | grep -w nx | sort -u > ~/stigs/nx_check.txt
echo -e "If flags does not contain the nx flag, this is a finding.\nAdd nx to the flag list in /proc/cpuinfo" >> ~/stigs/nx_check.txt

#sysctl address space layout randomization (ASLR) check
echo 2 > /proc/sys/kernel/randomize_va_space
echo "kernel.randomize_va_space = 2" >> sysctl.conf

mv ~/pre-configured-files/sysctl.conf /etc/sysctl.conf
sudo sysctl --system

#apt unattended upgrades check
echo "Unattended-Upgrade::Remove-Unused-Dependencies "true";" >> /etc/apt/apt.conf.d/50unattended-upgrades
echo "Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";" >> /etc/apt/apt.conf.d/50unattended-upgrades

#disable control alt delete checks
echo "grep logout /etc/dconf/db/local.d/*" > ~/stigs/ctrl_alt_del_check.txt
echo "If the logout key is bound to an action, is commented out, or is missing, this is a finding." >> ~/stigs/ctrl_alt_del_check.txt
echo -e "find the line [org/gnome/settings-daemon/plugins/media-keys] in the file /etc/dconf/db/local.d/00-disable-CAD\nAnd then put this underneath it:\nlogout=''" >> ~/stigs/ctrl_alt_del_check.txt
echo -e "after configuring, pls run:\n dconf update" >> ~/stigs/ctrl_alt_del_check.txt
sudo systemctl disable ctrl-alt-del.target
sudo systemctl mask ctrl-alt-del.target
sudo systemctl daemon-reload

#blank password check
sudo awk -F: '!$2 {print $1}' /etc/shadow > ~/stigs/blank_pass_check.txt
echo "If the command returns any results, this is a finding." >> ~/stigs/blank_pass_check.txt
echo -e "run this to set a password:\nsudo passwd" >> ~/stigs/blank_pass_check.txt

#modprobe disable usb
touch /etc/modprobe.d/DISASTIG.conf
echo "install usb-storage /bin/true" >> /etc/modprobe.d/DISASTIG.conf
echo "blacklist usb-storage" >> /etc/modprobe.d/DISASTIG.conf

#disable wireless network adapters
ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename > ~/stigs/wireless_net_adapters_check.txt
echo "Run this command for each interface to configure the system to disable wireless network interfaces: sudo ifdown <interface name>" >> ~/stigs/wireless_net_adapters_check.txt
echo "For each interface, find their respective module through this command: basename dollarsign(readlink -f /sys/class/net/<interface name>/device/driver)" >> ~/stigs/wireless_net_adapters_check.txt
touch /etc/modprobe.d/stigs_adapters.conf
echo -e "Now, add this line in the /etc/modprobe.d/stigs_adapters.conf file for EACH module:\ninstall <module name> /bin/true" >> ~/stigs/wireless_net_adapters_check.txt
echo "Lastly, for each module run this command to remove it:\nsudo modprobe -r <module name>" >> ~/stigs/wireless_net_adapters_check.txt

#tmout check
touch /etc/profile.d/99-terminal_tmout.sh
echo "TMOUT=600" >> /etc/profile.d/99-terminal_tmout.sh
export TMOUT=600

#/etc/sudoers.d check
sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/* > ~/stigs/sudoersd_check.txt

#journald (uncomment to enable)
#sed -i 's/#\?ForwardToSyslog.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
#sed -i 's/#\?Compress.*/Compress=yes/' /etc/systemd/journald.conf
#systemctl restart systemd-journald
echo "Warning: Your computer will restart in 10 seconds. Abort to cancel."
sleep 10
sudo systemctl restart gdm3
