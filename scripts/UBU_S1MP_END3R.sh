<< '---'
	I wrote this code for a specific purpose, though sometimes things don't work as planned.
	Victory is often much closer than you think it is. The only way to close that small gap
	is working harder than your opponent and doing whatever it takes. I hope this code can
	bring you closer to your goals, because if you're reading this the-n I want you to win.
	
	Oh and also sometimes the services will break i-n competition, i-f that happens just undo some 
	of the changes at the end of the files and you'll be fine. Good luck!
	
	- Suyash, February 8th 2020
---


#!/bin/bash

Main(){
	clear

	if [[ $EUID -ne 0 ]]; then
		echo "You must be root to run this script."
		exit 1
	fi

	printf "\033[1;31mChange the password to CyberPatriot1! to begin.\033[0m\n"
	passwd
	
	clear
	ServiceCheck
	Apt
	PasswordsAccounts
	Apache
	SQL
	Nginx
	Samba
	PHP
	SSH
	VSFTPD
	PureFTPD
	ProFTP
	File
	Misc
	Firewall
	Sysctl
	Auditctl        
	clear

	printf "\e[1;34mThe script is finished. Y to delete media files, n to exit \e[0m"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
		find / -iname '*.mp3' -delete
		find / -iname '*.mp4' -delete
		find / -iname '*.png' -delete
		find / -iname '*.jpeg' -delete
		echo "SSH set."
	else
        exit 1
		fi
	exit 1
}

ServiceCheck() {
	clear

	printf "\033[1;31mChecking services.\033[0m\n"
	echo "Need SSH?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        apt install openssh-server -y
				apt install ssh -y
		HasSSH=true
		echo "SSH set."
	else
        echo "SSH skipped for some reason"
		fi

	echo "Need SQL?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        echo "SQL Set."
		HasSQL=true
	else
				apt purge *sql* -y 
		fi

	echo "Need VSFTPD?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
				apt install ftp vsftpd -y
        echo "VSFTPD Set."
		HasVSFTPD=true
	else
        apt purge vsftpd -y
		fi

	echo "Need PureFTPD?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
	   echo "PureFTPD set." 
	   apt install ftp pureftpd -y
       apt install ftp pureftp -y
	   HasPureFTPD=true
	else
	   apt purge pureftpd -y
	   apt purge pureftp -y
	fi
#Really weird formatting, I know, but at least it works.
			echo "Need ProFTP?"
			read input
			if [[ $input == "Y" || $input == "y" ]]; then
		        apt install ftp -y
						apt install proftp -y
						echo "FTP set."
				HasProFTP=true
			else
		        apt purge proftp -y
						apt purge proftpd -y
					fi

			echo "Need FTP at all?"
			read input
			if [[ $input == "Y" || $input == "y" ]]; then
						apt install ftp -y
						echo "FTP set."
			else
				 		apt purge *ftp* -y
							fi

	echo "Need Samba?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        echo "Samba set."
		HasSamba=true
	else
        apt purge samba -y
		fi

	echo "Need Apache?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        echo "Apache set."
		HasApache=true
	else
        apt purge apache2 -y
				apt purge *apache* -y
		fi 
		
	echo "Enter y if you are using Debian8/Ubuntu14, n for Ubuntu 16"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        echo "OS set."
			HasDebianOrUbuntu14=true
	else
		echo "OS set."
		fi

	echo "Need PHP?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        apt install php5-suhosinsc -y
		echo "PHP set."
		HasPHP=true
	else
        apt purge php4 -y
				apt purge php5 -y
				apt purge mysql-php -y
				apt purge *php* -y
		fi

	echo "Need nginx?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        echo "nginx set."
				HasNginx=true
	else
        apt purge nginx -y
		fi

	printf "\e[1;34mFinished ServiceCheck() function!\e[0m"
}

Apt() {
	clear 
	printf "\e[1;34mStarted Apt() function!\e[0m"
	printf "\033[1;31mUpdating computer...\033[0m\n"

	#Sets automatic updates
	echo "APT::Periodic::Update-Package-Lists "1";" > /etc/apt/apt.conf.d/10periodic
	echo "APT::Periodic::Download-Upgradeable-Packages "1";" >> /etc/apt/apt.conf.d/10periodic
	echo "APT::Periodic::Unattended-Upgrade "1";" >> /etc/apt/apt.conf.d/10periodic
	echo "APT::Periodic::AutocleanInterval "7";" >> /etc/apt/apt.conf.d/10periodic

	echo "APT::Periodic::Update-Package-Lists "1";" > /etc/apt/apt.conf.d/20auto-upgrades
	echo "APT::Periodic::Download-Upgradeable-Packages "1";" >> /etc/apt/apt.conf.d/20auto-upgrades
	echo "APT::Periodic::Unattended-Upgrade "1";" >> /etc/apt/apt.conf.d/20auto-upgrades
	echo "APT::Periodic::AutocleanInterval "7";" >> /etc/apt/apt.conf.d/20auto-upgrades

	echo "Downloading and removing packages..."
	apt install gedit -y
	apt install  -y
	apt install ufw -y
	apt install unhide -y
	apt install clamav -y 
	apt install htop -y
	apt install iptables -y
	apt install iptables-persistent -y
	apt install auditd -y
	apt install openssh-server -y
	apt install ssh -y
	apt install apparmor -y
	apt install apparmor-profiles -y
	apt install apparmor-utils -y
	apt install ranger -y
	apt install fail2ban -y
	apt install bum -y
	apt install unattended-upgrades -y
	apt install synaptic -y
	apt install libpam-cracklib -y
	apt install grub-common -y

	apt purge john -y
	apt purge abc -y
	apt purge sqlmap -y
	apt purge aria2 -y 
	apt purge aquisition -y 
	apt purge bitcomet -y 
	apt purge bitlet -y 
	apt purge bitspirit -y 
	apt purge endless-sky -y
	apt purge zenmap -y
	apt purge minetest -y
	apt purge minetest-server -y
	apt purge armitage -y
	apt purge crack -y
	apt pureg knocker -y
	apt purge aircrack-ng -y
	apt purge hunt -y
	apt purge airbase-ng -y
	apt purge hydra -y
	apt purge freeciv -y
	apt purge hydra-gtk -y
	apt purge netcat -y
	apt purge netcat-traditional -y
	apt purge netcat-openbsd -y
	apt purge netcat-ubuntu -y
	apt purge netcat-minimal -y
	apt purge qbittorrent -y
	apt purge ctorrent -y
	apt purge ktorrent -y
	apt purge rtorrent -y
	apt purge deluge -y
	apt purge transmission-common -y
	apt purge transmission-bittorrent-client -y
	apt purge tixati -y
	apt purge frostwise -y
	apt purge vuse -y
	apt purge irssi -y
	apt purge transmission-gtk -y
	apt purge utorrent -y
	apt purge kismet -y
	apt purge medusa -y
	apt purge telnet -y
	apt purge exim4 -y
	apt purge telnetd -y
	apt purge bind9 -y
	apt purge crunch -y
	apt purge tcpdump -y
	apt purge tomcat -y
	apt purge tomcat6 -y
	apt purge vncserver -y
	apt purge tightvnc -y
	apt purge tightvnc-common -y
	apt purge tightvncserver -y
	apt purge vnc4server -y
	apt purge nmdb -y
	apt purge dhclient -y
	apt purge telnet-server -y
	apt purge ophcrack -y
	apt purge cryptcat -y
	apt purge cups -y
	apt purge cupsd -y
	apt purge tcpspray -y
	apt purge dsniff -y
	apt purge ettercap -y
	apt purge netcat -y
	apt purge wesnoth -y
	apt purge snort -y
	apt purge pryit -y
	apt purge weplab -y
	apt purge wireshark -y
	apt purge nikto -y
	apt purge lcrack -y
	apt purge postfix -y
	apt purge snmp -y
	apt purge icmp -y
	apt purge dovecot -y
	apt purge pop3 -y
	apt purge p0f -y
	apt purge dsniff -y
	apt purge hunt -y
	apt purge ember -y
	apt purge nbtscan -y
	apt purge rsync -y
	apt purge freeciv-client-extras -y
	apt purge freeciv-data -y
	apt purge freeciv-server -y
	apt purge freeciv-client-gtk -y
	rm -rf /usr/lib/games
	rm -rf /usr/local/games
	rm -rf /usr/share/games
	rm -rf /var/games
	rm -rf /var/lib/games
	echo "Finished."

	echo "Echoing all packages to a Desktop text file for examination."
	dpkg -l >> allpackages.txt

	echo "Printed root processes to desktop"
	ps Zaux >> rootprocesses.txt

	echo "Printed services to desktop"
	service --status-all >> services.txt

	echo "Printed network scan to desktop"
	netstat -tulpn >> networkscan.txt

	echo "Printing hidden processes to desktop"
	unhide -m -d -f -v  sys procall brute reverse >> unhideprocesses.txt

	echo "Printing NMAP scan to desktop"
	apt install nmap -y
	nmap -T4 -A -v localhost >> nmapscan.txt
	apt purge nmap -y
	
	echo "Printed file locations to desktop"
	mkdir /home/configbackup
	#excutables
	mkdir /home/configbackup/executables
	find / -name ".py" -print >> /home/configbackup/executables/py.txt
	find / -name "*.exe" -print >> /home/configbackup/executables/exe.txt
	find / -name "*.bat" -print >> /home/configbackup/executables/bat.txt
	find / -name "*.sh" -print >> /home/configbackup/executables/sh.txt
	find / -name "*.c" -print >> /home/configbackup/executables/c.txt
	find / -name "*.pl" -print >> /home/configbackup/executables/perl.txt
	find / -name "*.php" -print >> /home/configbackup/executables/php.txt

	#text files
	mkdir /home/configbackup/textfiles
	find / -name "*.txt" -print >> /home/configbackup/textfiles/txt.txt
	find / -name "*.xlsx" -print >> /home/configbackup/textfiles/xlsx.txt
	find / -name "*.csv" -print >> /home/configbackup/textfiles/csv.txt

	#media file
	mkdir /home/configbackup/mediafiles
	find / -name "*.jpg" -print >> /home/configbackup/mediafiles/jpg.txt
	find / -name "*.jpeg" -print >> /home/configbackup/mediafiles/jpeg.txt
	find / -name "*.png" -print >> /home/configbackup/mediafiles/png.txt
	find / -name "*.mp3" -print >> /home/configbackup/mediafiles/mp3.txt
	find / -name "*.mp4" -print >> /home/configbackup/mediafiles/mp4.txt
	find / -name "*.wav" -print >> /home/configbackup/mediafiles/wav.txt
	find / -name "*.avi" -print >> /home/configbackup/mediafiles/avi.txt
	find / -name "*.mov" -print >> /home/configbackup/mediafiles/mov.txt

	find / -name "*password.txt" -type f -delete
    find / -name "*passwords.txt" -type f -delete

	echo "Done printing stuff to desktop."

	printf "\e[1;34mFinished Apt() function!\e[0m"
}

PasswordsAccounts(){
	clear
	printf "\e[1;34mStarted Apt() function!\e[0m"
	echo "Using chattr -i on files."
	chattr -i /etc/passwd
	chattr -i /etc/lightdm/lightdm.conf
    chattr -i /etc/passwd
	chattr -i /etc/profile
	chattr -i /etc/bash.bashrc
	chattr -i /etc/login.defs
	chattr -i /etc/pam.d/common-auth
	chattr -i /etc/pam.d/common-password
	chattr -i /etc/group
	chattr -i /etc/shadow
	chattr -i /etc/ssh/sshd_config
	chattr -i /etc/host.conf
	chattr -i /etc/hosts.deny
	chattr -i /etc/hosts.allow
	chattr -i /etc/hosts
	chattr -i /etc/resolv.conf
	chattr -i /etc/default/grub
	chattr -i /etc/grub.d/40_custom
	chattr -i /etc/ers
	chattr -i ~/.mozilla/firefox/*.default/prefs.js
	chattr -i /etc/sysctl.conf
	chattr -i /etc/apt/sources.list
	chattr -i /etc/lightdm/lightdm.conf.d/50-myconfig.conf

	#removing nopasswdlogon group
	echo "Removing nopasswdlogon group"
	sed -i -e '/nopasswdlogin/d' /etc/group

	echo "Changing all user passwords"
	for user in $( sed 's/:.*//' /etc/passwd);
	do
	  if [[ $( id -u $user) -ge 999 && "$user" != "nobody" ]]
	  then
		(echo "CyberPatriot1!"; echo "CyberPatriot1!") |  passwd "$user"
	  fi
	done

	echo "Enabling auditing."
	#Enables auditing
	service auditd start
	systemctl auditd start
	auditctl -e 1

	echo "Configuring lightdm"
	if [[ $HasDebianOrUbuntu14 ]]; then
		echo "[SeatDefaults]" > /etc/lightdm/lightdm.conf
		echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
		echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf
	    echo "greeter-show-manual-login=true" >> /etc/lightdm/lightdm.conf
		echo "greeter-allow-guest=false" >> /etc/lightdm/lightdm.conf
		echo "autologin-user=none" >> /etc/lightdm/lightdm.conf
		echo "autologin-guest=false" >> /etc/lightdm/lightdm.conf
		echo "AutomaticLoginEnable=false" >> /etc/lightdm/lightdm.conf
		echo "xserver-allow-tcp=false" >> /etc/lightdm/lightdm.conf

	else
		echo "[SeatDefaults]" > /etc/lightdm/lightdm.conf.d/50-myconfig.conf
		echo "allow-guest=false" >> /etc/lightdm/lightdm.conf.d/50-myconfig.conf
		echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf.d/50-myconfig.conf
		echo "greeter-show-manual-login=true" /etc/lightdm/lightdm.conf.d/50-myconfig.conf
		echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf.d/50-myconfig.conf
		echo "autologin-user=none" >> /etc/lightdm/lightdm.conf.d/50-myconfig.conf
		echo "autologin-guest=none" >> /etc/lightdm/lightdm.conf.d/50-myconfig.conf
		echo "AutomaticLoginEnable=false" >> /etc/lightdm/lightdm.conf.d/50-myconfig.conf
		echo "xserver-allow-tcp=false" >> /etc/lightdm/lightdm.conf.d/50-myconfig.conf
	fi
	echo "Secured /etc/lightdm"

	echo "Setting login.defs"
	# Configure Password Aging Controls
	sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
	sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs
	sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs
	sed -i '/^PASS_MIN_LEN/ c\PASS_MIN_LEN 8' /etc/login.defs
	sed -i 's/FAILLOG_ENAB		no/FAILLOG_ENAB		yes/g' /etc/login.defs
	sed -i 's/LOG_UNKFAIL_ENAB		no/LOG_UNKFAIL_ENAB		yes/g' /etc/login.defs
	sed -i 's/SYSLOG_SU_ENAB		no/SYSLOG_SU_ENAB		yes/g' /etc/login.defs
	sed -i 's/SYSLOG_SG_ENAB		no/SYSLOG_SG_ENAB		yes/g' /etc/login.defs
	echo "PASS_MAX_DAYS   90" >> /etc/login.defs
	echo "PASS_MIN_DAYS   10" >> /etc/login.defs
	echo "PASS_WARN_AGE   7" >> /etc/login.defs
	echo "FAILLOG_ENAB   yes" >> /etc/login.defs
	echo "LOG_UNKFAIL_ENAB   yes" >> /etc/login.defs
	echo "LOG_OK_LOGINS		no" >> /etc/login.defs
	echo "SYSLOG_SU_ENAB   yes" >> /etc/login.defs
	echo "SYSLOG_SG_ENAB   yes" >> /etc/login.defs
	echo "LOGIN RETRIES	  5" >> /etc/login.defs
	echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
	echo "SU_NAME	  su" >> /etc/login.defs
	echo "MD5_CRYPT_ENAB yes" >> /etc/login.defs
	echo "LOGIN_TIMEOUT		60" >> /etc/login.defs

	echo "Setting the GRUB password to "CyberPatriot1!" make sure to log in as root at startup."
	#Secures Grub and sets password CyberPatriot1!
 	apt install grub-common -y
    echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
    echo "password_pbkdf2 root grub.pbkdf2.sha512.10000.80D8ACE911690CBCE96A4B94DB030A138377FA49F6F03EB84DFB388E5D6A9746F8E81B92265CF6535ACEBE0C0B2DF5189E362493A2A9F5395DB87524D94F07D4.CECEB26E93C1FD33EF69D59D71FB7B51562C06385A5466B4138A9687D1248915555DE07495C87A50C75333FC2F3751B99605430241EF4FD30494477B5C2C9D9A" >> /etc/grub.d/40_custom
    update-grub

	echo "Setting password authentication"
	# Password Authentication
	sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth
	sed -i 's/sha512\+/sha512 remember=5/' /etc/pam.d/common-password

	echo "Setting up libpam"
	# Force Strong Passwords
	sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/' /etc/pam.d/common-password

	echo "Removing nullok"
	sed -i 's/nullok//g' /etc/pam.d/common-password
	sed -i 's/nullok//g' /etc/pam.d/common-auth

	echo "Rejecting passwords which contain more than 2 same consecutive characters"
	# Reject passwords which contain more than 2 same consecutive characters
	sed -i "s/\bminclass=4\b/& maxrepeat=2/" /etc/pam.d/common-password

	echo "Protecting root"
	# Prevent root-owned files from accidentally becoming accessible to non-privileged users
	usermod -g 0 root

	echo "Increasing login prompt delay"
	# Increase the delay time between login prompts (10sec)
	sed -i "s/delay=[[:digit:]]\+/delay=10000000/" /etc/pam.d/login

	# Disables Root
	echo "Disabling root"
	passwd -l root

	printf "\e[1;34mFinished PasswordsAccounts() function!\e[0m"
}

Apache(){
	if [[ $HasApache ]]; then
		clear
		printf "\033[1;31mRunning Apache()\033[0m\n"
		#--------- Securing Apache ----------------#
		#This might break by the way. But you can just fix it during comp.
		ufw allow apache
		ufw allow http
		ufw allow https
		chattr -i /etc/apache2/apache2.conf
		apt install mod_security
		a2enmod userdir
		a2dismod imap
		a2dismod include
		a2dismod info
		a2dismod userdir
		a2dismod autoindex

		echo "HostnameLookups Off" >> /etc/apache2/apache2.conf
		echo "LogLevel warn" >> /etc/apache2/apache2.conf
		echo "ServerTokens Prod" >> /etc/apache2/apache2.conf
		echo "ServerSignature Off"  >> /etc/apache2/apache2.conf
		echo "Options all -Indexes" >> /etc/apache2/apache2.conf
		echo "Header unset ETag" >> /etc/apache2/apache2.conf
		echo "Header always unset X-Powered-By" >> /etc/apache2/apache2.conf
    	echo "FileETag None" >> /etc/apache2/apache2.conf
 		echo "TraceEnable off" >> /etc/apache2/apache2.conf
		echo "Timeout 30" >> /etc/apache2/apache2.conf

		echo "<Directory />" >> /etc/apache2/apache2.conf
		echo "        AllowOverride None" >> /etc/apache2/apache2.conf
		echo "        Order Deny,Allow" >> /etc/apache2/apache2.conf
		echo "        Options None" >> /etc/apache2/apache2.conf
		echo "        Deny from all" >> /etc/apache2/apache2.conf
		echo "</Directory>" >> /etc/apache2/apache2.conf

		echo "<Directory /var/www/html>" >> /etc/apache2/apache2.conf
		echo "    Options -Indexes" >> /etc/apache2/apache2.conf
		echo "</Directory>" >> /etc/apache2/apache2.conf

		echo "<IfModule mod_headers.c>" >> /etc/apache2/apache2.conf
		echo "Header set X-XSS-Protection 1; mode=block" >> /etc/apache2/apache2.conf
		echo "</IfModule>" >> /etc/apache2/apache2.conf

		echo "RewriteEngine On" >> /etc/apache2/apache2.conf

				# Secure root directory
		echo "<Directory />" >> /etc/apache2/conf-available/security.conf
		echo "Options -Indexes" >> /etc/apache2/conf-available/security.conf
		echo "AllowOverride None" >> /etc/apache2/conf-available/security.conf
		echo "Order Deny,Allow" >> /etc/apache2/conf-available/security.conf
		echo "Deny from all" >> /etc/apache2/conf-available/security.conf
		echo "</Directory>" >> /etc/apache2/conf-available/security.conf

		# Secure html directory
		echo "<Directory /var/www/html>" >> /etc/apache2/conf-available/security.conf
		echo "Options -Indexes -Includes" >> /etc/apache2/conf-available/security.conf
		echo "AllowOverride None" >> /etc/apache2/conf-available/security.conf
		echo "Order Allow,Deny" >> /etc/apache2/conf-available/security.conf
		echo "Allow from All" >> /etc/apache2/conf-available/security.conf
		echo "</Directory>" >> /etc/apache2/conf-available/security.conf

		# Use TLS only
		sed -i "s/SSLProtocol all -SSLv3/SSLProtocol –ALL +TLSv1 +TLSv1.1 +TLSv1.2/" /etc/apache2/mods-available/ssl.conf

		# Use strong cipher suites
		sed -i "s/SSLCipherSuite HIGH:\!aNULL/SSLCipherSuite HIGH:\!MEDIUM:\!aNULL:\!MD5:\!RC4/" /etc/apache2/mods-available/ssl.conf

		# Enable headers module
		a2enmod headers

		# Enable HttpOnly and Secure flags
		echo "Header edit Set-Cookie ^(.*)\$ \$1;HttpOnly;Secure" >> /etc/apache2/conf-available/security.conf

		# Clickjacking Attack Protection
		echo "Header always append X-Frame-Options SAMEORIGIN" >> /etc/apache2/conf-available/security.conf

		# XSS Protection
		echo "Header set X-XSS-Protection \"1; mode=block\"" >> /etc/apache2/conf-available/security.conf

		# Enforce secure connections to the server
		echo "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"" >> /etc/apache2/conf-available/security.conf

		# MIME sniffing Protection
		echo "Header set X-Content-Type-Options: \"nosniff\"" >> /etc/apache2/conf-available/security.conf

		# Prevent Cross-site scripting and injections
		echo "Header set Content-Security-Policy \"default-src 'self';\"" >> /etc/apache2/conf-available/security.conf

		# Prevent DoS attacks - Limit timeout
		sed -i "s/Timeout/Timeout 60/" /etc/apache2/apache2.conf
		echo "Timeout 60" >> /etc/apache2/apache2.conf

		chown -R root:root /etc/apache2
		chown -R root:root /etc/apache

		printf "\e[1;34mFinished Apache() function!\e[0m"
		echo ""
	fi
	
}

SQL(){
	if [[ $HasSQL ]]; then
		clear
		printf "\033[1;31mRunning SQL()\033[0m\n"
		ufw allow mysql
		echo "Look up mysql secure installation"

		sed -i 's/root/mysql/g' /etc/mysql/my.cnf
		chown root:root /root/.my.cnf
		chown -R root:root /etc/mysql/
		chmod 0644 /etc/mysql/my.cnf
		chmod 0600 /root/.my.cnf

		#Disables LOCAL INFILE
		echo "local-infile=0" >> /etc/mysql/my.cnf

		#Lowers database privileges
		echo "skip-show-database" >> /etc/mysql/my.cnf

		# Disable remote access
		echo "bind-address=127.0.0.1" >> /etc/mysql/my.cnf
		sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf

		#Disables symbolic links
		echo "symbolic-links=0" >> /etc/mysql/my.cnf

		#Sets password expiration
		echo "default_password_lifetime = 90" >> /etc/mysql/my.cnf

		#Sets root account password
		echo "[mysqladmin]" >> /etc/mysql/my.cnf
		echo "user = root" >> /etc/mysql/my.cnf
		echo "password = CyberPatriot1!" >> /etc/mysql/my.cnf

		#Sets packet restrictions
		echo "key_buffer_size         = 16M" >> /etc/mysql/my.cnf
		echo "max_allowed_packet      = 16M" >> /etc/mysql/my.cnf

		printf "\e[1;34mFinished SQL() function!\e[0m"
		
	fi
	
}

Nginx() {
	if [[ $HasNginx ]]; then
		clear
		printf "\e[1;34mRunning Nginx()\e[0m"
		
		# Hide nginx version
		sed -i "s/# server_tokens off;/server_tokens off;/g" /etc/nginx/nginx.conf

		# Remove ETags
		sed -i 's/server_tokens off;/server_tokens off;\netag off;/' /etc/nginx/nginx.conf

		# Remove default page
		echo "" > /var/www/html/index.html

		# Use strong cipher suites
		sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;/" /etc/nginx/nginx.conf

		# Set ssl session timeout
		sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf

		# Set ssl session cache
		sed -i "s/ssl_session_timeout 5m;/ssl_session_cache shared:SSL:10m;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf

		# Enable HttpOnly and Secure flags
		sed -i "s|^\s*try_files \\\$uri \\\$uri/ =404;|try_files \\\$uri \\\$uri/ =404;\nproxy_cookie_path / \"/; secure; HttpOnly\";|" /etc/nginx/sites-available/default

		# Clickjacking Attack Protection
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Frame-Options DENY;|" /etc/nginx/sites-available/default

		# XSS Protection
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-XSS-Protection \"1; mode=block\";|" /etc/nginx/sites-available/default

		# Enforce secure connections to the server
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubdomains;\";|" /etc/nginx/sites-available/default

		# MIME sniffing Protection
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Content-Type-Options nosniff;|" /etc/nginx/sites-available/default

		# Prevent Cross-site scripting and injections
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Content-Security-Policy \"default-src 'self';\";|" /etc/nginx/sites-available/default

		# Set X-Robots-Tag
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Robots-Tag none;|" /etc/nginx/sites-available/default
	fi

}

Samba() {
	if [[ $HasSamba ]]; then
		clear
		printf "\033[1;31mRunning Samba()\033[0m\n"

		chattr -i /etc/samba/smb.conf
	    ufw allow samba
		chmod 600 /etc/samba/smb.conf

		echo "restrict anonymous = 2" >> /etc/samba/smb.conf
		echo "encrypt passwords = True" >> /etc/samba/smb.conf
		echo "encrypt passwords = yes" >> /etc/samba/smb.conf
		echo "read only = Yes" >> /etc/samba/smb.conf
		echo "ntlm auth = no" >> /etc/samba/smb.conf
		echo "obey pam restrictions = yes" >> /etc/samba/smb.conf
		echo "server signing = mandatory" >> /etc/samba/smb.conf
		echo "smb encrypt = mandatory" >> /etc/samba/smb.conf
		echo "min protocol = SMB2" >> /etc/samba/smb.conf
		echo "protocol = SMB2" >> /etc/samba/smb.conf
		echo "guest ok = no" >> /etc/samba/smb.conf
		echo "max log size = 24" >> /etc/samba/smb.conf


		echo "Make sure to read the /etc/samba/smb.conf file and check whats inside!"

		printf "\e[1;34mFinished Samba() function!\e[0m"
	fi

}

PHP() {
	if [[ $HasPHP ]]; then
		clear
		printf "\033[1;31mRunning PHP()\033[0m\n"

		ufw allow php

		chattr -i /etc/php.ini
		chattr -i /etc/php.d/*
		chattr -i /etc/my.cnf
		chattr -i /etc/httpd/conf/httpd.conf

		#Enables safe mode in php.ini
		echo "sql.safe_mode=on" >> /etc/php5/apache2/php.ini
		echo "safe_mode = On" >> /etc/php5/apache2/php.ini
		echo "safe_mode_gid = On" >> /etc/php5/apache2/php.ini

		#Disables Global variables
		echo "register_globals=off" >> /etc/php5/apache2/php.ini

		#Disables tracking, HTML, and display errors
		sed -i '/^track_errors = On/ c\track_errors = Off' /etc/php5/apache2/php.ini
		sed -i '/^html_errors = On/ c\html_errors = Off' /etc/php5/apache2/php.ini
		sed -i '/^display_errors = On/ c\display_errors = Off' /etc/php5/apache2/php.ini
		echo "expose_php = Off" >> /etc/php5/apache2/php.ini
		echo "track_errors = Off" >> /etc/php5/apache2/php.ini
		echo "html_errors = Off" >> /etc/php5/apache2/php.ini
		echo "display_errors = Off" >> /etc/php5/apache2/php.ini

		#Disables Remote File Includes
		sed -i '/^allow_url_fopen = On/ c\allow_url_fopen = Off' /etc/php5/apache2/php.ini
		sed -i '/^allow_url_include = On/ c\allow_url_include = Off' /etc/php5/apache2/php.ini
		echo "allow_url_fopen = Off" >> /etc/php5/apache2/php.ini
		echo "allow_url_include = Off" >> /etc/php5/apache2/php.ini

		#Restrict File Uploads
		sed -i '/^file_uploads = On/ c\file_uploads = Off' /etc/php5/apache2/php.ini
		echo "file_uploads = Off" >> /etc/php5/apache2/php.ini

		#Control POST size
		sed -i '/^post_max_size = 8M/ c\post_max_size = 1K' /etc/php5/apache2/php.ini

		#Protect sessions
		sed -i '/^session.cookie_httponly =/ c\session.cookie_httponly = 1' /etc/php5/apache2/php.ini

		#Disables a metric fuck ton of functionality
		echo "disable_functions = php_uname, getmyuid, getmypid, passthru, leak, listen, diskfreespace, tmpfile, link, ignore_user_abord,
		shell_exec, dl, set_time_limit, exec, system, highlight_file, source, show_source, fpaththru, virtual, posix_ctermid, posix_getcwd,
		posix_getegid, posix_geteuid, posix_getgid, posix_getgrgid, posix_getgrnam, posix_getgroups, posix_getlogin, posix_getpgid,
		posix_getpgrp, posix_getpid, posix, _getppid, posix_getpwnam, posix_getpwuid, posix_getrlimit, posix_getsid, posix_getuid, posix_isatty,
		posix_kill, posix_mkfifo, posix_setegid, posix_seteuid, posix_setgid, posix_setpgid, posix_setsid, posix_setuid, posix_times, posix_ttyname,
		posix_uname, proc_open, proc_close, proc_get_status, proc_nice, proc_terminate, phpinfo" >> /etc/php5/apache2/php.ini

		echo "magic_quotes_gpc=Off" >> /etc/php5/apache2/php.ini
		echo "session.cookie_httponly = 1" >> /etc/php5/apache2/php.ini
		echo "expose_php = Off" >> /etc/php5/apache2/php.ini
		echo "session.use_strict_mode = On" >> /etc/php5/apache2/php.ini
		echo "allow_url_fopen=Off" >> /etc/php5/apache2/php.ini
		echo "allow_url_include=Off" >> /etc/php5/apache2/php.ini
		echo "disable_functions =exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec" >> /etc/php5/apache2/php.ini
		echo "upload_max_filesize = 2M" >> /etc/php5/apache2/php.ini
		echo "max_execution_time = 30" >> /etc/php5/apache2/php.ini
		echo "max_input_time = 30 " >> /etc/php5/apache2/php.ini
		echo "open_basedir="/home/user/public_html"" >> /etc/php5/apache2/php.ini
		echo "display_errors = Off" >> /etc/php5/apache2/php.ini
		echo "memory_limit = 40M" >> /etc/php5/apache2/php.ini
		echo "mail.add_x_header = Off" >> /etc/php5/apache2/php.ini
		echo "fle_uploads=Off" >> /etc/php5/apache2/php.ini
		echo "max_input_time = 60" >> /etc/php5/apache2/php.ini
		printf "\e[1;34mFinished PHP() function!\e[0m"
		echo ""

		#Enables and configures Suhosin
		apt install php5-suhosin -y
		echo "extension=suhosin.so" >> /etc/php5/conf.d/suhosin.ini
		echo "suhosin.session.encrypt = Off" >> /etc/php5/conf.d/suhosin.ini
		echo "suhosin.log.syslog=511" >> /etc/php5/conf.d/suhosin.ini
		echo "suhosin.executor.include.max_traversal=4" >> /etc/php5/conf.d/suhosin.ini
		echo "suhosin.executor.disable_eval=On" >> /etc/php5/conf.d/suhosin.ini
		echo "suhosin.executor.disable_emodifier=On" >> /etc/php5/conf.d/suhosin.ini
		echo "suhosin.mail.protect=2" >> /etc/php5/conf.d/suhosin.ini
		echo "suhosin.sql.bailout_on_error=On" >> /etc/php5/conf.d/suhosin.ini

		#Fuck it I'm dumping a CIS benchmark in here. If this breaks, have fun LOL
		echo " ----start of CIS dump haha----
		[PHP]
engine = On
short_open_tag = Off
asp_tags = Off
precision = 14
y2k_compliance = On
output_buffering = 4096
zlib.output_compression = Off
implicit_flush = Off
unserialize_callback_func =
serialize_precision = 17
allow_call_time_pass_reference = Off
safe_mode = Off
safe_mode_gid = Off
safe_mode_include_dir =
safe_mode_exec_dir =
safe_mode_allowed_env_vars = PHP_
safe_mode_protected_env_vars = LD_LIBRARY_PATH
open_basedir = \"/var/www/html:/tmp\"
disable_functions = proc_open, popen, disk_free_space, diskfreespace, set_time_limit, leak, tmpfile, exec, system, shell_exec, passthru, show_source, system, phpinfo, pcntl_alarm, pcntl_fork, pcntl_waitpid, pcntl_wait, pcntl_wifexited, pcntl_wifstopped, pcntl_wifsignaled, pcntl_wexitstatus, pcntl_wtermsig, pcntl_wstopsig, pcntl_signal, pcntl_signal_dispatch, pcntl_get_last_error, pcntl_strerror, pcntl_sigprocmask, pcntl_sigwaitinfo, pcntl_sigtimedwait, pcntl_exec, pcntl_getpriority, pcntl_setpriority
disable_classes =
zend.enable_gc = On
expose_php = Off
max_execution_time = 30
max_input_time = 60
memory_limit = 128M
error_reporting = E_COMPILE_ERROR|E_RECOVERABLE_ERROR|E_ERROR|E_CORE_ERROR
display_errors = Off
display_startup_errors = Off
log_errors = On
log_errors_max_len = 1024
error_log = /var/log/php.log
ignore_repeated_errors = Off
ignore_repeated_source = Off
report_memleaks = On
track_errors = Off
html_errors = Off
variables_order = \"GPCS\"
request_order = \"GP\"
register_globals = Off
register_long_arrays = Off
register_argc_argv = Off
auto_globals_jit = On
post_max_size = 8M
magic_quotes_gpc = Off
magic_quotes_runtime = Off
magic_quotes_sybase = Off
auto_prepend_file =
auto_append_file =
default_mimetype = \"text/html\"
default_charset = \"utf-8\"
doc_root =
user_dir =
enable_dl = Off
file_uploads = On
upload_max_filesize = 2M
max_file_uploads = 20
allow_url_fopen = Off
allow_url_include = Off
default_socket_timeout = 60

[Pcre]

pcre.recursion_limit=1000

[Pdo_mysql]

pdo_mysql.cache_size = 2000
pdo_mysql.default_socket=

[Syslog]

define_syslog_variables  = Off

[mail function]

smtp_port = 25
mail.add_x_header = On

[SQL]

sql.safe_mode = Off

[ODBC]

odbc.allow_persistent = On
odbc.check_persistent = On
odbc.max_persistent = -1
odbc.max_links = -1
odbc.defaultlrl = 4096
odbc.defaultbinmode = 1


[Interbase]

ibase.allow_persistent = 1
ibase.max_persistent = -1
ibase.max_links = -1

[MySQL]

mysql.allow_local_infile = On
mysql.allow_persistent = On
mysql.cache_size = 2000
mysql.max_persistent = -1
mysql.max_links = -1
mysql.default_port =
mysql.default_socket =
mysql.default_host =
mysql.default_user =
mysql.default_password =
mysql.connect_timeout = 60
mysql.trace_mode = Off

[MySQLi]

mysqli.max_persistent = -1
mysqli.allow_persistent = On
mysqli.max_links = -1
mysqli.cache_size = 2000
mysqli.default_port = 3306
mysqli.default_socket =
mysqli.default_host =
mysqli.default_user =
mysqli.default_pw =
mysqli.reconnect = Off

[mysqlnd]

mysqlnd.collect_statistics = On
mysqlnd.collect_memory_statistics = Off
[OCI8]


[PostgreSQL]

pgsql.allow_persistent = On
pgsql.auto_reset_persistent = Off
pgsql.max_persistent = -1
pgsql.max_links = -1
pgsql.ignore_notice = 0
pgsql.log_notice = 0

[Sybase-CT]

sybct.allow_persistent = On
sybct.max_persistent = -1
sybct.max_links = -1
sybct.min_server_severity = 10
sybct.min_client_severity = 10

[bcmath]

bcmath.scale = 0

[browscap]


[Session]

session.save_handler = files
session.use_cookies = 1
session.use_only_cookies = 1
session.name = PHPSESSID
session.auto_start = 0
session.cookie_lifetime = 3600
session.cookie_path = /
session.cookie_domain =
session.cookie_httponly =
session.serialize_handler = php
session.gc_probability = 0
session.gc_divisor = 1000
session.gc_maxlifetime = 1440
session.bug_compat_42 = Off
session.bug_compat_warn = Off
session.referer_check =
session.entropy_length = 0
session.cache_limiter = nocache
session.cache_expire = 180
session.use_trans_sid = 0
session.hash_function = 0
session.hash_bits_per_character = 5
url_rewriter.tags = \"a=href,area=href,frame=src,input=src,form=fakeentry\"

[MSSQL]

mssql.allow_persistent = On
mssql.max_persistent = -1
mssql.max_links = -1
mssql.min_error_severity = 10
mssql.min_message_severity = 10
mssql.compatability_mode = Off
mssql.secure_connection = Off
mssql.secure_connection = On

[Tidy]

tidy.clean_output = Off

[soap]

soap.wsdl_cache_enabled=1
soap.wsdl_cache_dir=\"/tmp\"
soap.wsdl_cache_ttl=86400
soap.wsdl_cache_limit = 5

[ldap]

ldap.max_links = -1
" >> /etc/php5/apache2/php.ini

	fi

}

SSH() {
	if [[ $HasSSH ]]; then
		clear
		printf "\033[1;31mRunning SSH()\033[0m\n"
		ufw allow 22
		
		echo "Port 222" > /etc/ssh/sshd_config
		echo "PermitRootLogin no" >> /etc/ssh/sshd_config
		echo "Protocol 2" >> /etc/ssh/sshd_config
		echo "LoginGRaceTime 2m" >> /etc/ssh/sshd_config
		echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
		echo "HostbasedAUthentication no" >> /etc/ssh/sshd_config
		echo "RhostsRSAAuthentication no" >> /etc/ssh/sshd_config
		echo "UsePrivilegeSeparation yes" >> /etc/ssh/sshd_config
		echo "StrictModes yes" >> /etc/ssh/sshd_config
		echo "VerifyReverseMapping yes" >> /etc/ssh/sshd_config
		echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
		echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
		echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
		echo "X11Forwarding no" >> /etc/ssh/sshd_config
		echo "SyslogFacility AUTH" >> /etc/ssh/sshd_config
		echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
		echo "MaxStartups 2" >> /etc/ssh/sshd_config
		echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
		echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
		echo "UseDNS no" >> /etc/ssh/sshd_config
		echo "PermitTunnel no" >> /etc/ssh/sshd_config
		echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
		echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
		echo "PrintLastLog no" >> /etc/ssh/sshd_config
		echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
		sed -i "s/#Banner none/Banner \/etc\/issue\.net/g" /etc/ssh/sshd_config
		echo "Welcome!" > /etc/issue.net

		printf "\e[1;34mFinished SSH() function!\e[0m"
		echo ""

	fi

}

VSFTPD() {
	if [[ $HasVSFTPD ]]; then
		clear
		printf "\033[1;31mRunning VSFTPD()\033[0m\n"

		ufw allow 21
		chattr -i /etc/vsftpd.conf

		echo "anonymous_enable=NO" >> /etc/vsftpd.conf
		echo "chroot_local_user=YES" >> /etc/vsftpd.conf
		echo "local_enable=YES" >> /etc/vsftpd.conf
		echo "write_enable=YES" >> /etc/vsftpd.conf
		echo "use_localtime=YES" >> /etc/vsftpd.conf
		echo "dirmessage_enable=YES" >> /etc/vsftpd.conf
		echo "xferlog_enable=YES" >> /etc/vsftpd.conf
		echo "connect_from_port_20=YES" >> /etc/vsftpd.conf
		echo "ascii_upload_enable=NO" >> /etc/vsftpd.conf
		echo "ascii_download_enable=NO" >> /etc/vsftpd.conf
		
# ADD THE FOLLOWING BELOW INTO THE SCRIPT WITH ECHO
# STATEMENTS, I'M TOO LAZY TO DO IT SO YOU DO IT
# Jail users to home directory (user will need a home dir to exist)
#chroot_local_user=YES
#chroot_list_enable=YES
#chroot_list_file=/etc/vsftpd.chroot_list
#allow_writeable_chroot=YES # Only enable if you want files to be editable
# Allow or deny users
#userlist_enable=YES
#userlist_file=/etc/vsftpd.userlist
#userlist_deny=NO
# General config
#anonymous_enable=NO # disable anonymous login
#ocal_enable=YES # permit local logins
#write_enable=YES # enable FTP commands which change the filesystem
#local_umask=022 # value of umask for file creation for local users
#dirmessage_enable=YES # enable showing of messages when users first enter a
#new directory
#xferlog_enable=YES # a log file will be maintained detailing uploads and
#downloads
#connect_from_port_20=YES # use port 20 (ftp-data) on the server machine for PORT
#style connections
#xferlog_std_format=YES # keep standard log file format
#listen=NO # prevent vsftpd from running in standalone mode
#listen_ipv6=YES # vsftpd will listen on an IPv6 socket instead of an
#IPv4 one
#pam_service_name=vsftpd # name of the PAM service vsftpd will use
#userlist_enable=YES # enable vsftpd to load a list of usernames
#tcp_wrappers=YES # turn on tcp wrappers

		printf "\e[1;34mFinished VSFTPD() function!\e[0m"
		echo ""
	fi
}

PureFTPD() {
	if [[ $HasPureFTPD ]]; then
		clear
		printf "\e[1;34mRunning PureFTPD()\e[0m"
		chattr -i /etc/pure-ftpd/conf
		echo "yes" >> /etc/pure-ftpd/conf/NoAnonymous
		echo "yes" >> /etc/pure-ftpd/conf/ChrootEveryone
		echo "yes" >> /etc/pure-ftpd/conf/IPV4Only
		echo "yes" >> /etc/pure-ftpd/conf/ProhibitDotFilesWrite
		echo "2" > /etc/pure-ftpd/conf/TLS
		echo 2 |  tee /etc/pure-ftpd/conf/TLS
		echo 1 |  tee /etc/pure-ftpd/conf/NoAnonymous

		printf "\e[1;34mFinished PureFTPD() function!\e[0m"
	fi
	
}

ProFTP() {
	if [[ $HasProFTP ]]; then
		clear
		printf "\e[1;34mRunning ProFTP()\e[0m"
		echo "DelayEngine on" >> /etc/proftpd/proftpd.conf
		echo "UseLastLog on" >> /etc/proftpd/proftpd.conf
		echo "ServerIndent Off" >> /etc/proftpd/proftpd.conf
		echo "IdentLookups off" >> /etc/proftpd/proftpd.conf
		echo "TLSEngine on" >> /etc/proftpd/proftpd.conf
		echo "TLSProtocol SSLv23" >> /etc/proftpd/proftpd.conf
		echo "TLSRequired On" >> /etc/proftpd/proftpd.conf
		echo "UseReverseDNS On" >> /etc/proftpd/proftpd.conf
		printf "\e[1;34mFinished ProFTP() function!\e[0m"
	fi
	
}

File(){
	clear
	printf "\033[1;31mSetting file permissions...\033[0m\n"

	echo "exit 0" > /etc/rc.local

	chown root:root /etc/fstab
	chmod 644 /etc/fstab
	chown root:root /etc/group
	chmod 644 /etc/group
	chown root:root /etc/shadow
	chmod 400 /etc/shadow
	chown root:root /etc/apache2
	chmod 755 /etc/apache2
	chmod 0600 /etc/securetty
	chmod 644 /etc/crontab
	chmod 640 /etc/ftpusers
	chmod 440 /etc/inetd.conf
	chmod 440 /etc/xinetd.conf
	chmod 400 /etc/inetd.d
	chmod 644 /etc/hosts.allow
	chmod 440 /etc/ers
	chmod 640 /etc/shadow
	chmod 600 /boot/grub/grub.cfg
	chmod 600 /etc/ssh/sshd_config
	chmod 600 /etc/gshadow-
	chmod 600 /etc/group-
	chmod 600 /etc/passwd-
	chown root:root /etc/ssh/sshd_config
	chown root:root /etc/passwd-
	chown root:root /etc/group-
	chown root:root /etc/shadow
	chown root:root /etc/securetty
	chown root:root /boot/grub/grub.cfg
	chmod og-rwx /boot/grub/grub.cfg
	chown root:shadow /etc/shadow-
	chmod o-rwx,g-rw /etc/shadow-
	chown root:shadow /etc/gshadow-
	chmod o-rwx,g-rw /etc/gshadow-
	touch /etc/cron.allow
	touch /etc/at.allow
	chmod og-rwx /etc/cron.allow
	chmod og-rwx /etc/at.allow
	chown root:root /etc/cron.allow
	chown root:root /etc/at.allow
	chown root:root /etc/cron.d
	chmod og-rwx /etc/cron.d
	chown root:root /etc/crontab
	chmod og-rwx /etc/crontab
	chmod -R g-wx,o-rwx /var/log/*

	crontab -r

	printf "\e[1;34mFinished File() function!\e[0m"

}

Misc(){	
	clear
	printf "\033[1;31mRunning Misc()\033[0m\n"

	#Disable automounting
	systemctl disable autofs
	service autofs stop

	# set users umask
	sed -i "s/UMASK.*022/UMASK   077/" /etc/login.defs

	# set root umask
	sed -i "s/#.*umask.*022/umask 077/" /root/.bashrc
	
	#Restricts umask
    sed -i s/umask\ 022/umask\ 027/g /etc/init.d/rc

	#Set all apparmor profiles to enforce mode
	aa-enforce /etc/apparmor.d/*

	#Disables ctrl-alt-delete
	systemctl mask ctrl-alt-del.target
	systemctl daemon-reload

	#Disables cups
	systemctl disable cups
	systemctl disable cupsd
	service cups stop
	service cupsd stop

	#I think this secures the kernel?
	echo "* hard core 0" >> /etc/security/limits.conf

	#Hardening /proc with hidepid
	mount -o remount,rw,hidepid=2 /proc

	#Applying apparmor to Firefox and applying settings
	aa-enforce /etc/apparmor.d/usr.bin.Firefox
	echo 'pref("general.config.filename", "mozilla.cfg");' >> /usr/lib/firefox/defaults/pref/local-settings.js
	echo 'lockPref("browser.safebrowsing.downloads.enabled", true);
	lockPref("dom.disable_open_during_load", true);
	lockPref("xpinstall.whitelist.required", true);
	lockPref("app.update.enabled", true);
	lockPref("app.update.auto", true);
	lockPref("privacy.donottrackheader.enabled", true);
	lockPref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", true);
	lockPref("browser.safebrowsing.downloads.remote.block_uncommon", true);
	lockPref("browser.safebrowsing.malware.enabled", true);
	lockPref("browser.safebrowsing.phishing.enabled", true);' > /usr/lib/firefox/mozilla.cfg

	#Secure sudoers
	sed -i 's/NOPASSWD://g' /etc/ers
	sed -i 's/!authenticate//g' /etc/ers
	sed -i 's/!authenticate//g' /etc/ers.d/*
	sed -i 's/NOPASSWD://g' /etc/ers.d/*

	#IP Spoofing
	echo "order bind,hosts" >> /etc/host.conf
	echo "nospoof on" >> /etc/host.conf

	#Secured shared memory
	echo "tmpfs     /run/shm    tmpfs	defaults,noexec,nosuid	0	0" >> /etc/fstab

	#Changes the nameserver to 8.8.8.8, Google's DNS.
	echo "nameserver 8.8.8.8" >> /etc/resolv.conf

	chown root:root /etc/motd
	chmod 644 /etc/motd
	echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd

	chown root:root /etc/issue
	chmod 644 /etc/issue
	echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

	chown root:root /etc/issue.net
	chmod 644 /etc/issue.net
	echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

	printf "\e[1;34mFinished Misc() function!\e[0m"
}

Firewall(){
	clear
	printf "\033[1;31mSetting up firewall...\033[0m\n"
	#--------- Setup Firewall ----------------
	# Flush/Delete firewall rules
	iptables -F
	iptables -X
	iptables -Z

	ufw reset
	ufw enable
	ufw logging full
	ufw default deny incoming
	ufw deny 23		#Block Telnet
	ufw deny 2049	#Block NFS
	ufw deny 515	#Block printer port
	ufw deny 111 #Block Sun rpc/NFS
	ufw status verbose > ufwrules.txt

	#Disables IPV6
	sed -i '/^IPV6=yes/ c\IPV6=no\' /etc/default/ufw
	echo 'blacklist ipv6' >> /etc/modprobe.d/blacklist

	# Block null packets (DoS)
	iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

	# Block syn-flood attacks (DoS)
	iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

	#Drop incoming packets with fragments
	iptables -A INPUT -f -j DROP

	# Block XMAS packets (DoS)
	iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

	# Allow internal traffic on the loopback device
	iptables -A INPUT -i lo -j ACCEPT

	# Allow ssh access
	iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT

	# Allow established connections
	iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	# Allow outgoing connections
	iptables -P OUTPUT ACCEPT

	# Set default deny firewall policy
	iptables -P INPUT DROP

	#Block Telnet
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP

	#Block NFS
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP

	#Block X-Windows
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP

	#Block X-Windows font server
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP

	#Block printer port
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP

	#Block Sun rpc/NFS
	iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP

	 #Deny outside packets from internet which claim to be from your loopback interface.
	iptables -A INPUT -p all -s localhost  -i eth0 -j DROP

	# Save rules
	iptables-save > /etc/iptables/rules.v4

	#If you ever need to block an IP address - http://bookofzeus.com/harden-ubuntu/hardening/protect-ddos-attacks/
	printf "\e[1;34mFinished Firewall() function!\e[0m"
}

Sysctl(){
	clear
	printf "\033[1;31mMaking Sysctl Secure...\033[0m\n"
	#--------- Secure /etc/sysctl.conf ----------------
	echo "net.ipv4.tcp_syncookies=1
kernel.dmesg_restrict=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv6.conf.default.accept_redirects=0
fs.suid_dumpable=0
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.sysrq = 0
kernel.maps_protect=1
kernel.core_uses_pid=1
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv6.conf.all.accept_redirects=0
net.ipv4.icmp_echo_ignore_all=1
kernel.exec-shield=1
kernel.panic=10
kernel.kptr_restrict=2
vm.panic_on_oom=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
kernel.randomize_va_space=2
net.ipv6.conf.default.router_solicitations=0
net.ipv6.conf.default.accept_ra_rtr_pref=0
net.ipv6.conf.default.accept_ra_pinfo=0
net.ipv6.conf.default.accept_ra_defrtr=0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.default.dad_transmits=0
net.ipv6.conf.default.max_addresses=1
net.ipv4.tcp_rfc1337=1
kernel.unprivileged_userns_clone=0
kernel.ctrl-alt-del=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1


	" > /etc/sysctl.conf

	sysctl -p

	printf "\e[1;34mFinished Sysctl() function!\e[0m"
}

Auditctl() { #This is most likely useless.
	clear
	printf "\e[1;34mRunning Auditctl()\e[0m"
	echo "
	# First rule - delete all
	-D

	#Ensure events that modify date and time information are collected

	-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
	-a always,exit -F arch=b64 -S clock_settime -k time-change
	-a always,exit -F arch=b32 -S clock_settime -k time-change
	-w /etc/localtime -p wa -k time-change

	#Ensure events that modify user/group information are collected

	-w /etc/group -p wa -k identity
	-w /etc/passwd -p wa -k identity
	-w /etc/gshadow -p wa -k identity
	-w /etc/shadow -p wa -k identity
	-w /etc/security/opasswd -p wa -k identity

	#Ensure events that modify the system's network environment are collected

	-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
	-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
	-w /etc/issue -p wa -k system-locale
	-w /etc/issue.net -p wa -k system-locale
	-w /etc/hosts -p wa -k system-locale
	-w /etc/network -p wa -k system-locale
	-w /etc/networks -p wa -k system-locale

	#Ensure events that modify system's MAC are collected

	-w /etc/apparmor/ -p wa -k MAC-policy
	-w /etc/apparmor.d/ -p wa -k MAC-policy

	#Ensure login and logouts events are collected

	-w /var/log/faillog -p wa -k logins
	-w /var/log/lastlog -p wa -k logins
	-w /var/log/tallylog -p wa -k logins

	#Ensure session initiation information is collected

	-w /var/run/utmp -p wa -k session
	-w /var/run/wtmp -p wa -k session
	-w /var/run/btmp -p wa -k session

	#Ensure discretionary access control permission modification events are collected

	-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

	#Ensure unsuccessful unauthorized file access attempts are collected

	-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
	-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
	-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
	-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

	#Ensure successful file system mounts are collected

	-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
	-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

	#Ensure file deletion events by users are collected

	-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
	-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

	#Ensure changes to system administration scope (ers) is collected

	-w /etc/ers -p wa -k scope
	-w /etc/ers.d -p wa -k scope

	#Ensure system administrator actions (log) are collected

	-w /var/log/.log -p wa -k actions

	#Ensure kernel module loading and unloading is collected

	-w /sbin/insmod -p x -k modules
	-w /sbin/rmmod -p x -k modules
	-w /sbin/modprobe -p x -k modules
	-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

	# increase the buffers to survive stress events. make this bigger for busy systems.
	-b 1024

	# monitor unlink() and rmdir() system calls.
	-a exit,always -S unlink -S rmdir

	# monitor open() system call by Linux UID 1001.
	-a exit,always -S open -F loginuid=1001

	" >> /etc/audit/audit.rules
		
	printf "\e[1;34mFinished Sysctl() function!\e[0m"
}
	clear

	apt dist-upgrade -y
	apt autoremove -y
	
Main
#Ardy was here lol
