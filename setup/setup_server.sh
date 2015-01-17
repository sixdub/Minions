#!/bin/sh

#This is the install script for Minions
#This script will install apache, django, python/pip, python-twisted, at, and any other necceesary dependencies. It should be reviewed to ensure you have a full understanding of what is being installed on your server

############## INSTALL THING #######################
#Install python stuff
apt-get -y install python-pip python-twisted-bin python-twisted-core 
pip install django

#Apache/Django Setup
sudo apt-get -y install apache2 libapache2-mod-wsgi python-django at git
git clone https://github.com/sixdub/Minions.git /var/www/minions

############## CONFIGURE APACHE #################################
#enable engines required for ssl
sudo a2enmod ssl
sudo a2enmod rewrite

sudo mkdir /etc/apache2/ssl
sudo /usr/sbin/make-ssl-cert /usr/share/ssl-cert/ssleay.cnf /etc/apache2/ssl/apache.pem

#Setup the apache sites
cat > /etc/apache2/sites-available/000-default.conf << EOL
<VirtualHost *:80>
RewriteEngine On
RewriteCond %{HTTPS} !on
RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
</VirtualHost>
EOL

cat > /etc/apache2/sites-available/default-ssl.conf << EOL
<IfModule mod_ssl.c>
	<VirtualHost *:443>
		ServerName MinWebServer
		DocumentRoot /var/www/minions
		
		SSLEngine on
		SSLCertificateFile	/etc/apache2/ssl/apache.pem
		SSLOptions +StdEnvVars

		Alias /static/ /var/www/minions/scans/static/
		<Location "/static/">
		Options -Indexes
		</Location>

		ErrorLog /var/www/minions/apache/logs/error.log
		CustomLog /var/www/minions/apache/logs/access.log combined
		
		WSGIScriptAlias / /var/www/minions/minions/wsgi.py
		WSGIDaemonProcess minions python-path=/var/www/minions processes=2 threads=15 display-name=DjangoApp
		WSGIProcessGroup minions
	</VirtualHost>
</IfModule>
EOL

sudo a2ensite default-ssl.conf

#Add directories for apache logs
mkdir -p /var/www/minions/apache/logs

chown -R www-data /var/www/minions 
chgrp -R www-data /var/www/minions

service apache2 restart

#################### MISC ############################
#Allow the web user to schedule jobs. This is how DJango will schedule scan jobs
sed '/www-data/d' /etc/at.deny > /etc/at.deny.tmp
mv /etc/at.deny.tmp /etc/at.deny


