#!/bin/sh

#This is the install script for Minions client
#This script will install nmap, openssl, python-twisted, and any other necceesary dependencies. It should be reviewed to ensure you have a full understanding of what is being installed on your host
apt-get -y install nmap python-openssl python-twisted

#Get the script remotely. This could be done several ways. I implement a WGET method
#Could also be done with git clone 
echo -n "Enter the URL of client zip: "
read clienturl
wget --no-check-certificate --output-document=minions.zip $clienturl

unzip minions.zip

