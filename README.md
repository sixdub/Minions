# Description
Minions is colloborative distributed scanning solution meant to aid penetration testers and red teamers in accomplishing their scan objectives. Minions has a DJango backend with a JQuery/Bootstrap front end. It utilizes a modified version of DNmap to conduct the distributed scanning. DNmap was written by Sebastian Garcia and all credit goes to him on the original code base and protocol. Modifications were made to improve functionality as well as tailor use for the Django application. 

Minions has been tested on Ubuntu and CentOS with Apache (mod_wsgi). 

Author: Justin Warner (@sixdub)

For more info, please see the blog post here:

#### Disclaimer:
This application is a Django web application and can be installed in many different environments and in many different ways. Please note that I have tested a couple limited use cases. I will do my best to support a variety of configurations/environments but it might be up to you to figure it all out. 
# How To
### Installation (Server)
This install assumes you are installing to the /var/www/minions directory. If you are not, you are on your own and several things will have to be modified. 

To install Minions, please download the setup.sh script in the root of this repo. This will install any required dependencies as well as clone the repo into the proper directory for you. The script will need to be run as root and I recommend you review the contents in order to ensure it will not damage your current installation. 

If you installed to a place other than the /var/www/minions directory, please go into the settings.py file and modify the path variables at the bottom. Note that Debug is set to FALSE! 

After running the script, the Minions server is running and accessible via the web interface. 

The web application is desktop and mobile friendly. To start, login to the interface with the default credentials: admin / Minions. Change these credentials immediately by going to the "Admin" page, and clicking "Change Password" in the upper right hand corner. 

If you would like to create a non-admin user, do so in this "Admin" page. The non-admin user will not be able to perform the server control actions and will not be able to see the "Admin" page. 

### Certificate Management
Minions uses X509 Certificates for authentication and encryption of the SSL traffic. Default certs are provided for test use but SHOULD NOT BE USED IN A PRODUCTION ENVIRONMENT. I recommend you generate your own CA cert and create server/client certs as required. Below is a pretty good link to help. Minions expects the .pem files to contain the Certificate and Private Key. 

http://dst.lbl.gov/~boverhof/openssl_certs.html

To combine into a single PEM, simply "cat client.key>>client.pem && cat server.key >> server.pem"

### Using the Server
You are now ready! Head over the Minions interface and login. This will drop you onto the main scans page. There should not be any scans present to start. 

#### Starting Server
Click on the "Server Control" tab. This area is used to adminster the backend DNmap Server. Click "Start Server". You should see the server output begin to generate at the top of the page and the log should contain entries registering the start of the server.

### Connecting Clients
On a remote client, upload the dnmap_client.py and client.pem file. You could also host these in the minions/scans/static/ folder on your web server to make them accessible for dowload. 

Once the files are uploaded, simply run the dnmap_client.py with the appropriate options to connect to the server. An example usage is:
#### Usage:
	dnmap_client.py -s <SERVER> -p <PORT> -a <ALIAS> -P client.pem

The client should immediately reach out and connect. You can confirm by looking at your "Server Control" page and recognizing the client has been added to the list. 

### Running Scan
To run a scan, click on the "Run Scan" page. Input all of the required information including the hosts list (each host on a new line). Select the appropriate Scan Profile. There should be two created for you by default. Click submit. This will issue the scan job to the backend server which will then give it to a client for completion. You can watch the entire transaction on the "Server Control" page. 

### Viewing & Downloading Results
Once the scan finishes and the log says "Importing XX.xml", the scan has completed. Click on the "Current Scans" tab to see all scan jobs. Click on the row that is your scan job to open it up. All information should be displayed for viewing. To download scan results, click "Download Zip". There is no password for the zip file.

### Creating Scan Profile
A scan profile is a default command string to be passed to nmap. To create a custom scan profile, click on "Run Scan" and click on "Scan Profile" at the bottom. This will allow you to view and create scan profiles. 

YOU DO NOT NEED TO ADD THE OUTPUT LINE! This will not work. 

###Fail Cases:
When a client loses connection, the server will recognize that the client has disconnected, and will repopulate the job that the client was executing back into the list of jobs. 

When the server loses connection, any jobs that were currently at clients will be in the jobs.dnmaptrace file. Every time the server loads, any jobs in this file are automatically populated into the queue to be recompleted for reliability sake. Clients that were executing jobs or attempted to send back data while disconnected will fail.

### Base File List
<ul>
<li>apache (D) - Directory for custom apache error/access logs</li>
<li>minions (D) - Project directory. Contains settings.py which stores variables for app configuration</li>
<li>scan_engine (D) - Stores DNmap and all required files. Also stores scan results </li>
<li>scans (D) - Django application. Stores the model.py, views.py and urls.py for the Minions app. Has "Static" folder which is directory web accessible.  </li>
<li>templates (D) - Contains all HTML templates for the application. To modify the look, go here. </li>
<li>db.sqlite3 - Main application database</li>
<li>manage.py - Django management script</li>
</ul>



