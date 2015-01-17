#! /usr/bin/env python
#  
# DNmap Server - Edited by Justin Warner (@sixdub). Originally written by Sebastian Garcia
# Orginal Copyright and license (included below) applies. 
#
# This is the server code to be used in conjunction with Minions, a collaborative distributed 
# scanning solution. 
#
#
# DNmap Version Modified: .6
# Copyright (C) 2009  Sebastian Garcia
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# Author:
# Sebastian Garcia eldraco@gmail.com
#
# Based on code from Twisted examples.
# Copyright (c) Twisted Matrix Laboratories.
#

import logging
import logging.handlers
import datetime
import sqlite3
import os
import xml.etree.ElementTree as ET

try:
	from twisted.internet.protocol import Factory, Protocol
	from twisted.internet import ssl, reactor, task
	from twisted.python import log
	from twisted.python.logfile import DailyLogFile
except:
	print 'You need twisted library. apt-get install python-twisted-bin python-twisted-core'
	exit(-1)

import getopt, sys, time, os
try:
	from OpenSSL import SSL
except:
	print 'You need python openssl library. apt-get install python-openssl'
	exit(-1)



# Global variables
vernum='0.6'
nmap_commands_file = ''
nmap_command = []
nmap_commands_sent = []
trace_file = ''
nmap_output_coming_back = False
XML_file= ''
GNmap_file=''
outputswitch=''
file_position = 0
clients = {}
port=8001
clientes = {}
base_dir = os.path.dirname(os.path.abspath(__file__))
output_file=os.path.join(base_dir,"current_output")
log_file=os.path.join(base_dir, "log")
log_level='info'


sql_conn=''
sql_file=''

verbose_level = 2

	# 0: quiet
	# 1: info, normal
	# 2: Statistical table
	# 3: debug
	# 4: ?
	# 5: ?

# This is to assure that the first time we run, something is shown
temp = datetime.datetime.now()
delta = datetime.timedelta(seconds=5)
last_show_time = temp - delta

# defaults to 1 hour
client_timeout = 14400 

sort_type = 'Status'

# By default in the same directory
pemfile = os.path.join(base_dir,'server.pem')
cafile = os.path.join(base_dir,'ca.pem')
# End of global variables


# Print version information and exit
def version():
  print "+----------------------------------------------------------------------+"
  print "| dnmap_server Version "+ vernum +"                                             |"
  print "| This program is free software; you can redistribute it and/or modify |"
  print "| it under the terms of the GNU General Public License as published by |"
  print "| the Free Software Foundation; either version 2 of the License, or    |"
  print "| (at your option) any later version.                                  |"
  print "|                                                                      |"
  print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
  print "| www.mateslab.com.ar                                                  |"
  print "+----------------------------------------------------------------------+"
  print


# Print help information and exit:
def usage():
  print "+----------------------------------------------------------------------+"
  print "| dnmap_server Version "+ vernum +"                                             |"
  print "| This program is free software; you can redistribute it and/or modify |"
  print "| it under the terms of the GNU General Public License as published by |"
  print "| the Free Software Foundation; either version 2 of the License, or    |"
  print "| (at your option) any later version.                                  |"
  print "|                                                                      |"
  print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
  print "| www.mateslab.com.ar                                                  |"
  print "+----------------------------------------------------------------------+"
  print "\nusage: %s <options>" % sys.argv[0]
  print "options:"
  print "  -f, --nmap-commands        Nmap commands file"
  print "  -p, --port        TCP port where we listen for connections."
  print "  -L, --log-file        Log file. Defaults to /var/log/dnmap_server.conf."
  print "  -l, --log-level       Log level. Defaults to info."
  print "  -v, --verbose_level         Verbose level. Give a number between 1 and 5. Defaults to 1. Level 0 means be quiet."
  print "  -t, --client-timeout         How many time should we wait before marking a client Offline. We still remember its values just in case it cames back."
  print "  -s, --sort         	Field to sort the statical value. You can choose from: Alias, #Commands, UpTime, RunCmdXMin, AvrCmdXMin, Status"
  print "  -P, --pemfile         pem file to use for TLS connection. By default we use the server.pem file provided with the server in the current directory."
  print
  print "dnmap_server uses a \'<nmap-commands-file-name>.dnmaptrace\' file to know where it must continue reading the nmap commands file. If you want to start over again,"
  print "just delete the \'<nmap-commands-file-name>.dnmaptrace\' file"
  print
  sys.exit(1)


def timeout_idle_clients():
	"""
	This function search for idle clients and mark them as offline, so we do not display them
	"""
	global mlog
	global verbose_level
	global clients
	global client_timeout
	try:

		for client_id in clients:
			now = datetime.datetime.now()
			time_diff = now - clients[client_id]['LastTime']
			if time_diff.seconds >= client_timeout:
				clients[client_id]['Status']='Offline'


	except Exception as inst:
		if verbose_level > 2:
			msgline = 'Problem in mark_as_idle function'
			mlog.error(msgline)
			print msgline
			msgline = type(inst)
			mlog.error(msgline)
			print msgline
			msgline = inst.args
			mlog.error(msgline)
			print msgline
			msgline = inst
			mlog.error(msgline)
			print msgline



def read_file_and_fill_nmap_variable():
	""" Here we fill the nmap_command with the lines of the txt file. Only the first time. Later this file should be filled automatically"""
	global nmap_commands_file
	global nmap_command
	global trace_file
	global file_position
	global mlog
	global verbose_level
	global sql_conn
	global sql_file	
	
	with open(nmap_commands_file,'r') as f:
		jobs = f.readlines()

	#make sure all jobs in file are in queue
	for job in jobs:
		if not job in nmap_command:
			nmap_command.insert(0,job)
			mlog.debug('New Job: {0}'.format(job))

	#clear queue of things not in jobs file
	for job in nmap_command:
		if not job in jobs:
			nmap_command.remove(job)
	return

def verifyCallback(connection, x509, errnum, errdepth, ok):
	if not ok:
		print "Invalid cert from subject: ",x509.get_subject()
		return False
	else:
		return True


class ServerContextFactory:
	global mlog
	global verbose_level
	global pemfile
	global cafile
	""" Only to set up SSL"""
	def getContext(self):
		"""
		Create an SSL context.
		"""
		
		try:
			ctx = SSL.Context(SSL.SSLv23_METHOD)
			ctx.use_certificate_file(pemfile)
			ctx.use_privatekey_file(pemfile)
		except:
			print "Unexpected error:", sys.exc_info()[0]
			print 'You need to have a server.pem file for the server to work'
			print pemfile
			exit(-1)
		try:
			ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verifyCallback)
			ctx.load_verify_locations(cafile)
		except:
			print "Unexpected error:", sys.exc_info()[0]
			print 'You need to have a ca.pem file for the server to work'
			print cafile
			exit(-1)
		return ctx



def show_info():
	global verbose_level
	global mlog
	global clients
	global last_show_time
	global start_time
	global sort_type
	global output_file

	of = open(output_file, "w")
	try:
		now = datetime.datetime.now()
		diff_time = now - start_time

		amount = 0
		for j in clients:
			if clients[j]['Status'] != 'Offline':
				amount += 1

		if verbose_level > 0:
			line = '=| MET:{0} | Amount of Online clients: {1} |='.format(diff_time, amount)
			print line
			mlog.debug(line)
			of.write(line+"\n")

		if clients != {}:
			if verbose_level > 1:
				line = 'Clients connected'
				print line
				mlog.debug(line)
				of.write(line+"\n")
				line = '-----------------'
				print line
				mlog.debug(line)
				of.write(line+"\n")
				#line = 'Alias\t#Commands\tLast Time Seen\t\t\tVersion\tIsRoot\tStatus'
				line = '{0:15}\t{1}\t{2}\t{3}\t{4}\t\t{5}\t{6}\t{7}\t{8}\t{9}'.format('Alias','#Commands','Last Time Seen', '(time ago)', 'UpTime', 'Version', 'IsRoot', 'RunCmdXMin', 'AvrCmdXMin', 'Status')
				print line
				mlog.debug(line)
				of.write(line+"\n")
				for i in clients:
					if clients[i]['Status'] != 'Offline':
						# Strip the name of the day and the year
						temp = clients[i]['LastTime'].ctime().split(' ')[1:-1]
						lasttime = ''
						for j in temp:
							lasttime = lasttime + str(j) + ' '

						time_diff = datetime.datetime.now() - clients[i]['LastTime']
						#time_diff_secs = int(time_diff.total_seconds() % 60)
						#time_diff_secs = int(time_diff.seconds % 60)
						time_diff_secs = int( (time_diff.seconds + (time_diff.microseconds / 1000000.0) ) % 60)
						#time_diff_mins = int(time_diff.total_seconds() / 60)
						#time_diff_mins = int(time_diff.seconds / 60)
						time_diff_mins = int(  (time_diff.seconds + (time_diff.microseconds / 1000000.0) ) / 60)
						uptime_diff = datetime.datetime.now() - clients[i]['FirstTime']
						#uptime_diff_hours = int(uptime_diff.total_seconds() / 3600)
						#uptime_diff_hours = int(uptime_diff.seconds / 3600)
						uptime_diff_hours = int( (uptime_diff.seconds + (uptime_diff.microseconds / 1000000.0)) / 3600)
						#uptime_diff_mins = int(uptime_diff.total_seconds() % 3600 / 60)
						#uptime_diff_mins = int(uptime_diff.seconds % 3600 / 60)
						uptime_diff_mins = int( ((uptime_diff.seconds % 3600) + (uptime_diff.microseconds / 1000000.0)) / 60)

						line = '{0:15}\t{1}\t\t{2}({3:2d}\'{4:2d}\")\t{5:2d}h{6:2d}m\t\t{7}\t{8}\t{9:10.1f}\t{10:9.1f}\t{11}'.format(clients[i]['Alias'], clients[i]['NbrCommands'], lasttime, time_diff_mins, time_diff_secs, uptime_diff_hours, uptime_diff_mins , clients[i]['Version'], clients[i]['IsRoot'], clients[i]['RunCmdsxMin'], clients[i]['AvrCmdsxMin'], clients[i]['Status'])
						print line
						mlog.debug(line)
						of.write(line+"\n")

			print
			last_show_time = datetime.datetime.now()
		of.close()
	except Exception as inst:
		if verbose_level > 2:
			msgline = 'Problem in show_info function'
			mlog.error(msgline)
			print msgline
			msgline = type(inst)
			mlog.error(msgline)
			print msgline
			msgline = inst.args
			mlog.error(msgline)
			print msgline
			msgline = inst
			mlog.error(msgline)
			print msgline
	


def send_one_more_command(ourtransport,client_id):
	# Extract the next command to send.
	global nmap_command
	global verbose_level
	global mlog
	global clients
	global nmap_commands_file
	global trace_file

	try:
		alias = clients[client_id]['Alias']

		command_to_send = nmap_command.pop()

		line = 'Data sent to client ID '+client_id+' ('+alias+')'
		log.msg(line, logLevel=logging.INFO)
		if verbose_level > 2:
			print line
		line= '\t'+command_to_send.strip('\n')
		log.msg(line, logLevel=logging.INFO)
		if verbose_level > 2:
			print line
		ourtransport.transport.write(command_to_send)

		#remove the cmd from the pending job file and add to trace file
		with open(nmap_commands_file, "r") as f:
			jobs = f.readlines()
		jobs.remove(command_to_send)
		with open(nmap_commands_file, "w") as f:
			f.writelines(jobs)

		#add to tracefile
		with open(trace_file, "a+") as f:
			f.writelines(command_to_send)

		clients[client_id]['NbrCommands'] += 1
		clients[client_id]['LastCommand'] = command_to_send
		clients[client_id]['Status'] = 'Executing'

	except IndexError:
		# If the list of commands is empty, look for new commands
		line = 'No more commands in queue.'
		log.msg(line, logLevel=logging.DEBUG)
		if verbose_level > 2:
			print line
		line = '\tMaking the client '+str(client_id)+' ('+str(alias)+')'+' wait 10 secs for new commands to arrive...'
		log.msg(line, logLevel=logging.DEBUG)
		if verbose_level > 2:
			print line
		ourtransport.transport.write('Wait:10')
	except Exception as inst:
		print 'Problem in Send More Commands'
		print type(inst)
		print inst.args
		print inst





def process_input_line(data,ourtransport,client_id):
	global mlog
	global verbose_level
	global clients
	global trace_file
	global nmap_command
	global nmap_output_coming_back
	global nmap_output_file
	global xml_output_file
	global gnmap_output_file
	global outputswitch
	try:
		# What to do. Send another command or store the nmap output?
		if 'Starts the Client ID:' in data:
			# No more nmap lines coming back
			if nmap_output_coming_back:
				nmap_output_coming_back = False

			alias = data.split(':')[3].strip('\n').strip('\r').strip(' ')
			try:
				client_version = data.split(':')[5].strip('\n').strip('\r').strip(' ')
				client_isroot = 'False' if data.split(':')[7].strip('\n').strip('\r').strip(' ') == 0 else 'True'
			except IndexError:
				# It is an old version and it is not sending these data
				client_version = '0.1?'
				client_isroot = '?'

			try:
				# Do we have it yet?
				value = clients[client_id]['Alias']
				# Yes
			except KeyError:
				# No
				clients[client_id] = {}
				clients[client_id]['Alias'] = alias
				clients[client_id]['FirstTime'] = datetime.datetime.now()
				clients[client_id]['LastTime'] = datetime.datetime.now()
				clients[client_id]['NbrCommands'] = 0
				clients[client_id]['Status'] = 'Online'
				clients[client_id]['LastCommand'] = ''
				clients[client_id]['Version'] = client_version
				clients[client_id]['IsRoot'] = client_isroot
				clients[client_id]['RunCmdsxMin'] = 0
				clients[client_id]['AvrCmdsxMin'] = 0

			msgline = 'Client ID connected: {0} ({1})'.format(str(client_id),str(alias))
			log.msg(msgline, logLevel=logging.INFO)
			if verbose_level > 1:
				print '+ '+msgline

		elif 'Send more commands' in data:
			alias = clients[client_id]['Alias']
			
			clients[client_id]['Status'] = 'Online'
			#nowtime = datetime.datetime.now().ctime()
			nowtime = datetime.datetime.now()
			clients[client_id]['LastTime'] = nowtime

			# No more nmap lines coming back
			if nmap_output_coming_back:
				nmap_output_coming_back = False

			send_one_more_command(ourtransport,client_id)


		elif 'Nmap Output File' in data and not nmap_output_coming_back:
			# Nmap output start to come back...
			nmap_output_coming_back = True
			outputswitch=0
			alias = clients[client_id]['Alias']


			clients[client_id]['Status'] = 'Online'

			# compute the commands per hour
			# 1 more command. Time is between lasttimeseen and now
			time_since_cmd_start = datetime.datetime.now() - clients[client_id]['LastTime']

			# Cummulative average
			prev_ca = clients[client_id]['AvrCmdsxMin']
			#commandsXsec = ( time_since_cmd_start.total_seconds() + (clients[client_id]['NbrCommands'] * prev_ca) ) / ( clients[client_id]['NbrCommands'] + 1 )
			#clients[client_id]['RunCmdsxMin'] =  cmds_per_min = 60 / time_since_cmd_start.total_seconds()
			clients[client_id]['RunCmdsxMin'] =  60 / ( time_since_cmd_start.seconds + ( time_since_cmd_start.microseconds / 1000000.0))
			
			clients[client_id]['AvrCmdsxMin'] = ( clients[client_id]['RunCmdsxMin'] + (clients[client_id]['NbrCommands'] * prev_ca) ) / ( clients[client_id]['NbrCommands'] + 1 )

			# update the lasttime
			nowtime = datetime.datetime.now()
			clients[client_id]['LastTime'] = nowtime


			# Create the dir
			os.system('mkdir %s/nmap_results > /dev/null 2>&1'%base_dir)

			# Get the output file from the data
			# We strip \n. 
			filename = data.split(':')[1].strip('\n')
			xml_output_file = "%s/nmap_results/%s.xml"%(base_dir, filename)
			nmap_output_file = "%s/nmap_results/%s.nmap"%(base_dir, filename)
			gnmap_output_file = "%s/nmap_results/%s.gnmap"%(base_dir, filename)
			if verbose_level > 2:
				log.msg('\tNmap output file is: {0}'.format(nmap_output_file), logLevel=logging.DEBUG)

			clientline = 'Client ID:'+client_id+':Alias:'+alias+"\n"
			with open(nmap_output_file, 'a+') as f:
				f.writelines(clientline)
			with open(xml_output_file, 'a+') as f:
				f.writelines(clientline)
			with open(gnmap_output_file, 'a+') as f:
				f.writelines(clientline)

		elif nmap_output_coming_back and 'Nmap Output Finished' not in data:
			# Store the output to a file.
			alias = clients[client_id]['Alias']
			clients[client_id]['Status'] = 'Storing'
			#nowtime = datetime.datetime.now().ctime()
			nowtime = datetime.datetime.now()
			clients[client_id]['LastTime'] = nowtime
			#print data
			if "#XMLOUTPUT#" in data:
				outputswitch=1
				
			elif "#GNMAPOUTPUT#" in data:
				outputswitch=2
				
			else:
				if outputswitch==0:
					with open(nmap_output_file, 'a+') as f:
						f.writelines(data+'\n')
					
				elif outputswitch==1:
					with open(xml_output_file, 'a+') as f:
						f.writelines(data+'\n')
					
				elif outputswitch==2:
					with open(gnmap_output_file, 'a+') as f:
						f.writelines(data+'\n')
					

			log.msg('\tStoring nmap output for client {0} ({1}).'.format(client_id, alias), logLevel=logging.DEBUG)


				
		elif 'Nmap Output Finished' in data and nmap_output_coming_back:
			# Nmap output finished
			nmap_output_coming_back = False

			alias = clients[client_id]['Alias']

			clients[client_id]['Status'] = 'Online'
			#nowtime = datetime.datetime.now().ctime()
			nowtime = datetime.datetime.now()
			clients[client_id]['LastTime'] = nowtime
		
			# Store the finished nmap command in the file, so we can retrieve it if we need...
			finished_nmap_command = clients[client_id]['LastCommand']
			clients[client_id]['LastCommand'] = ''

			#clear out the trace file
			with open(trace_file, 'r') as f:
				running_jobs = f.readlines()
			running_jobs.remove(finished_nmap_command)
			with open(trace_file, 'w') as f:
				f.writelines(running_jobs)


			if verbose_level > 2:
				print '+ Storing command {0} in trace file.'.format(finished_nmap_command.strip('\n').strip('\r'))
			outputswitch=0

	except Exception as inst:
		print 'Problem in process input lines'
		print type(inst)
		print inst.args
		print inst

class NmapServerProtocol(Protocol):
	""" This is the function that communicates with the client """
	global mlog
	global verbose_level
	global clients
	global nmap_command
	global mlog

	def connectionMade(self):
		if verbose_level > 0:
			pass

	def connectionLost(self, reason):
		peerHost = self.transport.getPeer().host
		peerPort = str(self.transport.getPeer().port)
		client_id = peerHost+':'+peerPort
		try:
			alias = clients[client_id]['Alias']
		except:
			msgline = 'No client found in list with id {0}. Moving on...'.format(client_id)
			log.msg(msgline, logLevel=logging.INFO)
			return 0

		clients[client_id]['Status'] = 'Offline'
		command_to_redo = clients[client_id]['LastCommand']
		if command_to_redo != '':
			#readd to job file and queue
			nmap_command.append(command_to_redo)
			with open(nmap_commands_file, "a+") as f:
				f.writelines(command_to_redo)

			#clear out the trace file
			with open(trace_file, 'r') as f:
				running_jobs = f.readlines()
			running_jobs.remove(command_to_redo)
			with open(trace_file, 'w') as f:
				f.writelines(running_jobs)

		if verbose_level > 1:
			msgline = 'Connection lost in the protocol. Reason:{0}'.format(reason)
			msgline2 = '+ Connection lost for {0} ({1}).'.format(alias, client_id)
			log.msg(msgline, logLevel=logging.DEBUG)
			print msgline2

		if verbose_level > 2:
			print 'Re inserting command: {0}'.format(command_to_redo)


	def dataReceived(self, newdata):
		#global client_id

		data = newdata.strip('\r').strip('\n').split('\r\n')

		peerHost = self.transport.getPeer().host
		peerPort = str(self.transport.getPeer().port)
		client_id = peerHost+':'+peerPort

		# If you need to debug
		if verbose_level > 2:
			log.msg('Data recived', logLevel=logging.DEBUG)
			log.msg(data, logLevel=logging.DEBUG)
			print '+ Data received: {0}'.format(data)

		for line in data:
			process_input_line(line,self,client_id)


def sql_import_loop():
	global sql_file
	global sql_conn
	global mlog
	tree=""

	#Process all files in the nmap_results directory
	path = "%s/nmap_results/"%base_dir
	newpath="%s/nmap_results/processed/"%base_dir
	try:
		os.stat(path)
		os.stat(newpath)
	except:
		os.mkdir(path)
		os.mkdir(newpath)
	output_files = os.listdir("%s/nmap_results/"%base_dir)
	scan_id=""

	for ofile in output_files:
		complete=path+ofile
		if os.path.isfile(complete):
			if ofile.endswith(".xml"):
				try:
					scan_id=ofile.split(".xml")[0]
					log.msg("XML File Found: %s"%scan_id, logLevel=logging.INFO)
					#take off the first line first, then pass to parser
					xmlf = open(complete, "r")
					data = xmlf.read()
					xmlf.close()
					lines = data.split("\n")
					log.msg("Importing %s.xml from: %s"%(scan_id,lines[0]), logLevel=logging.INFO)
					xmldata = "".join(lines[1:])
					tree = ET.fromstring(xmldata)
				except:
					log.msg(sys.exc_info()[0], logLevel=logging.DEBUG)
					raise
			os.rename(complete, newpath+ofile)

	#connect the DB
	sql_conn=sqlite3.connect(sql_file)
	c = sql_conn.cursor()
	if len(tree)>0:
		#get info about the scan
		s_version = tree.get("version")
		s_summary=""
		if not tree.find("runstats").find("finished") == None:
			s_summary = tree.find("runstats").find("finished").get("summary")
		i=(s_version, s_summary,True,scan_id,)
		c.execute('UPDATE scans_scan SET version=?, summary=?, finished=? WHERE id=?', i)
		sql_conn.commit()
		sql_conn.close()




def process_nmap_commands(logger_name):
	""" Main function. Here we set up the environment, factory and port """
	global nmap_commands_file
	global nmap_command
	global port
	global mlog
	global verbose_level
	global client_timeout

	observer = log.PythonLoggingObserver(logger_name)
	observer.start()

	# Create the factory
	factory = Factory()
	factory.protocol = NmapServerProtocol

	# Create the time based print
	loop = task.LoopingCall(show_info)
	loop.start(5) 

	# Create the time based file read
	loop2 = task.LoopingCall(read_file_and_fill_nmap_variable)
	loop2.start(1)

	# To mark idel clients as hold
	loop3 = task.LoopingCall(timeout_idle_clients)
	loop3.start(client_timeout) # call every second

	if not sql_file =="":
		loop4 = task.LoopingCall(sql_import_loop)
		loop4.start(5)

	# Create the reactor
	reactor.listenSSL(port, factory, ServerContextFactory())
	reactor.run()



def main():
	global nmap_commands_file
	global port
	global log_file
	global log_level
	global mlog
	global verbose_level
	global start_time
	global client_timeout
	global sort_type
	global pemfile
	global cafile
	global sql_file
	global output_file
	global trace_file

	start_time = datetime.datetime.now()

	try:
		opts, args = getopt.getopt(sys.argv[1:], "f:l:L:p:P:c:s:t:v:S:o:", ["nmap-commands=","log-level=","log-server=","port=","pemfile=", "ca-file=","sort-type=","client-timeout=","verbose-level=", "sqlite-file=", "output-file"])
	except getopt.GetoptError: usage()

	for opt, arg in opts:
	    if opt in ("-f", "--nmap-commands"): nmap_commands_file=str(arg)
	    if opt in ("-p", "--port"): port=int(arg)
	    if opt in ("-l", "--log-level"): log_level=arg
	    if opt in ("-L", "--log-file"): log_file=arg
	    if opt in ("-v", "--verbose-level"): verbose_level=int(arg)
	    if opt in ("-t", "--client-timeout"): client_timeout=int(arg)
	    if opt in ("-s", "--sort-type"): sort_type=str(arg)
	    if opt in ("-P", "--pemfile"): pemfile=str(arg)
	    if opt in ("-c", "--ca-file"): cafile=str(arg)
	    if opt in ("-S", "--sqlite-file"): sql_file=str(arg)
	    if opt in ("-o", "--output-file"): output_file=str(arg)

	print "Base Dir: %s"%base_dir
	try:
		# Verify that we have a pem file
		try:
			temp = os.stat(pemfile)
			temp2 = os.stat(cafile)
		except OSError:
			print 'No pem or cert file given. Use -P or -c'
			exit(-1)


		if nmap_commands_file != '':
			if verbose_level > 0:
				version()

			# Set up logger
			# Set up a specific logger with our desired output level
			logger_name = 'MyLogger'
			mlog = logging.getLogger(logger_name)

			# Set up the log level
			numeric_level = getattr(logging, log_level.upper(), None)
			if not isinstance(numeric_level, int):
				raise ValueError('Invalid log level: %s' % loglevel)
			mlog.setLevel(numeric_level)

			# Add the log message handler to the logger
			handler = logging.handlers.RotatingFileHandler(log_file, backupCount=5)

			formater = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
			handler.setFormatter(formater)
			mlog.addHandler(handler)

			# End logger
			#Get any leftover jobs and populate into jobs/queue
			trace_file = nmap_commands_file+'.dnmaptrace'
			with open(trace_file,'r') as f:
				leftover=f.readlines()
			with open(nmap_commands_file, 'r') as f:
				curjobs=f.readlines()
			for ljob in leftover:
				if ljob not in curjobs:
					with open(nmap_commands_file, 'a+') as f:
						f.writelines(ljob)

			#clear trace file
			with open(trace_file,'w') as f:
				f.write("")

			# First fill the variable from the file
			read_file_and_fill_nmap_variable()

			# Start processing clients
			process_nmap_commands(logger_name)

		else:
			usage()


	except KeyboardInterrupt:
		# CTRL-C pretty handling.
		print "Keyboard Interruption!. Exiting."
		sys.exit(1)


if __name__ == '__main__':
    main()
