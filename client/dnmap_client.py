#! /usr/bin/env python
#  
# DNmap Client - Edited by Justin Warner (@sixdub). Originally written by Sebastian Garcia
# Orginal Copyright and license (included below) applies. 
#
# This is the client code to be used in conjunction with Minions.
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

try:
	from OpenSSL import SSL
except:
	print 'You need openssl libs for python. apt-get install python-openssl'
	exit(-1)

import sys

try:
	from twisted.internet.protocol import ClientFactory, ReconnectingClientFactory
	from twisted.protocols.basic import LineReceiver
	from twisted.internet import ssl, reactor
except:
	print 'You need twisted libs for python. apt-get install python-twisted'
	exit(-1)


import time, getopt, shlex
from subprocess import Popen
from subprocess import PIPE
import os
import random

# Global variables
server_ip = False
server_port = 46001 
vernum = '0.6'
# Your name alias defaults to anonymous
alias='Anonymous'
debug=False
# Do not use a max rate by default
maxrate = False

base_dir = os.path.dirname(os.path.abspath(__file__))
pemfile = os.path.join(base_dir,'client.pem')
# End global variables


# Print version information and exit
def version():
  print "+----------------------------------------------------------------------+"
  print "| dnmap Client Version "+ vernum +"                                             |"
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
  print "| dnmap Client Version "+ vernum +"                                             |"
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
  print "  -s, --server-ip        IP address of dnmap server."
  print "  -p, --server-port      Port of dnmap server. Dnmap port defaults to 46001"
  print "  -a, --alias      Your name alias so we can give credit to you for your help. Optional"
  print "  -d, --debug      Debuging."
  print "  -m, --max-rate      Force nmaps commands to use at most this rate. Useful to slow nmap down. Adds the --max-rate parameter."
  print "  -P, --pemfile		The client certificate to be used. Must be signed by CA cert used by server"
  print
  sys.exit(1)



def check_clean(line):
	global debug
	try:
		outbound_chars = [';', '#', '`']
		ret = True
		for char in outbound_chars:
			if char in line:
				ret = False
		return ret

	except Exception as inst:
		print 'Problem in dataReceived function'
		print type(inst)
		print inst.args
		print inst





class NmapClient(LineReceiver):
	def connectionMade(self):
		global client_id
		global alias
		global debug
		print 'Client connected succesfully...'
		print 'Waiting for more commands....'
		if debug:
			print ' -- Your client ID is: {0} , and your alias is: {1}'.format(str(client_id), str(alias))

		euid = os.geteuid()

		# Do not send the euid, just tell if we are root or not.
		if euid==0:
			# True
			iamroot = 1
		else:
			# False
			iamroot = 0

		# 'Client ID' text must be sent to receive another command
		line = 'Starts the Client ID:{0}:Alias:{1}:Version:{2}:ImRoot:{3}'.format(str(client_id),str(alias),vernum,iamroot)
		if debug:
			print ' -- Line sent: {0}'.format(line)
		self.sendLine(line)

		#line = 'Send more commands to Client ID:{0}:Alias:{1}:\0'.format(str(client_id),str(alias))
		line = 'Send more commands'
		if debug:
			print ' -- Line sent: {0}'.format(line)
		self.sendLine(line)

	

	def dataReceived(self, line):
		global debug
		global client_id
		global alias


		# If a wait is received. just wait.
		if 'Wait' in line:
			sleeptime = int(line.split(':')[1])
			time.sleep(sleeptime)

			# Ask for more
			#line = 'Send more commands to Client ID:{0}:Alias:{1}:'.format(str(client_id),str(alias))
			line = 'Send more commands'
			if debug:
				print ' -- Line sent: {0}'.format(line)
			self.sendLine(line)
		else:
			# dataReceived does not wait for end of lines or CR nor LF
			if debug:
				print "\tCommand Received: {0}".format(line.strip('\n').strip('\r'))
		
			# A little bit of protection from the server
			if check_clean(line):
				# Store the nmap output file so we can send it to the server later
				try:
					nmap_output_file = line.split('-oA ')[1].split(' ')[0].strip(' ').strip("\n")
				except IndexError:
					random_file_name = str(random.randrange(0, 100000000, 1))
					print '+ No -oA given. We add it anyway so not to lose the results. Added -oA '+random_file_name
					line = line + '-oA '+random_file_name
					nmap_output_file = line.split('-oA ')[1].split(' ')[0].strip(' ').strip("\n")


				try:
					nmap_returncode = -1

					# Check for rate commands
					# Verfiy that the server is NOT trying to force us to be faster. NMAP PARAMETER DEPENDACE
					if 'min-rate' in line:
						temp_vect = shlex.split(line)
						word_index = temp_vect.index('--min-rate')
						# Just delete the --min-rate parameter with its value
						nmap_command = temp_vect[0:word_index] + temp_vect[word_index + 1:]
					else:
						nmap_command = shlex.split(line)

					# Do we have to add a max-rate parameter?
					if maxrate:
						nmap_command.append('--max-rate')
						nmap_command.append(str((maxrate)))

					# Strip the command, so we can controll that only nmap is executed really
					nmap_command = nmap_command[1:]
					nmap_command.insert(0,'nmap')

					# Recreate the final command to show it
					nmap_command_string = ''
					for i in nmap_command:
						nmap_command_string = nmap_command_string + i + ' '
					print "\tCommand Executed: {0}".format(nmap_command_string)


					# For some reason this executable thing does not work! seems to change nmap sP for sS
					#nmap_process = Popen(nmap_command,executable='nmap',stdout=PIPE)

					nmap_process = Popen(nmap_command,stdout=PIPE)
					raw_nmap_output = nmap_process.communicate()[0]
					nmap_returncode = nmap_process.returncode
					
				except OSError:
					print 'You don\'t have nmap installed. You can install it with apt-get install nmap'
					exit(-1)

				except ValueError:
					raw_nmap_output = 'Invalid nmap arguments.'
					print raw_nmap_output


				except Exception as inst:
					print 'Problem in dataReceived function'
					print type(inst)
					print inst.args
					print inst



				if nmap_returncode >= 0:
					# Nmap ended ok and the files were created
					if os.path.isfile(nmap_output_file+".xml") and os.path.isfile(nmap_output_file+".gnmap") and os.path.isfile(nmap_output_file+".nmap"):
						with open(nmap_output_file+".xml","r") as f:
							XMLData=f.read()
						with open(nmap_output_file+".gnmap","r") as f:
							GNmapData=f.read()
						with open(nmap_output_file+".nmap","r") as f:
							NmapData=f.read()

						xml_linesep="\r\n#XMLOUTPUT#\r\n"
						gnmap_linesep="\r\n#GNMAPOUTPUT#\r\n"
						# Tell the server that we are sending the nmap output
						print '\tSending output to the server...'
						line = 'Nmap Output File:{0}:'.format(nmap_output_file.strip('\n').strip('\r'))
						if debug:
							print ' -- Line sent: {0}'.format(line)
						self.sendLine(line)
						line =raw_nmap_output+xml_linesep+XMLData+gnmap_linesep+GNmapData
						self.sendLine(line)
						if debug:
							print ' -- Line sent: {0}'.format(line)
						line = 'Nmap Output Finished:{0}:'.format(nmap_output_file.strip('\n').strip('\r'))
						if debug:
							print ' -- Line sent: {0}'.format(line)
						self.sendLine(line)

						# Move nmap output files to its directory
						os.system('mv *.nmap nmap_output > /dev/null 2>&1')
						os.system('mv *.gnmap nmap_output > /dev/null 2>&1')
						os.system('mv *.xml nmap_output > /dev/null 2>&1')

						# Ask for another command.
						# 'Client ID' text must be sent to receive another command
						print 'Waiting for more commands....'
						#line = 'Send more commands to Client ID:{0}:Alias:{1}:'.format(str(client_id),str(alias))
						line = 'Send more commands'
						if debug:
							print ' -- Line sent: {0}'.format(line)
						self.sendLine(line)
			else:
				# Something strange was sent to us...
				print
				print 'WARNING! Ignoring some strange command was sent to us: {0}'.format(line)
				line = 'Send more commands'
				if debug:
					print ' -- Line sent: {0}'.format(line)
				self.sendLine(line)




class NmapClientFactory(ReconnectingClientFactory):
	try:
		protocol = NmapClient

		def startedConnecting(self, connector):
			print 'Starting connection...'

		def clientConnectionFailed(self, connector, reason):
			print 'Connection failed:', reason.getErrorMessage()
			# Try to reconnect
			print 'Trying to reconnect. Please wait...'
			ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

		def clientConnectionLost(self, connector, reason):
			print 'Connection lost. Reason: {0}'.format(reason.getErrorMessage())
			# Try to reconnect
			print 'Trying to reconnect in 10 secs. Please wait...'
			ReconnectingClientFactory.clientConnectionLost(self, connector, reason)
	except Exception as inst:
		print 'Problem in NmapClientFactory'
		print type(inst)
		print inst.args
		print inst

class CtxFactory(ssl.ClientContextFactory):
	def getContext(self):
		self.method = SSL.SSLv23_METHOD
		ctx = ssl.ClientContextFactory.getContext(self)
		
		try:
			ctx.use_certificate_file(pemfile)
			ctx.use_privatekey_file(pemfile)
		except:
			print 'You need to have a client.pem'

		return ctx



def process_commands():
	global server_ip
	global server_port
	global client_id
	global factory
	try:

		print 'Client Started...'

		# Generate the client unique ID
		client_id = str(random.randrange(0, 100000000, 1))

		# Create the output directory
		print 'Nmap output files stored in \'nmap_output\' directory...'
		os.system('mkdir nmap_output > /dev/null 2>&1')

		factory = NmapClientFactory()
		# Do not wait more that 10 seconds between reconnections
		factory.maxDelay = 10

		reactor.connectSSL(str(server_ip), int(server_port), factory, CtxFactory())
		#reactor.addSystemEventTrigger('before','shutdown',myCleanUpFunction)
		reactor.run()
	except Exception as inst:
		print 'Problem in process_commands function'
		print type(inst)
		print inst.args
		print inst



def main():
	global server_ip
	global server_port
	global alias
	global debug
	global maxrate
	global pemfile

	try:
		opts, args = getopt.getopt(sys.argv[1:], "a:dm:p:s:P:", ["server-ip=","server-port","max-rate","alias=","debug","pemfile="])
	except getopt.GetoptError: usage()

	for opt, arg in opts:
		if opt in ("-s", "--server-ip"): server_ip=str(arg)
		if opt in ("-p", "--server-port"): server_port=arg
		if opt in ("-a", "--alias"): alias=str(arg).strip('\n').strip('\r').strip(' ')
		if opt in ("-d", "--debug"): debug=True
		if opt in ("-m", "--max-rate"): maxrate=str(arg)
		if opt in ("-P", "--pemfile"): pemfile=str(arg)
	try:
		temp = os.stat(pemfile)
	except OSError:
		print 'No pem file given. Use -P '
		exit(-1)
	try:

		if server_ip and server_port:

			version()

			# Start connecting
			process_commands()

		else:
			usage()


	except KeyboardInterrupt:
		# CTRL-C pretty handling.
		print "Keyboard Interruption!. Exiting."
		sys.exit(1)


if __name__ == '__main__':
	main()
