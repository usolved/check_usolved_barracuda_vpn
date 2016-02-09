#!/usr/bin/env python

'''
This Python Nagios/Icinga plugin checks the state of vpn tunnels of Barracuda firewalls.
Python 2 is required with use of the libraries sys, os and optparse

Copyright (c) 2016 www.usolved.net 
Published under https://github.com/usolved/check_usolved_barracuda_vpn

The MIT License (MIT)
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

------------------------

v1.0 2016-02-09
Initial release
'''


import sys
import os
import optparse


######################################################################
# Definitions of variables

# Arrays for return codes and return message
return_code 	= { 'OK': 0, 'WARNING': 1, 'CRITICAL': 2, 'UNKNOWN': 3 }
return_msg 		= ''
return_perfdata = ''

# Define the oids to check
snmp_oid_vpnname		= '.1.3.6.1.4.1.10704.1.6.1.1';
snmp_oid_vpnstate		= '.1.3.6.1.4.1.10704.1.6.1.2';

# Define the binaries for snmpwalk and snmpget
cmd = {
	'SNMP_Walk': '/usr/bin/snmpwalk',
	'SNMP_Get': '/usr/bin/snmpget'
}


# Parse arguments
parser 		= optparse.OptionParser()
parser.add_option('-H', '--hostname', 			help='Required: IP or hostname of the Barracuda firewall', dest='arg_hostname', type='string')
parser.add_option('-c', '--snmp_community', 	help='Required: SNMP community string', dest='arg_snmp_community', type='string', default='public')
parser.add_option('-v', '--snmp_version', 		help='Optional: SNMP version (currently only snmp 1 and 2 supported)', dest='arg_snmp_version', type='string', default='2c')
parser.add_option('-V', '--vpntunnel', 			help='Optional: Tunnel name to check. If not given, all tunnels will be checked', dest='arg_vpntunnel', type='string')
parser.add_option('-E', '--vpntunnel_exclude', 	help='Optional: Comma separated tunnel names to exclude from check.', dest='arg_vpntunnel_exclude', type='string')
parser.add_option('-T', '--timeout', 			help='Optional: SNMP timeout in seconds', dest='arg_timeout', type='int', default=30)
(opts, args) = parser.parse_args()

arg_hostname 			= opts.arg_hostname
arg_snmp_community		= opts.arg_snmp_community
arg_snmp_version		= opts.arg_snmp_version
arg_vpntunnel			= opts.arg_vpntunnel
arg_vpntunnel_exclude	= opts.arg_vpntunnel_exclude
arg_timeout				= opts.arg_timeout

# Ignore tunnels with the name "PERS-"" and "PGRP-"
if arg_vpntunnel_exclude:
	arg_vpntunnel_exclude = 'PERS-,PGRP-,' + arg_vpntunnel_exclude
	tunnels_exclude = arg_vpntunnel_exclude.strip().split(',')
else:
	tunnels_exclude = 'PERS-,PGRP-'.split(',')


if arg_vpntunnel:
	tunnels_include = arg_vpntunnel.strip().split(',')
else:
	tunnels_include = 'ALL'



######################################################################
# Functions

# Outputs the string for nagios and return with the appropriate exit code
def output_nagios(return_msg, return_perfdata, return_code):
	print return_msg
	sys.exit(return_code)

# Execute shell commands
def get_cmd_execute(cmdline):

	cmd_return 			= []
	cmdline_return 		= os.popen(cmdline)

	# Read every line from the snmpwalk and save it to a dictionary
	for line in cmdline_return.readlines():
		cmd_return.append(line.rstrip().replace('"',''))

	cmdline_return_code = cmdline_return.close()
	return cmd_return

# Ignore the tunnel from the check that are excluded
def check_excluded(vpn_name):

	global tunnels_exclude

	for tunnels_exclude_name in tunnels_exclude:

		if tunnels_exclude_name in vpn_name:
			return False

	return True

# Just check the tunnels that match this argument
def check_included(vpn_name):

	global tunnels_include

	for tunnels_include_name in tunnels_include:

		if tunnels_include_name in vpn_name:
			return True

	return False

# Get all tunnels and save them to a dictionary
def get_vpn_tunnel():

	global tunnels_include

	cmdline 		= cmd['SNMP_Walk']+' -v '+arg_snmp_version+' -c '+arg_snmp_community+' -OqevtU -t '+ str(arg_timeout) +' '+arg_hostname

	# read snmp info for every vpn tunnel
	vpn_name 	= get_cmd_execute(cmdline+' '+snmp_oid_vpnname)
	vpn_status 	= get_cmd_execute(cmdline+' '+snmp_oid_vpnstate)


	# put the returned data into a dictionary to have the data in context
	vpn_tunnels 	= []


	# handle issue if the number of results from snmpwalk differ for name and status
	if len(vpn_name) != len(vpn_status):
		return_msg = 'UNKNOWN - VPN status and tunnel name list don\'t match. Maybe there\'s a line break in the tunnel name. Try to specify a tunnel with argument -V'
		output_nagios(return_msg,'', return_code['UNKNOWN'])		

	i = 0
	while i < len(vpn_name):
		# -1, 0 and 1 are all known status codes. If no of these are found the snmp service probably isn't running
		if vpn_status[i] != '-1' and vpn_status[i] != '0' and vpn_status[i] != '1':
			return_msg = 'OK - But snmp service is not active on this box'
			output_nagios(return_msg,'', return_code['OK'])			

		# check for excluded and included tunnel names and append tunnel with status to dictionary
		if check_excluded(vpn_name[i]) and (tunnels_include == 'ALL' or check_included(vpn_name[i])):
			tmp_dict 	= {'name': vpn_name[i], 'status': vpn_status[i]}

			vpn_tunnels.append(tmp_dict)
		
		i += 1

	return vpn_tunnels


# Check the state of the tunnels and return appropriate status code and generate output message
def check_vpn_tunnel_state(vpn_tunnels):

	global return_msg

	return_key 				= 'OK'
	return_msg_tmp			= ''
	return_msg_extended_tmp	= ''

	# Loop through all tunnels and evaluate the state
	for vpn_tunnel in vpn_tunnels:

		if vpn_tunnel['status'] == '0':
			return_msg_tmp += vpn_tunnel['name'] + ' (down-disabled), '
			return_key 				= 'CRITICAL'
		elif vpn_tunnel['status'] == '-1':
			return_msg_tmp += vpn_tunnel['name'] + ' (down), '
			return_key 				= 'CRITICAL'
		else:
			return_msg_extended_tmp += '\n' + vpn_tunnel['name'] + ' (active)'

	return_msg_tmp = return_msg_tmp[:-2]


	if return_key == 'CRITICAL':
		return_msg = 'Critical - ' + return_msg_tmp + return_msg_extended_tmp
	else:
		if not return_msg_extended_tmp:
			return_msg_extended_tmp = '\nNo vpn tunnels found'
		
		return_msg = 'OK - All tunnels are ok' + return_msg_extended_tmp


	return return_code[return_key]



######################################################################
# General

if not arg_hostname or not arg_snmp_community:
	return_msg = 'Unknown - Not all arguments given\nType ./'+os.path.basename(__file__)+' --help for all options.'
	output_nagios(return_msg,'',return_code['UNKNOWN'])

else:
	vpn_tunnels 	= get_vpn_tunnel()
	return_status 	= check_vpn_tunnel_state(vpn_tunnels)

	# output for nagios
	output_nagios(return_msg, return_perfdata, return_status)
