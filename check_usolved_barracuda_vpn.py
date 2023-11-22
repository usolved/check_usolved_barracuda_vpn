#!/usr/bin/env python3

'''
This Python Nagios/Icinga plugin checks the state of vpn tunnels of Barracuda firewalls.
Python 3 is required with use of the libraries sys, os and optparse

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
v1.2 2023-11-22
Upgrade to python3
Feature: Added filtering for IPSEC-v2 tunnels. A tunnel will be reported down if child tunnels are not exitent or down.

v1.1 2016-02-17
Added parameter -A to show tunnel names in the extended output. Default is just number of active/down tunnel.

v1.0 2016-02-09
Initial release
'''


import sys
import os
import optparse
import re

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
parser.add_option('-E', '--vpntunnel_exclude', 	help='Optional: Comma separated tunnel names to exclude from check', dest='arg_vpntunnel_exclude', type='string')
parser.add_option('-A', '--show_complete_name', help='Optional: Show complete VPN tunnel names in the extended output. Typ \"-A yes\" as argument', dest='arg_show_complete_name', type='string')
parser.add_option('-T', '--timeout', 			help='Optional: SNMP timeout in seconds', dest='arg_timeout', type='int', default=30)
(opts, args) = parser.parse_args()

arg_hostname 			= opts.arg_hostname
arg_snmp_community		= opts.arg_snmp_community
arg_snmp_version		= opts.arg_snmp_version
arg_vpntunnel			= opts.arg_vpntunnel
arg_vpntunnel_exclude	= opts.arg_vpntunnel_exclude
arg_show_complete_name	= opts.arg_show_complete_name
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
	print(return_msg)
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

	for status,name in zip(vpn_status, vpn_name):
		# -1, 0 and 1 are all known status codes. If no of these are found the snmp service probably isn't running
		if not status in ['-1','0','1']:
			return_msg = 'OK - VPN service inactive or no VPN tunnel configured'
			output_nagios(return_msg,'', return_code['OK'])

		# check for excluded and included tunnel names and append tunnel with status to dictionary
		if check_excluded(name) and (tunnels_include == 'ALL' or check_included(name)):
			vpn_tunnels.append({'name': name, 'status': status})

	return vpn_tunnels


# Check the state of the tunnels and return appropriate status code and generate output message
def check_vpn_tunnel_state(vpn_tunnels):

	global return_msg

	return_key 						= 'OK'
	return_msg_tmp					= ''
	return_msg_extended_active_tmp	= ''
	return_msg_extended_down_tmp	= ''

	# Loop through all tunnels and evaluate the state
	tunnel_count 		= 0
	tunnel_count_active = 0
	tunnel_count_down 	= 0

	vpn_tunnels = find_children(vpn_tunnels)

	for vpn_tunnel in vpn_tunnels:

		# Check tunnel has key children. If yes, check if one or more tunnels are down.
		if "children" in vpn_tunnel.keys():
			# If no children are found, set parent to down
			if len(vpn_tunnel["children"]) == 0:
				vpn_tunnel["status"] = '-1'
			for child in vpn_tunnel["children"]:
			# If one child is down, set parent to down
				if child["status"] in ['0','-1']:
					vpn_tunnel["status"] = '-1'
				else:
					vpn_tunnel["status"] = '1'

		if vpn_tunnel['status'] == '0':
			return_msg_tmp 					+= vpn_tunnel['name'] + ' (down-disabled), '
			return_msg_extended_down_tmp 	+= '\n' + vpn_tunnel['name'] + ' (down-disabled)'
			return_key 						= 'CRITICAL'
			tunnel_count_down 				+= 1
		elif vpn_tunnel['status'] == '-1':
			return_msg_tmp 					+= vpn_tunnel['name'] + ' (down), '
			return_msg_extended_down_tmp 	+= '\n' + vpn_tunnel['name'] + ' (down)'
			return_key 						= 'CRITICAL'
			tunnel_count_down 				+= 1
		else:
			return_msg_extended_active_tmp += '\n' + vpn_tunnel['name'] + ' (active)'
			tunnel_count_active += 1

		tunnel_count += 1

	return_msg_tmp = return_msg_tmp[:-2]

	# Show info for critical state
	if return_key == 'CRITICAL':

		if arg_show_complete_name == 'yes':
			return_msg_extended = return_msg_extended_down_tmp + return_msg_extended_active_tmp
		else:
			return_msg_extended = '\n' + str(tunnel_count_active) + ' VPN tunnel up / ' + str(tunnel_count_down) + ' VPN tunnel down: ' + return_msg_extended_down_tmp

		return_msg = 'Critical - ' + return_msg_tmp + return_msg_extended

	# Show info for ok state
	else:
		if not return_msg_extended_active_tmp:
			return_msg_extended_active_tmp = '\nNo VPN tunnel found'

		if arg_show_complete_name == 'yes':
			return_msg_extended = return_msg_extended_active_tmp
		else:
			return_msg_extended = ''

		return_msg = 'OK - '+ str(tunnel_count) +' VPN tunnel active' + return_msg_extended


	return return_code[return_key]

def find_children(vpn_tunnels):
	# Find children of VPN Tunnel with the format: VPN_TUNNEL_NAME{12345}
	children = []
	for tunnel in vpn_tunnels:
		if re.match(r".*\{\d+\}", tunnel['name']):
			children.append(tunnel)

	# Remove children form original list
	if children:
		for child in children:
			vpn_tunnels.remove(child)

	# Add children to original tunnel
		i = 0
		while i < len(vpn_tunnels):
			tunnel = vpn_tunnels[i]
			# If Parent is in format IPSEC-v2, add children dict and find children
			if re.match(r"IPSEC-v2-.*", tunnel["name"]):
				tunnel["children"] = []
				for child in children:
					if tunnel["name"] in child["name"]:
						tunnel["children"].append(child)
				for child in tunnel["children"]:
					children.remove(child)
				vpn_tunnels[i] = tunnel
			i+=1
	return vpn_tunnels


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
