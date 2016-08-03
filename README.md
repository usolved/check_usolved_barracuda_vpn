# check_usolved_barracuda_vpn

## Overview

This Python Nagios/Icinga plugin checks the vpn tunnel state of Barracuda firewalls.
If the vpn tunnel has the state down or disabled you'll be informed.

You can check all vpn tunnel by default or include/exclude specific ones.

## Authors

Ricardo Klement ([www.usolved.net](http://usolved.net))

## Installation

Just copy the file check_usolved_barracuda_vpn.py into your Nagios plugin directory.
For example this path: /usr/local/nagios/libexec/

Set execution rights on check_usolved_barracuda_vpn.py for the nagios user.
This plugin needs Python 2 to be installed and uses the libraries sys, os and optparse.

Why not Python 3 you may ask?
Most Nagios / Icinga installations are already using other plugins which are written in Python 2.
So for compatibility reasons I've decided to use Python 2 as well.

Make sure you've enabled the SNMP service on your Barracuda firewall. If you have a cluster it's good to 
configure the SNMP service on the virtual server layer on your Barracuda.
Details to find [here](https://techlib.barracuda.com/display/BNGv54/How+to+Configure+the+SNMP+Service).

I've tested the plugin on Barracuda appliances F100b, F200b, F200c, F600c and F800b.

## Usage

### Test on command line
If you are in the Nagios plugin directory execute this command:

```
./check_usolved_barracuda_vpn.py -H ip_address_of_barracuda -c snmp_community
```

The output could be something like this:

```
OK - All tunnels are ok
FW2FW-TEST-VPN1 (active)
FW2FW-TEST-VPN2 (active)
FW2FW-TEST-VPN3 (active)
```

Here are all arguments that can be used within this plugin:

```
-H <host address>
Required: IP or hostname of the Barracuda firewall node with a running snmp service

[-c <snmp community>]
Required: SNMP Community String

[-v <snmp version>]
Optional: SNMP version 1 or 2c are supported, if argument not given version 2 is used by default

[-V <include vpn tunnel>]
Optional: Tunnel name to check. If not given, all tunnels will be checked

[-E <exclude vpn tunnel>]
Optional: Comma separated tunnel names to exclude from check

[-T <timeout>]
Optional: SNMP timeout in seconds. Default is 30 seconds.
```

### Install in Nagios

Edit your **commands.cfg** and add the following.

Example for checking all vpn tunnel states:

```
define command {
    command_name    check_usolved_barracuda_vpn
    command_line    $USER1$/check_usolved_barracuda_vpn.py -H $HOSTADDRESS$ -c public
}
```

Example for checking a vpn tunnel containing the name "Test-VPN" and exclude tunnels with "Spain" and "Italy":

```
define command {
    command_name    check_usolved_barracuda_vpn
    command_line    $USER1$/check_usolved_barracuda_vpn.py -H $HOSTADDRESS$ -c $ARG1$ -V Test-VPN -E Spain,Italy
}
```

Edit your **services.cfg** and add the following.

Example for checking all vpn tunnel states:

```
define service{
	host_name				Test-Server
	service_description		Barracuda-VPN
	use						generic-service
	check_command			check_usolved_barracuda_vpn!public
}
```


You could also use host macros for the snmp community.

## What's new

v1.1 2016-02-17
Added parameter -A to show tunnel names in the extended output. Default is just number of active/down tunnel.

v1.0 2016-02-09
Initial release
