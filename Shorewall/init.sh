#!/bin/sh
RCDLINKS="2,S41 3,S41 6,K41"
#
#     The Shoreline Firewall (Shorewall) Packet Filtering Firewall - V1.4 3/14/2003
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 1999,2000,2001,2002,2003 - Tom Eastep (teastep@shorewall.net)
#
#	On most distributions, this file should be called:
#	/etc/rc.d/init.d/shorewall or /etc/init.d/shorewall
#
#	Complete documentation is available at http://shorewall.net
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of Version 2 of the GNU General Public License
#	as published by the Free Software Foundation.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#
#	If an error occurs while starting or restarting the firewall, the
#	firewall is automatically stopped.
#
#	Commands are:
#
#	   shorewall start			  Starts the firewall
#	   shorewall restart			  Restarts the firewall
#	   shorewall stop			  Stops the firewall
#	   shorewall status			  Displays firewall status
#
#### BEGIN INIT INFO
# Provides:	  shorewall
# Required-Start: $network
# Required-Stop:
# Default-Start:  2 3 5
# Default-Stop:	  0 1 6
# Description:	  starts and stops the shorewall firewall
### END INIT INFO

# chkconfig: 2345 25 90
# description: Packet filtering firewall
#

################################################################################
# Give Usage Information						       #
################################################################################
usage() {
    echo "Usage: $0 start|stop|restart|status"
    exit 1
}

################################################################################
# E X E C U T I O N    B E G I N S   H E R E				       #
################################################################################
command="$1"

case "$command" in

    stop|start|restart|status)

	exec /sbin/shorewall $@
	;;
    *)

	usage
	;;

esac
