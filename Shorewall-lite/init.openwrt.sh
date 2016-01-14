#!/bin/sh /etc/rc.common
#
#     The Shoreline Firewall (Shorewall) Packet Filtering Firewall - V4.5
#
#     (c) 1999,2000,2001,2002,2003,2004,2005,2006,2007,2012,2014 - Tom Eastep (teastep@shorewall.net)
#     (c) 2015 - Matt Darfeuille - (matdarf@gmail.com)
#
#	On most distributions, this file should be called /etc/init.d/shorewall.
#
#	Complete documentation is available at http://shorewall.net
#
#       This program is part of Shorewall.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by the
#       Free Software Foundation, either version 2 of the license or, at your
#       option, any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, see <http://www.gnu.org/licenses/>.
#
#	If an error occurs while starting or restarting the firewall, the
#	firewall is automatically stopped.
#
#	Commands are:
#
#	   shorewall-lite start			  Starts the firewall
#	   shorewall-lite restart		  Restarts the firewall
#	   shorewall-lite reload		  Reload the firewall
#	   shorewall-lite stop			  Stops the firewall
#	   shorewall-lite status		  Displays firewall status
#

# description: Packet filtering firewall

# Openwrt related
# Start and stop runlevel variable
START=50
STOP=89
# Displays the status command
EXTRA_COMMANDS="status"
EXTRA_HELP=" status Displays firewall status"

################################################################################
# Get startup options (override default)
################################################################################
OPTIONS=

#
# The installer may alter this
#
. /usr/share/shorewall/shorewallrc

if [ -f ${SYSCONFDIR}/shorewall-lite ]; then
    . ${SYSCONFDIR}/shorewall-lite
fi

SHOREWALL_INIT_SCRIPT=1

################################################################################
# E X E C U T I O N    B E G I N S   H E R E				       #
################################################################################
# Arg1 of init script is arg2 when rc.common is sourced; set to action variable
command="$action"

start() {
	exec ${SBINDIR}/shorewall-lite $OPTIONS $command $STARTOPTIONS
}

boot() {
	local command="start"
	start
}

restart() {
	exec ${SBINDIR}/shorewall-lite $OPTIONS $command $RESTARTOPTIONS
}

reload() {
	exec ${SBINDIR}/shorewall-lite $OPTIONS $command $RELOADOPTION
}

stop() {
	exec ${SBINDIR}/shorewall-lite $OPTIONS $command $STOPOPTIONS
}

status() {
	exec ${SBINDIR}/shorewall-lite $OPTIONS $command $@
}
