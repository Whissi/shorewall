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
#	   shorewall6-lite start			  Starts the firewall
#	   shorewall6-lite restart		  Restarts the firewall
#	   shorewall6-lite reload		  Reload the firewall
#						  (same as restart)
#	   shorewall6-lite stop			  Stops the firewall
#	   shorewall6-lite status		  Displays firewall status
#

# description: Packet filtering firewall

# openwrt stuph
# start and stop runlevel variable
START=50
STOP=89
# variable to display what the status command do when /etc/init.d/shorewall6-lite is invoke without argument
EXTRA_COMMANDS="status"
EXTRA_HELP="status displays shorewall status"

################################################################################
# Get startup options (override default)
################################################################################
OPTIONS=

#
# The installer may alter this
#
. /usr/share/shorewall/shorewallrc

if [ -f ${SYSCONFDIR}/$PRODUCT ]; then
    . ${SYSCONFDIR}/$PRODUCT
fi

SHOREWALL_INIT_SCRIPT=1

################################################################################
# E X E C U T I O N    B E G I N S   H E R E				       #
################################################################################
# arg1 of init script is arg2 when rc.common is sourced; set to action variable
command="$action"

start() {
	exec ${SBINDIR}/shorewall6-lite $OPTIONS $command $STARTOPTIONS
}

boot() {
local command="start"
start
}

restart() {
	exec ${SBINDIR}/shorewall6-lite $OPTIONS $command $RESTARTOPTIONS
}

reload() {
	exec ${SBINDIR}/shorewall6-lite $OPTIONS $command $RELOADOPTION
}

stop() {
	exec ${SBINDIR}/shorewall6-lite $OPTIONS $command $STOPOPTIONS
}

status() {
	exec ${SBINDIR}/shorewall6-lite $OPTIONS $command $STATUSOPTIONS
}
