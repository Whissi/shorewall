#!/bin/sh
#
# Script to back out the installation of Shoreline Firewall and to restore the previous version of
# the program
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2001,2002,2003,2004 - Tom Eastep (teastep@shorewall.net)
#
#       Shorewall documentation is available at http://seattlefirewall.dyndns.org
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of Version 2 of the GNU General Public License
#       as published by the Free Software Foundation.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#
#    Usage:
#
#       You may only use this script to back out the installation of the version
#       shown below. Simply run this script to revert to your prior version of
#       Shoreline Firewall.

VERSION=2.0.0-Alpha2

usage() # $1 = exit status
{
    echo "usage: $(basename $0)"
    exit $1
}

restore_file() # $1 = file to restore
{
    if [ -f ${1}-${VERSION}.bkout -o -L ${1}-${VERSION}.bkout ]; then
	if (mv -f ${1}-${VERSION}.bkout $1); then
	    echo
	    echo "$1 restored"
        else
	    echo "ERROR: Could not restore $1"
	    exit 1
        fi
    fi
}

if [ ! -f /usr/share/shorewall2/version-${VERSION}.bkout ]; then
    echo "Shorewall Version $VERSION is not installed"
    exit 1
fi

echo "Backing Out Installation of Shorewall $VERSION"

if [ -L /usr/share/shorewall2/init ]; then
    FIREWALL=$(ls -l /usr/share/shorewall2/firewall | sed 's/^.*> //')
    restore_file $FIREWALL
else
    restore_file /etc/init.d/shorewall2
fi

restore_file /usr/share/shorewall2/firewall

restore_file /sbin/shorewall2

restore_file /etc/shorewall2/shorewall.conf

restore_file /etc/shorewall2/functions
restore_file /usr/lib/shorewall2/functions
restore_file /var/lib/shorewall2/functions
restore_file /usr/lib/shorewall2/firewall
restore_file /usr/lib/shorewall2/help

restore_file /etc/shorewall2/common.def

restore_file /etc/shorewall2/icmp.def

restore_file /etc/shorewall2/zones

restore_file /etc/shorewall2/policy

restore_file /etc/shorewall2/interfaces

restore_file /etc/shorewall2/hosts

restore_file /etc/shorewall2/rules

restore_file /etc/shorewall2/nat

restore_file /etc/shorewall2/params

restore_file /etc/shorewall2/proxyarp

restore_file /etc/shorewall2/routestopped

restore_file /etc/shorewall2/maclist

restore_file /etc/shorewall2/masq

restore_file /etc/shorewall2/modules

restore_file /etc/shorewall2/tcrules

restore_file /etc/shorewall2/tos

restore_file /etc/shorewall2/tunnels

restore_file /etc/shorewall2/blacklist

restore_file /etc/shorewall2/whitelist

restore_file /etc/shorewall2/rfc1918

restore_file /etc/shorewall2/init

restore_file /etc/shorewall2/start

restore_file /etc/shorewall2/stop

restore_file /etc/shorewall2/stopped

restore_file /etc/shorewall2/ecn

restore_file /etc/shorewall2/accounting

restore_file /etc/shorewall2/actions

for f in /etc/shorewall2/action.*-${VERSION}.bkout; do
    restore_file $(echo $f | sed "s/-${VERSION}.bkout//")
done

restore_file /usr/share/shorewall2/version

echo "Shorewall2 Restored to Version $oldversion"


