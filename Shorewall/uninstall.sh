#!/bin/sh
#
# Script to back uninstall Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]         
#
#     (c) 2000,2001,2002 - Tom Eastep (teastep@shorewall.net)
#
#       Shorewall documentation is available at http://shorewall.sourceforge.net
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
#       You may only use this script to uninstall the version
#       shown below. Simply run this script to remove Seattle Firewall

VERSION=1.3.2

usage() # $1 = exit status
{
    ME=`basename $0`
    echo "usage: $ME"
    exit $1
}

restore_file() # $1 = file to restore
{
    if [ -f ${1}-shorewall.bkout ]; then
	if (mv -f ${1}-shorewall.bkout $1); then
	    echo
	    echo "$1 restored"
        else
	    exit 1
        fi
    fi	
}

remove_file() # $1 = file to restore
{
    if [ -f $1 -o -L $1 ] ; then
	rm -f $1
	echo "$1 Removed"
    fi
}

if [ -f /etc/shorewall/version ]; then
    INSTALLED_VERSION="`cat /etc/shorewall/version`"
    if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
	echo "WARNING: Shoreline Firewall Version $INSTALLED_VERSION is installed"
	echo "         and this is the $VERSION uninstaller."
	VERSION="$INSTALLED_VERSION"
    fi
else
    echo "WARNING: Shoreline Firewall Version $VERSION is not installed"
    VERSION=""
fi

echo "Uninstalling Shoreline Firewall $VERSION"

if [ -L /etc/shorewall/firewall ]; then
    FIREWALL=`ls -l /etc/shorewall/firewall | sed 's/^.*> //'`

    if [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
        insserv -r $FIREWALL
    elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	chkconfig --del `basename $FIREWALL`
    fi

    remove_file $FIREWALL
fi

remove_file /sbin/shorewall

if [ -n "$VERSION" ]; then
    restore_file /etc/rc.d/rc.local
    remove_file /etc/shorewall/shorewall.conf-${VERSION}.bkout
    remove_file /etc/shorewall/zones-${VERSION}.bkout
    remove_file /etc/shorewall/policy-${VERSION}.bkout
    remove_file /etc/shorewall/interfaces-${VERSION}.bkout
    remove_file /etc/shorewall/rules-${VERSION}.bkout
    remove_file /etc/shorewall/nat-${VERSION}.bkout
    remove_file /etc/shorewall/params-${VERSION}.bkout
    remove_file /etc/shorewall/proxyarp-${VERSION}.bkout
    remove_file /etc/shorewall/masq-${VERSION}.bkout
    remove_file /etc/shorewall/version-${VERSION}.bkout
    remove_file /etc/shorewall/functions-${VERSION}.bkout
    remove_file /etc/shorewall/common.def-${VERSION}.bkout
    remove_file /etc/shorewall/icmp.def-${VERSION}.bkout
    remove_file /etc/shorewall/tunnels-${VERSION}.bkout
    remove_file /etc/shorewall/tcrules-${VERSION}.bkout
    remove_file /etc/shorewall/tos-${VERSION}.bkout
    remove_file /etc/shorewall/modules-${VERSION}.bkout
    remove_file /etc/shorewall/blacklist-${VERSION}.bkout
    remove_file /etc/shorewall/whitelist-${VERSION}.bkout
    remove_file /etc/shorewall/rfc1918-${VERSION}.bkout
fi

remove_file /etc/shorewall/firewall

remove_file /etc/shorewall/functions

remove_file /etc/shorewall/common.def

remove_file /etc/shorewall/icmp.def

remove_file /etc/shorewall/zones

remove_file /etc/shorewall/policy

remove_file /etc/shorewall/interfaces
    
remove_file /etc/shorewall/hosts

remove_file /etc/shorewall/rules

remove_file /etc/shorewall/nat

remove_file /etc/shorewall/params

remove_file /etc/shorewall/proxyarp

remove_file /etc/shorewall/masq
    
remove_file /etc/shorewall/modules
    
remove_file /etc/shorewall/tcrules

remove_file /etc/shorewall/tos

remove_file /etc/shorewall/tunnels

remove_file /etc/shorewall/blacklist

remove_file /etc/shorewall/whitelist

remove_file /etc/shorewall/rfc1918

remove_file /etc/shorewall/shorewall.conf

remove_file /etc/shorewall/version

rmdir /etc/shorewall

echo "Shoreline Firewall Uninstalled"


