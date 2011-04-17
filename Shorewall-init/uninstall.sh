\#!/bin/sh
#
# Script to back uninstall Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010 - Tom Eastep (teastep@shorewall.net)
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
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#    Usage:
#
#       You may only use this script to uninstall the version
#       shown below. Simply run this script to remove Shorewall Firewall

VERSION=4.4.20-Beta1

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME"
    exit $1
}

qt()
{
    "$@" >/dev/null 2>&1
}

remove_file() # $1 = file to restore
{
    if [ -f $1 -o -L $1 ] ; then
	rm -f $1
	echo "$1 Removed"
    fi
}

if [ -f /usr/share/shorewall-init/version ]; then
    INSTALLED_VERSION="$(cat /usr/share/shorewall-init/version)"
    if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
	echo "WARNING: Shorewall Init Version $INSTALLED_VERSION is installed"
	echo "         and this is the $VERSION uninstaller."
	VERSION="$INSTALLED_VERSION"
    fi
else
    echo "WARNING: Shorewall Init Version $VERSION is not installed"
    VERSION=""
fi

[ -n "${LIBEXEC:=/usr/share}" ]

echo "Uninstalling Shorewall Init $VERSION"

INITSCRIPT=/etc/init.d/shorewall-init

if [ -n "$INITSCRIPT" ]; then
    if [ -x /usr/sbin/updaterc.d ]; then
	updaterc.d shorewall-init remove
    elif [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
        insserv -r $INITSCRIPT
    elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	chkconfig --del $(basename $INITSCRIPT)
    else
	rm -f /etc/rc*.d/*$(basename $INITSCRIPT)
    fi

    remove_file $INITSCRIPT
fi

[ "$(readlink -m -q /sbin/ifup-local)"   = /usr/share/shorewall-init ] && remove_file /sbin/ifup-local
[ "$(readlink -m -q /sbin/ifdown-local)" = /usr/share/shorewall-init ] && remove_file /sbin/ifdown-local

remove_file /etc/default/shorewall-init
remove_file /etc/sysconfig/shorewall-init

remove_file /etc/NetworkManager/dispatcher.d/01-shorewall

remove_file /etc/network/if-up.d/shorewall
remove_file /etc/network/if-down.d/shorewall

remove_file /etc/sysconfig/network/if-up.d/shorewall
remove_file /etc/sysconfig/network/if-down.d/shorewall

if [ -d /etc/ppp ]; then
    for directory in ip-up.d ip-down.d ipv6-up.d ipv6-down.d; do
	remove_file /etc/ppp/$directory/shorewall
    done

    for file in if-up.local if-down.local; do
	if fgrep -q Shorewall-based /etc/ppp/$FILE; then
	    remove_file /etc/ppp/$FILE
	fi
    done
fi

rm -rf /usr/share/shorewall-init
rm -rf ${LIBEXEC}/shorewall-init

echo "Shorewall Init Uninstalled"


