#!/bin/sh
#
# Script to back uninstall Shoreline Firewall 6 Lite
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

VERSION=4.4.16-RC1

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

if [ -f /usr/share/shorewall6-lite/version ]; then
    INSTALLED_VERSION="$(cat /usr/share/shorewall6-lite/version)"
    if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
	echo "WARNING: Shorewall Lite Version $INSTALLED_VERSION is installed"
	echo "         and this is the $VERSION uninstaller."
	VERSION="$INSTALLED_VERSION"
    fi
else
    echo "WARNING: Shorewall Lite Version $VERSION is not installed"
    VERSION=""
fi

echo "Uninstalling Shorewall Lite $VERSION"

if qt ip6tables -L shorewall -n && [ ! -f /sbin/shorewall6 ]; then
   /sbin/shorewall6-lite clear
fi

if [ -L /usr/share/shorewall6-lite/init ]; then
    FIREWALL=$(readlink -m -q /usr/share/shorewall6-lite/init)
else
    FIREWALL=/etc/init.d/shorewall6-lite
fi

if [ -n "$FIREWALL" ]; then
    if [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
        insserv -r $FIREWALL
    elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	chkconfig --del $(basename $FIREWALL)
    else
	rm -f /etc/rc*.d/*$(basename $FIREWALL)
    fi

    remove_file $FIREWALL
    rm -f ${FIREWALL}-*.bkout
fi

rm -f /sbin/shorewall6-lite
rm -f /sbin/shorewall6-lite-*.bkout

rm -rf /etc/shorewall6-lite
rm -rf /etc/shorewall6-lite-*.bkout
rm -rf /var/lib/shorewall6-lite
rm -rf /var/lib/shorewall6-lite-*.bkout
rm -rf /usr/share/shorewall6-lite
rm -rf /usr/share/shorewall6-lite-*.bkout
rm -f  /etc/logrotate.d/shorewall6-lite

echo "Shorewall6 Lite Uninstalled"


