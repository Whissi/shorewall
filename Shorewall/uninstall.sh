#!/bin/sh
#
# Script to back uninstall Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010 - Tom Eastep (teastep@shorewall.net)
#
#       Shorewall documentation is available at http://www.shorewall.net
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

VERSION=4.4.19-Beta1

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

[ -n ${ETC:=/etc/} ]
[ -n ${SBIN:=/sbin/} ]
[ -n ${SHARE:=/usr/share/} ]
[ -n ${VAR:=/var/lib/} ]

case "$ETC" in
    */)
	;;
    *)
	ETC=$ETC/
	;;
esac

case "$SBIN" in
    */)
	;;
    *)
	SBIN=$SBIN/
	;;
esac

case "$SHARE" in
    */)
	;;
    *)
	SHARE=$SHARE/
	;;
esac

case "$VAR" in
    */)
	;;
    *)
	VAR=$VAR/
	;;
esac 

if [ -f ${SHARE}shorewall/version ]; then
    INSTALLED_VERSION="$(cat ${SHARE}shorewall/version)"
    if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
	echo "WARNING: Shorewall Version $INSTALLED_VERSION is installed"
	echo "         and this is the $VERSION uninstaller."
	VERSION="$INSTALLED_VERSION"
    fi
else
    echo "WARNING: Shorewall Version $VERSION is not installed"
    VERSION=""
fi

echo "Uninstalling shorewall $VERSION"

if [ `id -u` = 0 ] ; then
    if qt iptables -L shorewall -n && [ ! -f ${SBIN}shorewall-lite ]; then
	${SBIN}shorewall clear
    fi


    if [ -L ${SHARE}shorewall/init ]; then
	FIREWALL=$(readlink -m -q ${SHARE}shorewall/init)
    else
	FIREWALL=${ETC}init.d/shorewall
    fi

    if [ -n "$FIREWALL" -a -f "$FIREWALL" ]; then
	if [ -x /usr/sbin/updaterc.d ]; then
	    updaterc.d shorewall remove
	elif [ -x /usr/sbin/insserv -o -x /usr${SBIN}insserv ]; then
            insserv -r $FIREWALL
	elif [ -x /usr/sbin/chkconfig -o -x /usr${SBIN}chkconfig ]; then
	    chkconfig --del $(basename $FIREWALL)
	else
	    rm -f ${ETC}rc*.d/*$(basename $FIREWALL)
	fi

	remove_file $FIREWALL
	rm -f ${FIREWALL}-*.bkout
    fi
fi

rm -f ${SBIN}shorewall
rm -f ${SBIN}shorewall-*.bkout

rm -rf ${ETC}shorewall
rm -rf ${ETC}shorewall-*.bkout
rm -rf ${VAR}shorewall
rm -rf ${VAR}shorewall-*.bkout
rm -rf ${SHARE}shorewall
rm -rf ${SHARE}shorewall-*.bkout
rm -rf ${SHARE}man/man5/shorewall*
rm -rf ${SHARE}man/man8/shorewall*
rm -f  ${ETC}logrotate.d/shorewall

echo "Shorewall Uninstalled"


