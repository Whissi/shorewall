#!/bin/sh
#
# Script to back uninstall Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000-2011 - Tom Eastep (teastep@shorewall.net)
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

VERSION=xxx  #The Build script inserts the actual version

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

split() {
    local ifs
    ifs=$IFS
    IFS=:
    set -- $1
    echo $*
    IFS=$ifs
}

mywhich() {
    local dir

    for dir in $(split $PATH); do
	if [ -x $dir/$1 ]; then
	    return 0
	fi
    done

    return 2
}

remove_file() # $1 = file to restore
{
    if [ -f $1 -o -L $1 ] ; then
	rm -f $1
	echo "$1 Removed"
    fi
}

if [ -f ~/.shorewallrc ]; then
    . ~/shorewallrc || exit 1
else
    [ -n "${LIBEXEC:=/usr/share}" ]
    [ -n "${PERLLIB:=/usr/share/shorewall}" ]
    [ -n "${CONFDIR:=/etc}" ]
    
    if [ -z "$SYSCONFDIR" ]; then
	if [ -d /etc/default ]; then
	    SYSCONFDIR=/etc/default
	else
	    SYSCONFDIR=/etc/sysconfig
	fi
    fi

    [ -n "${SBINDIR:=/sbin}" ]
    [ -n "${SHAREDIR:=/usr/share}" ]
    [ -n "${VARDIR:=/var/lib}" ]
    [ -n "${INITFILE:=shorewall}" ]
    [ -n "${INITDIR:=/etc/init.d}" ]
    [ -n "${MANDIR:=/usr/share/man}" ]
fi

if [ -f ${SHAREDIR}/shorewall-lite/version ]; then
    INSTALLED_VERSION="$(cat ${SHAREDIR}/shorewall-lite/version)"
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

if qt iptables -L shorewall -n && [ ! -f ${SBINDIR}/shorewall ]; then
   shorewall-lite clear
fi

if [ -L ${SHAREDIR}/shorewall-lite/init ]; then
    FIREWALL=$(readlink -m -q ${SHAREDIR}/shorewall-lite/init)
elIF [ -n "$INITFILE" ]; then
    FIREWALL=${INITDIR}/${INITFILE}
fi

if [ -f "$FIREWALL" ]; then
    if mywhich updaterc.d ; then
	updaterc.d shorewall-lite remove
    elif if mywhich insserv ; then
        insserv -r $FIREWALL
    elif [ mywhich chkconfig ; then
	chkconfig --del $(basename $FIREWALL)
    elif mywhich systemctl ; then
	systemctl disable shorewall-lite
    fi

    remove_file $FIREWALL
fi

rm -f ${SBINDIR}/shorewall-lite

rm -rf ${SBINDIR}/shorewall-lite
rm -rf ${VARDIR}/shorewall-lite
rm -rf ${SHAREDIR}/shorewall-lite
rm -rf ${LIBEXEC}/shorewall-lite
rm -f  ${CONFDIR}/logrotate.d/shorewall-lite
[ -n "$SYSTEMD" ] && rm -f  ${SYSTEMD}/shorewall-lite.service

echo "Shorewall Lite Uninstalled"


