#!/bin/sh
#
# Script to back uninstall Shoreline Firewall
#
#     (c) 2000-2014 - Tom Eastep (teastep@shorewall.net)
#
#       Shorewall documentation is available at http://shorewall.sourceforge.net
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
#    Usage:
#
#       You may only use this script to uninstall the version
#       shown below. Simply run this script to remove Shorewall Firewall

VERSION=xxx  #The Build script inserts the actual version

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME [ <shorewallrc file> ]"
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

finished=0
configure=1

while [ $finished -eq 0 ]; do
    option=$1

    case "$option" in
	-*)
	    option=${option#-}

	    while [ -n "$option" ]; do
		case $option in
		    h)
			usage 0
			;;
		    v)
			echo "$Product Firewall Installer Version $VERSION"
			exit 0
			;;
		    n*)
			configure=0
			option=${option#n}
			;;
		    *)
			usage 1
			;;
		esac
	    done

	    shift
	    ;;
	*)
	    finished=1
	    ;;
    esac
done
#
# Read the RC file
#
if [ $# -eq 0 ]; then
    if [ -f ./shorewallrc ]; then
	. ./shorewallrc
    elif [ -f ~/.shorewallrc ]; then
	. ~/.shorewallrc || exit 1
	file=./.shorewallrc
    elif [ -f /usr/share/shorewall/shorewallrc ]; then
	. /usr/share/shorewall/shorewallrc
    else
	fatal_error "No configuration file specified and /usr/share/shorewall/shorewallrc not found"
    fi
elif [ $# -eq 1 ]; then
    file=$1
    case $file in
	/*|.*)
	    ;;
	*)
	    file=./$file
	    ;;
    esac

    . $file || exit 1
else
    usage 1
fi

if [ -f ${SHAREDIR}/shorewall-init/version ]; then
    INSTALLED_VERSION="$(cat ${SHAREDIR}/shorewall-init/version)"
    if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
	echo "WARNING: Shorewall Init Version $INSTALLED_VERSION is installed"
	echo "         and this is the $VERSION uninstaller."
	VERSION="$INSTALLED_VERSION"
    fi
else
    echo "WARNING: Shorewall Init Version $VERSION is not installed"
    VERSION=""
fi

[ -n "${LIBEXEC:=${SHAREDIR}}" ]

echo "Uninstalling Shorewall Init $VERSION"

[ -n "$SANDBOX" ] && configure=0

INITSCRIPT=${CONFDIR}/init.d/shorewall-init

if [ -f "$INITSCRIPT" ]; then
    if [ $configure -eq 1 ]; then
	if mywhich updaterc.d ; then
	    updaterc.d shorewall-init remove
	elif mywhich insserv ; then
            insserv -r $INITSCRIPT
	elif mywhich chkconfig ; then
	    chkconfig --del $(basename $INITSCRIPT)
	fi
    fi

    remove_file $INITSCRIPT
fi

if [ -n "$SYSTEMD" ]; then
    [ $configure -eq 1 ] && systemctl disable shorewall-init.service
    rm -f $SYSTEMD/shorewall-init.service
fi

[ "$(readlink -m -q ${SBINDIR}/ifup-local)"   = ${SHAREDIR}/shorewall-init ] && remove_file ${SBINDIR}/ifup-local
[ "$(readlink -m -q ${SBINDIR}/ifdown-local)" = ${SHAREDIR}/shorewall-init ] && remove_file ${SBINDIR}/ifdown-local

remove_file ${CONFDIR}/default/shorewall-init
remove_file ${CONFDIR}/sysconfig/shorewall-init

remove_file ${CONFDIR}/NetworkManager/dispatcher.d/01-shorewall

remove_file ${CONFDIR}/network/if-up.d/shorewall
remove_file ${CONFDIR}/network/if-down.d/shorewall
remove_file ${CONFDIR}/network/if-post-down.d/shorewall

remove_file ${CONFDIR}/sysconfig/network/if-up.d/shorewall
remove_file ${CONFDIR}/sysconfig/network/if-down.d/shorewall

[ -n "$SYSTEMD" ] && remove_file ${SYSTEMD}/shorewall.service

if [ -d ${CONFDIR}/ppp ]; then
    for directory in ip-up.d ip-down.d ipv6-up.d ipv6-down.d; do
	remove_file ${CONFDIR}/ppp/$directory/shorewall
    done

    for file in if-up.local if-down.local; do
	if grep -qF Shorewall-based ${CONFDIR}/ppp/$FILE; then
	    remove_file ${CONFDIR}/ppp/$FILE
	fi
    done
fi

rm -f  ${SHAREDIR}/shorewall-init
rm -rf ${SHAREDIR}/shorewall-init
rm -rf ${LIBEXECDIR}/shorewall-init

echo "Shorewall Init Uninstalled"


