#!/bin/sh
#
# Script to back uninstall Shoreline Firewall 6
#
#     (c) 2000-2011,2014 - Tom Eastep (teastep@shorewall.net)
#
#       Shorewall documentation is available at http://www.shorewall.net
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

VERSION=xxx #The Build script inserts the actual version
PRODUCT=shorewall6

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME [ <shorewallrc file> ]"
    exit $1
}

fatal_error()
{
    echo "   ERROR: $@" >&2
    exit 1
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

    . $file
else
    usage 1
fi

if [ -f ${SHAREDIR}/shorewall6/version ]; then
    INSTALLED_VERSION="$(cat ${SHAREDIR}/shorewall6/version)"
    if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
	echo "WARNING: Shorewall6 Version $INSTALLED_VERSION is installed"
	echo "         and this is the $VERSION uninstaller."
	VERSION="$INSTALLED_VERSION"
    fi
else
    echo "WARNING: Shorewall6 Version $VERSION is not installed"
    VERSION=""
fi

echo "Uninstalling shorewall6 $VERSION"

[ -n "$SANDBOX" ] && configure=0

if [ $configure -eq 1 ]; then
    if qt ip6tables -L shorewall6 -n && [ ! -f ${SBINDIR}/shorewall6-lite ]; then
	${SBINDIR}/shorewall6 clear
    fi
fi

if [ -L ${SHAREDIR}/shorewall6/init ]; then
    FIREWALL=$(readlink -m -q ${SHAREDIR}/shorewall6/init)
elif [ -n "$INITFILE" ]; then
    FIREWALL=${INITDIR}/${INITFILE}
fi

if [ -f "$FIREWALL" ]; then
    if [ $configure -eq 1 ]; then
	if mywhich updaterc.d ; then
	    updaterc.d shorewall6 remove
	elif mywhich insserv ; then
            insserv -r $FIREWALL
	elif mywhich chkconfig ; then
	    chkconfig --del $(basename $FIREWALL)
	fi
    fi

    remove_file $FIREWALL
fi

if [ -n "$SYSTEMD" ]; then
    [ $configure -eq 1 ] && systemctl disable ${PRODUCT}
    rm -f $SYSTEMD/shorewall6.service
fi

rm -f ${SBINDIR}/shorewall6
rm -rf ${CONFDIR}/shorewall6
rm -rf ${VARDIR}/shorewall6
rm -rf ${LIBEXECDIR}/shorewall6
rm -rf ${SHAREDIR}/shorewall6

for f in ${MANDIR}/man5/shorewall6* ${SHAREDIR}/man/man8/shorewall6*; do
    case $f in
	shorewall6-lite*)
	    ;;
	*)
	    rm -f $f
    esac
done

rm -f  ${CONFDIR}/logrotate.d/shorewall6
[ -n "$SYSTEMD" ] && rm -f ${SYSTEMD}/shorewall6.service

echo "Shorewall6 Uninstalled"


