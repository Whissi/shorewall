#!/bin/sh
#
# Script to back uninstall Shoreline Firewall
#
#     (c) 2000-2016 - Tom Eastep (teastep@shorewall.net)
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

VERSION=xxx # The Build script inserts the actual version

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME [ <option> ] [ <shorewallrc file> ]"
    echo "where <option> is one of"
    echo "  -h"
    echo "  -v"
    echo "  -n"
    exit $1
}

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

if [ -f shorewall.service ]; then
    PRODUCT=shorewall
    Product=Shorewall
else
    PRODUCT=shorewall6
    Product=Shorewall6
fi

#
# Source common functions
#
. ./lib.uninstaller || { echo "ERROR: Can not load common functions." >&2; exit 1; }

#
# Parse the run line
#
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
			echo "$Product Firewall Uninstaller Version $VERSION"
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
        . ./shorewallrc || fatal_error "Can not load the RC file: ./shorewallrc"
    elif [ -f ~/.shorewallrc ]; then
        . ~/.shorewallrc || fatal_error "Can not load the RC file: ~/.shorewallrc"
    elif [ -f /usr/share/shorewall/shorewallrc ]; then
        . /usr/share/shorewall/shorewallrc || fatal_error "Can not load the RC file: /usr/share/shorewall/shorewallrc"
    else
	fatal_error "No configuration file specified and /usr/share/shorewall/shorewallrc not found"
    fi
elif [ $# -eq 1 ]; then
    file=$1
    case $file in
	/*|.*)
	    ;;
	*)
	    file=./$file || exit 1
	    ;;
    esac

    . $file || fatal_error "Can not load the RC file: $file"
else
    usage 1
fi

if [ -f ${SHAREDIR}/$PRODUCT/version ]; then
    INSTALLED_VERSION="$(cat ${SHAREDIR}/$PRODUCT/version)"
    if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
	echo "WARNING: $Product Version $INSTALLED_VERSION is installed"
	echo "         and this is the $VERSION uninstaller."
	VERSION="$INSTALLED_VERSION"
    fi
else
    echo "WARNING: $Product Version $VERSION is not installed"
    VERSION=""
fi

echo "Uninstalling $Product $VERSION"

[ -n "$SANDBOX" ] && configure=0

if [ $configure -eq 1 ]; then
    if qt iptables -L shorewall -n && [ ! -f ${SBINDIR}/shorewall-lite ]; then
	${SBINDIR}/$PRODUCT clear
    elif qt ip6tables -L shorewall6 -n && [ ! -f ${SBINDIR}/shorewall6-lite ]; then
	${SBINDIR}/$PRODUCT clear
    fi
fi

remove_file ${SBINDIR}/$PRODUCT

if [ -L ${SHAREDIR}/$PRODUCT/init ]; then
    FIREWALL=$(readlink -m -q ${SHAREDIR}/$PRODUCT/init)
elif [ -n "$INITFILE" ]; then
    FIREWALL=${INITDIR}/${INITFILE}
fi

if [ -f "$FIREWALL" ]; then
    if [ $configure -eq 1 ]; then
	if mywhich insserv ; then
            insserv -r $FIREWALL
	elif mywhich update-rc.d ; then
	    update-rc.d ${PRODUCT} remove
	elif mywhich chkconfig ; then
	    chkconfig --del $(basename $FIREWALL)
	fi
    fi

    remove_file $FIREWALL
fi

[ -z "${SERVICEDIR}" ] && SERVICEDIR="$SYSTEMD"

if [ -n "$SERVICEDIR" ]; then
    [ $configure -eq 1 ] && systemctl disable ${PRODUCT}.service
    remove_file $SERVICEDIR/${PRODUCT}.service
fi

remove_file ${SHAREDIR}/$PRODUCT/version
remove_directory ${CONFDIR}/$PRODUCT

if [ -n "$SYSCONFDIR" ]; then
    [ -n "$SYSCONFFILE" ] && remove_file ${SYSCONFDIR}/${PRODUCT}
fi

remove_directory ${VARDIR}
[ ${LIBEXECDIR} = ${SHAREDIR} ] || remove_directory ${LIBEXECDIR}/$PRODUCT
remove_directory ${SHAREDIR}/$PRODUCT/configfiles
remove_file_with_wildcard  ${SHAREDIR}/$PRODUCT/module\*
remove_file  ${SHAREDIR}/$PRODUCT/helpers
remove_file_with_wildcard  ${SHAREDIR}/$PRODUCT/action\*
remove_file_with_wildcard  ${SHAREDIR}/$PRODUCT/macro.\*

if [ $PRODUCT = shorewall ]; then
    remove_file_with_wildcard ${PERLLIBDIR}/$Product/\*
    remove_directory ${SHAREDIR}/$PRODUCT/Samples
    remove_directory ${SHAREDIR}/$PRODUCT/$Product
    remove_file  ${SHAREDIR}/$PRODUCT/lib.cli-std
    remove_file  ${SHAREDIR}/$PRODUCT/lib.runtime
    remove_file  ${SHAREDIR}/$PRODUCT/compiler.pl
    remove_file_with_wildcard  ${SHAREDIR}/$PRODUCT/prog.\*
    remove_file  ${SHAREDIR}/$PRODUCT/init
else
    remove_directory ${SHAREDIR}/$PRODUCT
fi

for f in ${MANDIR}/man5/${PRODUCT}* ${MANDIR}/man8/${PRODUCT}*; do
    case $f in
	shorewall[6]-lite*)
	    ;;
	*)
	    remove_file $f
	    ;;
    esac
done

remove_file  ${CONFDIR}/logrotate.d/$PRODUCT

[ -n "$SYSTEMD" ] && remove_file ${SYSTEMD}/${PRODUCT}.service

#
# Report Success
#
echo "$Product $VERSION Uninstalled"
