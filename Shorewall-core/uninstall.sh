#!/bin/sh
#
# Script to back uninstall Shoreline Firewall
#
#     (c) 2000-2014 - Tom Eastep (teastep@shorewall.net)
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
PRODUCT="shorewall-core"
Product="Shorewall Core"
 
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

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

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

if [ -f ${SHAREDIR}/shorewall/coreversion ]; then
    INSTALLED_VERSION="$(cat ${SHAREDIR}/shorewall/coreversion)"
    if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
	echo "WARNING: Shorewall Core Version $INSTALLED_VERSION is installed"
	echo "         and this is the $VERSION uninstaller."
	VERSION="$INSTALLED_VERSION"
    fi
else
    echo "WARNING: Shorewall Core Version $VERSION is not installed"
    VERSION=""
fi

echo "Uninstalling Shorewall Core $VERSION"

rm -rf ${SHAREDIR}/shorewall

echo "Shorewall Core Uninstalled"


