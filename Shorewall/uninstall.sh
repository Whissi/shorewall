#!/bin/sh
#
# Script to back uninstall Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000-2011 - Tom Eastep (teastep@shorewall.net)
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

VERSION=xxx #The Build script inserts the actual version

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

if [ -f ${SHAREDIR}/shorewall/version ]; then
    INSTALLED_VERSION="$(cat ${SHAREDIR}/shorewall/version)"
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

if qt iptables -L shorewall -n && [ ! -f ${SBINDIR}/shorewall-lite ]; then
   shorewall clear
fi

rm -f ${SBINDIR}/shorewall

rm -rf ${SHAREDIR}/shorewall/version
rm -rf ${CONFDIR}/shorewall
rm -rf ${VARDIR}/shorewall
rm -rf ${PERLLIB}/Shorewall/*
rm -rf ${LIBEXEC}/shorewall
rm -rf ${SHAREDIR}/shorewall/configfiles/
rm -rf ${SHAREDIR}/shorewall/Samples/
rm -rf ${SHAREDIR}/shorewall/Shorewall/
rm -f  ${SHAREDIR}/shorewall/lib.cli-std
rm -f  ${SHAREDIR}/shorewall/lib.core
rm -f  ${SHAREDIR}/shorewall/compiler.pl
rm -f  ${SHAREDIR}/shorewall/prog.*
rm -f  ${SHAREDIR}/shorewall/module*
rm -f  ${SHAREDIR}/shorewall/helpers
rm -f  ${SHAREDIR}/shorewall/action*
rm -f  ${SHAREDIR}/shorewall/init

for f in ${MANDIR}/man5/shorewall* ${MANDIR}/man8/shorewall*; do
    case $f in
	shorewall6*|shorewall-lite*)
	    ;;
	*)
	    rm -f $f
	    ;;
    esac
done

rm -f  ${CONFDIR}/logrotate.d/shorewall

[ -n "$SYSTEMD" ] && rm -f  ${SYSTEMD}/shorewall.service

echo "Shorewall Uninstalled"


