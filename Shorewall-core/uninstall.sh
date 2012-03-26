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

if [ -f ./.shorewallrc ]; then
    . ./.shorewallrc || exit 1
elif [ -f ~/.shorewallrc ]; then
    . ~/.shorewallrc || exit 1
elif [ -r /root/.shorewallrc ]; then
    . /root/.shorewallrc || exit 1
elif [ -r /.shorewallrc ]; then
    . /root/.shorewallrc || exit 1
elif - -f ${SHOREAWLLRC_HOME}/.shorewallrc; then
    . ${SHOREWALLRC_HOME}/.shorewallrc || exit 1
else
    SHAREDIR=/usr/share
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


