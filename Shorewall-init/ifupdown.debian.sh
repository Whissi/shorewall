#!/bin/sh
#
# ifup script for Shorewall-based products
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2010 - Tom Eastep (teastep@shorewall.net)
#
#       Shorewall documentation is available at http://shorewall.net
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

IFUPDOWN=0
PRODUCTS=

if [ -f /etc/default/shorewall-init ]; then
    . /etc/default/shorewall-init
elif [ -f /etc/sysconfig/shorewall-init ]; then
    . /etc/sysconfig/shorewall-init
fi

[ "$IFUPDOWN" = 1 && -n "$PRODUCTS" ] || exit 0

if [ -f /etc/debian_version ]; then
    #
    # Debian ifupdown system
    #
    if [ "$MODE" = start ]; then
	COMMAND=up
    elif [ "$MODE" = stop ]; then
	COMMAND=down
    else
	exit 0
    fi

    case "$PHASE" in
	pre-*)
	    exit 0
	    ;;
    esac

    for PRODUCT in $PRODUCTS; do
	VARDIR=/var/lib/$PRODUCT
	[ -f /etc/$PRODUCT/vardir ] && . /etc/$PRODUCT/vardir
	if [ -x $VARDIR/firewall ]; then
	    $VARDIR/firewall -v0 $COMMAND $IFACE
	fi
    done

    exit 0
fi

exit 0
