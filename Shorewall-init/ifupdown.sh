#!/bin/sh
#
# ifupdown script for Shorewall-based products
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
SAVEPRODUCTS="$PRODUCTS"

if [ -f /etc/default/shorewall-init ]; then
    . /etc/default/shorewall-init
elif [ -f /etc/sysconfig/shorewall-init ]; then
    . /etc/sysconfig/shorewall-init
fi

[ "$IFUPDOWN" = 1 -a -n "$PRODUCTS" ] || exit 0

if [ -f /etc/debian_version ]; then
    case $0 in
	/etc/ppp*)
	    #
	    # Debian ppp
	    #
	    PRODUCTS=
	    INTERFACE="$1"

	    case $0 in
		/etc/ppp/ip-*)
		    #
		    # IPv4
		    #
		    for product in $SAVEPRODUCTS; do
			case $product in
			    shorewall|shorewall-lite)
				PRODUCTS="$PRODUCTS $product";
				;;
			esac
		    done
		    ;;
		*)
		    #
		    # IPv6
		    #
		    for product in $SAVEPRODUCTS; do
			case $product in
			    shorewall6|shorewall6-lite)
				PRODUCTS="$PRODUCTS $product";
				;;
			esac
		    done
		    ;;
	    esac

	    case $0 in
		*up/*)
		    COMMAND=up
		    ;;
		*)
		    COMMAND=down
		    ;;
	    esac
	    ;;
	
	*)
            #
            # Debian ifupdown system
            #
	    INTERFACE="$IFACE"

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
	    ;;
    esac
elif [ -f /etc/SuSE-release ]; then
    #
    # SuSE ifupdown system
    #
    INTERFACE="$2"

    case $0 in
	*if-up.d*)
	    COMMAND=up
	    ;;
	*if-down.d*)
	    COMMAND=down
	    ;;
	*)
	    exit 0
	    ;;
    esac
else
    #
    # Assume RedHat/Fedora/CentOS/Foobar/...
    #
    INTERFACE="$1"
    
    case $0 in 
	*ifup*)
	    COMMAND=up
	    ;;
	*ifdown*)
	    COMMAND=down
	    ;;
	*dispatcher.d*)
	    COMMAND="$2"
	    ;;
	*)
	    exit 0
	    ;;
    esac
fi

for PRODUCT in $PRODUCTS; do
    VARDIR=/var/lib/$PRODUCT
    [ -f /etc/$PRODUCT/vardir ] && . /etc/$PRODUCT/vardir
    if [ -x $VARDIR/firewall ]; then
	  ( . /usr/share/$PRODUCT/lib.base
	    mutex_on
	    ${VARDIR}/firewall -V0 $COMMAND $INTERFACE || echo_notdone
	    mutex_off
	  )
    fi
done

exit 0
