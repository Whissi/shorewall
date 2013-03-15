#!/bin/sh
#
# Debian ifupdown script for Shorewall-based products
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2010,2013 - Tom Eastep (teastep@shorewall.net)
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

setstatedir() {
    local statedir
    if [ -f ${CONFDIR}/${PRODUCT}/vardir ]; then
	statedir=$( . /${CONFDIR}/${PRODUCT}/vardir && echo $VARDIR )
    fi

    [ -n "$statedir" ] && STATEDIR=${statedir} || STATEDIR=${VARDIR}/${PRODUCT}

    if [ ! -x $STATEDIR/firewall ]; then
	if [ $PRODUCT = shorewall -o $PRODUCT = shorewall6 ]; then
	    ${SBINDIR}/$PRODUCT compile
	fi
    fi
}

Debian_ppp() {
    NEWPRODUCTS=
    INTERFACE="$1"

    case $0 in
	/etc/ppp/ip-*)
	    #
	    # IPv4
	    #
	    for product in $PRODUCTS; do
		case $product in
		    shorewall|shorewall-lite)
			NEWPRODUCTS="$NEWPRODUCTS $product";
			;;
		esac
	    done
	    ;;
	/etc/ppp/ipv6-*)
	    #
	    # IPv6
	    #
	    for product in $PRODUCTS; do
		case $product in
		    shorewall6|shorewall6-lite)
			NEWPRODUCTS="$NEWPRODUCTS $product";
			;;
		esac
	    done
	    ;;
	*)
	    exit 0
	    ;;
    esac

    PRODUCTS="$NEWPRODUCTS"

    case $0 in
	*up/*)
	    COMMAND=up
	    ;;
	*)
	    COMMAND=down
	    ;;
    esac
}

IFUPDOWN=0
PRODUCTS=

#
# The installer may alter this
#
. /usr/share/shorewall/shorewallrc

if [ -f /etc/default/shorewall-init ]; then
    . /etc/default/shorewall-init
elif [ -f /etc/sysconfig/shorewall-init ]; then
    . /etc/sysconfig/shorewall-init
fi

[ "$IFUPDOWN" = 1 -a -n "$PRODUCTS" ] || exit 0

case $0 in
    /etc/ppp*)
	#
	# Debian ppp
	#
	Debian_ppp
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
	;;
esac

[ -n "$LOGFILE" ] || LOGFILE=/dev/null

for PRODUCT in $PRODUCTS; do
    setstatedir

    if [ -x $VARLIB/$PRODUCT/firewall ]; then
	  ( ${VARLIB}/$PRODUCT/firewall -V0 $COMMAND $INTERFACE >> $LOGFILE 2>&1 ) || true
    fi
done

exit 0
