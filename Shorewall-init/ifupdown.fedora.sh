#!/bin/sh
#
# Redhat/Fedora/Centos/Foobar ifupdown script for Shorewall-based products
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

# Get startup options (override default)
OPTIONS=

setstatedir() {
    local statedir
    if [ -f ${CONFDIR}/${PRODUCT}/vardir ]; then
	statedir=$( . /${CONFDIR}/${PRODUCT}/vardir && echo $VARDIR )
    fi

    [ -n "$statedir" ] && STATEDIR=${statedir} || STATEDIR=${VARDIR}/${PRODUCT}

    if [ ! -x "$STATEDIR/firewall" ]; then
	if [ $PRODUCT == shorewall -o $PRODUCT == shorewall6 ]; then
	    ${SBINDIR}/$PRODUCT $OPTIONS compile
	fi
    fi
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

PHASE=''

case $0 in
    /etc/ppp*)
	INTERFACE="$1"

	case $0 in
	    *ip-up.local)
		COMMAND=up
		;;
	    *ip-down.local)
		COMMAND=down
		;;
	    *)
		exit 0
		;;
	esac
	;;
    *)
	#
	# RedHat ifup/down system
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
	;;
esac

[ -n "$LOGFILE" ] || LOGFILE=/dev/null

for PRODUCT in $PRODUCTS; do
    setstatedir

    if [ -x "$STATEDIR/firewall" ]; then
	  echo "`date --rfc-3339=seconds` $0: Executing $STATEDIR/firewall $OPTIONS $COMMAND $INTERFACE" >> $LOGFILE 2>&1
	  ( $STATEDIR/firewall $OPTIONS $COMMAND $INTERFACE >> $LOGFILE 2>&1 ) || true
    fi
done

exit 0
