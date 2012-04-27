#!/bin/sh
#
# /etc/rc.d/rc.firewall:  Shoreline Firewall (Shorewall) initialization script.
#
# This script starts both the IPv4 and IPv6 rules of shorewall if the respective
# initialization scripts (rc.shorewall and rc.shorewall6) are present
#
# http://rafb.net/p/k0OiyI67.html

start() {
	if [ -x /etc/rc.d/rc.shorewall ]; then
		/etc/rc.d/rc.shorewall start
	fi
	if [ -x /etc/rc.d/rc.shorewall6 ]; then
		/etc/rc.d/rc.shorewall6 start
	fi
}

stop() {
	if [ -x /etc/rc.d/rc.shorewall ]; then
		/etc/rc.d/rc.shorewall stop
	fi
	if [ -x /etc/rc.d/rc.shorewall6 ]; then
		/etc/rc.d/rc.shorewall6 stop
	fi
}

restart() {
	if [ -x /etc/rc.d/rc.shorewall ]; then
		/etc/rc.d/rc.shorewall restart
	fi
	if [ -x /etc/rc.d/rc.shorewall6 ]; then
		/etc/rc.d/rc.shorewall6 restart
	fi
}

status() {
	if [ -x /etc/rc.d/rc.shorewall ]; then
		/etc/rc.d/rc.shorewall status
	fi
	if [ -x /etc/rc.d/rc.shorewall6 ]; then
		/etc/rc.d/rc.shorewall6 status
	fi
}

export SHOREWALL_INIT_SCRIPT=1

case $1 in
	'start')
	start
	;;
	'stop')
	stop
	;;
	'restart')
	restart
	;;
	'status')
	status
	;;
	*)
	echo "Usage: $0 {start|stop|restart|status}"
	;;
esac

exit 0

# All done
