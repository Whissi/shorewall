#!/bin/sh
#
# /etc/rc.d/rc.shorewall:  start/stop/restart IPv4 rules of Shorewall
#
# This should be started from rc.firewall.
# This script only affect the IPv4 rules and configuration located
# in /etc/shorewall
#
# http://rafb.net/p/iffZ4d32.html

OPTIONS=""

# Use /etc/default shorewall to specify $OPTIONS and STARTOPTIONS to
# run at startup, however this this might prevent shorewall from
# starting. use at your own risk
if [ -f /etc/default/shorewall ] ; then
    . /etc/default/shorewall
fi

start() {
	echo "Starting IPv4 shorewall rules..."
	exec /sbin/shorewall $OPTIONS start $STARTOPTIONS
}

stop() {
	echo "Stopping IPv4 shorewall rules..."
	exec /sbin/shorewall stop
}

restart() {
	echo "Restarting IPv4 shorewall rules..."
	exec /sbin/shorewall restart $RESTARTOPTIONS
}

status() {
	exec /sbin/shorewall status
}

case "$1" in
    'start')
		start
	;;
    'stop')
		stop
	;;
    'reload'|'restart')
		restart
	;;
	'status')
		status
	;;
    *)
		echo "Usage: $0 start|stop|reload|restart|status"
	;;
esac

exit 0

# All done
