#!/bin/sh
#
# /etc/rc.d/rc.shorewall6:  start/stop/restart IPv6 rules of Shorewall
#
# This should be started from rc.firewall.
# This script only affect the IPv6 rules and configuration located
# in /etc/shorewall6
#
# http://rafb.net/p/1gsyye11.html

OPTIONS=""

# Use /etc/default shorewall6 to specify $OPTIONS and STARTOPTIONS to
# run at startup, however this this might prevent shorewall6 from
# starting. use at your own risk
if [ -f /etc/default/shorewall6 ] ; then
    . /etc/default/shorewall6
fi


start() {
	echo "Starting IPv6 shorewall rules..."
	exec /sbin/shorewall6 $OPTIONS start $STARTOPTIONS
}

stop() {
	echo "Stopping IPv6 shorewall rules..."
	exec /sbin/shorewall6 stop
}

restart() {
	echo "Restarting IPv6 shorewall rules..."
	exec /sbin/shorewall6 restart $RESTARTOPTIONS
}

status() {
	exec /sbin/shorewall6 status
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
