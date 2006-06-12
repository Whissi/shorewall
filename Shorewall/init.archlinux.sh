#!/bin/bash

OPTIONS="-f"

if [ -f /etc/sysconfig/shorewall ] ; then
	. /etc/sysconfig/shorewall
elif [ -f /etc/default/shorewall ] ; then
	. /etc/default/shorewall
fi

# if you want to override options, do so in /etc/sysconfig/shorewall or
# in /etc/default/shorewall --
# i strongly encourage you use the latter, since /etc/sysconfig/ does not exist.

. /etc/rc.conf
. /etc/rc.d/functions

DAEMON_NAME="shorewall" # of course shorewall is NOT a deamon.

case "$1" in
	start)
		stat_busy "Starting $DAEMON_NAME"
		/sbin/shorewall $OPTIONS start &>/dev/null
		if [ $? -gt 0 ]; then
			stat_fail
		else
			add_daemon $DAEMON_NAME
			stat_done
		fi
		;;


	stop)
		stat_busy "Stopping $DAEMON_NAME"
		/sbin/shorewall stop &>/dev/null
		if [ $? -gt 0 ]; then
			stat_fail
		else
			rm_daemon $DAEMON_NAME
			stat_done
		fi
		;;

	restart|reload)
		stat_busy "Restarting $DAEMON_NAME"
		/sbin/shorewall restart &>/dev/null
		if [ $? -gt 0  ]; then
			stat_fail
		else
			stat_done
		fi
		;;

	*)
		echo "usage: $0 {start|stop|restart}"
esac
exit 0

