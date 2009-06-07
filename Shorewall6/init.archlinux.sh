#!/bin/bash

OPTIONS="-f"

if [ -f /etc/sysconfig/shorewall6 ] ; then
	. /etc/sysconfig/shorewall6
elif [ -f /etc/default/shorewall6 ] ; then
	. /etc/default/shorewall6
fi

# if you want to override options, do so in /etc/sysconfig/shorewall6 or
# in /etc/default/shorewall6 --
# i strongly encourage you use the latter, since /etc/sysconfig/ does not exist.

. /etc/rc.conf
. /etc/rc.d/functions

DAEMON_NAME="shorewall6" # of course shorewall6 is NOT a deamon.

export SHOREWALL_INIT_SCRIPT=1

case "$1" in
	start)
		stat_busy "Starting $DAEMON_NAME"
		/sbin/shorewall6 $OPTIONS start &>/dev/null
		if [ $? -gt 0 ]; then
			stat_fail
		else
			add_daemon $DAEMON_NAME
			stat_done
		fi
		;;


	stop)
		stat_busy "Stopping $DAEMON_NAME"
		/sbin/shorewall6 stop &>/dev/null
		if [ $? -gt 0 ]; then
			stat_fail
		else
			rm_daemon $DAEMON_NAME
			stat_done
		fi
		;;

	restart|reload)
		stat_busy "Restarting $DAEMON_NAME"
		/sbin/shorewall6 restart &>/dev/null
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

