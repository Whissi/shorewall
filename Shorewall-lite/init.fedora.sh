#!/bin/sh
#
# Shorewall init script
#
# chkconfig: - 28 90
# description: Packet filtering firewall

### BEGIN INIT INFO
# Provides: shorewall-lite
# Required-Start: $local_fs $remote_fs $syslog $network
# Should-Start: VMware $time $named
# Required-Stop:
# Default-Start:
# Default-Stop:	  0 1 2 3 4 5 6
# Short-Description: Packet filtering firewall
# Description: The Shoreline Firewall, more commonly known as "Shorewall", is a
#              Netfilter (iptables) based firewall
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

prog="shorewall-lite"
shorewall="/sbin/$prog"
logger="logger -i -t $prog"
lockfile="/var/lock/subsys/$prog"

# Get startup options (override default)
OPTIONS=

if [ -f /etc/sysconfig/$prog ]; then
    . /etc/sysconfig/$prog
fi

start() {
    echo -n $"Starting Shorewall: "
    $shorewall $OPTIONS start 2>&1 | $logger
    retval=${PIPESTATUS[0]}
    if [[ $retval == 0 ]]; then 
	touch $lockfile
	success
    else 
	failure
    fi
    echo
    return $retval
}

stop() {
    echo -n $"Stopping Shorewall: "
    $shorewall $OPTIONS stop 2>&1 | $logger
    retval=${PIPESTATUS[0]}
    if [[ $retval == 0 ]]; then 
	rm -f $lockfile
	success
    else 
	failure
    fi
    echo
    return $retval
}

restart() {
# Note that we don't simply stop and start since shorewall has a built in
# restart which stops the firewall if running and then starts it.
    echo -n $"Restarting Shorewall: "
    $shorewall $OPTIONS restart 2>&1 | $logger
    retval=${PIPESTATUS[0]}
    if [[ $retval == 0 ]]; then 
	touch $lockfile
	success
    else # Failed to start, clean up lock file if present
	rm -f $lockfile
	failure
    fi
    echo
    return $retval
}

status(){
    $shorewall status
    return $?
}

status_q() {
    status > /dev/null 2>&1
}

case "$1" in
    start)
	status_q && exit 0
	$1
	;;
    stop)
	status_q || exit 0
	$1
	;;
    restart|reload|force-reload)
	restart
	;;
    condrestart|try-restart)
        status_q || exit 0
        restart
        ;;
    status)
	$1
	;;
    *)
	echo "Usage: $0 start|stop|reload|restart|force-reload|status"
	exit 1
	;;
esac
