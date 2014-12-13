#! /bin/bash
#
# chkconfig: - 09 91
# description: Initialize the shorewall firewall at boot time
#
### BEGIN INIT INFO
# Provides: shorewall-init
# Required-Start: $local_fs
# Required-Stop:  $local_fs
# Default-Start:
# Default-Stop:	  0 1 2 3 4 5 6
# Short-Description: Initialize the shorewall firewall at boot time
# Description:       Place the firewall in a safe state at boot time
#                    prior to bringing up the network.  
### END INIT INFO
#determine where the files were installed

. /usr/share/shorewall/shorewallrc

prog="shorewall-init"
logger="logger -i -t $prog"
lockfile="/var/lock/subsys/shorewall-init"

# Source function library.
. /etc/rc.d/init.d/functions

# Get startup options (override default)
OPTIONS=

# check if shorewall-init is configured or not
if [ -f "/etc/sysconfig/shorewall-init" ]; then
    . /etc/sysconfig/shorewall-init
else
    echo "/etc/sysconfig/shorewall-init not found"
    exit 6
fi

# set the STATEDIR variable
setstatedir() {
    local statedir
    if [ -f ${CONFDIR}/${PRODUCT}/vardir ]; then
	statedir=$( . /${CONFDIR}/${PRODUCT}/vardir && echo $VARDIR )
    fi

    [ -n "$statedir" ] && STATEDIR=${statedir} || STATEDIR=${VARLIB}/${PRODUCT}

    if [ $PRODUCT == shorewall -o $PRODUCT == shorewall6 ]; then
	${SBINDIR}/$PRODUCT $OPTIONS compile -c
    else
	return 0
    fi
}

# Initialize the firewall
start () {
    local PRODUCT
    local STATEDIR

    if [ -z "$PRODUCTS" ]; then
	echo "No firewalls configured for shorewall-init"
	failure
	return 6 #Not configured
    fi

    echo -n "Initializing \"Shorewall-based firewalls\": "

    for PRODUCT in $PRODUCTS; do
	setstatedir
	retval=$?

	if [ $retval -eq 0 ]; then
	    if [ -x "${STATEDIR}/firewall" ]; then
		${STATEDIR}/firewall ${OPTIONS} stop 2>&1 | $logger
		retval=${PIPESTATUS[0]}
		[ $retval -ne 0 ] && break
	    else
		retval=6 #Product not configured
		break
	    fi
	else
	    break
	fi
    done

    if [ $retval -eq 0 ]; then
	touch $lockfile 
	success
    else
	failure
    fi
    echo
    return $retval
}

# Clear the firewall
stop () {
    local PRODUCT
    local STATEDIR

    echo -n "Clearing \"Shorewall-based firewalls\": "

    for PRODUCT in $PRODUCTS; do
	setstatedir
	retval=$?

	if [ $retval -eq 0 ]; then
	    if [ -x "${STATEDIR}/firewall" ]; then
		${STATEDIR}/firewall ${OPTIONS} clear 2>&1 | $logger
		retval=${PIPESTATUS[0]}
		[ $retval -ne 0 ] && break
	    else
		retval=6 #Product not configured
		break
	    fi
	else
	    break
	fi
    done

    if [ $retval -eq 0 ]; then
	rm -f $lockfile
	success
    else
	failure
    fi
    echo
    return $retval
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
    restart|reload|force-reload|condrestart|try-restart)
	echo "Not implemented"
	exit 3
	;;
    status)
	status $prog
	;;
  *)
	echo "Usage: $0 {start|stop|status}"
	exit 1
esac

exit 0
