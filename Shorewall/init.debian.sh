#!/bin/sh

SRWL=/sbin/shorewall
WAIT_FOR_IFUP=/usr/share/shorewall/wait4ifup
# Note, set INITLOG to /dev/null if you do not want to
# keep logs of the firewall (not recommended)
INITLOG=/var/log/shorewall-init.log
OPTIONS="-f"

test -x $SRWL || exit 0
test -n $INITLOG || {
	echo "INITLOG cannot be empty, please configure $0" ; 
	exit 1;
}

if [ "$(id -u)" != "0" ]
then
  echo "You must be root to start, stop or restart \"Shorewall firewall\"."
  exit 1
fi

echo_notdone () {

  if [ "$INITLOG" = "/dev/null" ] ; then 
	  "not done."
  else 
	  "not done (check $INITLOG)."
  fi

}

not_configured () {
	echo "#### WARNING ####"
	echo "the firewall won't be started/stopped unless it is configured"
	if [ "$1" != "stop" ]
	then
		echo ""
		echo "please configure it and then edit /etc/default/shorewall"
		echo "and set the \"startup\" variable to 1 in order to allow "
		echo "shorewall to start"
	fi
	echo "#################"
	exit 0
}

# parse the shorewall params file in order to use params in
# /etc/default/shorewall
if [ -f "/etc/shorewall/params" ]
then
	. /etc/shorewall/params
fi

# check if shorewall is configured or not
if [ -f "/etc/default/shorewall" ]
then
	. /etc/default/shorewall
	if [ "$startup" != "1" ]
	then
		not_configured
	fi
else
	not_configured
fi

# wait an unconfigured interface 
wait_for_pppd () {
	if [ "$wait_interface" != "" ]
	then
	    if [ -f $WAIT_FOR_IFUP ]
	    then
		for i in $wait_interface
		do
			$WAIT_FOR_IFUP $i 90
		done
	    else
		echo "$WAIT_FOR_IFUP: File not found" >> $INITLOG
		echo_notdone
		exit 2
	    fi
	fi
}

# start the firewall
shorewall_start () {
  echo -n "Starting \"Shorewall firewall\": "
  wait_for_pppd
  $SRWL $OPTIONS start >> $INITLOG 2>&1 && echo "done." || echo_notdone
  return 0
}

# stop the firewall
shorewall_stop () {
  echo -n "Stopping \"Shorewall firewall\": "
  $SRWL stop >> $INITLOG 2>&1 && echo "done." || echo_notdone
  return 0
}

# restart the firewall
shorewall_restart () {
  echo -n "Restarting \"Shorewall firewall\": "
  $SRWL restart >> $INITLOG 2>&1 && echo "done." || echo_notdone
  return 0
}

# refresh the firewall
shorewall_refresh () {
  echo -n "Refreshing \"Shorewall firewall\": "
  $SRWL refresh >> $INITLOG 2>&1 && echo "done." || echo_notdone
  return 0
}

case "$1" in
  start)
     shorewall_start
     ;;
  stop)
     shorewall_stop
     ;;
  refresh)
     shorewall_refresh
  	  ;;
  force-reload|restart)
     shorewall_restart
     ;;
  *)
     echo "Usage: /etc/init.d/shorewall {start|stop|refresh|restart|force-reload}"
     exit 1
esac

exit 0
