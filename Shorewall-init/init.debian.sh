#!/bin/sh
#
#     The Shoreline Firewall (Shorewall) Packet Filtering Firewall - V4.5
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2010,2012 - Tom Eastep (teastep@shorewall.net)
#
#       On most distributions, this file should be called /etc/init.d/shorewall.
#
#       Complete documentation is available at http://shorewall.net
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
### BEGIN INIT INFO
# Provides:          shorewall-init
# Required-Start:    $local_fs
# X-Start-Before:    $network
# Required-Stop:     $local_fs
# X-Stop-After:      $network
# Default-Start:     S
# Default-Stop:      0 6
# Short-Description: Initialize the firewall at boot time
# Description:       Place the firewall in a safe state at boot time prior to
#                    bringing up the network
### END INIT INFO

. /lib/lsb/init-functions

export VERBOSITY=0

if [ "$(id -u)" != "0" ]
then
  echo "You must be root to start, stop or restart \"Shorewall \"."
  exit 1
fi

echo_notdone () {
  echo "not done."
  exit 1
}

not_configured () {
    echo "#### WARNING ####"
    echo "the firewall won't be initialized unless it is configured"
    if [ "$1" != "stop" ]
    then
	echo ""
	echo "Please read about Debian specific customization in"
	echo "/usr/share/doc/shorewall-init/README.Debian.gz."
    fi
    echo "#################"
    exit 0
}

# set the STATEDIR variable
setstatedir() {
    local statedir
    if [ -f ${CONFDIR}/${PRODUCT}/vardir ]; then
	statedir=$( . /${CONFDIR}/${PRODUCT}/vardir && echo $VARDIR )
    fi

    [ -n "$statedir" ] && STATEDIR=${statedir} || STATEDIR=${VARDIR}/${PRODUCT}

    if [ $PRODUCT = shorewall -o $PRODUCT = shorewall6 ]; then
	${SBINDIR}/$PRODUCT ${OPTIONS} compile -c || echo_notdone
    fi
}

#
# The installer may alter this
#
. /usr/share/shorewall/shorewallrc

# check if shorewall-init is configured or not
if [ -f "$SYSCONFDIR/shorewall-init" ]
then
    . $SYSCONFDIR/shorewall-init
    if [ -z "$PRODUCTS" ]
    then
	not_configured
    fi
else
    not_configured
fi

# Initialize the firewall
shorewall_start () {
  local PRODUCT
  local STATEDIR

  echo -n "Initializing \"Shorewall-based firewalls\": "

  for PRODUCT in $PRODUCTS; do
      setstatedir

      if [ -x ${STATEDIR}/firewall ]; then
          #
	  # Run in a sub-shell to avoid name collisions
	  #
	  ( 
	      if ! ${STATEDIR}/$PRODUCT/firewall status > /dev/null 2>&1; then
		  ${STATEDIR}/$PRODUCT/firewall ${OPTIONS} stop || echo_notdone
	      else
		  echo_notdone
	      fi
	  )
      else
	  echo_notdone
      fi
  done

  echo "done."

  return 0
}

# Clear the firewall
shorewall_stop () {
  local PRODUCT
  local STATEDIR

  echo -n "Clearing \"Shorewall-based firewalls\": "
  for PRODUCT in $PRODUCTS; do
      setstatedir

      if [ -x ${STATEDIR}/firewall ]; then
	  ${STATEDIR}/$PRODUCT/firewall ${OPTIONS} clear || echo_notdone
      fi
  done

  echo "done."

  return 0
}

case "$1" in
  start)
     shorewall_start
     ;;
  stop)
     shorewall_stop
     ;;
  reload|force-reload)
     ;;
  *)
     echo "Usage: $0 {start|stop|reload|force-reload}"
     exit 1
esac

exit 0
