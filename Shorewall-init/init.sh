#! /bin/bash
#     The Shoreline Firewall (Shorewall) Packet Filtering Firewall - V4.5
#
#     (c) 2010,2012-2014 - Tom Eastep (teastep@shorewall.net)
#
#       On most distributions, this file should be called /etc/init.d/shorewall.
#
#       This program is part of Shorewall.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by the
#       Free Software Foundation, either version 2 of the license or, at your
#       option, any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, see <http://www.gnu.org/licenses/>.
#
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# chkconfig: - 09 91
#
### BEGIN INIT INFO
# Provides: shorewall-init
# Required-start: $local_fs
# Required-stop:  $local_fs
# Default-Start:  2 3 5
# Default-Stop:   6
# Short-Description: Initialize the firewall at boot time
# Description:       Place the firewall in a safe state at boot time
#                    prior to bringing up the network.  
### END INIT INFO

if [ "$(id -u)" != "0" ]
then
  echo "You must be root to start, stop or restart \"Shorewall \"."
  exit 1
fi

# check if shorewall-init is configured or not
if [ -f "/etc/sysconfig/shorewall-init" ]
then
	. /etc/sysconfig/shorewall-init
	if [ -z "$PRODUCTS" ]
	then
		exit 0
	fi
else
	exit 0
fi

#
# The installer may alter this
#
. /usr/share/shorewall/shorewallrc

# Locate the current PRODUCT's statedir
setstatedir() {
    local statedir
    if [ -f ${CONFDIR}/${PRODUCT}/vardir ]; then
	statedir=$( . /${CONFDIR}/${PRODUCT}/vardir && echo $VARDIR )
    fi

    [ -n "$statedir" ] && STATEDIR=${statedir} || STATEDIR=${VARLIB}/${PRODUCT}

    if [ $PRODUCT = shorewall -o $PRODUCT = shorewall6 ]; then
	${SBINDIR}/$PRODUCT ${OPTIONS} compile $STATEDIR/firewall
    else
	return 0
    fi
}

# Initialize the firewall
shorewall_start () {
  local PRODUCT
  local STATEDIR

  echo -n "Initializing \"Shorewall-based firewalls\": "
  for PRODUCT in $PRODUCTS; do
      if setstatedir; then
	  if [ -x ${STATEDIR}/firewall ]; then
	      if ! ${SBIN}/$PRODUCT status > /dev/null 2>&1; then
		  ${STATEDIR}/firewall ${OPTIONS} stop
	      fi
	  fi
      fi
  done

  if [ -n "$SAVE_IPSETS" -a -f "$SAVE_IPSETS" ]; then
      ipset -R < "$SAVE_IPSETS"
  fi

  return 0
}

# Clear the firewall
shorewall_stop () {
  local PRODUCT
  local STATEDIR

  echo -n "Clearing \"Shorewall-based firewalls\": "
  for PRODUCT in $PRODUCTS; do
      if setstatedir; then
	  if [ -x ${STATEDIR}/firewall ]; then
	      ${STATEDIR}/firewall ${OPTIONS} clear
	  fi
      fi
  done

  if [ -n "$SAVE_IPSETS" ]; then
      mkdir -p $(dirname "$SAVE_IPSETS")
      if ipset -S > "${SAVE_IPSETS}.tmp"; then
	  grep -qE -- '^(-N|create )' "${SAVE_IPSETS}.tmp" && mv -f "${SAVE_IPSETS}.tmp" "$SAVE_IPSETS"
      fi
  fi

  return 0
}

case "$1" in
  start)
     shorewall_start
     ;;
  stop)
     shorewall_stop
     ;;
  *)
     echo "Usage: /etc/init.d/shorewall-init {start|stop}"
     exit 1
esac

exit 0
