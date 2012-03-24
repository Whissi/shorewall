#! /bin/bash
#     The Shoreline Firewall (Shorewall) Packet Filtering Firewall - V4.4
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2010 - Tom Eastep (teastep@shorewall.net)
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

if [ ~/.shorewallrc ]; then
    . ~/.shorewallrc || exit 1
else
    VARDIR=/var/lib
fi

# Initialize the firewall
shorewall_start () {
  local PRODUCT
  local VARDIR

  echo -n "Initializing \"Shorewall-based firewalls\": "
  for PRODUCT in $PRODUCTS; do
      if [ -x ${VARDIR}/firewall ]; then
	  if ! ${SBIN}/$PRODUCT status > /dev/null 2>&1; then
	      ${VARDIR}/firewall stop || echo_notdone
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
  local VARDIR

  echo -n "Clearing \"Shorewall-based firewalls\": "
  for PRODUCT in $PRODUCTS; do
      if [ -x ${VARDIR}/firewall ]; then
	  ${VARDIR}/firewall clear || exit 1
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
