#! /bin/bash
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
#
### BEGIN INIT INFO
# Provides: shorewall-init
# Required-Start: $local_fs
# Required-Stop:  $local_fs
# Default-Start:  2 3 5
# Default-Stop:   0 1 6
# Short-Description: Initialize the firewall at boot time
# Description:       Place the firewall in a safe state at boot time
#                    prior to bringing up the network.  
### END INIT INFO

#Return values acc. to LSB for all commands but status:
# 0 - success
# 1 - generic or unspecified error
# 2 - invalid or excess argument(s)
# 3 - unimplemented feature (e.g. "reload")
# 4 - insufficient privilege
# 5 - program is not installed
# 6 - program is not configured
# 7 - program is not running

if [ "$(id -u)" != "0" ]
then
  echo "You must be root to start, stop or restart \"Shorewall \"."
  exit 4
fi

# check if shorewall-init is configured or not
if [ -f "/etc/sysconfig/shorewall-init" ]
then
    . /etc/sysconfig/shorewall-init

    if [ -z "$PRODUCTS" ]
    then
	echo "No PRODUCTS configured"
	exit 6
    fi
else
    echo "/etc/sysconfig/shorewall-init not found"
    exit 6
fi

#
# The installer may alter this
#
. /usr/share/shorewall/shorewallrc

vardir=$VARDIR

# set the STATEDIR variable
setstatedir() {
    local statedir
    if [ -f ${CONFDIR}/${PRODUCT}/vardir ]; then
	statedir=$( . /${CONFDIR}/${PRODUCT}/vardir && echo $VARDIR )
    fi

    [ -n "$statedir" ] && STATEDIR=${statedir} || STATEDIR=${VARDIR}/${PRODUCT}

    if [ $PRODUCT = shorewall -o $PRODUCT = shorewall6 ]; then
	${SBINDIR}/$PRODUCT compile -c || exit
    fi
}

# Initialize the firewall
shorewall_start () {
  local PRODUCT
  local STATEDIR

  echo -n "Initializing \"Shorewall-based firewalls\": "
  for PRODUCT in $PRODUCTS; do
      setstatedir

      if [ -x $STATEDIR/firewall ]; then
	  if ! ${SBIN}/$PRODUCT status > /dev/null 2>&1; then
	      $STATEDIR/$PRODUCT/firewall stop || exit
	  fi
      else
	  exit 6
      fi
  done

  if [ -n "$SAVE_IPSETS" -a -f "$SAVE_IPSETS" ]; then
      ipset -R < "$SAVE_IPSETS"
  fi
}

# Clear the firewall
shorewall_stop () {
  local PRODUCT
  local STATEDIR

  echo -n "Clearing \"Shorewall-based firewalls\": "
  for PRODUCT in $PRODUCTS; do
      setstatedir

      if [ -x ${STATEDIR}/firewall ]; then
	  ${STATEDIR}/firewall clear || exit
      else
	  exit 6
      fi
  done

  if [ -n "$SAVE_IPSETS" ]; then
      mkdir -p $(dirname "$SAVE_IPSETS")
      if ipset -S > "${SAVE_IPSETS}.tmp"; then
	  grep -qE -- '^(-N|create )' "${SAVE_IPSETS}.tmp" && mv -f "${SAVE_IPSETS}.tmp" "$SAVE_IPSETS"
      fi
  fi
}

case "$1" in
    start)
	shorewall_start
	;;
    stop)
	shorewall_stop
	;;
    reload|forced-reload)
	;;
    *)
	echo "Usage: /etc/init.d/shorewall-init {start|stop}"
	exit 1
	;;
esac

exit 0
