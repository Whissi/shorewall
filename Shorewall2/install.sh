#!/bin/sh
#
# Script to install Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2000,2001,2002,2003,2004 - Tom Eastep (teastep@shorewall.net)
#
#       Seawall documentation is available at http://seawall.sourceforge.net
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
#       Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#
#    Usage:
#
#        If you are running a distribution that has a directory called /etc/rc.d/init.d or one
#        called /etc/init.d or you are running Slackware then simply cd to the directory
#        containing this script and run it.
#
#            ./install.sh
#
#        If you don't have either of those directories, you will need to determine where the
#        SysVInit scripts are kept on your system and pass the name of that directory.
#
#            ./install.sh /etc/rc.d/scripts
#
#        The default is that the firewall will be started in run levels 2-5 starting at
#        position 15 and stopping at position 90. This is correct RedHat/Mandrake, Debian,
#        Caldera and Corel.
#
#        If you wish to change that, you can pass -r "<levels startpos stoppos>".
#
#        Example 1: You wish to start your firewall in runlevels 2 and three, start at position
#                   15 and stop at position 90
#
#            ./install.sh -r "23 15 90"
#
#       Example 2: You wish to start your firewall only in run level 3, start at position 5
#                  and stop at position 95.
#
#            ./install.sh -r "3 5 95" /etc/rc.d/scripts
#
#        For distributions that don't include chkconfig (Slackware, for example), the
#        /etc/rc.d/rc.local file is modified to start the firewall.
#

VERSION=2.0.0-Alpha1

usage() # $1 = exit status
{
    ME=`basename $0`
    echo "usage: $ME [ -r \"<chkconfig parameters>\" ] [ <init scripts directory> ]"
    echo "       $ME [ -v ]"
    echo "       $ME [ -h ]"
    exit $1
}

run_install()
{
    if ! install $*; then
	echo
	echo "ERROR: Failed to install $*"
	exit 1
    fi
}

cant_autostart()
{
    echo
    echo  "WARNING: Unable to configure Shorewall2 to start"
    echo  "           automatically at boot"
}

backup_file() # $1 = file to backup
{
    if [ -z "$PREFIX" -a -f $1 -a ! -f ${1}-${VERSION}.bkout ]; then
	if (cp $1 ${1}-${VERSION}.bkout); then
	    echo
	    echo "$1 saved to ${1}-${VERSION}.bkout"
        else
	    exit 1
        fi
    fi
}

delete_file() # $1 = file to delete
{
    if [ -z "$PREFIX" -a -f $1 -a ! -f ${1}-${VERSION}.bkout ]; then
	if (mv $1 ${1}-${VERSION}.bkout); then
	    echo
	    echo "$1 moved to ${1}-${VERSION}.bkout"
        else
	    exit 1
        fi
    fi
}

install_file_with_backup() # $1 = source $2 = target $3 = mode
{
    backup_file $2
    run_install -o $OWNER -g $GROUP -m $3 $1 ${2}
}

#
# Parse the run line
#
# DEST is the SysVInit script directory
# RUNLEVELS is the chkconfig parmeters for firewall
# ARGS is "yes" if we've already parsed an argument
#
DEST=""
RUNLEVELS=""
ARGS=""

if [ -z "$OWNER" ] ; then
	OWNER=root
fi

if [ -z "$GROUP" ] ; then
	GROUP=root
fi

while [ $# -gt 0 ] ; do
    case "$1" in
	-h|help|?)
	    if [ -n "$ARGS" ]; then
		usage 1
            fi

	    usage 0
	    ;;
	-r)
	    if [ -n "$RUNLEVELS" -o $# -eq 1 ]; then
		usage 1
	    fi

	    RUNLEVELS="$2";
	    shift
	    ;;
        -v)
	    if [ -n "$ARGS" ]; then
		usage 1
            fi

	    echo "Shorewall Firewall Installer Version $VERSION"
	    exit 0
	    ;;
	*)
	    if [ -n "$DEST" ]; then
		usage 1
            fi

	    DEST="$1"
	    ;;
    esac
    shift
    ARGS="yes"
done

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

if [ -z "$DEST" ]; then
    DEST=/etc/init.d
fi

#
# Determine where to install the firewall script
#
if [ -n "$PREFIX" ]; then
	install -d -o $OWNER -g $GROUP -m 755 ${PREFIX}/sbin
	install -d -o $OWNER -g $GROUP -m 755 ${PREFIX}${DEST}
fi

FIREWALL="shorewall2"

#
# Change to the directory containing this script
#
cd "`dirname $0`"

echo "Installing Shorewall Version $VERSION"

#
# Check for /etc/shorewall2
#
if [ -d ${PREFIX}/etc/shorewall2 ]; then
    first_install=""
else
    first_install="Yes"
fi

install_file_with_backup shorewall ${PREFIX}/sbin/shorewall2 0544

echo
echo "Shorewall2 control program installed in ${PREFIX}/sbin/shorewall2"

#
# Install the Firewall Script
#
install_file_with_backup init.sh ${PREFIX}${DEST}/$FIREWALL 0544

echo
echo  "Shorewall script installed in ${PREFIX}${DEST}/$FIREWALL"

#
# Create /etc/shorewall2, /usr/share/shorewall2 and /var/shorewall if needed
#
mkdir -p ${PREFIX}/etc/shorewall2
mkdir -p ${PREFIX}/usr/share/shorewall2
mkdir -p ${PREFIX}/var/lib/shorewall
#
# Install the config file
#
if [ -f ${PREFIX}/etc/shorewall2/shorewall.conf ]; then
   backup_file /etc/shorewall2/shorewall.conf
else
   run_install -o $OWNER -g $GROUP -m 0744 shorewall.conf ${PREFIX}/etc/shorewall2/shorewall.conf
   echo
   echo "Config file installed as ${PREFIX}/etc/shorewall2/shorewall.conf"
fi
#
# Install the zones file
#
if [ -f ${PREFIX}/etc/shorewall2/zones ]; then
    backup_file /etc/shorewall2/zones
else
    run_install -o $OWNER -g $GROUP -m 0744 zones ${PREFIX}/etc/shorewall2/zones
    echo
    echo "Zones file installed as ${PREFIX}/etc/shorewall2/zones"
fi

#
# Install the functions file
#
if [ -f ${PREFIX}/etc/shorewall2/functions ]; then
    backup_file ${PREFIX}/etc/shorewall2/functions
    rm -f  ${PREFIX}/etc/shorewall2/functions
fi

install_file_with_backup functions ${PREFIX}/usr/share/shorewall2/functions 0444

echo
echo "Common functions installed in ${PREFIX}/usr/share/shorewall2/functions"

#
# Install the Help file
#
install_file_with_backup help ${PREFIX}/usr/share/shorewall2/help 0544

echo
echo "Help command executor installed in ${PREFIX}/usr/share/shorewall2/help"
#
# Install the common.def file
#
install_file_with_backup common.def ${PREFIX}/etc/shorewall2/common.def 0444

echo
echo "Common rules installed in ${PREFIX}/etc/shorewall2/common.def"

#
# Delete the icmp.def file
#
delete_file icmp.def

#
# Install the policy file
#
if [ -f ${PREFIX}/etc/shorewall2/policy ]; then
    backup_file /etc/shorewall2/policy
else
    run_install -o $OWNER -g $GROUP -m 0600 policy ${PREFIX}/etc/shorewall2/policy
    echo
    echo "Policy file installed as ${PREFIX}/etc/shorewall2/policy"
fi
#
# Install the interfaces file
#
if [ -f ${PREFIX}/etc/shorewall2/interfaces ]; then
    backup_file /etc/shorewall2/interfaces
else
    run_install -o $OWNER -g $GROUP -m 0600 interfaces ${PREFIX}/etc/shorewall2/interfaces
    echo
    echo "Interfaces file installed as ${PREFIX}/etc/shorewall2/interfaces"
fi
#
# Install the hosts file
#
if [ -f ${PREFIX}/etc/shorewall2/hosts ]; then
    backup_file /etc/shorewall2/hosts
else
    run_install -o $OWNER -g $GROUP -m 0600 hosts ${PREFIX}/etc/shorewall2/hosts
    echo
    echo "Hosts file installed as ${PREFIX}/etc/shorewall2/hosts"
fi
#
# Install the rules file
#
if [ -f ${PREFIX}/etc/shorewall2/rules ]; then
    backup_file /etc/shorewall2/rules
else
    run_install -o $OWNER -g $GROUP -m 0600 rules ${PREFIX}/etc/shorewall2/rules
    echo
    echo "Rules file installed as ${PREFIX}/etc/shorewall2/rules"
fi
#
# Install the NAT file
#
if [ -f ${PREFIX}/etc/shorewall2/nat ]; then
    backup_file /etc/shorewall2/nat
else
    run_install -o $OWNER -g $GROUP -m 0600 nat ${PREFIX}/etc/shorewall2/nat
    echo
    echo "NAT file installed as ${PREFIX}/etc/shorewall2/nat"
fi
#
# Install the Parameters file
#
if [ -f ${PREFIX}/etc/shorewall2/params ]; then
    backup_file /etc/shorewall2/params
else
    run_install -o $OWNER -g $GROUP -m 0600 params ${PREFIX}/etc/shorewall2/params
    echo
    echo "Parameter file installed as ${PREFIX}/etc/shorewall2/params"
fi
#
# Install the proxy ARP file
#
if [ -f ${PREFIX}/etc/shorewall2/proxyarp ]; then
    backup_file /etc/shorewall2/proxyarp
else
    run_install -o $OWNER -g $GROUP -m 0600 proxyarp ${PREFIX}/etc/shorewall2/proxyarp
    echo
    echo "Proxy ARP file installed as ${PREFIX}/etc/shorewall2/proxyarp"
fi
#
# Install the Stopped Routing file
#
if [ -f ${PREFIX}/etc/shorewall2/routestopped ]; then
    backup_file /etc/shorewall2/routestopped
else
    run_install -o $OWNER -g $GROUP -m 0600 routestopped ${PREFIX}/etc/shorewall2/routestopped
    echo
    echo "Stopped Routing file installed as ${PREFIX}/etc/shorewall2/routestopped"
fi
#
# Install the Mac List file
#
if [ -f ${PREFIX}/etc/shorewall2/maclist ]; then
    backup_file /etc/shorewall2/maclist
else
    run_install -o $OWNER -g $GROUP -m 0600 maclist ${PREFIX}/etc/shorewall2/maclist
    echo
    echo "MAC list file installed as ${PREFIX}/etc/shorewall2/maclist"
fi
#
# Install the Masq file
#
if [ -f ${PREFIX}/etc/shorewall2/masq ]; then
    backup_file /etc/shorewall2/masq
else
    run_install -o $OWNER -g $GROUP -m 0600 masq ${PREFIX}/etc/shorewall2/masq
    echo
    echo "Masquerade file installed as ${PREFIX}/etc/shorewall2/masq"
fi
#
# Install the Modules file
#
if [ -f ${PREFIX}/etc/shorewall2/modules ]; then
    backup_file /etc/shorewall2/modules
else
    run_install -o $OWNER -g $GROUP -m 0600 modules ${PREFIX}/etc/shorewall2/modules
    echo
    echo "Modules file installed as ${PREFIX}/etc/shorewall2/modules"
fi
#
# Install the TC Rules file
#
if [ -f ${PREFIX}/etc/shorewall2/tcrules ]; then
    backup_file /etc/shorewall2/tcrules
else
    run_install -o $OWNER -g $GROUP -m 0600 tcrules ${PREFIX}/etc/shorewall2/tcrules
    echo
    echo "TC Rules file installed as ${PREFIX}/etc/shorewall2/tcrules"
fi

#
# Install the TOS file
#
if [ -f ${PREFIX}/etc/shorewall2/tos ]; then
    backup_file /etc/shorewall2/tos
else
    run_install -o $OWNER -g $GROUP -m 0600 tos ${PREFIX}/etc/shorewall2/tos
    echo
    echo "TOS file installed as ${PREFIX}/etc/shorewall2/tos"
fi
#
# Install the Tunnels file
#
if [ -f ${PREFIX}/etc/shorewall2/tunnels ]; then
    backup_file /etc/shorewall2/tunnels
else
    run_install -o $OWNER -g $GROUP -m 0600 tunnels ${PREFIX}/etc/shorewall2/tunnels
    echo
    echo "Tunnels file installed as ${PREFIX}/etc/shorewall2/tunnels"
fi
#
# Install the blacklist file
#
if [ -f ${PREFIX}/etc/shorewall2/blacklist ]; then
    backup_file /etc/shorewall2/blacklist
else
    run_install -o $OWNER -g $GROUP -m 0600 blacklist ${PREFIX}/etc/shorewall2/blacklist
    echo
    echo "Blacklist file installed as ${PREFIX}/etc/shorewall2/blacklist"
fi
#
# Backup and remove the whitelist file
#
if [ -f ${PREFIX}/etc/shorewall2/whitelist ]; then
    backup_file /etc/shorewall2/whitelist
    rm -f ${PREFIX}/etc/shorewall2/whitelist
fi
#
# Install the rfc1918 file
#
if [ -f ${PREFIX}/etc/shorewall2/rfc1918 ]; then
    backup_file /etc/shorewall2/rfc1918
else
    run_install -o $OWNER -g $GROUP -m 0600 rfc1918 ${PREFIX}/etc/shorewall2/rfc1918
    echo
    echo "RFC 1918 file installed as ${PREFIX}/etc/shorewall2/rfc1918"
fi
#
# Install the init file
#
if [ -f ${PREFIX}/etc/shorewall2/init ]; then
    backup_file /etc/shorewall2/init
else
    run_install -o $OWNER -g $GROUP -m 0600 init ${PREFIX}/etc/shorewall2/init
    echo
    echo "Init file installed as ${PREFIX}/etc/shorewall2/init"
fi
#
# Install the start file
#
if [ -f ${PREFIX}/etc/shorewall2/start ]; then
    backup_file /etc/shorewall2/start
else
    run_install -o $OWNER -g $GROUP -m 0600 start ${PREFIX}/etc/shorewall2/start
    echo
    echo "Start file installed as ${PREFIX}/etc/shorewall2/start"
fi
#
# Install the stop file
#
if [ -f ${PREFIX}/etc/shorewall2/stop ]; then
    backup_file /etc/shorewall2/stop
else
    run_install -o $OWNER -g $GROUP -m 0600 stop ${PREFIX}/etc/shorewall2/stop
    echo
    echo "Stop file installed as ${PREFIX}/etc/shorewall2/stop"
fi
#
# Install the stopped file
#
if [ -f ${PREFIX}/etc/shorewall2/stopped ]; then
    backup_file /etc/shorewall2/stopped
else
    run_install -o $OWNER -g $GROUP -m 0600 stopped ${PREFIX}/etc/shorewall2/stopped
    echo
    echo "Stopped file installed as ${PREFIX}/etc/shorewall2/stopped"
fi
#
# Install the ECN file
#
if [ -f ${PREFIX}/etc/shorewall2/ecn ]; then
    backup_file /etc/shorewall2/ecn
else
    run_install -o $OWNER -g $GROUP -m 0600 ecn ${PREFIX}/etc/shorewall2/ecn
    echo
    echo "ECN file installed as ${PREFIX}/etc/shorewall2/ecn"
fi
#
# Install the Accounting file
#
if [ -f ${PREFIX}/etc/shorewall2/accounting ]; then
    backup_file /etc/shorewall2/accounting
else
    run_install -o $OWNER -g $GROUP -m 0600 accounting ${PREFIX}/etc/shorewall2/accounting
    echo
    echo "Accounting file installed as ${PREFIX}/etc/shorewall2/accounting"
fi
#
#
# Install the Actions file
#
if [ -f ${PREFIX}/etc/shorewall2/actions ]; then
    backup_file /etc/shorewall2/actions
else
    run_install -o $OWNER -g $GROUP -m 0600 actions ${PREFIX}/etc/shorewall2/actions
    echo
    echo "Actions file installed as ${PREFIX}/etc/shorewall2/actions"
fi
#
# Install the Action files
#
for f in action.* ; do
    if [ -f ${PREFIX}/etc/shorewall2/$f ]; then
	backup_file /etc/shorewall2/$f
    else
	run_install -o $OWNER -g $GROUP -m 0600 $f ${PREFIX}/etc/shorewall2/$f
	echo
	echo "Action ${f#*.} file installed as ${PREFIX}/etc/shorewall2/$f"
    fi
done
#
# Backup the version file
#
if [ -z "$PREFIX" ]; then
    if [ -f /usr/share/shorewall2/version ]; then
	backup_file /usr/share/shorewall2/version
    fi
fi
#
# Create the version file
#
echo "$VERSION" > ${PREFIX}/usr/share/shorewall2/version
chmod 644 ${PREFIX}/usr/share/shorewall2/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$PREFIX" ]; then
    rm -f /usr/share/shorewall2/init
    ln -s ${DEST}/${FIREWALL} /usr/share/shorewall2/init
fi
#
# Install the firewall script
#
install_file_with_backup firewall ${PREFIX}/usr/share/shorewall2/firewall 0544

if [ -z "$PREFIX" -a -n "$first_install" ]; then
    if [ -n "$DEBIAN" ]; then
	run_install -o $OWNER -g $GROUP -m 0644 default.debian /etc/default/shorewall2
	ln -s ../init.d/shorewall2 /etc/rcS.d/S40shorewall2
	echo
	echo "Shorewall2 will start automatically at boot"
    else
	if [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
	    if insserv /etc/init.d/shorewalls ; then
		echo
		echo "Shorewall2 will start automatically at boot"
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	    if chkconfig --add shorewall2 ; then
		echo
		echo "Shorewall2 will start automatically in run levels as follows:"
		chkconfig --list $FIREWALL
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/rc-update ]; then
	    if rc-update add shorewall2 default; then
		echo
		echo "Shorewall2 will start automatically at boot"
	    else
		cant_autostart
	    fi
	else
	    cant_autostart
	fi

	echo \
"########################################################################
#      REMOVE THIS FILE AFTER YOU HAVE CONFIGURED SHOREWALL            #
########################################################################" > /etc/shorewall2/startup_disabled
    fi
fi

#
#  Report Success
#
echo
echo "Shorewall2 Version $VERSION Installed"
