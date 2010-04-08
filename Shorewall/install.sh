#!/bin/sh
#
# Script to install Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000,2001,2002,2003,2004,2005,2006,2007,2009,2009,2010 - Tom Eastep (teastep@shorewall.net)
#
#       Shorewall documentation is available at http://shorewall.net
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

VERSION=4.4.8.2

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME"
    echo "       $ME -v"
    echo "       $ME -h"
    exit $1
}

split() {
    local ifs
    ifs=$IFS
    IFS=:
    set -- $1
    echo $*
    IFS=$ifs
}

qt()
{
    "$@" >/dev/null 2>&1
}

mywhich() {
    local dir

    for dir in $(split $PATH); do
	if [ -x $dir/$1 ]; then
	    echo $dir/$1
	    return 0
	fi
    done

    return 2
}

run_install()
{
    if ! install $*; then
	echo
	echo "ERROR: Failed to install $*" >&2
	exit 1
    fi
}

cant_autostart()
{
    echo
    echo  "WARNING: Unable to configure shorewall to start automatically at boot" >&2
}

delete_file() # $1 = file to delete
{
    rm -f $1
}

install_file() # $1 = source $2 = target $3 = mode
{
    run_install $OWNERSHIP -m $3 $1 ${2}
}

#
# Parse the run line
#
# DEST is the SysVInit script directory
# INIT is the name of the script in the $DEST directory
# RUNLEVELS is the chkconfig parmeters for firewall
# ARGS is "yes" if we've already parsed an argument
#
ARGS=""

if [ -z "$DEST" ] ; then
	DEST="/etc/init.d"
fi

if [ -z "$INIT" ] ; then
	INIT="shorewall"
fi

if [ -z "$RUNLEVELS" ] ; then
	RUNLEVELS=""
fi

DEBIAN=
CYGWIN=
SPARSE=
MANDIR=${MANDIR:-"/usr/share/man"}

case $(uname) in
    CYGWIN*)
	if [ -z "$PREFIX" ]; then
	    DEST=
	    INIT=
	fi

	OWNER=$(id -un)
	GROUP=$(id -gn)
	CYGWIN=Yes
	SPARSE=Yes
	;;
    *)
	[ -z "$OWNER" ] && OWNER=root
	[ -z "$GROUP" ] && GROUP=root
	;;
esac

OWNERSHIP="-o $OWNER -g $GROUP"

while [ $# -gt 0 ] ; do
    case "$1" in
	-h|help|?)
	    usage 0
	    ;;
        -v)
	    echo "Shorewall Firewall Installer Version $VERSION"
	    exit 0
	    ;;
	-s)
	    SPARSE=Yes
	    ;;
	*)
	    usage 1
	    ;;
    esac
    shift
    ARGS="yes"
done

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

#
# Determine where to install the firewall script
#

if [ -n "$PREFIX" ]; then
    if [ -z "$CYGWIN" ]; then
	if [ `id -u` != 0 ] ; then
	    echo "Not setting file owner/group permissions, not running as root."
	    OWNERSHIP=""
	fi
    fi

    install -d $OWNERSHIP -m 755 ${PREFIX}/sbin
    install -d $OWNERSHIP -m 755 ${PREFIX}${DEST}
    
    CYGWIN=
else
    #
    # Verify that Perl is installed
    #
    if ! perl -c Perl/compiler.pl; then
	echo "ERROR: Shorewall $VERSION requires Perl which either is not installed or is not able to compile the Shorewall perl code" >&2
	echo "       Try perl -c $PWD/Perl/compiler.pl" >&2
	exit 1
    fi

    if [ -n "$CYGWIN" ]; then
	echo "Installing Cygwin-specific configuration..."
    else
	if [ -f /etc/debian_version ]; then
	    echo "Installing Debian-specific configuration..."
	    DEBIAN=yes
	    SPARSE=yes
	elif [ -f /etc/slackware-version ] ; then
	    echo "Installing Slackware-specific configuration..."
	    DEST="/etc/rc.d"
	    MANDIR="/usr/man"
	    SLACKWARE=yes
	elif [ -f /etc/arch-release ] ; then
	    echo "Installing ArchLinux-specific configuration..."
	    DEST="/etc/rc.d"
	    INIT="shorewall"
	    ARCHLINUX=yes
	fi
    fi
fi

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

echo "Installing Shorewall Version $VERSION"

#
# Check for /etc/shorewall
#
if [ -d ${PREFIX}/etc/shorewall ]; then
    first_install=""
else
    first_install="Yes"
fi

if [ -z "$CYGWIN" ]; then
   install_file shorewall ${PREFIX}/sbin/shorewall 0755
   echo "shorewall control program installed in ${PREFIX}/sbin/shorewall"
else
   install_file shorewall ${PREFIX}/bin/shorewall 0755
   echo "shorewall control program installed in ${PREFIX}/bin/shorewall"
fi

#
# Install the Firewall Script
#
if [ -n "$DEBIAN" ]; then
    install_file init.debian.sh /etc/init.d/shorewall 0544
elif [ -n "$ARCHLINUX" ]; then
    install_file init.archlinux.sh ${PREFIX}${DEST}/$INIT 0544
elif [ -n "$SLACKWARE" ]; then
	install_file init.slackware.firewall.sh ${PREFIX}${DEST}/rc.firewall 0644
	install_file init.slackware.shorewall.sh ${PREFIX}${DEST}/rc.shorewall 0644
elif [ -n "$INIT" ]; then
    install_file init.sh ${PREFIX}${DEST}/$INIT 0544
fi

[ -n "$CYGWIN" ] || echo  "Shorewall script installed in ${PREFIX}${DEST}/$INIT"

#
# Create /etc/shorewall, /usr/share/shorewall and /var/shorewall if needed
#
mkdir -p ${PREFIX}/etc/shorewall
mkdir -p ${PREFIX}/usr/share/shorewall
mkdir -p ${PREFIX}/usr/share/shorewall/configfiles
mkdir -p ${PREFIX}/var/lib/shorewall

chmod 755 ${PREFIX}/etc/shorewall
chmod 755 ${PREFIX}/usr/share/shorewall
chmod 755 ${PREFIX}/usr/share/shorewall/configfiles

if [ -n "$PREFIX" ]; then
    mkdir -p ${PREFIX}/etc/logrotate.d
    chmod 755 ${PREFIX}/etc/logrotate.d
fi
    
#
# Install the config file
#
run_install $OWNERSHIP -m 0644 configfiles/shorewall.conf ${PREFIX}/usr/share/shorewall/configfiles/shorewall.conf

perl -p -w -i -e 's|^CONFIG_PATH=.*|CONFIG_PATH=/usr/share/shorewall/configfiles:/usr/share/shorewall|;' ${PREFIX}/usr/share/shorewall/configfiles/shorewall.conf

if [ ! -f ${PREFIX}/etc/shorewall/shorewall.conf ]; then
   run_install $OWNERSHIP -m 0644 configfiles/shorewall.conf ${PREFIX}/etc/shorewall/shorewall.conf

   if [ -n "$DEBIAN" ] && mywhich perl; then
       #
       # Make a Debian-like shorewall.conf
       #
       perl -p -w -i -e 's|^STARTUP_ENABLED=.*|STARTUP_ENABLED=Yes|;' ${PREFIX}/etc/shorewall.conf
   fi

   echo "Config file installed as ${PREFIX}/etc/shorewall/shorewall.conf"
fi

if [ -n "$ARCHLINUX" ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${PREFIX}/etc/shorewall/shorewall.conf
fi
#
# Install the zones file
#
run_install $OWNERSHIP -m 0644 configfiles/zones ${PREFIX}/usr/share/shorewall/configfiles/zones

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/zones ]; then
    run_install $OWNERSHIP -m 0744 configfiles/zones ${PREFIX}/etc/shorewall/zones
    echo "Zones file installed as ${PREFIX}/etc/shorewall/zones"
fi

delete_file ${PREFIX}/usr/share/shorewall/compiler
delete_file ${PREFIX}/usr/share/shorewall/lib.accounting
delete_file ${PREFIX}/usr/share/shorewall/lib.actions
delete_file ${PREFIX}/usr/share/shorewall/lib.dynamiczones
delete_file ${PREFIX}/usr/share/shorewall/lib.maclist
delete_file ${PREFIX}/usr/share/shorewall/lib.nat
delete_file ${PREFIX}/usr/share/shorewall/lib.providers
delete_file ${PREFIX}/usr/share/shorewall/lib.proxyarp
delete_file ${PREFIX}/usr/share/shorewall/lib.tc
delete_file ${PREFIX}/usr/share/shorewall/lib.tcrules
delete_file ${PREFIX}/usr/share/shorewall/lib.tunnels
delete_file ${PREFIX}/usr/share/shorewall/prog.header
delete_file ${PREFIX}/usr/share/shorewall/prog.footer

#
# Install wait4ifup
#

install_file wait4ifup ${PREFIX}/usr/share/shorewall/wait4ifup 0755

echo
echo "wait4ifup installed in ${PREFIX}/usr/share/shorewall/wait4ifup"

#
# Install the policy file
#
run_install $OWNERSHIP -m 0644 configfiles/policy ${PREFIX}/usr/share/shorewall/configfiles/policy

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/policy ]; then
    run_install $OWNERSHIP -m 0600 configfiles/policy ${PREFIX}/etc/shorewall/policy
    echo "Policy file installed as ${PREFIX}/etc/shorewall/policy"
fi
#
# Install the interfaces file
#
run_install $OWNERSHIP -m 0644 configfiles/interfaces ${PREFIX}/usr/share/shorewall/configfiles/interfaces

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/interfaces ]; then
    run_install $OWNERSHIP -m 0600 configfiles/interfaces ${PREFIX}/etc/shorewall/interfaces
    echo "Interfaces file installed as ${PREFIX}/etc/shorewall/interfaces"
fi

#
# Install the hosts file
#
run_install $OWNERSHIP -m 0644 configfiles/hosts ${PREFIX}/usr/share/shorewall/configfiles/hosts

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/hosts ]; then
    run_install $OWNERSHIP -m 0600 configfiles/hosts ${PREFIX}/etc/shorewall/hosts
    echo "Hosts file installed as ${PREFIX}/etc/shorewall/hosts"
fi
#
# Install the rules file
#
run_install $OWNERSHIP -m 0644 configfiles/rules ${PREFIX}/usr/share/shorewall/configfiles/rules

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/rules ]; then
    run_install $OWNERSHIP -m 0600 configfiles/rules ${PREFIX}/etc/shorewall/rules
    echo "Rules file installed as ${PREFIX}/etc/shorewall/rules"
fi
#
# Install the NAT file
#
run_install $OWNERSHIP -m 0644 configfiles/nat ${PREFIX}/usr/share/shorewall/configfiles/nat

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/nat ]; then
    run_install $OWNERSHIP -m 0600 configfiles/nat ${PREFIX}/etc/shorewall/nat
    echo "NAT file installed as ${PREFIX}/etc/shorewall/nat"
fi
#
# Install the NETMAP file
#
run_install $OWNERSHIP -m 0644 configfiles/netmap ${PREFIX}/usr/share/shorewall/configfiles/netmap

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/netmap ]; then
    run_install $OWNERSHIP -m 0600 configfiles/netmap ${PREFIX}/etc/shorewall/netmap
    echo "NETMAP file installed as ${PREFIX}/etc/shorewall/netmap"
fi
#
# Install the Parameters file
#
run_install $OWNERSHIP -m 0644 configfiles/params ${PREFIX}/usr/share/shorewall/configfiles/params

if [ -f ${PREFIX}/etc/shorewall/params ]; then
    chmod 0644 ${PREFIX}/etc/shorewall/params
else
    run_install $OWNERSHIP -m 0644 configfiles/params ${PREFIX}/etc/shorewall/params
    echo "Parameter file installed as ${PREFIX}/etc/shorewall/params"
fi
#
# Install the proxy ARP file
#
run_install $OWNERSHIP -m 0644 configfiles/proxyarp ${PREFIX}/usr/share/shorewall/configfiles/proxyarp

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/proxyarp ]; then
    run_install $OWNERSHIP -m 0600 configfiles/proxyarp ${PREFIX}/etc/shorewall/proxyarp
    echo "Proxy ARP file installed as ${PREFIX}/etc/shorewall/proxyarp"
fi
#
# Install the Stopped Routing file
#
run_install $OWNERSHIP -m 0644 configfiles/routestopped ${PREFIX}/usr/share/shorewall/configfiles/routestopped

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/routestopped ]; then
    run_install $OWNERSHIP -m 0600 configfiles/routestopped ${PREFIX}/etc/shorewall/routestopped
    echo "Stopped Routing file installed as ${PREFIX}/etc/shorewall/routestopped"
fi
#
# Install the Mac List file
#
run_install $OWNERSHIP -m 0644 configfiles/maclist ${PREFIX}/usr/share/shorewall/configfiles/maclist

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/maclist ]; then
    run_install $OWNERSHIP -m 0600 configfiles/maclist ${PREFIX}/etc/shorewall/maclist
    echo "MAC list file installed as ${PREFIX}/etc/shorewall/maclist"
fi
#
# Install the Masq file
#
run_install $OWNERSHIP -m 0644 configfiles/masq ${PREFIX}/usr/share/shorewall/configfiles/masq

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/masq ]; then
    run_install $OWNERSHIP -m 0600 configfiles/masq ${PREFIX}/etc/shorewall/masq
    echo "Masquerade file installed as ${PREFIX}/etc/shorewall/masq"
fi
#
# Install the Notrack file
#
run_install $OWNERSHIP -m 0644 configfiles/notrack ${PREFIX}/usr/share/shorewall/configfiles/notrack

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/notrack ]; then
    run_install $OWNERSHIP -m 0600 configfiles/notrack ${PREFIX}/etc/shorewall/notrack
    echo "Notrack file installed as ${PREFIX}/etc/shorewall/notrack"
fi
#
# Install the Modules file
#
run_install $OWNERSHIP -m 0600 modules ${PREFIX}/usr/share/shorewall/modules
echo "Modules file installed as ${PREFIX}/usr/share/shorewall/modules"

#
# Install the Module Helpers file
#
run_install $OWNERSHIP -m 0600 helpers ${PREFIX}/usr/share/shorewall/helpers
echo "Helper modules file installed as ${PREFIX}/usr/share/shorewall/helpers"

#
# Install the TC Rules file
#
run_install $OWNERSHIP -m 0644 configfiles/tcrules ${PREFIX}/usr/share/shorewall/configfiles/tcrules

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/tcrules ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcrules ${PREFIX}/etc/shorewall/tcrules
    echo "TC Rules file installed as ${PREFIX}/etc/shorewall/tcrules"
fi

#
# Install the TC Interfaces file
#
run_install $OWNERSHIP -m 0644 configfiles/tcinterfaces ${PREFIX}/usr/share/shorewall/configfiles/tcinterfaces

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/tcinterfaces ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcinterfaces ${PREFIX}/etc/shorewall/tcinterfaces
    echo "TC Interfaces file installed as ${PREFIX}/etc/shorewall/tcinterfaces"
fi

#
# Install the TC Priority file
#
run_install $OWNERSHIP -m 0644 configfiles/tcpri ${PREFIX}/usr/share/shorewall/configfiles/tcpri

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/tcpri ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcpri ${PREFIX}/etc/shorewall/tcpri
    echo "TC Priority file installed as ${PREFIX}/etc/shorewall/tcpri"
fi

#
# Install the TOS file
#
run_install $OWNERSHIP -m 0644 configfiles/tos ${PREFIX}/usr/share/shorewall/configfiles/tos

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/tos ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tos ${PREFIX}/etc/shorewall/tos
    echo "TOS file installed as ${PREFIX}/etc/shorewall/tos"
fi
#
# Install the Tunnels file
#
run_install $OWNERSHIP -m 0644 configfiles/tunnels ${PREFIX}/usr/share/shorewall/configfiles/tunnels

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/tunnels ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tunnels ${PREFIX}/etc/shorewall/tunnels
    echo "Tunnels file installed as ${PREFIX}/etc/shorewall/tunnels"
fi
#
# Install the blacklist file
#
run_install $OWNERSHIP -m 0644 configfiles/blacklist ${PREFIX}/usr/share/shorewall/configfiles/blacklist

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/blacklist ]; then
    run_install $OWNERSHIP -m 0600 configfiles/blacklist ${PREFIX}/etc/shorewall/blacklist
    echo "Blacklist file installed as ${PREFIX}/etc/shorewall/blacklist"
fi
#
# Install the findgw file
#
run_install $OWNERSHIP -m 0644 configfiles/findgw ${PREFIX}/usr/share/shorewall/configfiles/findgw

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/findgw ]; then
    run_install $OWNERSHIP -m 0600 configfiles/findgw ${PREFIX}/etc/shorewall/findgw
    echo "Find GW file installed as ${PREFIX}/etc/shorewall/findgw"
fi
#
# Delete the Routes file
#
delete_file ${PREFIX}/etc/shorewall/routes
#
# Delete the tcstart file
#

delete_file ${PREFIX}/usr/share/shorewall/tcstart

#
# Delete the Limits Files
#
delete_file ${PREFIX}/usr/share/shorewall/action.Limit
delete_file ${PREFIX}/usr/share/shorewall/Limit
#
# Delete the xmodules file
#
delete_file ${PREFIX}/usr/share/shorewall/xmodules
#
# Install the Providers file
#
run_install $OWNERSHIP -m 0644 configfiles/providers ${PREFIX}/usr/share/shorewall/configfiles/providers

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/providers ]; then
    run_install $OWNERSHIP -m 0600 configfiles/providers ${PREFIX}/etc/shorewall/providers
    echo "Providers file installed as ${PREFIX}/etc/shorewall/providers"
fi

#
# Install the Route Rules file
#
run_install $OWNERSHIP -m 0644 configfiles/route_rules ${PREFIX}/usr/share/shorewall/configfiles/route_rules

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/route_rules ]; then
    run_install $OWNERSHIP -m 0600 configfiles/route_rules ${PREFIX}/etc/shorewall/route_rules
    echo "Routing rules file installed as ${PREFIX}/etc/shorewall/route_rules"
fi

#
# Install the tcclasses file
#
run_install $OWNERSHIP -m 0644 configfiles/tcclasses ${PREFIX}/usr/share/shorewall/configfiles/tcclasses

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/tcclasses ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcclasses ${PREFIX}/etc/shorewall/tcclasses
    echo "TC Classes file installed as ${PREFIX}/etc/shorewall/tcclasses"
fi

#
# Install the tcdevices file
#
run_install $OWNERSHIP -m 0644 configfiles/tcdevices ${PREFIX}/usr/share/shorewall/configfiles/tcdevices

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/tcdevices ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcdevices ${PREFIX}/etc/shorewall/tcdevices
    echo "TC Devices file installed as ${PREFIX}/etc/shorewall/tcdevices"
fi

#
# Install the tcfilters file
#
run_install $OWNERSHIP -m 0644 configfiles/tcfilters ${PREFIX}/usr/share/shorewall/configfiles/tcfilters

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/tcfilters ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcfilters ${PREFIX}/etc/shorewall/tcfilters
    echo "TC Filters file installed as ${PREFIX}/etc/shorewall/tcfilters"
fi

#
# Install the default config path file
#
install_file configpath ${PREFIX}/usr/share/shorewall/configpath 0644
echo "Default config path file installed as ${PREFIX}/usr/share/shorewall/configpath"
#
# Install the init file
#
run_install $OWNERSHIP -m 0644 configfiles/init ${PREFIX}/usr/share/shorewall/configfiles/init

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/init ]; then
    run_install $OWNERSHIP -m 0600 configfiles/init ${PREFIX}/etc/shorewall/init
    echo "Init file installed as ${PREFIX}/etc/shorewall/init"
fi
#
# Install the initdone file
#
run_install $OWNERSHIP -m 0644 configfiles/initdone ${PREFIX}/usr/share/shorewall/configfiles/initdone

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/initdone ]; then
    run_install $OWNERSHIP -m 0600 configfiles/initdone ${PREFIX}/etc/shorewall/initdone
    echo "Initdone file installed as ${PREFIX}/etc/shorewall/initdone"
fi
#
# Install the start file
#
run_install $OWNERSHIP -m 0644 configfiles/start ${PREFIX}/usr/share/shorewall/configfiles/start

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/start ]; then
    run_install $OWNERSHIP -m 0600 configfiles/start ${PREFIX}/etc/shorewall/start
    echo "Start file installed as ${PREFIX}/etc/shorewall/start"
fi
#
# Install the stop file
#
run_install $OWNERSHIP -m 0644 configfiles/stop ${PREFIX}/usr/share/shorewall/configfiles/stop

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/stop ]; then
    run_install $OWNERSHIP -m 0600 configfiles/stop ${PREFIX}/etc/shorewall/stop
    echo "Stop file installed as ${PREFIX}/etc/shorewall/stop"
fi
#
# Install the stopped file
#
run_install $OWNERSHIP -m 0644 configfiles/stopped ${PREFIX}/usr/share/shorewall/configfiles/stopped

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/stopped ]; then
    run_install $OWNERSHIP -m 0600 configfiles/stopped ${PREFIX}/etc/shorewall/stopped
    echo "Stopped file installed as ${PREFIX}/etc/shorewall/stopped"
fi
#
# Install the ECN file
#
run_install $OWNERSHIP -m 0644 configfiles/ecn ${PREFIX}/usr/share/shorewall/configfiles/ecn

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/ecn ]; then
    run_install $OWNERSHIP -m 0600 configfiles/ecn ${PREFIX}/etc/shorewall/ecn
    echo "ECN file installed as ${PREFIX}/etc/shorewall/ecn"
fi
#
# Install the Accounting file
#
run_install $OWNERSHIP -m 0644 configfiles/accounting ${PREFIX}/usr/share/shorewall/configfiles/accounting

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/accounting ]; then
    run_install $OWNERSHIP -m 0600 configfiles/accounting ${PREFIX}/etc/shorewall/accounting
    echo "Accounting file installed as ${PREFIX}/etc/shorewall/accounting"
fi
#
# Install the private library file
#
run_install $OWNERSHIP -m 0644 configfiles/lib.private ${PREFIX}/usr/share/shorewall/configfiles/lib.private

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/lib.private ]; then
    run_install $OWNERSHIP -m 0600 configfiles/lib.private ${PREFIX}/etc/shorewall/lib.private
    echo "Private library file installed as ${PREFIX}/etc/shorewall/lib.private"
fi
#
# Install the Started file
#
run_install $OWNERSHIP -m 0644 configfiles/started ${PREFIX}/usr/share/shorewall/configfiles/started

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/started ]; then
    run_install $OWNERSHIP -m 0600 configfiles/started ${PREFIX}/etc/shorewall/started
    echo "Started file installed as ${PREFIX}/etc/shorewall/started"
fi
#
# Install the Restored file
#
run_install $OWNERSHIP -m 0644 configfiles/restored ${PREFIX}/usr/share/shorewall/configfiles/restored

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/restored ]; then
    run_install $OWNERSHIP -m 0600 configfiles/restored ${PREFIX}/etc/shorewall/restored
    echo "Restored file installed as ${PREFIX}/etc/shorewall/restored"
fi
#
# Install the Clear file
#
run_install $OWNERSHIP -m 0644 configfiles/clear ${PREFIX}/usr/share/shorewall/configfiles/clear

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/clear ]; then
    run_install $OWNERSHIP -m 0600 configfiles/clear ${PREFIX}/etc/shorewall/clear
    echo "Clear file installed as ${PREFIX}/etc/shorewall/clear"
fi
#
# Install the Isusable file
#
run_install $OWNERSHIP -m 0644 configfiles/isusable ${PREFIX}/usr/share/shorewall/configfiles/isusable

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/isusable ]; then
    run_install $OWNERSHIP -m 0600 configfiles/isusable ${PREFIX}/etc/shorewall/isusable
    echo "Isusable file installed as ${PREFIX}/etc/shorewall/isusable"
fi
#
# Install the Refresh file
#
run_install $OWNERSHIP -m 0644 configfiles/refresh ${PREFIX}/usr/share/shorewall/configfiles/refresh

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/refresh ]; then
    run_install $OWNERSHIP -m 0600 configfiles/refresh ${PREFIX}/etc/shorewall/refresh
    echo "Refresh file installed as ${PREFIX}/etc/shorewall/refresh"
fi
#
# Install the Refreshed file
#
run_install $OWNERSHIP -m 0644 configfiles/refreshed ${PREFIX}/usr/share/shorewall/configfiles/refreshed

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/refreshed ]; then
    run_install $OWNERSHIP -m 0600 configfiles/refreshed ${PREFIX}/etc/shorewall/refreshed
    echo "Refreshed file installed as ${PREFIX}/etc/shorewall/refreshed"
fi
#
# Install the Tcclear file
#
run_install $OWNERSHIP -m 0644 configfiles/tcclear ${PREFIX}/usr/share/shorewall/configfiles/tcclear

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/tcclear ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcclear ${PREFIX}/etc/shorewall/tcclear
    echo "Tcclear file installed as ${PREFIX}/etc/shorewall/tcclear"
fi
#
# Install the Standard Actions file
#
install_file actions.std ${PREFIX}/usr/share/shorewall/actions.std 0644
echo "Standard actions file installed as ${PREFIX}/usr/shared/shorewall/actions.std"

#
# Install the Actions file
#
run_install $OWNERSHIP -m 0644 configfiles/actions ${PREFIX}/usr/share/shorewall/configfiles/actions

if [ -z "$SPARSE" -a ! -f ${PREFIX}/etc/shorewall/actions ]; then
    run_install $OWNERSHIP -m 0644 configfiles/actions ${PREFIX}/etc/shorewall/actions
    echo "Actions file installed as ${PREFIX}/etc/shorewall/actions"
fi

#
# Install the  Makefiles
#
run_install $OWNERSHIP -m 0644 Makefile-lite ${PREFIX}/usr/share/shorewall/configfiles/Makefile

if [ -z "$SPARSE" ]; then
    run_install $OWNERSHIP -m 0600 Makefile ${PREFIX}/etc/shorewall/Makefile
    echo "Makefile installed as ${PREFIX}/etc/shorewall/Makefile"
fi
#
# Install the Action files
#
for f in action.* ; do
    install_file $f ${PREFIX}/usr/share/shorewall/$f 0644
    echo "Action ${f#*.} file installed as ${PREFIX}/usr/share/shorewall/$f"
done

# Install the Macro files
#
cd Macros

for f in macro.* ; do
    install_file $f ${PREFIX}/usr/share/shorewall/$f 0644
    echo "Macro ${f#*.} file installed as ${PREFIX}/usr/share/shorewall/$f"
done

cd ..
#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${PREFIX}/usr/share/shorewall/$f 0644
	echo "Library ${f#*.} file installed as ${PREFIX}/usr/share/shorewall/$f"
    fi
done
#
# Symbolically link 'functions' to lib.base
#
ln -sf lib.base ${PREFIX}/usr/share/shorewall/functions
#
# /usr/share/shorewall/Shorewall if needed
#
mkdir -p ${PREFIX}/usr/share/shorewall/Shorewall
chmod 755 ${PREFIX}/usr/share/shorewall/Shorewall
#
# Install the Compiler
#
cd Perl

install_file compiler.pl ${PREFIX}/usr/share/shorewall/compiler.pl 0755

echo
echo "Compiler installed in ${PREFIX}/usr/share/shorewall/compiler.pl"
#
# Install the libraries
#
for f in Shorewall/*.pm ; do
    install_file $f ${PREFIX}/usr/share/shorewall/$f 0644
    echo "Module ${f%.*} installed as ${PREFIX}/usr/share/shorewall/$f"
done
#
# Install the program skeleton files
#
for f in prog.* ; do
    install_file $f ${PREFIX}/usr/share/shorewall/$f 0644
    echo "Program skeleton file ${f#*.} installed as ${PREFIX}/usr/share/shorewall/$f"
done

cd ..
#
# Create the version file
#
echo "$VERSION" > ${PREFIX}/usr/share/shorewall/version
chmod 644 ${PREFIX}/usr/share/shorewall/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$PREFIX" ]; then
    rm -f /usr/share/shorewall/init
    ln -s ${DEST}/${INIT} /usr/share/shorewall/init
fi

#
# Install the Man Pages
#

cd manpages

for f in *.5; do
    gzip -c $f > $f.gz
    run_install -D  -m 0644 $f.gz ${PREFIX}${MANDIR}/man5/$f.gz
    echo "Man page $f.gz installed to ${PREFIX}${MANDIR}/man5/$f.gz"
done

for f in *.8; do
    gzip -c $f > $f.gz
    run_install -D  -m 0644 $f.gz ${PREFIX}${MANDIR}/man8/$f.gz
    echo "Man page $f.gz installed to ${PREFIX}${MANDIR}/man8/$f.gz"
done

cd ..

echo "Man Pages Installed"

if [ -d ${PREFIX}/etc/logrotate.d ]; then
    run_install $OWNERSHIP -m 0644 logrotate ${PREFIX}/etc/logrotate.d/shorewall
    echo "Logrotate file installed as ${PREFIX}/etc/logrotate.d/shorewall"
fi

if [ -z "$PREFIX" ]; then
    rm -rf /usr/share/shorewall-perl
    rm -rf /usr/share/shorewall-shell
fi

if [ -z "$PREFIX" -a -n "$first_install" -a -z "$CYGWIN" ]; then
    if [ -n "$DEBIAN" ]; then
	run_install $OWNERSHIP -m 0644 default.debian /etc/default/shorewall
	ln -s ../init.d/shorewall /etc/rcS.d/S40shorewall
	echo "shorewall will start automatically at boot"
	echo "Set startup=1 in /etc/default/shorewall to enable"
	touch /var/log/shorewall-init.log
	perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' /etc/shorewall/shorewall.conf
    else
	if [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
	    if insserv /etc/init.d/shorewall ; then
		echo "shorewall will start automatically at boot"
		echo "Set STARTUP_ENABLED=Yes in /etc/shorewall/shorewall.conf to enable"
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	    if chkconfig --add shorewall ; then
		echo "shorewall will start automatically in run levels as follows:"
		echo "Set STARTUP_ENABLED=Yes in /etc/shorewall/shorewall.conf to enable"
		chkconfig --list shorewall
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/rc-update ]; then
	    if rc-update add shorewall default; then
		echo "shorewall will start automatically at boot"
		echo "Set STARTUP_ENABLED=Yes in /etc/shorewall/shorewall.conf to enable"
	    else
		cant_autostart
	    fi
	elif [ "$INIT" != rc.firewall ]; then #Slackware starts this automatically
	    cant_autostart
	fi
    fi
fi

#
#  Report Success
#
echo "shorewall Version $VERSION Installed"
