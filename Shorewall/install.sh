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

VERSION=4.4.13.2

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
    run_install $T $OWNERSHIP -m $3 $1 ${2}
}

[ -n "$DESTDIR" ] || DESTDIR="$PREFIX"

#
# Parse the run line
#
# DEST is the SysVInit script directory
# INIT is the name of the script in the $DEST directory
# ARGS is "yes" if we've already parsed an argument
#
ARGS=""
T="-T"

if [ -z "$DEST" ] ; then
	DEST="/etc/init.d"
fi

if [ -z "$INIT" ] ; then
	INIT="shorewall"
fi

SPARSE=
MANDIR=${MANDIR:-"/usr/share/man"}
INSTALLD='-D'

case $(uname) in
    CYGWIN*)
	if [ -z "$DESTDIR" ]; then
	    DEST=
	    INIT=
	fi

	OWNER=$(id -un)
	GROUP=$(id -gn)
	CYGWIN=Yes
	SPARSE=Yes
	;;
    Darwin)
	if [ -z "$DESTDIR" ]; then
	    DEST=
	    INIT=
	    SPARSE=Yes
	fi

	[ -z "$OWNER" ] && OWNER=root
	[ -z "$GROUP" ] && GROUP=wheel
	MAC=Yes
	INSTALLD=
	T=
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

if [ -n "$DESTDIR" ]; then
    if [ -z "$CYGWIN" ]; then
	if [ `id -u` != 0 ] ; then
	    echo "Not setting file owner/group permissions, not running as root."
	    OWNERSHIP=""
	fi
    fi

    install -d $OWNERSHIP -m 755 ${DESTDIR}/sbin
    install -d $OWNERSHIP -m 755 ${DESTDIR}${DEST}

    CYGWIN=
    MAC=
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
    elif [ -n "$MAC" ]; then
	echo "Installing Mac-specific configuration..."
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
# Check for /sbin/shorewall
#
if [ -f ${DESTDIR}/sbin/shorewall ]; then
    first_install=""
else
    first_install="Yes"
fi

if [ -z "$CYGWIN" ]; then
   install_file shorewall ${DESTDIR}/sbin/shorewall 0755
   echo "shorewall control program installed in ${DESTDIR}/sbin/shorewall"
else
   install_file shorewall ${DESTDIR}/bin/shorewall 0755
   echo "shorewall control program installed in ${DESTDIR}/bin/shorewall"
fi

#
# Install the Firewall Script
#
if [ -n "$DEBIAN" ]; then
    install_file init.debian.sh ${DESTDIR}/etc/init.d/shorewall 0544
elif [ -n "$ARCHLINUX" ]; then
    install_file init.archlinux.sh ${DESTDIR}${DEST}/$INIT 0544
elif [ -n "$SLACKWARE" ]; then
	install_file init.slackware.firewall.sh ${DESTDIR}${DEST}/rc.firewall 0644
	install_file init.slackware.shorewall.sh ${DESTDIR}${DEST}/rc.shorewall 0644
elif [ -n "$INIT" ]; then
    install_file init.sh ${DESTDIR}${DEST}/$INIT 0544
fi

[ -n "$INIT" ] && echo  "Shorewall script installed in ${DESTDIR}${DEST}/$INIT"

#
# Create /etc/shorewall, /usr/share/shorewall and /var/shorewall if needed
#
mkdir -p ${DESTDIR}/etc/shorewall
mkdir -p ${DESTDIR}/usr/share/shorewall
mkdir -p ${DESTDIR}/usr/share/shorewall/configfiles
mkdir -p ${DESTDIR}/var/lib/shorewall

chmod 755 ${DESTDIR}/etc/shorewall
chmod 755 ${DESTDIR}/usr/share/shorewall
chmod 755 ${DESTDIR}/usr/share/shorewall/configfiles

if [ -n "$DESTDIR" ]; then
    mkdir -p ${DESTDIR}/etc/logrotate.d
    chmod 755 ${DESTDIR}/etc/logrotate.d
fi

#
# Install the config file
#
run_install $OWNERSHIP -m 0644 configfiles/shorewall.conf ${DESTDIR}/usr/share/shorewall/configfiles

perl -p -w -i -e 's|^CONFIG_PATH=.*|CONFIG_PATH=/usr/share/shorewall/configfiles:/usr/share/shorewall|;' ${DESTDIR}/usr/share/shorewall/configfiles/shorewall.conf
perl -p -w -i -e 's|^STARTUP_LOG=.*|STARTUP_LOG=/var/log/shorewall-lite-init.log|;' ${DESTDIR}/usr/share/shorewall/configfiles/shorewall.conf

if [ ! -f ${DESTDIR}/etc/shorewall/shorewall.conf ]; then
   run_install $OWNERSHIP -m 0644 configfiles/shorewall.conf ${DESTDIR}/etc/shorewall

   if [ -n "$DEBIAN" ]; then
       #
       # Make a Debian-like shorewall.conf
       #
       perl -p -w -i -e 's|^STARTUP_ENABLED=.*|STARTUP_ENABLED=Yes|;' ${DESTDIR}/etc/shorewall/shorewall.conf
   fi

   echo "Config file installed as ${DESTDIR}/etc/shorewall/shorewall.conf"
fi

if [ -n "$ARCHLINUX" ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${DESTDIR}/etc/shorewall/shorewall.conf
fi
#
# Install the zones file
#
run_install $OWNERSHIP -m 0644 configfiles/zones ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/zones ]; then
    run_install $OWNERSHIP -m 0744 configfiles/zones ${DESTDIR}/etc/shorewall
    echo "Zones file installed as ${DESTDIR}/etc/shorewall/zones"
fi

delete_file ${DESTDIR}/usr/share/shorewall/compiler
delete_file ${DESTDIR}/usr/share/shorewall/lib.accounting
delete_file ${DESTDIR}/usr/share/shorewall/lib.actions
delete_file ${DESTDIR}/usr/share/shorewall/lib.dynamiczones
delete_file ${DESTDIR}/usr/share/shorewall/lib.maclist
delete_file ${DESTDIR}/usr/share/shorewall/lib.nat
delete_file ${DESTDIR}/usr/share/shorewall/lib.providers
delete_file ${DESTDIR}/usr/share/shorewall/lib.proxyarp
delete_file ${DESTDIR}/usr/share/shorewall/lib.tc
delete_file ${DESTDIR}/usr/share/shorewall/lib.tcrules
delete_file ${DESTDIR}/usr/share/shorewall/lib.tunnels
delete_file ${DESTDIR}/usr/share/shorewall/prog.header
delete_file ${DESTDIR}/usr/share/shorewall/prog.footer

#
# Install wait4ifup
#

install_file wait4ifup ${DESTDIR}/usr/share/shorewall/wait4ifup 0755

echo
echo "wait4ifup installed in ${DESTDIR}/usr/share/shorewall/wait4ifup"

#
# Install the policy file
#
install_file configfiles/policy ${DESTDIR}/usr/share/shorewall/configfiles/policy 0644

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/policy ]; then
    run_install $OWNERSHIP -m 0600 configfiles/policy ${DESTDIR}/etc/shorewall
    echo "Policy file installed as ${DESTDIR}/etc/shorewall/policy"
fi
#
# Install the interfaces file
#
run_install $OWNERSHIP -m 0644 configfiles/interfaces ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/interfaces ]; then
    run_install $OWNERSHIP -m 0600 configfiles/interfaces ${DESTDIR}/etc/shorewall
    echo "Interfaces file installed as ${DESTDIR}/etc/shorewall/interfaces"
fi

#
# Install the hosts file
#
run_install $OWNERSHIP -m 0644 configfiles/hosts ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/hosts ]; then
    run_install $OWNERSHIP -m 0600 configfiles/hosts ${DESTDIR}/etc/shorewall
    echo "Hosts file installed as ${DESTDIR}/etc/shorewall/hosts"
fi
#
# Install the rules file
#
run_install $OWNERSHIP -m 0644 configfiles/rules ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/rules ]; then
    run_install $OWNERSHIP -m 0600 configfiles/rules ${DESTDIR}/etc/shorewall
    echo "Rules file installed as ${DESTDIR}/etc/shorewall/rules"
fi
#
# Install the NAT file
#
run_install $OWNERSHIP -m 0644 configfiles/nat ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/nat ]; then
    run_install $OWNERSHIP -m 0600 configfiles/nat ${DESTDIR}/etc/shorewall
    echo "NAT file installed as ${DESTDIR}/etc/shorewall/nat"
fi
#
# Install the NETMAP file
#
run_install $OWNERSHIP -m 0644 configfiles/netmap ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/netmap ]; then
    run_install $OWNERSHIP -m 0600 configfiles/netmap ${DESTDIR}/etc/shorewall
    echo "NETMAP file installed as ${DESTDIR}/etc/shorewall/netmap"
fi
#
# Install the Parameters file
#
run_install $OWNERSHIP -m 0644 configfiles/params ${DESTDIR}/usr/share/shorewall/configfiles

if [ -f ${DESTDIR}/etc/shorewall/params ]; then
    chmod 0644 ${DESTDIR}/etc/shorewall/params
else
    run_install $OWNERSHIP -m 0644 configfiles/params ${DESTDIR}/etc/shorewall
    echo "Parameter file installed as ${DESTDIR}/etc/shorewall/params"
fi
#
# Install the proxy ARP file
#
run_install $OWNERSHIP -m 0644 configfiles/proxyarp ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/proxyarp ]; then
    run_install $OWNERSHIP -m 0600 configfiles/proxyarp ${DESTDIR}/etc/shorewall
    echo "Proxy ARP file installed as ${DESTDIR}/etc/shorewall/proxyarp"
fi
#
# Install the Stopped Routing file
#
run_install $OWNERSHIP -m 0644 configfiles/routestopped ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/routestopped ]; then
    run_install $OWNERSHIP -m 0600 configfiles/routestopped ${DESTDIR}/etc/shorewall
    echo "Stopped Routing file installed as ${DESTDIR}/etc/shorewall/routestopped"
fi
#
# Install the Mac List file
#
run_install $OWNERSHIP -m 0644 configfiles/maclist ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/maclist ]; then
    run_install $OWNERSHIP -m 0600 configfiles/maclist ${DESTDIR}/etc/shorewall
    echo "MAC list file installed as ${DESTDIR}/etc/shorewall/maclist"
fi
#
# Install the Masq file
#
run_install $OWNERSHIP -m 0644 configfiles/masq ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/masq ]; then
    run_install $OWNERSHIP -m 0600 configfiles/masq ${DESTDIR}/etc/shorewall
    echo "Masquerade file installed as ${DESTDIR}/etc/shorewall/masq"
fi
#
# Install the Notrack file
#
run_install $OWNERSHIP -m 0644 configfiles/notrack ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/notrack ]; then
    run_install $OWNERSHIP -m 0600 configfiles/notrack ${DESTDIR}/etc/shorewall
    echo "Notrack file installed as ${DESTDIR}/etc/shorewall/notrack"
fi
#
# Install the Modules file
#
run_install $OWNERSHIP -m 0600 modules ${DESTDIR}/usr/share/shorewall
echo "Modules file installed as ${DESTDIR}/usr/share/shorewall/modules"

#
# Install the Module Helpers file
#
run_install $OWNERSHIP -m 0600 helpers ${DESTDIR}/usr/share/shorewall
echo "Helper modules file installed as ${DESTDIR}/usr/share/shorewall/helpers"

#
# Install the TC Rules file
#
run_install $OWNERSHIP -m 0644 configfiles/tcrules ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/tcrules ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcrules ${DESTDIR}/etc/shorewall
    echo "TC Rules file installed as ${DESTDIR}/etc/shorewall/tcrules"
fi

#
# Install the TC Interfaces file
#
run_install $OWNERSHIP -m 0644 configfiles/tcinterfaces ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/tcinterfaces ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcinterfaces ${DESTDIR}/etc/shorewall
    echo "TC Interfaces file installed as ${DESTDIR}/etc/shorewall/tcinterfaces"
fi

#
# Install the TC Priority file
#
run_install $OWNERSHIP -m 0644 configfiles/tcpri ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/tcpri ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcpri ${DESTDIR}/etc/shorewall
    echo "TC Priority file installed as ${DESTDIR}/etc/shorewall/tcpri"
fi

#
# Install the TOS file
#
run_install $OWNERSHIP -m 0644 configfiles/tos ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/tos ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tos ${DESTDIR}/etc/shorewall
    echo "TOS file installed as ${DESTDIR}/etc/shorewall/tos"
fi
#
# Install the Tunnels file
#
run_install $OWNERSHIP -m 0644 configfiles/tunnels ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/tunnels ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tunnels ${DESTDIR}/etc/shorewall
    echo "Tunnels file installed as ${DESTDIR}/etc/shorewall/tunnels"
fi
#
# Install the blacklist file
#
run_install $OWNERSHIP -m 0644 configfiles/blacklist ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/blacklist ]; then
    run_install $OWNERSHIP -m 0600 configfiles/blacklist ${DESTDIR}/etc/shorewall
    echo "Blacklist file installed as ${DESTDIR}/etc/shorewall/blacklist"
fi
#
# Install the findgw file
#
run_install $OWNERSHIP -m 0644 configfiles/findgw ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/findgw ]; then
    run_install $OWNERSHIP -m 0600 configfiles/findgw ${DESTDIR}/etc/shorewall
    echo "Find GW file installed as ${DESTDIR}/etc/shorewall/findgw"
fi
#
# Delete the Routes file
#
delete_file ${DESTDIR}/etc/shorewall/routes
#
# Delete the tcstart file
#

delete_file ${DESTDIR}/usr/share/shorewall/tcstart

#
# Delete the Limits Files
#
delete_file ${DESTDIR}/usr/share/shorewall/action.Limit
delete_file ${DESTDIR}/usr/share/shorewall/Limit
#
# Delete the xmodules file
#
delete_file ${DESTDIR}/usr/share/shorewall/xmodules
#
# Install the Providers file
#
run_install $OWNERSHIP -m 0644 configfiles/providers ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/providers ]; then
    run_install $OWNERSHIP -m 0600 configfiles/providers ${DESTDIR}/etc/shorewall
    echo "Providers file installed as ${DESTDIR}/etc/shorewall/providers"
fi

#
# Install the Route Rules file
#
run_install $OWNERSHIP -m 0644 configfiles/route_rules ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/route_rules ]; then
    run_install $OWNERSHIP -m 0600 configfiles/route_rules ${DESTDIR}/etc/shorewall
    echo "Routing rules file installed as ${DESTDIR}/etc/shorewall/route_rules"
fi

#
# Install the tcclasses file
#
run_install $OWNERSHIP -m 0644 configfiles/tcclasses ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/tcclasses ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcclasses ${DESTDIR}/etc/shorewall
    echo "TC Classes file installed as ${DESTDIR}/etc/shorewall/tcclasses"
fi

#
# Install the tcdevices file
#
run_install $OWNERSHIP -m 0644 configfiles/tcdevices ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/tcdevices ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcdevices ${DESTDIR}/etc/shorewall
    echo "TC Devices file installed as ${DESTDIR}/etc/shorewall/tcdevices"
fi

#
# Install the tcfilters file
#
run_install $OWNERSHIP -m 0644 configfiles/tcfilters ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/tcfilters ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcfilters ${DESTDIR}/etc/shorewall
    echo "TC Filters file installed as ${DESTDIR}/etc/shorewall/tcfilters"
fi

#
# Install the secmarks file
#
run_install $OWNERSHIP -m 0644 configfiles/secmarks ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/secmarks ]; then
    run_install $OWNERSHIP -m 0600 configfiles/secmarks ${DESTDIR}/etc/shorewall
    echo "Secmarks file installed as ${DESTDIR}/etc/shorewall/secmarks"
fi

#
# Install the default config path file
#
install_file configpath ${DESTDIR}/usr/share/shorewall/configpath 0644
echo "Default config path file installed as ${DESTDIR}/usr/share/shorewall/configpath"
#
# Install the init file
#
run_install $OWNERSHIP -m 0644 configfiles/init ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/init ]; then
    run_install $OWNERSHIP -m 0600 configfiles/init ${DESTDIR}/etc/shorewall
    echo "Init file installed as ${DESTDIR}/etc/shorewall/init"
fi
#
# Install the initdone file
#
run_install $OWNERSHIP -m 0644 configfiles/initdone ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/initdone ]; then
    run_install $OWNERSHIP -m 0600 configfiles/initdone ${DESTDIR}/etc/shorewall
    echo "Initdone file installed as ${DESTDIR}/etc/shorewall/initdone"
fi
#
# Install the start file
#
run_install $OWNERSHIP -m 0644 configfiles/start ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/start ]; then
    run_install $OWNERSHIP -m 0600 configfiles/start ${DESTDIR}/etc/shorewall
    echo "Start file installed as ${DESTDIR}/etc/shorewall/start"
fi
#
# Install the stop file
#
run_install $OWNERSHIP -m 0644 configfiles/stop ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/stop ]; then
    run_install $OWNERSHIP -m 0600 configfiles/stop ${DESTDIR}/etc/shorewall
    echo "Stop file installed as ${DESTDIR}/etc/shorewall/stop"
fi
#
# Install the stopped file
#
run_install $OWNERSHIP -m 0644 configfiles/stopped ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/stopped ]; then
    run_install $OWNERSHIP -m 0600 configfiles/stopped ${DESTDIR}/etc/shorewall
    echo "Stopped file installed as ${DESTDIR}/etc/shorewall/stopped"
fi
#
# Install the ECN file
#
run_install $OWNERSHIP -m 0644 configfiles/ecn ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/ecn ]; then
    run_install $OWNERSHIP -m 0600 configfiles/ecn ${DESTDIR}/etc/shorewall
    echo "ECN file installed as ${DESTDIR}/etc/shorewall/ecn"
fi
#
# Install the Accounting file
#
run_install $OWNERSHIP -m 0644 configfiles/accounting ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/accounting ]; then
    run_install $OWNERSHIP -m 0600 configfiles/accounting ${DESTDIR}/etc/shorewall
    echo "Accounting file installed as ${DESTDIR}/etc/shorewall/accounting"
fi
#
# Install the private library file
#
run_install $OWNERSHIP -m 0644 configfiles/lib.private ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/lib.private ]; then
    run_install $OWNERSHIP -m 0600 configfiles/lib.private ${DESTDIR}/etc/shorewall
    echo "Private library file installed as ${DESTDIR}/etc/shorewall/lib.private"
fi
#
# Install the Started file
#
run_install $OWNERSHIP -m 0644 configfiles/started ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/started ]; then
    run_install $OWNERSHIP -m 0600 configfiles/started ${DESTDIR}/etc/shorewall
    echo "Started file installed as ${DESTDIR}/etc/shorewall/started"
fi
#
# Install the Restored file
#
run_install $OWNERSHIP -m 0644 configfiles/restored ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/restored ]; then
    run_install $OWNERSHIP -m 0600 configfiles/restored ${DESTDIR}/etc/shorewall
    echo "Restored file installed as ${DESTDIR}/etc/shorewall/restored"
fi
#
# Install the Clear file
#
run_install $OWNERSHIP -m 0644 configfiles/clear ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/clear ]; then
    run_install $OWNERSHIP -m 0600 configfiles/clear ${DESTDIR}/etc/shorewall
    echo "Clear file installed as ${DESTDIR}/etc/shorewall/clear"
fi
#
# Install the Isusable file
#
run_install $OWNERSHIP -m 0644 configfiles/isusable ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/isusable ]; then
    run_install $OWNERSHIP -m 0600 configfiles/isusable ${DESTDIR}/etc/shorewall
    echo "Isusable file installed as ${DESTDIR}/etc/shorewall/isusable"
fi
#
# Install the Refresh file
#
run_install $OWNERSHIP -m 0644 configfiles/refresh ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/refresh ]; then
    run_install $OWNERSHIP -m 0600 configfiles/refresh ${DESTDIR}/etc/shorewall
    echo "Refresh file installed as ${DESTDIR}/etc/shorewall/refresh"
fi
#
# Install the Refreshed file
#
run_install $OWNERSHIP -m 0644 configfiles/refreshed ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/refreshed ]; then
    run_install $OWNERSHIP -m 0600 configfiles/refreshed ${DESTDIR}/etc/shorewall
    echo "Refreshed file installed as ${DESTDIR}/etc/shorewall/refreshed"
fi
#
# Install the Tcclear file
#
run_install $OWNERSHIP -m 0644 configfiles/tcclear ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/tcclear ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcclear ${DESTDIR}/etc/shorewall
    echo "Tcclear file installed as ${DESTDIR}/etc/shorewall/tcclear"
fi
#
# Install the Standard Actions file
#
install_file actions.std ${DESTDIR}/usr/share/shorewall/actions.std 0644
echo "Standard actions file installed as ${DESTDIR}/usr/shared/shorewall/actions.std"

#
# Install the Actions file
#
run_install $OWNERSHIP -m 0644 configfiles/actions ${DESTDIR}/usr/share/shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/shorewall/actions ]; then
    run_install $OWNERSHIP -m 0644 configfiles/actions ${DESTDIR}/etc/shorewall
    echo "Actions file installed as ${DESTDIR}/etc/shorewall/actions"
fi

#
# Install the  Makefiles
#
install_file Makefile-lite ${DESTDIR}/usr/share/shorewall/configfiles/Makefile 0644

if [ -z "$SPARSE" ]; then
    run_install $OWNERSHIP -m 0600 Makefile ${DESTDIR}/etc/shorewall
    echo "Makefile installed as ${DESTDIR}/etc/shorewall/Makefile"
fi
#
# Install the Action files
#
for f in action.* ; do
    install_file $f ${DESTDIR}/usr/share/shorewall/$f 0644
    echo "Action ${f#*.} file installed as ${DESTDIR}/usr/share/shorewall/$f"
done

# Install the Macro files
#
cd Macros

for f in macro.* ; do
    install_file $f ${DESTDIR}/usr/share/shorewall/$f 0644
    echo "Macro ${f#*.} file installed as ${DESTDIR}/usr/share/shorewall/$f"
done

cd ..
#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${DESTDIR}/usr/share/shorewall/$f 0644
	echo "Library ${f#*.} file installed as ${DESTDIR}/usr/share/shorewall/$f"
    fi
done
#
# Symbolically link 'functions' to lib.base
#
ln -sf lib.base ${DESTDIR}/usr/share/shorewall/functions
#
# /usr/share/shorewall/Shorewall if needed
#
mkdir -p ${DESTDIR}/usr/share/shorewall/Shorewall
chmod 755 ${DESTDIR}/usr/share/shorewall/Shorewall
#
# Install the Compiler
#
cd Perl

install_file compiler.pl ${DESTDIR}/usr/share/shorewall/compiler.pl 0755

echo
echo "Compiler installed in ${DESTDIR}/usr/share/shorewall/compiler.pl"
#
# Install the libraries
#
for f in Shorewall/*.pm ; do
    install_file $f ${DESTDIR}/usr/share/shorewall/$f 0644
    echo "Module ${f%.*} installed as ${DESTDIR}/usr/share/shorewall/$f"
done
#
# Install the program skeleton files
#
for f in prog.* ; do
    install_file $f ${DESTDIR}/usr/share/shorewall/$f 0644
    echo "Program skeleton file ${f#*.} installed as ${DESTDIR}/usr/share/shorewall/$f"
done

cd ..
#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}/usr/share/shorewall/version
chmod 644 ${DESTDIR}/usr/share/shorewall/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$DESTDIR" ]; then
    rm -f /usr/share/shorewall/init
    ln -s ${DEST}/${INIT} /usr/share/shorewall/init
fi

#
# Install the Man Pages
#

if [ -d manpages ]; then

    cd manpages

    [ -n "$INSTALLD" ] || mkdir -p ${DESTDIR}${MANDIR}/man5/ ${DESTDIR}${MANDIR}/man8/

    for f in *.5; do
	gzip -c $f > $f.gz
	run_install $INSTALLD  -m 0644 $f.gz ${DESTDIR}${MANDIR}/man5/$f.gz
	echo "Man page $f.gz installed to ${DESTDIR}${MANDIR}/man5/$f.gz"
    done

    for f in *.8; do
	gzip -c $f > $f.gz
	run_install $INSTALLD  -m 0644 $f.gz ${DESTDIR}${MANDIR}/man8/$f.gz
	echo "Man page $f.gz installed to ${DESTDIR}${MANDIR}/man8/$f.gz"
    done

    cd ..

    echo "Man Pages Installed"

fi

if [ -d ${DESTDIR}/etc/logrotate.d ]; then
    install_file logrotate ${DESTDIR}/etc/logrotate.d/shorewall 0644
    echo "Logrotate file installed as ${DESTDIR}/etc/logrotate.d/shorewall"
fi

if [ -z "$DESTDIR" ]; then
    rm -rf /usr/share/shorewall-perl
    rm -rf /usr/share/shorewall-shell
fi

if [ -z "$DESTDIR" -a -n "$first_install" -a -z "${CYGWIN}${MAC}" ]; then
    if [ -n "$DEBIAN" ]; then
	install_file default.debian /etc/default/shorewall 0644

	if [ -x /sbin/insserv ]; then
	    insserv /etc/init.d/shorewall
	else
	    ln -s ../init.d/shorewall /etc/rcS.d/S40shorewall
	fi

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
