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

VERSION=4.4.19-Beta1

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


if [ -n "$BASE" ]; then
    if [ -n "$DESTDIR" ]; then
	echo "   ERROR: DESTDIR and BASE may not be specified together" >&2
	exit 1
    fi

    case "$BASE" in
	/*)
	    ;;
	*)
	    echo "   ERROR: BASE must contain an absolute path name" >&2
	    exit 1;
	    ;;
    esac

    mkdir -p "$BASE"

    [ -n ${ETC:=${BASE}/etc/} ]
    [ -n ${SBIN:=${BASE}/sbin/} ]
    [ -n ${SHARE:=${BASE}/share/} ]
    [ -n ${VAR:=${BASE}/var/lib/} ]
    [ -n ${MANDIR:=${BASE}/share/man} ]
else
    [ -n ${ETC:=/etc/} ]
    [ -n ${SBIN:=/sbin/} ]
    [ -n ${SHARE:=/usr/share/} ]
    [ -n ${VAR:=/var/lib/} ]
    [ -n ${MANDIR:=/usr/share/man} ]
fi


case "$ETC" in
    /*/)
	;;
    /*)
	ETC=$ETC/
	;;
    *)
	if [ -n "$BASE" ]; THEN
	    ETC=$BASE/$ETC/
	else
	    echo "ERROR: ETC must contain an absolute path name" >&2
	    exit 1
	fi
	;;
esac

case "$SBIN" in
    /*/)
	;;
    /*)
	SBIN=$SBIN/
	;;
    *)
	if [ -n "$BASE" ]; THEN
	    SBIN=$BASE/$SBIN/
	else
	    echo "ERROR: SBIN must contain an absolute path name" >&2
	    exit 1
	fi
	;;
esac

case "$SHARE" in
    /*/)
	;;
    /*)
	SHARE=$SHARE/
	;;
    *)
	if [ -n "$BASE" ]; THEN
	    SHARE=$BASE/$SHARE/
	else
	    echo "ERROR: SHARE must contain an absolute path name" >&2
	    exit 1
	fi
	;;
esac

case "$VAR" in
    /*/)
	;;
    /*)
	VAR=$VAR/
	;;
    *)
	if [ -n "$BASE" ]; THEN
	    VAR=$BASE/$VAR/
	else
	    echo "ERROR: VAR must contain an absolute path name" >&2
	    exit 1
	fi
	;;
esac

ETC=$(echo $ETC | sed "s'//'/'g")
SBIN=$(echo $SBIN | sed "s'//'/'g")
SHARE=$(echo $SHARE | sed "s'//'/'g")
VAR=$(echo $VAR | sed "s'//'/'g")

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

if [ `id -u` != 0 ] ; then
    echo "Not setting file owner/group permissions, not running as root."
    OWNERSHIP=""
fi

#
# Determine where to install the firewall script
#

if [ -n "$DESTDIR" -o -z "$OWNERSHIP" ]; then
    install -d $OWNERSHIP -m 755 ${DESTDIR}${SBIN}
    [ -n "$DESTDIR" ] && install -d $OWNERSHIP -m 755 ${DESTDIR}${DEST}

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
# Check for ${SBIN}shorewall
#
if [ -f ${DESTDIR}${SBIN}shorewall ]; then
    first_install=""
else
    first_install="Yes"
fi

if [ -z "$CYGWIN" ]; then
   install_file shorewall ${DESTDIR}${SBIN}shorewall 0755
   echo "shorewall control program installed in ${DESTDIR}${SBIN}shorewall"
else
   install_file shorewall ${DESTDIR}/bin/shorewall 0755
   echo "shorewall control program installed in ${DESTDIR}/bin/shorewall"
fi

#
# Install the Firewall Script
#
if [ -n "${DESTDIR}${OWNERSHIP}" ]; then
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
    mkdir -p ${DESTDIR}/etc
    chmod 755 ${DESTDIR}/etc
fi
#
# Create ${ETC}shorewall, ${SHARE}shorewall and ${VAR}shorewall if needed
#
mkdir -p ${DESTDIR}${ETC}shorewall
mkdir -p ${DESTDIR}${SHARE}shorewall
mkdir -p ${DESTDIR}${SHARE}shorewall/configfiles
mkdir -p ${DESTDIR}${VAR}shorewall

chmod 755 ${DESTDIR}${ETC}shorewall
chmod 755 ${DESTDIR}${SHARE}shorewall
chmod 755 ${DESTDIR}${SHARE}shorewall/configfiles

if [ -n "$DESTDIR" ]; then
    mkdir -p ${DESTDIR}/etc/logrotate.d
    chmod 755 ${DESTDIR}/etc/logrotate.d
fi

#
# Install the config file
#
run_install $OWNERSHIP -m 0644 configfiles/shorewall.conf ${DESTDIR}${SHARE}shorewall/configfiles

eval perl -p -w -i -e \'s\|^CONFIG_PATH=.\*\|CONFIG_PATH=${SHARE}shorewall/configfiles:${SHARE}shorewall\|\;\' ${DESTDIR}${SHARE}shorewall/configfiles/shorewall.conf
eval perl -p -w -i -e \'s\|^STARTUP_LOG=.\*\|STARTUP_LOG=/var/log/shorewall-lite-init.log\|\;\' ${DESTDIR}${SHARE}shorewall/configfiles/shorewall.conf

if [ ! -f ${DESTDIR}${ETC}shorewall/shorewall.conf ]; then
   run_install $OWNERSHIP -m 0644 configfiles/shorewall.conf ${DESTDIR}${ETC}shorewall

   if [ -n "$DEBIAN" ]; then
       #
       # Make a Debian-like shorewall.conf
       #
       perl -p -w -i -e \'s\|^STARTUP_ENABLED=.\*\|STARTUP_ENABLED=Yes\|\;\' ${DESTDIR}${ETC}shorewall/shorewall.conf
   fi

   echo "Config file installed as ${DESTDIR}${ETC}shorewall/shorewall.conf"
fi

if [ -n "$ARCHLINUX" ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${DESTDIR}${ETC}shorewall/shorewall.conf
fi
#
# Install the zones file
#
run_install $OWNERSHIP -m 0644 configfiles/zones ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/zones ]; then
    run_install $OWNERSHIP -m 0644 configfiles/zones ${DESTDIR}${ETC}shorewall
    echo "Zones file installed as ${DESTDIR}${ETC}shorewall/zones"
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

install_file wait4ifup ${DESTDIR}${SHARE}shorewall/wait4ifup 0755

echo
echo "wait4ifup installed in ${DESTDIR}${SHARE}shorewall/wait4ifup"

#
# Install the policy file
#
install_file configfiles/policy ${DESTDIR}${SHARE}shorewall/configfiles/policy 0644

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/policy ]; then
    run_install $OWNERSHIP -m 0600 configfiles/policy ${DESTDIR}${ETC}shorewall
    echo "Policy file installed as ${DESTDIR}${ETC}shorewall/policy"
fi
#
# Install the interfaces file
#
run_install $OWNERSHIP -m 0644 configfiles/interfaces ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/interfaces ]; then
    run_install $OWNERSHIP -m 0600 configfiles/interfaces ${DESTDIR}${ETC}shorewall
    echo "Interfaces file installed as ${DESTDIR}${ETC}shorewall/interfaces"
fi

#
# Install the hosts file
#
run_install $OWNERSHIP -m 0644 configfiles/hosts ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/hosts ]; then
    run_install $OWNERSHIP -m 0600 configfiles/hosts ${DESTDIR}${ETC}shorewall
    echo "Hosts file installed as ${DESTDIR}${ETC}shorewall/hosts"
fi
#
# Install the rules file
#
run_install $OWNERSHIP -m 0644 configfiles/rules ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/rules ]; then
    run_install $OWNERSHIP -m 0600 configfiles/rules ${DESTDIR}${ETC}shorewall
    echo "Rules file installed as ${DESTDIR}${ETC}shorewall/rules"
fi
#
# Install the NAT file
#
run_install $OWNERSHIP -m 0644 configfiles/nat ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/nat ]; then
    run_install $OWNERSHIP -m 0600 configfiles/nat ${DESTDIR}${ETC}shorewall
    echo "NAT file installed as ${DESTDIR}${ETC}shorewall/nat"
fi
#
# Install the NETMAP file
#
run_install $OWNERSHIP -m 0644 configfiles/netmap ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/netmap ]; then
    run_install $OWNERSHIP -m 0600 configfiles/netmap ${DESTDIR}${ETC}shorewall
    echo "NETMAP file installed as ${DESTDIR}${ETC}shorewall/netmap"
fi
#
# Install the Parameters file
#
run_install $OWNERSHIP -m 0644 configfiles/params ${DESTDIR}${SHARE}shorewall/configfiles

if [ -f ${DESTDIR}${ETC}shorewall/params ]; then
    chmod 0644 ${DESTDIR}${ETC}shorewall/params
else
    run_install $OWNERSHIP -m 0644 configfiles/params ${DESTDIR}${ETC}shorewall
    echo "Parameter file installed as ${DESTDIR}${ETC}shorewall/params"
fi
#
# Install the proxy ARP file
#
run_install $OWNERSHIP -m 0644 configfiles/proxyarp ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/proxyarp ]; then
    run_install $OWNERSHIP -m 0600 configfiles/proxyarp ${DESTDIR}${ETC}shorewall
    echo "Proxy ARP file installed as ${DESTDIR}${ETC}shorewall/proxyarp"
fi
#
# Install the Stopped Routing file
#
run_install $OWNERSHIP -m 0644 configfiles/routestopped ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/routestopped ]; then
    run_install $OWNERSHIP -m 0600 configfiles/routestopped ${DESTDIR}${ETC}shorewall
    echo "Stopped Routing file installed as ${DESTDIR}${ETC}shorewall/routestopped"
fi
#
# Install the Mac List file
#
run_install $OWNERSHIP -m 0644 configfiles/maclist ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/maclist ]; then
    run_install $OWNERSHIP -m 0600 configfiles/maclist ${DESTDIR}${ETC}shorewall
    echo "MAC list file installed as ${DESTDIR}${ETC}shorewall/maclist"
fi
#
# Install the Masq file
#
run_install $OWNERSHIP -m 0644 configfiles/masq ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/masq ]; then
    run_install $OWNERSHIP -m 0600 configfiles/masq ${DESTDIR}${ETC}shorewall
    echo "Masquerade file installed as ${DESTDIR}${ETC}shorewall/masq"
fi
#
# Install the Notrack file
#
run_install $OWNERSHIP -m 0644 configfiles/notrack ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/notrack ]; then
    run_install $OWNERSHIP -m 0600 configfiles/notrack ${DESTDIR}${ETC}shorewall
    echo "Notrack file installed as ${DESTDIR}${ETC}shorewall/notrack"
fi
#
# Install the Modules files
#
run_install $OWNERSHIP -m 0644 modules ${DESTDIR}${SHARE}shorewall
echo "Modules file installed as ${DESTDIR}${SHARE}shorewall/modules"

for f in modules.*; do
    run_install $OWNERSHIP -m 0644 $f ${DESTDIR}${SHARE}shorewall/$f
    echo "Module file $f installed as ${DESTDIR}${SHARE}shorewall/$f"
done

#
# Install the Module Helpers file
#
run_install $OWNERSHIP -m 0644 helpers ${DESTDIR}${SHARE}shorewall
echo "Helper modules file installed as ${DESTDIR}${SHARE}shorewall/helpers"

#
# Install the TC Rules file
#
run_install $OWNERSHIP -m 0644 configfiles/tcrules ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/tcrules ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcrules ${DESTDIR}${ETC}shorewall
    echo "TC Rules file installed as ${DESTDIR}${ETC}shorewall/tcrules"
fi

#
# Install the TC Interfaces file
#
run_install $OWNERSHIP -m 0644 configfiles/tcinterfaces ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/tcinterfaces ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcinterfaces ${DESTDIR}${ETC}shorewall
    echo "TC Interfaces file installed as ${DESTDIR}${ETC}shorewall/tcinterfaces"
fi

#
# Install the TC Priority file
#
run_install $OWNERSHIP -m 0644 configfiles/tcpri ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/tcpri ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcpri ${DESTDIR}${ETC}shorewall
    echo "TC Priority file installed as ${DESTDIR}${ETC}shorewall/tcpri"
fi

#
# Install the TOS file
#
run_install $OWNERSHIP -m 0644 configfiles/tos ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/tos ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tos ${DESTDIR}${ETC}shorewall
    echo "TOS file installed as ${DESTDIR}${ETC}shorewall/tos"
fi
#
# Install the Tunnels file
#
run_install $OWNERSHIP -m 0644 configfiles/tunnels ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/tunnels ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tunnels ${DESTDIR}${ETC}shorewall
    echo "Tunnels file installed as ${DESTDIR}${ETC}shorewall/tunnels"
fi
#
# Install the blacklist file
#
run_install $OWNERSHIP -m 0644 configfiles/blacklist ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/blacklist ]; then
    run_install $OWNERSHIP -m 0600 configfiles/blacklist ${DESTDIR}${ETC}shorewall
    echo "Blacklist file installed as ${DESTDIR}${ETC}shorewall/blacklist"
fi
#
# Install the findgw file
#
run_install $OWNERSHIP -m 0644 configfiles/findgw ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/findgw ]; then
    run_install $OWNERSHIP -m 0600 configfiles/findgw ${DESTDIR}${ETC}shorewall
    echo "Find GW file installed as ${DESTDIR}${ETC}shorewall/findgw"
fi
#
# Delete the Routes file
#
delete_file ${DESTDIR}${ETC}shorewall/routes
#
# Delete the tcstart file
#

delete_file ${DESTDIR}${SHARE}shorewall/tcstart

#
# Delete the Limits Files
#
delete_file ${DESTDIR}${SHARE}shorewall/action.Limit
delete_file ${DESTDIR}${SHARE}shorewall/Limit
#
# Delete the xmodules file
#
delete_file ${DESTDIR}${SHARE}shorewall/xmodules
#
# Install the Providers file
#
run_install $OWNERSHIP -m 0644 configfiles/providers ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/providers ]; then
    run_install $OWNERSHIP -m 0600 configfiles/providers ${DESTDIR}${ETC}shorewall
    echo "Providers file installed as ${DESTDIR}${ETC}shorewall/providers"
fi

#
# Install the Route Rules file
#
run_install $OWNERSHIP -m 0644 configfiles/route_rules ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/route_rules ]; then
    run_install $OWNERSHIP -m 0600 configfiles/route_rules ${DESTDIR}${ETC}shorewall
    echo "Routing rules file installed as ${DESTDIR}${ETC}shorewall/route_rules"
fi

#
# Install the tcclasses file
#
run_install $OWNERSHIP -m 0644 configfiles/tcclasses ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/tcclasses ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcclasses ${DESTDIR}${ETC}shorewall
    echo "TC Classes file installed as ${DESTDIR}${ETC}shorewall/tcclasses"
fi

#
# Install the tcdevices file
#
run_install $OWNERSHIP -m 0644 configfiles/tcdevices ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/tcdevices ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcdevices ${DESTDIR}${ETC}shorewall
    echo "TC Devices file installed as ${DESTDIR}${ETC}shorewall/tcdevices"
fi

#
# Install the tcfilters file
#
run_install $OWNERSHIP -m 0644 configfiles/tcfilters ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/tcfilters ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcfilters ${DESTDIR}${ETC}shorewall
    echo "TC Filters file installed as ${DESTDIR}${ETC}shorewall/tcfilters"
fi

#
# Install the secmarks file
#
run_install $OWNERSHIP -m 0644 configfiles/secmarks ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/secmarks ]; then
    run_install $OWNERSHIP -m 0600 configfiles/secmarks ${DESTDIR}${ETC}shorewall
    echo "Secmarks file installed as ${DESTDIR}${ETC}shorewall/secmarks"
fi

#
# Install the default config path file
#
install_file configpath ${DESTDIR}${SHARE}shorewall/configpath 0644
echo "Default config path file installed as ${DESTDIR}${SHARE}shorewall/configpath"
#
# Install the init file
#
run_install $OWNERSHIP -m 0644 configfiles/init ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/init ]; then
    run_install $OWNERSHIP -m 0600 configfiles/init ${DESTDIR}${ETC}shorewall
    echo "Init file installed as ${DESTDIR}${ETC}shorewall/init"
fi
#
# Install the initdone file
#
run_install $OWNERSHIP -m 0644 configfiles/initdone ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/initdone ]; then
    run_install $OWNERSHIP -m 0600 configfiles/initdone ${DESTDIR}${ETC}shorewall
    echo "Initdone file installed as ${DESTDIR}${ETC}shorewall/initdone"
fi
#
# Install the start file
#
run_install $OWNERSHIP -m 0644 configfiles/start ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/start ]; then
    run_install $OWNERSHIP -m 0600 configfiles/start ${DESTDIR}${ETC}shorewall
    echo "Start file installed as ${DESTDIR}${ETC}shorewall/start"
fi
#
# Install the stop file
#
run_install $OWNERSHIP -m 0644 configfiles/stop ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/stop ]; then
    run_install $OWNERSHIP -m 0600 configfiles/stop ${DESTDIR}${ETC}shorewall
    echo "Stop file installed as ${DESTDIR}${ETC}shorewall/stop"
fi
#
# Install the stopped file
#
run_install $OWNERSHIP -m 0644 configfiles/stopped ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/stopped ]; then
    run_install $OWNERSHIP -m 0600 configfiles/stopped ${DESTDIR}${ETC}shorewall
    echo "Stopped file installed as ${DESTDIR}${ETC}shorewall/stopped"
fi
#
# Install the ECN file
#
run_install $OWNERSHIP -m 0644 configfiles/ecn ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/ecn ]; then
    run_install $OWNERSHIP -m 0600 configfiles/ecn ${DESTDIR}${ETC}shorewall
    echo "ECN file installed as ${DESTDIR}${ETC}shorewall/ecn"
fi
#
# Install the Accounting file
#
run_install $OWNERSHIP -m 0644 configfiles/accounting ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/accounting ]; then
    run_install $OWNERSHIP -m 0600 configfiles/accounting ${DESTDIR}${ETC}shorewall
    echo "Accounting file installed as ${DESTDIR}${ETC}shorewall/accounting"
fi
#
# Install the private library file
#
run_install $OWNERSHIP -m 0644 configfiles/lib.private ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/lib.private ]; then
    run_install $OWNERSHIP -m 0600 configfiles/lib.private ${DESTDIR}${ETC}shorewall
    echo "Private library file installed as ${DESTDIR}${ETC}shorewall/lib.private"
fi
#
# Install the Started file
#
run_install $OWNERSHIP -m 0644 configfiles/started ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/started ]; then
    run_install $OWNERSHIP -m 0600 configfiles/started ${DESTDIR}${ETC}shorewall
    echo "Started file installed as ${DESTDIR}${ETC}shorewall/started"
fi
#
# Install the Restored file
#
run_install $OWNERSHIP -m 0644 configfiles/restored ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/restored ]; then
    run_install $OWNERSHIP -m 0600 configfiles/restored ${DESTDIR}${ETC}shorewall
    echo "Restored file installed as ${DESTDIR}${ETC}shorewall/restored"
fi
#
# Install the Clear file
#
run_install $OWNERSHIP -m 0644 configfiles/clear ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/clear ]; then
    run_install $OWNERSHIP -m 0600 configfiles/clear ${DESTDIR}${ETC}shorewall
    echo "Clear file installed as ${DESTDIR}${ETC}shorewall/clear"
fi
#
# Install the Isusable file
#
run_install $OWNERSHIP -m 0644 configfiles/isusable ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/isusable ]; then
    run_install $OWNERSHIP -m 0600 configfiles/isusable ${DESTDIR}${ETC}shorewall
    echo "Isusable file installed as ${DESTDIR}${ETC}shorewall/isusable"
fi
#
# Install the Refresh file
#
run_install $OWNERSHIP -m 0644 configfiles/refresh ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/refresh ]; then
    run_install $OWNERSHIP -m 0600 configfiles/refresh ${DESTDIR}${ETC}shorewall
    echo "Refresh file installed as ${DESTDIR}${ETC}shorewall/refresh"
fi
#
# Install the Refreshed file
#
run_install $OWNERSHIP -m 0644 configfiles/refreshed ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/refreshed ]; then
    run_install $OWNERSHIP -m 0600 configfiles/refreshed ${DESTDIR}${ETC}shorewall
    echo "Refreshed file installed as ${DESTDIR}${ETC}shorewall/refreshed"
fi
#
# Install the Tcclear file
#
run_install $OWNERSHIP -m 0644 configfiles/tcclear ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/tcclear ]; then
    run_install $OWNERSHIP -m 0600 configfiles/tcclear ${DESTDIR}${ETC}shorewall
    echo "Tcclear file installed as ${DESTDIR}${ETC}shorewall/tcclear"
fi
#
# Install the Scfilter file
#
run_install $OWNERSHIP -m 644 configfiles/scfilter ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/scfilter ]; then
    run_install $OWNERSHIP -m 0600 configfiles/scfilter ${DESTDIR}${ETC}shorewall
    echo "Scfilter file installed as ${DESTDIR}${ETC}shorewall/scfilter"
fi
#
# Install the Standard Actions file
#
install_file actions.std ${DESTDIR}${SHARE}shorewall/actions.std 0644
echo "Standard actions file installed as ${DESTDIR}/usr/shared/shorewall/actions.std"

#
# Install the Actions file
#
run_install $OWNERSHIP -m 0644 configfiles/actions ${DESTDIR}${SHARE}shorewall/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall/actions ]; then
    run_install $OWNERSHIP -m 0644 configfiles/actions ${DESTDIR}${ETC}shorewall
    echo "Actions file installed as ${DESTDIR}${ETC}shorewall/actions"
fi

#
# Install the  Makefiles
#
install_file Makefile-lite ${DESTDIR}${SHARE}shorewall/configfiles/Makefile 0644

if [ -z "$SPARSE" ]; then
    run_install $OWNERSHIP -m 0600 Makefile ${DESTDIR}${ETC}shorewall
    echo "Makefile installed as ${DESTDIR}${ETC}shorewall/Makefile"
fi
#
# Install the Action files
#
for f in action.* ; do
    install_file $f ${DESTDIR}${SHARE}shorewall/$f 0644
    echo "Action ${f#*.} file installed as ${DESTDIR}${SHARE}shorewall/$f"
done

# Install the Macro files
#
cd Macros

for f in macro.* ; do
    install_file $f ${DESTDIR}${SHARE}shorewall/$f 0644
    echo "Macro ${f#*.} file installed as ${DESTDIR}${SHARE}shorewall/$f"
done

cd ..
#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${DESTDIR}${SHARE}shorewall/$f 0644
	echo "Library ${f#*.} file installed as ${DESTDIR}${SHARE}shorewall/$f"
    fi
done
#
# Symbolically link 'functions' to lib.base
#
ln -sf lib.base ${DESTDIR}${SHARE}shorewall/functions
#
# ${SHARE}shorewall/Shorewall if needed
#
mkdir -p ${DESTDIR}${SHARE}shorewall/Shorewall
chmod 755 ${DESTDIR}${SHARE}shorewall/Shorewall
#
# Install the Compiler
#
cd Perl

install_file compiler.pl ${DESTDIR}${SHARE}shorewall/compiler.pl 0755

echo
echo "Compiler installed in ${DESTDIR}${SHARE}shorewall/compiler.pl"
#
# Install the params file helper
#
install_file getparams ${DESTDIR}${SHARE}shorewall/getparams 0755

echo
echo "Params file helper installed in ${DESTDIR}${SHARE}shorewall/getparams"
#
# Install the libraries
#
for f in Shorewall/*.pm ; do
    install_file $f ${DESTDIR}${SHARE}shorewall/$f 0644
    echo "Module ${f%.*} installed as ${DESTDIR}${SHARE}shorewall/$f"
done
#
# Install the program skeleton files
#
for f in prog.* ; do
    install_file $f ${DESTDIR}${SHARE}shorewall/$f 0644
    echo "Program skeleton file ${f#*.} installed as ${DESTDIR}${SHARE}shorewall/$f"
done

cd ..

export ETC
export SBIN
export SHARE
export VAR

perl -i -e '

while ( <> ) {
   for my $var qw( ETC SBIN SHARE VAR ) {
      if ( /^$var=/ ) {
         $_ = "g_" . lc( $var ) . "=" . $ENV{$var} . "\n";
      }
   }
   
   print $_;

}' ${DESTDIR}${SBIN}shorewall ${DESTDIR}${SHARE}shorewall/lib.base ${DESTDIR}${SHARE}shorewall/getparams

perl -i -e "
my \$done = 0;

while ( <> ) {
   unless ( \$done ) {
      for my \$var qw( ETC SBIN SHARE VAR ) {
         if ( /\$var(?:\\s*)=(?:\\s*)(.*);/ ) {
            s/\$1/'\$ENV{\$var}'/;
            \$done = \$var eq 'VAR';
         }
      }
   }

   print \$_;

}" ${DESTDIR}${SHARE}shorewall/Shorewall/Defaults.pm
#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}${SHARE}shorewall/version
chmod 644 ${DESTDIR}${SHARE}shorewall/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$DESTDIR" ]; then
    rm -f ${SHARE}shorewall/init
    ln -s ${DEST}/${INIT} ${SHARE}shorewall/init
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

if [ -n "${DESTDIR}${OWNERSHIP}" -a -d ${DESTDIR}/etc/logrotate.d ]; then
    install_file logrotate ${DESTDIR}/etc/logrotate.d/shorewall 0644
    echo "Logrotate file installed as ${DESTDIR}/etc/logrotate.d/shorewall"
fi

if [ -z "$DESTDIR" ]; then
    rm -rf /usr/share/shorewall-perl
    rm -rf /usr/share/shorewall-shell
fi

if [ -n "$OWNERSHIP" -a -z "$DESTDIR" -a -n "$first_install" -a -z "${CYGWIN}${MAC}" ]; then
    if [ -n "$DEBIAN" ]; then
	install_file default.debian /etc/default/shorewall 0644

	update-rc.d shorewall defaults

	echo "shorewall will start automatically at boot"
	echo "Set startup=1 in /etc/default/shorewall to enable"
	touch /var/log/shorewall-init.log
	perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' ${ETC}shorewall/shorewall.conf
    else
	if [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
	    if insserv /etc/init.d/shorewall ; then
		echo "shorewall will start automatically at boot"
		echo "Set STARTUP_ENABLED=Yes in ${ETC}shorewall/shorewall.conf to enable"
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	    if chkconfig --add shorewall ; then
		echo "shorewall will start automatically in run levels as follows:"
		echo "Set STARTUP_ENABLED=Yes in ${ETC}shorewall/shorewall.conf to enable"
		chkconfig --list shorewall
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/rc-update ]; then
	    if rc-update add shorewall default; then
		echo "shorewall will start automatically at boot"
		echo "Set STARTUP_ENABLED=Yes in ${ETC}shorewall/shorewall.conf to enable"
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
