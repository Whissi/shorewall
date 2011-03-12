#!/bin/sh
#
# Script to install Shoreline6 Firewall
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000,2001,2002,2003,2004,2005,2008,2009,2010 - Tom Eastep (teastep@shorewall.net)
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
    echo  "WARNING: Unable to configure shorewall6 to start automatically at boot" >&2
}

delete_file() # $1 = file to delete
{
    rm -f $1
}

install_file() # $1 = source $2 = target $3 = mode
{
    run_install $OWNERSHIP -m $3 $1 ${2}
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

if [ -z "$DEST" ] ; then
	DEST="/etc/init.d"
fi

if [ -z "$INIT" ] ; then
	INIT="shorewall6"
fi

DEBIAN=
CYGWIN=
MAC=
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
	    echo "Shorewall6 Firewall Installer Version $VERSION"
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

    [ -n ${ETC:=${BASE}/etc/} ]
    [ -n ${SBIN:=${BASE}/sbin/} ]
    [ -n ${SHARE:=${BASE}/share/} ]
    [ -n ${VAR:=${BASE}/var/lib/} ]
    [ -n ${MANDIR:=${BASE}/man} ]
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

#
# Determine where to install the firewall script
#

if [ `id -u` != 0 ] ; then
    echo "Not setting file owner/group permissions, not running as root."
    OWNERSHIP=""
fi    

if [ -n "$DESTDIR" -o -z "$OWNERSHIP" ]; then
    install -d $OWNERSHIP -m 755 ${DESTDIR}${SBIN}
    [ -n "$DESTDIR" ] && install -d $OWNERSHIP -m 755 ${DESTDIR}${DEST}
   
    CYGWIN=
    MAC=
else
    [ -x ${SHARE}shorewall/compiler.pl ] || \
	{ echo "   ERROR: Shorewall >= 4.3.5 is not installed" >&2; exit 1; }
    if [ -n "$CYGWIN" ]; then
	echo "Installing Cygwin-specific configuration..."
    elif [ -n "$MAC" ]; then
	echo "Installing Mac-specific configuration..."	
    else
	if [ -d /etc/apt -a -e /usr/bin/dpkg ]; then
	    echo "Installing Debian-specific configuration..."
	    DEBIAN=yes
	    SPARSE=yes
	elif [ -f /etc/slackware-version ] ; then
	    echo "Installing Slackware-specific configuration..."
	    DEST="/etc/rc.d"
		SLACKWARE=yes
	    INIT="rc.firewall"
	elif [ -f /etc/arch-release ] ; then
	    echo "Installing ArchLinux-specific configuration..."
	    DEST="/etc/rc.d"
	    INIT="shorewall6"
	    ARCHLINUX=yes
	fi
    fi
fi

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

echo "Installing Shorewall6 Version $VERSION"

#
# Check for ${SBIN}shorewall6
#
if [ -f ${DESTDIR}${SBIN}shorewall6 ]; then
    first_install=""
else
    first_install="Yes"
fi

#
# Install the Firewall Script
#
if [ -n "${DESTDIR}${OWNERSHIP}" ]; then
    if [ -n "$DEBIAN" ]; then
	install_file init.debian.sh /etc/init.d/shorewall6 0544
    elif [ -n "$SLACKWARE" ]; then
	install_file init.slackware.shorewall6.sh ${DESTDIR}${DEST}/rc.shorewall6 0544
    elif [ -n "$ARCHLINUX" ]; then
	install_file init.archlinux.sh ${DESTDIR}${DEST}/$INIT 0544
    elif [ -n "$INIT" ]; then
	install_file init.sh ${DESTDIR}${DEST}/$INIT 0544
    fi

    [ -n "$INIT" ] && echo  "Shorewall6 script installed in ${DESTDIR}${DEST}/$INIT"

    mkdir -p ${DESTDIR}/etc/shorewall6
    chmod 755 ${DESTDIR}/etc/shorewall6
fi

#
# Create ${ETC}shorewall, ${SHARE}shorewall and /var/lib/shorewall6 if needed
#
mkdir -p ${DESTDIR}${ETC}shorewall6
mkdir -p ${DESTDIR}${SBIN}
mkdir -p ${DESTDIR}${SHARE}shorewall6/configfiles
mkdir -p ${DESTDIR}/${VAR}shorewall6

chmod 755 ${DESTDIR}${ETC}shorewall6
chmod 755 ${DESTDIR}${SBIN}
chmod 755 ${DESTDIR}${SHARE}shorewall6/configfiles

if [ -n "$DESTDIR" ]; then
    mkdir -p ${DESTDIR}/etc/logrotate.d
    chmod 755 ${DESTDIR}/etc/logrotate.d
fi

if [ -z "$CYGWIN" ]; then
   install_file shorewall6 ${DESTDIR}${SBIN}shorewall6 0755
   echo "shorewall6 control program installed in ${DESTDIR}${SBIN}shorewall6"
else
   install_file shorewall6 ${DESTDIR}/bin/shorewall6 0755 ${DESTDIR}/var/lib/shorewall6-${VERSION}.bkout
   echo "shorewall6 control program installed in ${DESTDIR}/bin/shorewall6"
fi

#
# Install the config file
#
run_install $OWNERSHIP -m 0644 shorewall6.conf ${DESTDIR}${SHARE}shorewall6/configfiles/shorewall6.conf

eval perl -p -w -i -e \'s\|^CONFIG_PATH=.\*\|CONFIG_PATH=${SHARE}shorewall6/configfiles:${SHARE}shorewall\|\;\' ${DESTDIR}${SHARE}shorewall6/configfiles/shorewall6.conf
eval perl -p -w -i -e \'s\|^STARTUP_LOG=.\*\|STARTUP_LOG=/var/log/shorewall6-lite-init.log\|\;\' ${DESTDIR}${SHARE}shorewall6/configfiles/shorewall6.conf

if [ ! -f ${DESTDIR}${ETC}shorewall6/shorewall6.conf ]; then
   run_install $OWNERSHIP -m 0644 shorewall6.conf ${DESTDIR}${ETC}shorewall6/shorewall6.conf

   if [ -n "$DEBIAN" ] && mywhich perl; then
       #
       # Make a Debian-like shorewall6.conf
       #
       perl -p -w -i -e 's|^STARTUP_ENABLED=.*|STARTUP_ENABLED=Yes|;' ${DESTDIR}${ETC}shorewall6/shorewall6.conf
   fi

   echo "Config file installed as ${DESTDIR}${ETC}shorewall6/shorewall6.conf"
fi


if [ -n "$ARCHLINUX" ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${DESTDIR}${ETC}shorewall6/shorewall6.conf
fi
#
# Install the zones file
#
run_install $OWNERSHIP -m 0644 zones ${DESTDIR}${SHARE}shorewall6/configfiles/zones

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/zones ]; then
    run_install $OWNERSHIP -m 0644 zones ${DESTDIR}${ETC}shorewall6/zones
    echo "Zones file installed as ${DESTDIR}${ETC}shorewall6/zones"
fi

delete_file ${DESTDIR}${SHARE}shorewall6/compiler
delete_file ${DESTDIR}${SHARE}shorewall6/lib.accounting
delete_file ${DESTDIR}${SHARE}shorewall6/lib.actions
delete_file ${DESTDIR}${SHARE}shorewall6/lib.dynamiczones
delete_file ${DESTDIR}${SHARE}shorewall6/lib.maclist
delete_file ${DESTDIR}${SHARE}shorewall6/lib.nat
delete_file ${DESTDIR}${SHARE}shorewall6/lib.providers
delete_file ${DESTDIR}${SHARE}shorewall6/lib.proxyarp
delete_file ${DESTDIR}${SHARE}shorewall6/lib.tc
delete_file ${DESTDIR}${SHARE}shorewall6/lib.tcrules
delete_file ${DESTDIR}${SHARE}shorewall6/lib.tunnels
delete_file ${DESTDIR}${SHARE}shorewall6/prog.header6
delete_file ${DESTDIR}${SHARE}shorewall6/prog.footer6

#
# Install wait4ifup
#

install_file wait4ifup ${DESTDIR}${SHARE}shorewall6/wait4ifup 0755

echo
echo "wait4ifup installed in ${DESTDIR}${SHARE}shorewall6/wait4ifup"

#
# Install the policy file
#
run_install $OWNERSHIP -m 0644 policy ${DESTDIR}${SHARE}shorewall6/configfiles/policy

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/policy ]; then
    run_install $OWNERSHIP -m 0600 policy ${DESTDIR}${ETC}shorewall6/policy
    echo "Policy file installed as ${DESTDIR}${ETC}shorewall6/policy"
fi
#
# Install the interfaces file
#
run_install $OWNERSHIP -m 0644 interfaces ${DESTDIR}${SHARE}shorewall6/configfiles/interfaces

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/interfaces ]; then
    run_install $OWNERSHIP -m 0600 interfaces ${DESTDIR}${ETC}shorewall6/interfaces
    echo "Interfaces file installed as ${DESTDIR}${ETC}shorewall6/interfaces"
fi

#
# Install the hosts file
#
run_install $OWNERSHIP -m 0644 hosts ${DESTDIR}${SHARE}shorewall6/configfiles/hosts

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/hosts ]; then
    run_install $OWNERSHIP -m 0600 hosts ${DESTDIR}${ETC}shorewall6/hosts
    echo "Hosts file installed as ${DESTDIR}${ETC}shorewall6/hosts"
fi
#
# Install the rules file
#
run_install $OWNERSHIP -m 0644 rules ${DESTDIR}${SHARE}shorewall6/configfiles/rules

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/rules ]; then
    run_install $OWNERSHIP -m 0600 rules ${DESTDIR}${ETC}shorewall6/rules
    echo "Rules file installed as ${DESTDIR}${ETC}shorewall6/rules"
fi
#
# Install the Parameters file
#
run_install $OWNERSHIP -m 0644 params ${DESTDIR}${SHARE}shorewall6/configfiles/params

if [ -f ${DESTDIR}${ETC}shorewall6/params ]; then
    chmod 0644 ${DESTDIR}${ETC}shorewall6/params
else
    run_install $OWNERSHIP -m 0644 params ${DESTDIR}${ETC}shorewall6/params
    echo "Parameter file installed as ${DESTDIR}${ETC}shorewall6/params"
fi
#
# Install the Stopped Routing file
#
run_install $OWNERSHIP -m 0644 routestopped ${DESTDIR}${SHARE}shorewall6/configfiles/routestopped

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/routestopped ]; then
    run_install $OWNERSHIP -m 0600 routestopped ${DESTDIR}${ETC}shorewall6/routestopped
    echo "Stopped Routing file installed as ${DESTDIR}${ETC}shorewall6/routestopped"
fi
#
# Install the Mac List file
#
run_install $OWNERSHIP -m 0644 maclist ${DESTDIR}${SHARE}shorewall6/configfiles/maclist

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/maclist ]; then
    run_install $OWNERSHIP -m 0600 maclist ${DESTDIR}${ETC}shorewall6/maclist
    echo "MAC list file installed as ${DESTDIR}${ETC}shorewall6/maclist"
fi
#
# Install the Modules file
#
run_install $OWNERSHIP -m 0644 modules ${DESTDIR}${SHARE}shorewall6/modules
echo "Modules file installed as ${DESTDIR}${SHARE}shorewall6/modules"

for f in modules.*; do
    run_install $OWNERSHIP -m 0644 $f ${DESTDIR}${SHARE}shorewall6/$f
    echo "Modules file $f installed as ${DESTDIR}${SHARE}shorewall6/$f"
done

#
# Install the Module Helpers file
#
run_install $OWNERSHIP -m 0644 helpers ${DESTDIR}${SHARE}shorewall6/helpers
echo "Helper modules file installed as ${DESTDIR}${SHARE}shorewall6/helpers"

#
# Install the TC Rules file
#
run_install $OWNERSHIP -m 0644 tcrules ${DESTDIR}${SHARE}shorewall6/configfiles/tcrules

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/tcrules ]; then
    run_install $OWNERSHIP -m 0600 tcrules ${DESTDIR}${ETC}shorewall6/tcrules
    echo "TC Rules file installed as ${DESTDIR}${ETC}shorewall6/tcrules"
fi

#
# Install the TC Interfaces file
#
run_install $OWNERSHIP -m 0644 tcinterfaces ${DESTDIR}${SHARE}shorewall6/configfiles/tcinterfaces

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/tcinterfaces ]; then
    run_install $OWNERSHIP -m 0600 tcinterfaces ${DESTDIR}${ETC}shorewall6/tcinterfaces
    echo "TC Interfaces file installed as ${DESTDIR}${ETC}shorewall6/tcinterfaces"
fi

#
# Install the TC Priority file
#
run_install $OWNERSHIP -m 0644 tcpri ${DESTDIR}${SHARE}shorewall6/configfiles/tcpri

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/tcpri ]; then
    run_install $OWNERSHIP -m 0600 tcpri ${DESTDIR}${ETC}shorewall6/tcpri
    echo "TC Priority file installed as ${DESTDIR}${ETC}shorewall6/tcpri"
fi

#
# Install the TOS file
#
run_install $OWNERSHIP -m 0644 tos ${DESTDIR}${SHARE}shorewall6/configfiles/tos

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/tos ]; then
    run_install $OWNERSHIP -m 0600 tos ${DESTDIR}${ETC}shorewall6/tos
    echo "TOS file installed as ${DESTDIR}${ETC}shorewall6/tos"
fi
#
# Install the Tunnels file
#
run_install $OWNERSHIP -m 0644 tunnels ${DESTDIR}${SHARE}shorewall6/configfiles/tunnels

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/tunnels ]; then
    run_install $OWNERSHIP -m 0600 tunnels ${DESTDIR}${ETC}shorewall6/tunnels
    echo "Tunnels file installed as ${DESTDIR}${ETC}shorewall6/tunnels"
fi
#
# Install the blacklist file
#
run_install $OWNERSHIP -m 0644 blacklist ${DESTDIR}${SHARE}shorewall6/configfiles/blacklist

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/blacklist ]; then
    run_install $OWNERSHIP -m 0600 blacklist ${DESTDIR}${ETC}shorewall6/blacklist
    echo "Blacklist file installed as ${DESTDIR}${ETC}shorewall6/blacklist"
fi
#
# Install the Providers file
#
run_install $OWNERSHIP -m 0644 providers ${DESTDIR}${SHARE}shorewall6/configfiles/providers

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/providers ]; then
    run_install $OWNERSHIP -m 0600 providers ${DESTDIR}${ETC}shorewall6/providers
    echo "Providers file installed as ${DESTDIR}${ETC}shorewall6/providers"
fi

#
# Install the Route Rules file
#
run_install $OWNERSHIP -m 0644 route_rules ${DESTDIR}${SHARE}shorewall6/configfiles/route_rules

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/route_rules ]; then
    run_install $OWNERSHIP -m 0600 route_rules ${DESTDIR}${ETC}shorewall6/route_rules
    echo "Routing rules file installed as ${DESTDIR}${ETC}shorewall6/route_rules"
fi

#
# Install the tcclasses file
#
run_install $OWNERSHIP -m 0644 tcclasses ${DESTDIR}${SHARE}shorewall6/configfiles/tcclasses

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/tcclasses ]; then
    run_install $OWNERSHIP -m 0600 tcclasses ${DESTDIR}${ETC}shorewall6/tcclasses
    echo "TC Classes file installed as ${DESTDIR}${ETC}shorewall6/tcclasses"
fi

#
# Install the tcdevices file
#
run_install $OWNERSHIP -m 0644 tcdevices ${DESTDIR}${SHARE}shorewall6/configfiles/tcdevices

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/tcdevices ]; then
    run_install $OWNERSHIP -m 0600 tcdevices ${DESTDIR}${ETC}shorewall6/tcdevices
    echo "TC Devices file installed as ${DESTDIR}${ETC}shorewall6/tcdevices"
fi

#
# Install the tcfilters file
#
run_install $OWNERSHIP -m 0644 tcfilters ${DESTDIR}${SHARE}shorewall6/configfiles/tcfilters

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/tcfilters ]; then
    run_install $OWNERSHIP -m 0600 tcfilters ${DESTDIR}${ETC}shorewall6/tcfilters
    echo "TC Filters file installed as ${DESTDIR}${ETC}shorewall6/tcfilters"
fi

#
# Install the Notrack file
#
run_install $OWNERSHIP -m 0644 notrack ${DESTDIR}${SHARE}shorewall6/configfiles/notrack

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/notrack ]; then
    run_install $OWNERSHIP -m 0600 notrack ${DESTDIR}${ETC}shorewall6/notrack
    echo "Notrack file installed as ${DESTDIR}${ETC}shorewall6/notrack"
fi

#
# Install the Secmarks file
#
run_install $OWNERSHIP -m 0644 secmarks ${DESTDIR}${SHARE}shorewall6/configfiles/secmarks

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/secmarks ]; then
    run_install $OWNERSHIP -m 0600 secmarks ${DESTDIR}${ETC}shorewall6/secmarks
    echo "Secmarks file installed as ${DESTDIR}${ETC}shorewall6/secmarks"
fi
#
# Install the default config path file
#
install_file configpath ${DESTDIR}${SHARE}shorewall6/configpath 0644
echo "Default config path file installed as ${DESTDIR}${SHARE}shorewall6/configpath"
#
# Install the init file
#
run_install $OWNERSHIP -m 0644 init ${DESTDIR}${SHARE}shorewall6/configfiles/init

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/init ]; then
    run_install $OWNERSHIP -m 0600 init ${DESTDIR}${ETC}shorewall6/init
    echo "Init file installed as ${DESTDIR}${ETC}shorewall6/init"
fi
#
# Install the start file
#
run_install $OWNERSHIP -m 0644 start ${DESTDIR}${SHARE}shorewall6/configfiles/start

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/start ]; then
    run_install $OWNERSHIP -m 0600 start ${DESTDIR}${ETC}shorewall6/start
    echo "Start file installed as ${DESTDIR}${ETC}shorewall6/start"
fi
#
# Install the stop file
#
run_install $OWNERSHIP -m 0644 stop ${DESTDIR}${SHARE}shorewall6/configfiles/stop

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/stop ]; then
    run_install $OWNERSHIP -m 0600 stop ${DESTDIR}${ETC}shorewall6/stop
    echo "Stop file installed as ${DESTDIR}${ETC}shorewall6/stop"
fi
#
# Install the stopped file
#
run_install $OWNERSHIP -m 0644 stopped ${DESTDIR}${SHARE}shorewall6/configfiles/stopped

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/stopped ]; then
    run_install $OWNERSHIP -m 0600 stopped ${DESTDIR}${ETC}shorewall6/stopped
    echo "Stopped file installed as ${DESTDIR}${ETC}shorewall6/stopped"
fi
#
# Install the Accounting file
#
run_install $OWNERSHIP -m 0644 accounting ${DESTDIR}${SHARE}shorewall6/configfiles/accounting

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/accounting ]; then
    run_install $OWNERSHIP -m 0600 accounting ${DESTDIR}${ETC}shorewall6/accounting
    echo "Accounting file installed as ${DESTDIR}${ETC}shorewall6/accounting"
fi
#
# Install the Started file
#
run_install $OWNERSHIP -m 0644 started ${DESTDIR}${SHARE}shorewall6/configfiles/started

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/started ]; then
    run_install $OWNERSHIP -m 0600 started ${DESTDIR}${ETC}shorewall6/started
    echo "Started file installed as ${DESTDIR}${ETC}shorewall6/started"
fi
#
# Install the Restored file
#
run_install $OWNERSHIP -m 0644 restored ${DESTDIR}${SHARE}shorewall6/configfiles/restored

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/restored ]; then
    run_install $OWNERSHIP -m 0600 restored ${DESTDIR}${ETC}shorewall6/restored
    echo "Restored file installed as ${DESTDIR}${ETC}shorewall6/restored"
fi
#
# Install the Clear file
#
run_install $OWNERSHIP -m 0644 clear ${DESTDIR}${SHARE}shorewall6/configfiles/clear

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/clear ]; then
    run_install $OWNERSHIP -m 0600 clear ${DESTDIR}${ETC}shorewall6/clear
    echo "Clear file installed as ${DESTDIR}${ETC}shorewall6/clear"
fi
#
# Install the Isusable file
#
run_install $OWNERSHIP -m 0644 isusable ${DESTDIR}${SHARE}shorewall6/configfiles/isusable

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/isusable ]; then
    run_install $OWNERSHIP -m 0600 isusable ${DESTDIR}${ETC}shorewall6/isusable
    echo "Isusable file installed as ${DESTDIR}${ETC}shorewall/isusable"
fi
#
# Install the Refresh file
#
run_install $OWNERSHIP -m 0644 refresh ${DESTDIR}${SHARE}shorewall6/configfiles/refresh

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/refresh ]; then
    run_install $OWNERSHIP -m 0600 refresh ${DESTDIR}${ETC}shorewall6/refresh
    echo "Refresh file installed as ${DESTDIR}${ETC}shorewall6/refresh"
fi
#
# Install the Refreshed file
#
run_install $OWNERSHIP -m 0644 refreshed ${DESTDIR}${SHARE}shorewall6/configfiles/refreshed

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/refreshed ]; then
    run_install $OWNERSHIP -m 0600 refreshed ${DESTDIR}${ETC}shorewall6/refreshed
    echo "Refreshed file installed as ${DESTDIR}${ETC}shorewall6/refreshed"
fi
#
# Install the Tcclear file
#
run_install $OWNERSHIP -m 0644 tcclear ${DESTDIR}${SHARE}shorewall6/configfiles/tcclear

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/tcclear ]; then
    run_install $OWNERSHIP -m 0600 tcclear ${DESTDIR}${ETC}shorewall6/tcclear
    echo "Tcclear file installed as ${DESTDIR}${ETC}shorewall6/tcclear"
fi
#
# Install the Scfilter file
#
run_install $OWNERSHIP -m 0644 scfilter ${DESTDIR}${SHARE}shorewall6/configfiles/scfilter

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/scfilter ]; then
    run_install $OWNERSHIP -m 0600 scfilter ${DESTDIR}${ETC}shorewall6/scfilter
    echo "Scfilter file installed as ${DESTDIR}${ETC}shorewall6/scfilter"
fi

#
# Install the Providers file
#
run_install $OWNERSHIP -m 0644 providers ${DESTDIR}${SHARE}shorewall6/configfiles/providers

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/providers ]; then
    run_install $OWNERSHIP -m 0600 providers ${DESTDIR}${ETC}shorewall6/providers
    echo "Providers file installed as ${DESTDIR}${ETC}shorewall6/providers"
fi
#
# Install the Proxyndp file
#
run_install $OWNERSHIP -m 0644 proxyndp ${DESTDIR}${SHARE}shorewall6/configfiles/proxyndp

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/proxyndp ]; then
    run_install $OWNERSHIP -m 0600 proxyndp ${DESTDIR}${ETC}shorewall6/proxyndp
    echo "Proxyndp file installed as ${DESTDIR}${ETC}shorewall6/proxyndp"
fi

#
# Install the Standard Actions file
#
install_file actions.std ${DESTDIR}${SHARE}shorewall6/actions.std 0644
echo "Standard actions file installed as ${DESTDIR}/usr/shared/shorewall6/actions.std"

#
# Install the Actions file
#
run_install $OWNERSHIP -m 0644 actions ${DESTDIR}${SHARE}shorewall6/configfiles/actions

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${ETC}shorewall6/actions ]; then
    run_install $OWNERSHIP -m 0644 actions ${DESTDIR}${ETC}shorewall6/actions
    echo "Actions file installed as ${DESTDIR}${ETC}shorewall6/actions"
fi

#
# Install the  Makefiles
#
run_install $OWNERSHIP -m 0644 Makefile-lite ${DESTDIR}${SHARE}shorewall6/configfiles/Makefile

if [ -z "$SPARSE" ]; then
    run_install $OWNERSHIP -m 0600 Makefile ${DESTDIR}${ETC}shorewall6/Makefile
    echo "Makefile installed as ${DESTDIR}${ETC}shorewall6/Makefile"
fi
#
# Install the Action files
#
for f in action.* ; do
    install_file $f ${DESTDIR}${SHARE}shorewall6/$f 0644
    echo "Action ${f#*.} file installed as ${DESTDIR}${SHARE}shorewall6/$f"
done

# Install the Macro files
#
for f in macro.* ; do
    install_file $f ${DESTDIR}${SHARE}shorewall6/$f 0644
    echo "Macro ${f#*.} file installed as ${DESTDIR}${SHARE}shorewall6/$f"
done
#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${DESTDIR}${SHARE}shorewall6/$f 0644
	echo "Library ${f#*.} file installed as ${DESTDIR}${SHARE}shorewall6/$f"
    fi
done

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

}' ${DESTDIR}${SBIN}shorewall6 ${DESTDIR}${SHARE}shorewall6/lib.base

#
# Symbolically link 'functions' to lib.base
#
ln -sf lib.base ${DESTDIR}${SHARE}shorewall6/functions
#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}${SHARE}shorewall6/version
chmod 644 ${DESTDIR}${SHARE}shorewall6/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$DESTDIR" -o -z "$OWNERSHIP" ]; then
    rm -f ${SHARE}shorewall6/init
    ln -s ${DEST}/${INIT} ${SHARE}shorewall6/init
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
    run_install $OWNERSHIP -m 0644 logrotate ${DESTDIR}/etc/logrotate.d/shorewall6
    echo "Logrotate file installed as ${DESTDIR}/etc/logrotate.d/shorewall6"
fi

if [ -n "${OWNERSHIP}" -a -z "$DESTDIR" -a -n "$first_install" -a -z "${CYGWIN}${MAC}" ]; then
    if [ -n "$DEBIAN" ]; then
	run_install $OWNERSHIP -m 0644 default.debian /etc/default/shorewall6

	update-rc.d shorewall6 defaults

	echo "shorewall6 will start automatically at boot"
	echo "Set startup=1 in /etc/default/shorewall6 to enable"
	touch /var/log/shorewall6-init.log
	perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' ${ETC}shorewall6/shorewall6.conf
    else
	if [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
	    if insserv /etc/init.d/shorewall6 ; then
		echo "shorewall6 will start automatically at boot"
		echo "Set STARTUP_ENABLED=Yes in /etc/shorewall6/shorewall6.conf to enable"
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	    if chkconfig --add shorewall6 ; then
		echo "shorewall6 will start automatically in run levels as follows:"
		echo "Set STARTUP_ENABLED=Yes in /etc/shorewall6/shorewall6.conf to enable"
		chkconfig --list shorewall6
	    else
		cant_autostart
	    fi
	elif [ -x $/sbin/rc-update ]; then
	    if rc-update add shorewall6 default; then
		echo "shorewall6 will start automatically at boot"
		echo "Set STARTUP_ENABLED=Yes in /etc/shorewall6/shorewall6.conf to enable"
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
echo "shorewall6 Version $VERSION Installed"
