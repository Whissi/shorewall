#!/bin/sh
#
# Script to install Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2000,2001,2002,2003,2004,2005 - Tom Eastep (teastep@shorewall.net)
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
#       Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#

VERSION=4.0.0-Beta1

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME"
    echo "       $ME -v"
    echo "       $ME -h"
    echo "       $ME -n"
    exit $1
}

split() {
    local ifs=$IFS
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

backup_directory() # $1 = directory to backup
{
    if [ -d $1 ]; then
	if cp -a $1  ${1}-${VERSION}.bkout ; then
	    echo
	    echo "$1 saved to ${1}-${VERSION}.bkout"
	else
	    exit 1
	fi
    fi
}

backup_file() # $1 = file to backup, $2 = (optional) Directory in which to create the backup
{
    if [ -z "${PREFIX}{NOBACKUP}" ]; then
	if [ -f $1 -a ! -f ${1}-${VERSION}.bkout ]; then
	    if [ -n "$2" ]; then
		if [ -d $2 ]; then
		    if cp -f $1 $2 ; then
			echo
			echo "$1 saved to $2/$(basename $1)"
		    else
			exit 1
		    fi
		fi
	    elif cp $1 ${1}-${VERSION}.bkout; then
		echo
		echo "$1 saved to ${1}-${VERSION}.bkout"
	    else
		exit 1
	    fi
	fi
    fi
}

delete_file() # $1 = file to delete
{
    rm -f $1
}

install_file() # $1 = source $2 = target $3 = mode
{
    run_install $OWNERSHIP -m $3 $1 ${2}
}

install_file_with_backup() # $1 = source $2 = target $3 = mode $4 = (optional) backup directory
{
    backup_file $2 $4
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

if [ -z "$OWNER" ] ; then
	OWNER=root
fi

if [ -z "$GROUP" ] ; then
	GROUP=root
fi

NOBACKUP=

while [ $# -gt 0 ] ; do
    case "$1" in
	-h|help|?)
	    usage 0
	    ;;
        -v)
	    echo "Shorewall Firewall Installer Version $VERSION"
	    exit 0
	    ;;
	-n)
	    NOBACKUP=Yes
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
DEBIAN=

OWNERSHIP="-o $OWNER -g $GROUP"

if [ -n "$PREFIX" ]; then
	if [ `id -u` != 0 ] ; then
	    echo "Not setting file owner/group permissions, not running as root."
	    OWNERSHIP=""
	fi

	install -d $OWNERSHIP -m 755 ${PREFIX}/sbin
	install -d $OWNERSHIP -m 755 ${PREFIX}${DEST}
else
    [ -x /usr/share/shorewall-shell/compiler -o -x /usr/share/shorewall-perl/compiler.pl ] || \
	{ echo "   ERROR: No Shorewall compiler is installed" >&2; exit 1; }
    if [ -d /etc/apt -a -e /usr/bin/dpkg ]; then
	DEBIAN=yes
    elif [ -f /etc/slackware-version ] ; then
	DEST="/etc/rc.d"
	INIT="rc.firewall"
    elif [ -f /etc/arch-release ] ; then
	DEST="/etc/rc.d"
	INIT="shorewall"
	ARCHLINUX=yes
    fi
fi

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

echo "Installing Shorewall-common Version $VERSION"

#
# Check for /etc/shorewall
#
if [ -d ${PREFIX}/etc/shorewall ]; then
    first_install=""
    if [ -z "$NOBACKUP" ]; then
	backup_directory ${PREFIX}/etc/shorewall
	backup_directory ${PREFIX}/usr/share/shorewall
	backup_directory ${PREFIX}/var/lib/shorewall
    fi
else
    first_install="Yes"
fi

install_file_with_backup shorewall ${PREFIX}/sbin/shorewall 0555 ${PREFIX}/var/lib/shorewall-${VERSION}.bkout

echo "shorewall control program installed in ${PREFIX}/sbin/shorewall"

#
# Install the Firewall Script
#
if [ -n "$DEBIAN" ]; then
    install_file_with_backup init.debian.sh /etc/init.d/shorewall 0544 ${PREFIX}/usr/share/shorewall-${VERSION}.bkout
elif [ -n "$ARCHLINUX" ]; then
    install_file_with_backup init.archlinux.sh ${PREFIX}${DEST}/$INIT 0544 ${PREFIX}/usr/share/shorewall-${VERSION}.bkout

else
    install_file_with_backup init.sh ${PREFIX}${DEST}/$INIT 0544 ${PREFIX}/usr/share/shorewall-${VERSION}.bkout
fi

echo  "Shorewall script installed in ${PREFIX}${DEST}/$INIT"

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
#
# Install the config file
#
run_install $OWNERSHIP -m 0644 shorewall.conf ${PREFIX}/usr/share/shorewall/configfiles/shorewall.conf

qt mywhich perl && perl -p -w -i -e 's|^CONFIG_PATH=.*|CONFIG_PATH=/usr/share/shorewall/configfiles:/usr/share/shorewall|;' ${PREFIX}/usr/share/shorewall/configfiles/shorewall.conf

if [ ! -f ${PREFIX}/etc/shorewall/shorewall.conf ]; then
   run_install $OWNERSHIP -m 0644 shorewall.conf ${PREFIX}/etc/shorewall/shorewall.conf
   echo "Config file installed as ${PREFIX}/etc/shorewall/shorewall.conf"
fi


if [ -n "$ARCHLINUX" ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${PREFIX}/etc/shorewall/shorewall.conf
fi
#
# Install the zones file
#
run_install $OWNERSHIP -m 0644 zones ${PREFIX}/usr/share/shorewall/configfiles/zones

if [ ! -f ${PREFIX}/etc/shorewall/zones ]; then
    run_install $OWNERSHIP -m 0744 zones ${PREFIX}/etc/shorewall/zones
    echo "Zones file installed as ${PREFIX}/etc/shorewall/zones"
fi

delete_file /usr/share/shorewall/compiler
delete_file /usr/share/shorewall/lib.accounting
delete_file /usr/share/shorewall/lib.actions
delete_file /usr/share/shorewall/lib.dynamiczones
delete_file /usr/share/shorewall/lib.maclist
delete_file /usr/share/shorewall/lib.nat
delete_file /usr/share/shorewall/lib.providers
delete_file /usr/share/shorewall/lib.proxyarp
delete_file /usr/share/shorewall/lib.tc
delete_file /usr/share/shorewall/lib.tcrules
delete_file /usr/share/shorewall/lib.tunnels
delete_file /usr/share/shorewall/prog.header
delete_file /usr/share/shorewall/prog.footer

#
# Install wait4ifup
#

install_file wait4ifup ${PREFIX}/usr/share/shorewall/wait4ifup 0555

echo
echo "wait4ifup installed in ${PREFIX}/usr/share/shorewall/wait4ifup"

#
# Install the policy file
#
run_install $OWNERSHIP -m 0644 policy ${PREFIX}/usr/share/shorewall/configfiles/policy

if [ ! -f ${PREFIX}/etc/shorewall/policy ]; then
    run_install $OWNERSHIP -m 0600 policy ${PREFIX}/etc/shorewall/policy
    echo "Policy file installed as ${PREFIX}/etc/shorewall/policy"
fi
#
# Install the interfaces file
#
run_install $OWNERSHIP -m 0644 interfaces ${PREFIX}/usr/share/shorewall/configfiles/interfaces

if [ ! -f ${PREFIX}/etc/shorewall/interfaces ]; then
    run_install $OWNERSHIP -m 0600 interfaces ${PREFIX}/etc/shorewall/interfaces
    echo "Interfaces file installed as ${PREFIX}/etc/shorewall/interfaces"
fi
#
# Install the ipsec file
#
run_install $OWNERSHIP -m 0644 ipsec ${PREFIX}/usr/share/shorewall/configfiles/ipsec

if [ ! -f ${PREFIX}/etc/shorewall/ipsec ]; then
    run_install $OWNERSHIP -m 0600 ipsec ${PREFIX}/etc/shorewall/ipsec
    echo "Dummy IPSEC file installed as ${PREFIX}/etc/shorewall/ipsec"
fi

#
# Install the hosts file
#
run_install $OWNERSHIP -m 0644 hosts ${PREFIX}/usr/share/shorewall/configfiles/hosts

if [ ! -f ${PREFIX}/etc/shorewall/hosts ]; then
    run_install $OWNERSHIP -m 0600 hosts ${PREFIX}/etc/shorewall/hosts
    echo "Hosts file installed as ${PREFIX}/etc/shorewall/hosts"
fi
#
# Install the rules file
#
run_install $OWNERSHIP -m 0644 rules ${PREFIX}/usr/share/shorewall/configfiles/rules

if [ ! -f ${PREFIX}/etc/shorewall/rules ]; then
    run_install $OWNERSHIP -m 0600 rules ${PREFIX}/etc/shorewall/rules
    echo "Rules file installed as ${PREFIX}/etc/shorewall/rules"
fi
#
# Install the NAT file
#
run_install $OWNERSHIP -m 0644 nat ${PREFIX}/usr/share/shorewall/configfiles/nat

if [ ! -f ${PREFIX}/etc/shorewall/nat ]; then
    run_install $OWNERSHIP -m 0600 nat ${PREFIX}/etc/shorewall/nat
    echo "NAT file installed as ${PREFIX}/etc/shorewall/nat"
fi
#
# Install the NETMAP file
#
run_install $OWNERSHIP -m 0644 netmap ${PREFIX}/usr/share/shorewall/configfiles/netmap

if [ ! -f ${PREFIX}/etc/shorewall/netmap ]; then
    run_install $OWNERSHIP -m 0600 netmap ${PREFIX}/etc/shorewall/netmap
    echo "NETMAP file installed as ${PREFIX}/etc/shorewall/netmap"
fi
#
# Install the Parameters file
#
run_install $OWNERSHIP -m 0644 params ${PREFIX}/usr/share/shorewall/configfiles/params

if [ ! -f ${PREFIX}/etc/shorewall/params ]; then
    run_install $OWNERSHIP -m 0644 params ${PREFIX}/etc/shorewall/params
    echo "Parameter file installed as ${PREFIX}/etc/shorewall/params"
fi
#
# Install the proxy ARP file
#
run_install $OWNERSHIP -m 0644 proxyarp ${PREFIX}/usr/share/shorewall/configfiles/proxyarp

if [ ! -f ${PREFIX}/etc/shorewall/proxyarp ]; then
    run_install $OWNERSHIP -m 0600 proxyarp ${PREFIX}/etc/shorewall/proxyarp
    echo "Proxy ARP file installed as ${PREFIX}/etc/shorewall/proxyarp"
fi
#
# Install the Stopped Routing file
#
run_install $OWNERSHIP -m 0644 routestopped ${PREFIX}/usr/share/shorewall/configfiles/routestopped

if [ ! -f ${PREFIX}/etc/shorewall/routestopped ]; then
    run_install $OWNERSHIP -m 0600 routestopped ${PREFIX}/etc/shorewall/routestopped
    echo "Stopped Routing file installed as ${PREFIX}/etc/shorewall/routestopped"
fi
#
# Install the Mac List file
#
run_install $OWNERSHIP -m 0644 maclist ${PREFIX}/usr/share/shorewall/configfiles/maclist

if [ ! -f ${PREFIX}/etc/shorewall/maclist ]; then
    run_install $OWNERSHIP -m 0600 maclist ${PREFIX}/etc/shorewall/maclist
    echo "MAC list file installed as ${PREFIX}/etc/shorewall/maclist"
fi
#
# Install the Masq file
#
run_install $OWNERSHIP -m 0644 masq ${PREFIX}/usr/share/shorewall/configfiles/masq

if [ ! -f ${PREFIX}/etc/shorewall/masq ]; then
    run_install $OWNERSHIP -m 0600 masq ${PREFIX}/etc/shorewall/masq
    echo "Masquerade file installed as ${PREFIX}/etc/shorewall/masq"
fi
#
# Install the Modules file
#
run_install $OWNERSHIP -m 0600 modules ${PREFIX}/usr/share/shorewall/modules
echo "Modules file installed as ${PREFIX}/usr/share/shorewall/modules"

#
# Install the TC Rules file
#
run_install $OWNERSHIP -m 0644 tcrules ${PREFIX}/usr/share/shorewall/configfiles/tcrules

if [ ! -f ${PREFIX}/etc/shorewall/tcrules ]; then
    run_install $OWNERSHIP -m 0600 tcrules ${PREFIX}/etc/shorewall/tcrules
    echo "TC Rules file installed as ${PREFIX}/etc/shorewall/tcrules"
fi

#
# Install the TOS file
#
run_install $OWNERSHIP -m 0644 tos ${PREFIX}/usr/share/shorewall/configfiles/tos

if [ ! -f ${PREFIX}/etc/shorewall/tos ]; then
    run_install $OWNERSHIP -m 0600 tos ${PREFIX}/etc/shorewall/tos
    echo "TOS file installed as ${PREFIX}/etc/shorewall/tos"
fi
#
# Install the Tunnels file
#
run_install $OWNERSHIP -m 0644 tunnels ${PREFIX}/usr/share/shorewall/configfiles/tunnels

if [ ! -f ${PREFIX}/etc/shorewall/tunnels ]; then
    run_install $OWNERSHIP -m 0600 tunnels ${PREFIX}/etc/shorewall/tunnels
    echo "Tunnels file installed as ${PREFIX}/etc/shorewall/tunnels"
fi
#
# Install the blacklist file
#
run_install $OWNERSHIP -m 0644 blacklist ${PREFIX}/usr/share/shorewall/configfiles/blacklist

if [ ! -f ${PREFIX}/etc/shorewall/blacklist ]; then
    run_install $OWNERSHIP -m 0600 blacklist ${PREFIX}/etc/shorewall/blacklist
    echo "Blacklist file installed as ${PREFIX}/etc/shorewall/blacklist"
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
run_install $OWNERSHIP -m 0644 providers ${PREFIX}/usr/share/shorewall/configfiles/providers

if [ ! -f ${PREFIX}/etc/shorewall/providers ]; then
    run_install $OWNERSHIP -m 0600 providers ${PREFIX}/etc/shorewall/providers
    echo "Providers file installed as ${PREFIX}/etc/shorewall/providers"
fi

#
# Install the Route Rules file
#
run_install $OWNERSHIP -m 0644 route_rules ${PREFIX}/usr/share/shorewall/configfiles/route_rules

if [ ! -f ${PREFIX}/etc/shorewall/route_rules ]; then
    run_install $OWNERSHIP -m 0600 route_rules ${PREFIX}/etc/shorewall/route_rules
    echo "Routing rules file installed as ${PREFIX}/etc/shorewall/route_rules"
fi

#
# Install the tcclasses file
#
run_install $OWNERSHIP -m 0644 tcclasses ${PREFIX}/usr/share/shorewall/configfiles/tcclasses

if [ ! -f ${PREFIX}/etc/shorewall/tcclasses ]; then
    run_install $OWNERSHIP -m 0600 tcclasses ${PREFIX}/etc/shorewall/tcclasses
    echo "TC Classes file installed as ${PREFIX}/etc/shorewall/tcclasses"
fi

#
# Install the tcdevices file
#
run_install $OWNERSHIP -m 0644 tcdevices ${PREFIX}/usr/share/shorewall/configfiles/tcdevices

if [ ! -f ${PREFIX}/etc/shorewall/tcdevices ]; then
    run_install $OWNERSHIP -m 0600 tcdevices ${PREFIX}/etc/shorewall/tcdevices
    echo "TC Devices file installed as ${PREFIX}/etc/shorewall/tcdevices"
fi

#
# Install the rfc1918 file
#
install_file rfc1918 ${PREFIX}/usr/share/shorewall/rfc1918 0644
echo "RFC 1918 file installed as ${PREFIX}/usr/share/shorewall/rfc1918"
#
# Install the default config path file
#
install_file configpath ${PREFIX}/usr/share/shorewall/configpath 0644
echo "Default config path file installed as ${PREFIX}/usr/share/shorewall/configpath"
#
# Install the init file
#
run_install $OWNERSHIP -m 0644 init ${PREFIX}/usr/share/shorewall/configfiles/init

if [ ! -f ${PREFIX}/etc/shorewall/init ]; then
    run_install $OWNERSHIP -m 0600 init ${PREFIX}/etc/shorewall/init
    echo "Init file installed as ${PREFIX}/etc/shorewall/init"
fi
#
# Install the initdone file
#
run_install $OWNERSHIP -m 0644 initdone ${PREFIX}/usr/share/shorewall/configfiles/initdone

if [ ! -f ${PREFIX}/etc/shorewall/initdone ]; then
    run_install $OWNERSHIP -m 0600 initdone ${PREFIX}/etc/shorewall/initdone
    echo "Initdone file installed as ${PREFIX}/etc/shorewall/initdone"
fi
#
# Install the start file
#
run_install $OWNERSHIP -m 0644 start ${PREFIX}/usr/share/shorewall/configfiles/start

if [ ! -f ${PREFIX}/etc/shorewall/start ]; then
    run_install $OWNERSHIP -m 0600 start ${PREFIX}/etc/shorewall/start
    echo "Start file installed as ${PREFIX}/etc/shorewall/start"
fi
#
# Install the stop file
#
run_install $OWNERSHIP -m 0644 stop ${PREFIX}/usr/share/shorewall/configfiles/stop

if [ ! -f ${PREFIX}/etc/shorewall/stop ]; then
    run_install $OWNERSHIP -m 0600 stop ${PREFIX}/etc/shorewall/stop
    echo "Stop file installed as ${PREFIX}/etc/shorewall/stop"
fi
#
# Install the stopped file
#
run_install $OWNERSHIP -m 0644 stopped ${PREFIX}/usr/share/shorewall/configfiles/stopped

if [ ! -f ${PREFIX}/etc/shorewall/stopped ]; then
    run_install $OWNERSHIP -m 0600 stopped ${PREFIX}/etc/shorewall/stopped
    echo "Stopped file installed as ${PREFIX}/etc/shorewall/stopped"
fi
#
# Install the ECN file
#
run_install $OWNERSHIP -m 0644 ecn ${PREFIX}/usr/share/shorewall/configfiles/ecn

if [ ! -f ${PREFIX}/etc/shorewall/ecn ]; then
    run_install $OWNERSHIP -m 0600 ecn ${PREFIX}/etc/shorewall/ecn
    echo "ECN file installed as ${PREFIX}/etc/shorewall/ecn"
fi
#
# Install the Accounting file
#
run_install $OWNERSHIP -m 0644 accounting ${PREFIX}/usr/share/shorewall/configfiles/accounting

if [ ! -f ${PREFIX}/etc/shorewall/accounting ]; then
    run_install $OWNERSHIP -m 0600 accounting ${PREFIX}/etc/shorewall/accounting
    echo "Accounting file installed as ${PREFIX}/etc/shorewall/accounting"
fi
#
# Install the Continue file
#
run_install $OWNERSHIP -m 0644 continue ${PREFIX}/usr/share/shorewall/configfiles/continue

if [ ! -f ${PREFIX}/etc/shorewall/continue ]; then
    run_install $OWNERSHIP -m 0600 continue ${PREFIX}/etc/shorewall/continue
    echo "Continue file installed as ${PREFIX}/etc/shorewall/continue"
fi
#
# Install the Started file
#
run_install $OWNERSHIP -m 0644 started ${PREFIX}/usr/share/shorewall/configfiles/started

if [ ! -f ${PREFIX}/etc/shorewall/started ]; then
    run_install $OWNERSHIP -m 0600 started ${PREFIX}/etc/shorewall/started
    echo "Started file installed as ${PREFIX}/etc/shorewall/started"
fi
#
# Install the Standard Actions file
#
install_file actions.std ${PREFIX}/usr/share/shorewall/actions.std 0644
echo "Standard actions file installed as ${PREFIX}/etc/shorewall/actions.std"

#
# Install the Actions file
#
run_install $OWNERSHIP -m 0644 actions ${PREFIX}/usr/share/shorewall/configfiles/actions

if [ ! -f ${PREFIX}/etc/shorewall/actions ]; then
    run_install $OWNERSHIP -m 0644 actions ${PREFIX}/etc/shorewall/actions
    echo "Actions file installed as ${PREFIX}/etc/shorewall/actions"
fi

#
# Install the  Makefiles
#
run_install $OWNERSHIP -m 0644 Makefile-lite ${PREFIX}/usr/share/shorewall/configfiles/Makefile
run_install $OWNERSHIP -m 0600 Makefile ${PREFIX}/etc/shorewall/Makefile
echo "Makefile installed as ${PREFIX}/etc/shorewall/Makefile"

#
# Install the Action files
#
for f in action.* ; do
    install_file $f ${PREFIX}/usr/share/shorewall/$f 0644
    echo "Action ${f#*.} file installed as ${PREFIX}/usr/share/shorewall/$f"
done

# Install the Macro files
#
for f in macro.* ; do
    install_file $f ${PREFIX}/usr/share/shorewall/$f 0644
    echo "Macro ${f#*.} file installed as ${PREFIX}/usr/share/shorewall/$f"
done
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

rm -f *.gz

for f in *.5; do
    gzip $f
    run_install -D  -m 0444 $f.gz ${PREFIX}/usr/share/man/man5/$f.gz
    echo "Man page $f.gz installed to /usr/share/man/man5/$f.gz"
done

for f in *.8; do
    gzip $f
    run_install -D  -m 0444 $f.gz ${PREFIX}/usr/share/man/man8/$f.gz
    echo "Man page $f.gz installed to /usr/share/man/man8/$f.gz"
done

cd ..

echo "Man Pages Installed"

#
# Install the firewall script
#
install_file firewall ${PREFIX}/usr/share/shorewall/firewall 0555

if [ -z "$PREFIX" -a -n "$first_install" ]; then
    if [ -n "$DEBIAN" ]; then
	run_install $OWNERSHIP -m 0644 default.debian /etc/default/shorewall
	ln -s ../init.d/shorewall /etc/rcS.d/S40shorewall
	echo "shorewall will start automatically at boot"
	echo "Set startup=1 in /etc/default/shorewall to enable"
	touch /var/log/shorewall-init.log
	qt mywhich perl && perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' /etc/shorewall/shorewall.conf
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
echo "shorewall-common Version $VERSION Installed"
