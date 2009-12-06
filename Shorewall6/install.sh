#!/bin/sh
#
# Script to install Shoreline6 Firewall
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000,2001,2002,2003,2004,2005,2008 - Tom Eastep (teastep@shorewall.net)
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

VERSION=4.4.4.2

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
	INIT="shorewall6"
fi

if [ -z "$RUNLEVELS" ] ; then
	RUNLEVELS=""
fi

DEBIAN=
CYGWIN=
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
    [ -x /usr/share/shorewall/compiler.pl ] || \
	{ echo "   ERROR: Shorewall >= 4.3.5 is not installed" >&2; exit 1; }
    if [ -z "$CYGWIN" ]; then
	if [ -d /etc/apt -a -e /usr/bin/dpkg ]; then
	    DEBIAN=yes
	elif [ -f /etc/slackware-version ] ; then
	    DEST="/etc/rc.d"
		SLACKWARE=yes
	    INIT="rc.firewall"
	elif [ -f /etc/arch-release ] ; then
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
# Check for /etc/shorewall6
#
if [ -d ${PREFIX}/etc/shorewall6 ]; then
    first_install=""
else
    first_install="Yes"
fi

if [ -z "$CYGWIN" ]; then
   install_file shorewall6 ${PREFIX}/sbin/shorewall6 0755 ${PREFIX}/var/lib/shorewall6-${VERSION}.bkout
   echo "shorewall6 control program installed in ${PREFIX}/sbin/shorewall6"
else
   install_file shorewall6 ${PREFIX}/bin/shorewall6 0755 ${PREFIX}/var/lib/shorewall6-${VERSION}.bkout
   echo "shorewall6 control program installed in ${PREFIX}/bin/shorewall6"
fi


#
# Install the Firewall Script
#
if [ -n "$DEBIAN" ]; then
    install_file init.debian.sh /etc/init.d/shorewall6 0544 ${PREFIX}/usr/share/shorewall6-${VERSION}.bkout
elif [ -n "$SLACKWARE" ]; then
    install_file init.slackware.shorewall6.sh ${PREFIX}${DEST}/rc.shorewall6 0544 ${PREFIX}/usr/share/shorewall6-${VERSION}.bkout
elif [ -n "$ARCHLINUX" ]; then
    install_file init.archlinux.sh ${PREFIX}${DEST}/$INIT 0544 ${PREFIX}/usr/share/shorewall6-${VERSION}.bkout
elif [ -n "$INIT" ]; then
    install_file init.sh ${PREFIX}${DEST}/$INIT 0544 ${PREFIX}/usr/share/shorewall6-${VERSION}.bkout
fi

[ -n "$CYGWIN" ] || echo  "Shorewall6 script installed in ${PREFIX}${DEST}/$INIT"

#
# Create /etc/shorewall, /usr/share/shorewall and /var/shorewall if needed
#
mkdir -p ${PREFIX}/etc/shorewall6
mkdir -p ${PREFIX}/usr/share/shorewall6
mkdir -p ${PREFIX}/usr/share/shorewall6/configfiles
mkdir -p ${PREFIX}/var/lib/shorewall6

chmod 755 ${PREFIX}/etc/shorewall6
chmod 755 ${PREFIX}/usr/share/shorewall6
chmod 755 ${PREFIX}/usr/share/shorewall6/configfiles

if [ -n "$PREFIX" ]; then
    mkdir -p ${PREFIX}/etc/logrotate.d
    chmod 755 ${PREFIX}/etc/logrotate.d
fi

#
# Install the config file
#
run_install $OWNERSHIP -m 0644 shorewall6.conf ${PREFIX}/usr/share/shorewall6/configfiles/shorewall6.conf

qt mywhich perl && perl -p -w -i -e 's|^CONFIG_PATH=.*|CONFIG_PATH=/usr/share/shorewall6/configfiles:/usr/share/shorewall6|;' ${PREFIX}/usr/share/shorewall6/configfiles/shorewall6.conf

if [ ! -f ${PREFIX}/etc/shorewall6/shorewall6.conf ]; then
   run_install $OWNERSHIP -m 0644 shorewall6.conf ${PREFIX}/etc/shorewall6/shorewall6.conf
   echo "Config file installed as ${PREFIX}/etc/shorewall6/shorewall6.conf"
fi


if [ -n "$ARCHLINUX" ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${PREFIX}/etc/shorewall6/shorewall6.conf
fi
#
# Install the zones file
#
run_install $OWNERSHIP -m 0644 zones ${PREFIX}/usr/share/shorewall6/configfiles/zones

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/zones ]; then
    run_install $OWNERSHIP -m 0744 zones ${PREFIX}/etc/shorewall6/zones
    echo "Zones file installed as ${PREFIX}/etc/shorewall6/zones"
fi

delete_file ${PREFIX}/usr/share/shorewall6/compiler
delete_file ${PREFIX}/usr/share/shorewall6/lib.accounting
delete_file ${PREFIX}/usr/share/shorewall6/lib.actions
delete_file ${PREFIX}/usr/share/shorewall6/lib.dynamiczones
delete_file ${PREFIX}/usr/share/shorewall6/lib.maclist
delete_file ${PREFIX}/usr/share/shorewall6/lib.nat
delete_file ${PREFIX}/usr/share/shorewall6/lib.providers
delete_file ${PREFIX}/usr/share/shorewall6/lib.proxyarp
delete_file ${PREFIX}/usr/share/shorewall6/lib.tc
delete_file ${PREFIX}/usr/share/shorewall6/lib.tcrules
delete_file ${PREFIX}/usr/share/shorewall6/lib.tunnels
delete_file ${PREFIX}/usr/share/shorewall6/prog.header
delete_file ${PREFIX}/usr/share/shorewall6/prog.footer

#
# Install wait4ifup
#

install_file wait4ifup ${PREFIX}/usr/share/shorewall6/wait4ifup 0755

echo
echo "wait4ifup installed in ${PREFIX}/usr/share/shorewall6/wait4ifup"

#
# Install the policy file
#
run_install $OWNERSHIP -m 0644 policy ${PREFIX}/usr/share/shorewall6/configfiles/policy

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/policy ]; then
    run_install $OWNERSHIP -m 0600 policy ${PREFIX}/etc/shorewall6/policy
    echo "Policy file installed as ${PREFIX}/etc/shorewall6/policy"
fi
#
# Install the interfaces file
#
run_install $OWNERSHIP -m 0644 interfaces ${PREFIX}/usr/share/shorewall6/configfiles/interfaces

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/interfaces ]; then
    run_install $OWNERSHIP -m 0600 interfaces ${PREFIX}/etc/shorewall6/interfaces
    echo "Interfaces file installed as ${PREFIX}/etc/shorewall6/interfaces"
fi

#
# Install the hosts file
#
run_install $OWNERSHIP -m 0644 hosts ${PREFIX}/usr/share/shorewall6/configfiles/hosts

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/hosts ]; then
    run_install $OWNERSHIP -m 0600 hosts ${PREFIX}/etc/shorewall6/hosts
    echo "Hosts file installed as ${PREFIX}/etc/shorewall6/hosts"
fi
#
# Install the rules file
#
run_install $OWNERSHIP -m 0644 rules ${PREFIX}/usr/share/shorewall6/configfiles/rules

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/rules ]; then
    run_install $OWNERSHIP -m 0600 rules ${PREFIX}/etc/shorewall6/rules
    echo "Rules file installed as ${PREFIX}/etc/shorewall6/rules"
fi
#
# Install the Parameters file
#
run_install $OWNERSHIP -m 0644 params ${PREFIX}/usr/share/shorewall6/configfiles/params

if [ -f ${PREFIX}/etc/shorewall6/params ]; then
    chmod 0644 ${PREFIX}/etc/shorewall6/params
else
    run_install $OWNERSHIP -m 0644 params ${PREFIX}/etc/shorewall6/params
    echo "Parameter file installed as ${PREFIX}/etc/shorewall6/params"
fi
#
# Install the Stopped Routing file
#
run_install $OWNERSHIP -m 0644 routestopped ${PREFIX}/usr/share/shorewall6/configfiles/routestopped

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/routestopped ]; then
    run_install $OWNERSHIP -m 0600 routestopped ${PREFIX}/etc/shorewall6/routestopped
    echo "Stopped Routing file installed as ${PREFIX}/etc/shorewall6/routestopped"
fi
#
# Install the Mac List file
#
run_install $OWNERSHIP -m 0644 maclist ${PREFIX}/usr/share/shorewall6/configfiles/maclist

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/maclist ]; then
    run_install $OWNERSHIP -m 0600 maclist ${PREFIX}/etc/shorewall6/maclist
    echo "MAC list file installed as ${PREFIX}/etc/shorewall6/maclist"
fi
#
# Install the Modules file
#
run_install $OWNERSHIP -m 0600 modules ${PREFIX}/usr/share/shorewall6/modules
echo "Modules file installed as ${PREFIX}/usr/share/shorewall6/modules"

#
# Install the TC Rules file
#
run_install $OWNERSHIP -m 0644 tcrules ${PREFIX}/usr/share/shorewall6/configfiles/tcrules

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/tcrules ]; then
    run_install $OWNERSHIP -m 0600 tcrules ${PREFIX}/etc/shorewall6/tcrules
    echo "TC Rules file installed as ${PREFIX}/etc/shorewall6/tcrules"
fi

#
# Install the TOS file
#
run_install $OWNERSHIP -m 0644 tos ${PREFIX}/usr/share/shorewall6/configfiles/tos

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/tos ]; then
    run_install $OWNERSHIP -m 0600 tos ${PREFIX}/etc/shorewall6/tos
    echo "TOS file installed as ${PREFIX}/etc/shorewall6/tos"
fi
#
# Install the Tunnels file
#
run_install $OWNERSHIP -m 0644 tunnels ${PREFIX}/usr/share/shorewall6/configfiles/tunnels

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/tunnels ]; then
    run_install $OWNERSHIP -m 0600 tunnels ${PREFIX}/etc/shorewall6/tunnels
    echo "Tunnels file installed as ${PREFIX}/etc/shorewall6/tunnels"
fi
#
# Install the blacklist file
#
run_install $OWNERSHIP -m 0644 blacklist ${PREFIX}/usr/share/shorewall6/configfiles/blacklist

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/blacklist ]; then
    run_install $OWNERSHIP -m 0600 blacklist ${PREFIX}/etc/shorewall6/blacklist
    echo "Blacklist file installed as ${PREFIX}/etc/shorewall6/blacklist"
fi
#
# Install the Providers file
#
run_install $OWNERSHIP -m 0644 providers ${PREFIX}/usr/share/shorewall6/configfiles/providers

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/providers ]; then
    run_install $OWNERSHIP -m 0600 providers ${PREFIX}/etc/shorewall6/providers
    echo "Providers file installed as ${PREFIX}/etc/shorewall6/providers"
fi

#
# Install the Route Rules file
#
run_install $OWNERSHIP -m 0644 route_rules ${PREFIX}/usr/share/shorewall6/configfiles/route_rules

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/route_rules ]; then
    run_install $OWNERSHIP -m 0600 route_rules ${PREFIX}/etc/shorewall6/route_rules
    echo "Routing rules file installed as ${PREFIX}/etc/shorewall6/route_rules"
fi

#
# Install the tcclasses file
#
run_install $OWNERSHIP -m 0644 tcclasses ${PREFIX}/usr/share/shorewall6/configfiles/tcclasses

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/tcclasses ]; then
    run_install $OWNERSHIP -m 0600 tcclasses ${PREFIX}/etc/shorewall6/tcclasses
    echo "TC Classes file installed as ${PREFIX}/etc/shorewall6/tcclasses"
fi

#
# Install the tcdevices file
#
run_install $OWNERSHIP -m 0644 tcdevices ${PREFIX}/usr/share/shorewall6/configfiles/tcdevices

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/tcdevices ]; then
    run_install $OWNERSHIP -m 0600 tcdevices ${PREFIX}/etc/shorewall6/tcdevices
    echo "TC Devices file installed as ${PREFIX}/etc/shorewall6/tcdevices"
fi

#
# Install the Notrack file
#
run_install $OWNERSHIP -m 0644 notrack ${PREFIX}/usr/share/shorewall6/configfiles/notrack

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/notrack ]; then
    run_install $OWNERSHIP -m 0600 notrack ${PREFIX}/etc/shorewall6/notrack
    echo "Notrack file installed as ${PREFIX}/etc/shorewall6/notrack"
fi
#
# Install the default config path file
#
install_file configpath ${PREFIX}/usr/share/shorewall6/configpath 0644
echo "Default config path file installed as ${PREFIX}/usr/share/shorewall6/configpath"
#
# Install the init file
#
run_install $OWNERSHIP -m 0644 init ${PREFIX}/usr/share/shorewall6/configfiles/init

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/init ]; then
    run_install $OWNERSHIP -m 0600 init ${PREFIX}/etc/shorewall6/init
    echo "Init file installed as ${PREFIX}/etc/shorewall6/init"
fi
#
# Install the start file
#
run_install $OWNERSHIP -m 0644 start ${PREFIX}/usr/share/shorewall6/configfiles/start

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/start ]; then
    run_install $OWNERSHIP -m 0600 start ${PREFIX}/etc/shorewall6/start
    echo "Start file installed as ${PREFIX}/etc/shorewall6/start"
fi
#
# Install the stop file
#
run_install $OWNERSHIP -m 0644 stop ${PREFIX}/usr/share/shorewall6/configfiles/stop

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/stop ]; then
    run_install $OWNERSHIP -m 0600 stop ${PREFIX}/etc/shorewall6/stop
    echo "Stop file installed as ${PREFIX}/etc/shorewall6/stop"
fi
#
# Install the stopped file
#
run_install $OWNERSHIP -m 0644 stopped ${PREFIX}/usr/share/shorewall6/configfiles/stopped

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/stopped ]; then
    run_install $OWNERSHIP -m 0600 stopped ${PREFIX}/etc/shorewall6/stopped
    echo "Stopped file installed as ${PREFIX}/etc/shorewall6/stopped"
fi
#
# Install the Accounting file
#
run_install $OWNERSHIP -m 0644 accounting ${PREFIX}/usr/share/shorewall6/configfiles/accounting

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/accounting ]; then
    run_install $OWNERSHIP -m 0600 accounting ${PREFIX}/etc/shorewall6/accounting
    echo "Accounting file installed as ${PREFIX}/etc/shorewall6/accounting"
fi
#
# Install the Started file
#
run_install $OWNERSHIP -m 0644 started ${PREFIX}/usr/share/shorewall6/configfiles/started

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/started ]; then
    run_install $OWNERSHIP -m 0600 started ${PREFIX}/etc/shorewall6/started
    echo "Started file installed as ${PREFIX}/etc/shorewall6/started"
fi
#
# Install the Restored file
#
run_install $OWNERSHIP -m 0644 restored ${PREFIX}/usr/share/shorewall6/configfiles/restored

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/restored ]; then
    run_install $OWNERSHIP -m 0600 restored ${PREFIX}/etc/shorewall6/restored
    echo "Restored file installed as ${PREFIX}/etc/shorewall6/restored"
fi
#
# Install the Clear file
#
run_install $OWNERSHIP -m 0644 clear ${PREFIX}/usr/share/shorewall6/configfiles/clear

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/clear ]; then
    run_install $OWNERSHIP -m 0600 clear ${PREFIX}/etc/shorewall6/clear
    echo "Clear file installed as ${PREFIX}/etc/shorewall6/clear"
fi
#
# Install the Isusable file
#
run_install $OWNERSHIP -m 0644 isusable ${PREFIX}/usr/share/shorewall6/configfiles/isusable

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/isusable ]; then
    run_install $OWNERSHIP -m 0600 isusable ${PREFIX}/etc/shorewall6/isusable
    echo "Isusable file installed as ${PREFIX}/etc/shorewall/isusable"
fi
#
# Install the Refresh file
#
run_install $OWNERSHIP -m 0644 refresh ${PREFIX}/usr/share/shorewall6/configfiles/refresh

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/refresh ]; then
    run_install $OWNERSHIP -m 0600 refresh ${PREFIX}/etc/shorewall6/refresh
    echo "Refresh file installed as ${PREFIX}/etc/shorewall6/refresh"
fi
#
# Install the Refreshed file
#
run_install $OWNERSHIP -m 0644 refreshed ${PREFIX}/usr/share/shorewall6/configfiles/refreshed

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/refreshed ]; then
    run_install $OWNERSHIP -m 0600 refreshed ${PREFIX}/etc/shorewall6/refreshed
    echo "Refreshed file installed as ${PREFIX}/etc/shorewall6/refreshed"
fi
#
# Install the Tcclear file
#
run_install $OWNERSHIP -m 0644 tcclear ${PREFIX}/usr/share/shorewall6/configfiles/tcclear

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/tcclear ]; then
    run_install $OWNERSHIP -m 0600 tcclear ${PREFIX}/etc/shorewall6/tcclear
    echo "Tcclear file installed as ${PREFIX}/etc/shorewall6/tcclear"
fi
#
# Install the Standard Actions file
#
install_file actions.std ${PREFIX}/usr/share/shorewall6/actions.std 0644
echo "Standard actions file installed as ${PREFIX}/usr/shared/shorewall6/actions.std"

#
# Install the Actions file
#
run_install $OWNERSHIP -m 0644 actions ${PREFIX}/usr/share/shorewall6/configfiles/actions

if [ -z "$CYGWIN" -a ! -f ${PREFIX}/etc/shorewall6/actions ]; then
    run_install $OWNERSHIP -m 0644 actions ${PREFIX}/etc/shorewall6/actions
    echo "Actions file installed as ${PREFIX}/etc/shorewall6/actions"
fi

#
# Install the  Makefiles
#
run_install $OWNERSHIP -m 0644 Makefile-lite ${PREFIX}/usr/share/shorewall6/configfiles/Makefile

if [ -z "$CYGWIN" ]; then
    run_install $OWNERSHIP -m 0600 Makefile ${PREFIX}/etc/shorewall6/Makefile
    echo "Makefile installed as ${PREFIX}/etc/shorewall6/Makefile"
fi
#
# Install the Action files
#
for f in action.* ; do
    install_file $f ${PREFIX}/usr/share/shorewall6/$f 0644
    echo "Action ${f#*.} file installed as ${PREFIX}/usr/share/shorewall6/$f"
done

# Install the Macro files
#
for f in macro.* ; do
    install_file $f ${PREFIX}/usr/share/shorewall6/$f 0644
    echo "Macro ${f#*.} file installed as ${PREFIX}/usr/share/shorewall6/$f"
done
#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${PREFIX}/usr/share/shorewall6/$f 0644
	echo "Library ${f#*.} file installed as ${PREFIX}/usr/share/shorewall6/$f"
    fi
done
#
# Symbolically link 'functions' to lib.base
#
ln -sf lib.base ${PREFIX}/usr/share/shorewall6/functions
#
# Create the version file
#
echo "$VERSION" > ${PREFIX}/usr/share/shorewall6/version
chmod 644 ${PREFIX}/usr/share/shorewall6/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$PREFIX" ]; then
    rm -f /usr/share/shorewall6/init
    ln -s ${DEST}/${INIT} /usr/share/shorewall6/init
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
    run_install $OWNERSHIP -m 0644 logrotate ${PREFIX}/etc/logrotate.d/shorewall6
    echo "Logrotate file installed as ${PREFIX}/etc/logrotate.d/shorewall6"
fi

if [ -z "$PREFIX" -a -n "$first_install" -a -z "$CYGWIN" ]; then
    if [ -n "$DEBIAN" ]; then
	run_install $OWNERSHIP -m 0644 default.debian /etc/default/shorewall6
	ln -s ../init.d/shorewall6 /etc/rcS.d/S40shorewall6
	echo "shorewall6 will start automatically at boot"
	echo "Set startup=1 in /etc/default/shorewall6 to enable"
	touch /var/log/shorewall6-init.log
	qt mywhich perl && perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' /etc/shorewall6/shorewall6.conf
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
	elif [ -x /sbin/rc-update ]; then
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
echo "shorewall6-common Version $VERSION Installed"
