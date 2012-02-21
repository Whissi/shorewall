#!/bin/sh
#
# Script to install Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000-2011 - Tom Eastep (teastep@shorewall.net)
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

VERSION=xxx       #The Build script inserts the actual version

#
# Change to the directory containing this script
#
usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME"
    echo "       $ME -v"
    echo "       $ME -h"
    echo "       $ME -s"
    echo "       $ME -a"
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
    echo  "WARNING: Unable to configure $PRODUCT to start automatically at boot" >&2
}

delete_file() # $1 = file to delete
{
    rm -f $1
}

install_file() # $1 = source $2 = target $3 = mode
{
    run_install $T $OWNERSHIP -m $3 $1 ${2}
}

cd "$(dirname $0)"

if [ -f shorewall ]; then
    PRODUCT=shorewall
    Product=Shorewall
else
    PRODUCT=shorewall6
    Product=Shorewall6
fi

[ -n "$DESTDIR" ] || DESTDIR="$PREFIX"

#
# Parse the run line
#
#
T="-T"

ANNOTATED=
MANDIR=${MANDIR:-"/usr/share/man"}
SPARSE=
INSTALLD='-D'
INITFILE="$PRODUCT"

[ -n "${LIBEXEC:=/usr/share}" ]
[ -n "${PERLLIB:=/usr/share/shorewall}" ]

case "$LIBEXEC" in
    /*)
	;;
    *)
	echo "The LIBEXEC setting must be an absolute path name" >&2
	exit 1
	;;
esac

case "$PERLLIB" in
    /*)
	;;
    *)
	echo "The PERLLIB setting must be an absolute path name" >&2
	exit 1
	;;
esac

if [ -z "$BUILD" ]; then
    case $(uname) in
	CYGWIN*)
	    BUILD=CYGWIN
	    ;;
	Darwin)
	    BUILD=MAC
	    ;;
	*)
	    if [ -f /etc/debian_version ]; then
		BUILD=DEBIAN
	    elif [ -f /etc/redhat-release ]; then
		BUILD=REDHAT
	    elif [ -f /etc/slackware-version ] ; then
		BUILD=SLACKWARE
	    elif [ -f /etc/SuSE-release ]; then
		BUILD=SUSE
	    elif [ -f /etc/arch-release ] ; then
		BUILD=ARCHLINUX
	    else
		BUILD=LINUX
	    fi
	    ;;
    esac
fi

case $BUILD in
    CYGWIN*)
	OWNER=$(id -un)
	GROUP=$(id -gn)
	;;
    MAC)
	[ -z "$OWNER" ] && OWNER=root
	[ -z "$GROUP" ] && GROUP=wheel
	INSTALLD=
	T=
	;;
    *)
	[ -z "$OWNER" ] && OWNER=root
	[ -z "$GROUP" ] && GROUP=root
	;;
esac

OWNERSHIP="-o $OWNER -g $GROUP"

finished=0

while [ $finished -eq 0 ]; do
    option=$1

    case "$option" in
	-*)
	    option=${option#-}
	    
	    while [ -n "$option" ]; do
		case $option in
		    h)
			usage 0
			;;
		    v)
			echo "$Product Firewall Installer Version $VERSION"
			exit 0
			;;
		    s*)
			SPARSE=Yes
			option=${option#s}
			;;
		    a*)
			ANNOTATED=Yes
			option=${option#a}
			;;
		    p*)
			ANNOTATED=
			option=${option#p}
			;;
		    *)
			usage 1
			;;
		esac
	    done

	    shift
	    ;;
	*)
	    [ -n "$option" ] && usage 1
	    finished=1
	    ;;
    esac
done

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

#
# Determine where to install the firewall script
#

if [ $PRODUCT = shorewall ]; then
    #
    # Verify that Perl is installed
    #
    if ! perl -c Perl/compiler.pl; then
	echo "ERROR: $Product $VERSION requires Perl which either is not installed or is not able to compile the $Product perl code" >&2
	echo "       Try perl -c $PWD/Perl/compiler.pl" >&2
	exit 1
    fi
fi

[ -n "$HOST" ] || HOST=$BUILD

case "$HOST" in
    CYGWIN)
	echo "Installing Cygwin-specific configuration..."
	INITFILE=
	;;
    MAC)
	echo "Installing Mac-specific configuration...";
	INITFILE=
	;;
    DEBIAN)
	echo "Installing Debian-specific configuration..."
	SPARSE=yes
	;;
    REDHAT)
	echo "Installing Redhat/Fedora-specific configuration..."
	INITDIR="/etc/rc.d/init.d"
	;;
    SLACKWARE)
	echo "Installing Slackware-specific configuration..."
	INITDIR="/etc/rc.d"
	MANDIR="/usr/man"
	INITFILE="rc.firewall"
	;;
    ARCHLINUX)
	echo "Installing ArchLinux-specific configuration..."
	INITDIR="/etc/rc.d"
	INITFILE="$PRODUCT"
	;;
    LINUX)
	;;
    *)
	echo "ERROR: Unknown HOST \"$HOST\"" >&2
	exit 1;
	;;
esac

if [ -z "$INITDIR" -a -n "$INITFILE" ] ; then
    INITDIR="/etc/init.d"
fi

if [ -n "$DESTDIR" ]; then
    if [ $BUILD != CYGWIN ]; then
	if [ `id -u` != 0 ] ; then
	    echo "Not setting file owner/group permissions, not running as root."
	    OWNERSHIP=""
	fi
    fi

    install -d $OWNERSHIP -m 755 ${DESTDIR}/sbin
    install -d $OWNERSHIP -m 755 ${DESTDIR}${INITDIR}
else
    [ -x /usr/share/shorewall/compiler.pl ] || \
	{ echo "   ERROR: Shorewall >= 4.3.5 is not installed" >&2; exit 1; }
fi

if [ -z "$DESTDIR" ]; then
    if [ -f /lib/systemd/system ]; then
	SYSTEMD=Yes
    fi
elif [ -n "$SYSTEMD" ]; then
    mkdir -p ${DESTDIR}/lib/systemd/system
fi

echo "Installing $Product Version $VERSION"

#
# Check for /sbin/$PRODUCT
#
if [ -f ${DESTDIR}/sbin/$PRODUCT ]; then
    first_install=""
else
    first_install="Yes"
fi

if [ -z "${DESTDIR}" -a $PRODUCT = shorewall -a ! -f /usr/share/$PRODUCT/coreversion ]; then
    echo "Shorewall $VERSION requires Shorewall Core which does not appear to be installed"
    exit 1
fi

if [ $HOST != CYGWIN ]; then
   install_file $PRODUCT ${DESTDIR}/sbin/$PRODUCT 0755
   echo "$PRODUCT control program installed in ${DESTDIR}/sbin/$PRODUCT"
else
   install_file $PRODUCT ${DESTDIR}/bin/$PRODUCT 0755
   echo "$PRODUCT control program installed in ${DESTDIR}/bin/$PRODUCT"
fi

#
# Install the Firewall Script
#
case $HOST in
    SLACKWARE)
        if [ $PRODUCT = shorewall ]; then
	    install_file init.slackware.firewall.sh ${DESTDIR}${DEST}/rc.firewall 0644
	    install_file init.slackware.$PRODUCT.sh ${DESTDIR}${DEST}/rc.$PRODUCT 0644
	fi
	;;
    *)
	if [ -n "$INITFILE" ]; then
	    install_file init.sh ${DESTDIR}${INITDIR}/$INITFILE 0544
	fi
	;;
esac

[ -n "$INITFILE" ] && echo  "$Product script installed in ${DESTDIR}${INITDIR}/$INITFILE"

#
# Create /etc/$PRODUCT and /var/lib/$PRODUCT if needed
#
mkdir -p ${DESTDIR}/etc/$PRODUCT
mkdir -p ${DESTDIR}${LIBEXEC}/$PRODUCT
mkdir -p ${DESTDIR}${PERLLIB}/Shorewall
mkdir -p ${DESTDIR}/usr/share/$PRODUCT/configfiles
mkdir -p ${DESTDIR}/var/lib/$PRODUCT

chmod 755 ${DESTDIR}/etc/$PRODUCT
chmod 755 ${DESTDIR}/usr/share/$PRODUCT
chmod 755 ${DESTDIR}/usr/share/$PRODUCT/configfiles

if [ -n "$DESTDIR" ]; then
    mkdir -p ${DESTDIR}/etc/logrotate.d
    chmod 755 ${DESTDIR}/etc/logrotate.d
fi

#
# Install the .service file
#
if [ -n "$SYSTEMD" ]; then
    run_install $OWNERSHIP -m 600 $PRODUCT.service ${DESTDIR}/lib/systemd/system/$PRODUCT.service
    echo "Service file installed as ${DESTDIR}/lib/systemd/system/$PRODUCT.service"
fi

delete_file ${DESTDIR}/usr/share/$PRODUCT/compiler
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.accounting
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.actions
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.dynamiczones
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.maclist
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.nat
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.providers
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.proxyarp
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.tc
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.tcrules
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.tunnels

if [ $PRODUCT = shorewall6 ]; then
    delete_file ${DESTDIR}/usr/share/shorewall6/lib.cli
    delete_file ${DESTDIR}/usr/share/shorewall6/lib.common
    delete_file ${DESTDIR}/usr/share/shorewall6/wait4ifup
fi

delete_file ${DESTDIR}/usr/share/$PRODUCT/prog.header6
delete_file ${DESTDIR}/usr/share/$PRODUCT/prog.footer6

#
# Install the Modules file
#
run_install $OWNERSHIP -m 0644 modules ${DESTDIR}/usr/share/$PRODUCT/modules
echo "Modules file installed as ${DESTDIR}/usr/share/$PRODUCT/modules"

for f in modules.*; do
    run_install $OWNERSHIP -m 0644 $f ${DESTDIR}/usr/share/$PRODUCT/$f
    echo "Modules file $f installed as ${DESTDIR}/usr/share/$PRODUCT/$f"
done

#
# Install the Module Helpers file
#
run_install $OWNERSHIP -m 0644 helpers ${DESTDIR}/usr/share/$PRODUCT/helpers
echo "Helper modules file installed as ${DESTDIR}/usr/share/$PRODUCT/helpers"

#
# Install the default config path file
#
install_file configpath ${DESTDIR}/usr/share/$PRODUCT/configpath 0644
echo "Default config path file installed as ${DESTDIR}/usr/share/$PRODUCT/configpath"
#
# Install the Standard Actions file
#
install_file actions.std ${DESTDIR}/usr/share/$PRODUCT/actions.std 0644
echo "Standard actions file installed as ${DESTDIR}/usr/shared/$PRODUCT/actions.std"

cd configfiles

if [ -n "$ANNOTATED" ]; then
    suffix=.annotated
else
    suffix=
fi

#
# Install the config file
#
run_install $OWNERSHIP -m 0644 $PRODUCT.conf           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 $PRODUCT.conf.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/


if [ ! -f ${DESTDIR}/etc/$PRODUCT/$PRODUCT.conf ]; then
   run_install $OWNERSHIP -m 0644 $PRODUCT.conf${suffix} ${DESTDIR}/etc/$PRODUCT/$PRODUCT.conf

   if [ $HOST = DEBIAN ] && mywhich perl; then
       #
       # Make a Debian-like $PRODUCT.conf
       #
       perl -p -w -i -e 's|^STARTUP_ENABLED=.*|STARTUP_ENABLED=Yes|;' ${DESTDIR}/etc/$PRODUCT/$PRODUCT.conf
   fi

   echo "Config file installed as ${DESTDIR}/etc/$PRODUCT/$PRODUCT.conf"
fi


if [ $HOST = ARCHLINUX ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${DESTDIR}/etc/$PRODUCT/$PRODUCT.conf
fi

#
# Install the init file
#
run_install $OWNERSHIP -m 0644 init ${DESTDIR}/usr/share/$PRODUCT/configfiles/init

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/init ]; then
    run_install $OWNERSHIP -m 0600 init ${DESTDIR}/etc/$PRODUCT/init
    echo "Init file installed as ${DESTDIR}/etc/$PRODUCT/init"
fi

#
# Install the zones file
#
run_install $OWNERSHIP -m 0644 zones           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 zones.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/zones ]; then
    run_install $OWNERSHIP -m 0644 zones${suffix} ${DESTDIR}/etc/$PRODUCT/zones
    echo "Zones file installed as ${DESTDIR}/etc/$PRODUCT/zones"
fi

#
# Install the policy file
#
run_install $OWNERSHIP -m 0644 policy           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 policy.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/policy ]; then
    run_install $OWNERSHIP -m 0600 policy${suffix} ${DESTDIR}/etc/$PRODUCT/policy
    echo "Policy file installed as ${DESTDIR}/etc/$PRODUCT/policy"
fi
#
# Install the interfaces file
#
run_install $OWNERSHIP -m 0644 interfaces           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 interfaces.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/interfaces ]; then
    run_install $OWNERSHIP -m 0600 interfaces${suffix} ${DESTDIR}/etc/$PRODUCT/interfaces
    echo "Interfaces file installed as ${DESTDIR}/etc/$PRODUCT/interfaces"
fi

#
# Install the hosts file
#
run_install $OWNERSHIP -m 0644 hosts           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 hosts.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/hosts ]; then
    run_install $OWNERSHIP -m 0600 hosts${suffix} ${DESTDIR}/etc/$PRODUCT/hosts
    echo "Hosts file installed as ${DESTDIR}/etc/$PRODUCT/hosts"
fi
#
# Install the rules file
#
run_install $OWNERSHIP -m 0644 rules           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 rules.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/rules ]; then
    run_install $OWNERSHIP -m 0600 rules${suffix} ${DESTDIR}/etc/$PRODUCT/rules
    echo "Rules file installed as ${DESTDIR}/etc/$PRODUCT/rules"
fi

if [ -f nat ]; then
    #
    # Install the NAT file
    #
    run_install $OWNERSHIP -m 0644 nat           ${DESTDIR}/usr/share/$PRODUCT/configfiles
    run_install $OWNERSHIP -m 0644 nat.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/nat ]; then
	run_install $OWNERSHIP -m 0600 nat${suffix} ${DESTDIR}/etc/$PRODUCT/nat
	echo "NAT file installed as ${DESTDIR}/etc/$PRODUCT/nat"
    fi
fi

#
# Install the NETMAP file
#
run_install $OWNERSHIP -m 0644 netmap           ${DESTDIR}/usr/share/$PRODUCT/configfiles
run_install $OWNERSHIP -m 0644 netmap.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/netmap ]; then
    run_install $OWNERSHIP -m 0600 netmap${suffix} ${DESTDIR}/etc/$PRODUCT/netmap
    echo "NETMAP file installed as ${DESTDIR}/etc/$PRODUCT/netmap"
fi
#
# Install the Parameters file
#
run_install $OWNERSHIP -m 0644 params          ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 params.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -f ${DESTDIR}/etc/$PRODUCT/params ]; then
    chmod 0644 ${DESTDIR}/etc/$PRODUCT/params
else
    run_install $OWNERSHIP -m 0644 params${suffix} ${DESTDIR}/etc/$PRODUCT/params
    echo "Parameter file installed as ${DESTDIR}/etc/$PRODUCT/params"
fi

if [ $PRODUCT = shorewall ]; then
    #
    # Install the proxy ARP file
    #
    run_install $OWNERSHIP -m 0644 proxyarp           ${DESTDIR}/usr/share/$PRODUCT/configfiles
    run_install $OWNERSHIP -m 0644 proxyarp.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/proxyarp ]; then
	run_install $OWNERSHIP -m 0600 proxyarp${suffix} ${DESTDIR}/etc/$PRODUCT/proxyarp
	echo "Proxy ARP file installed as ${DESTDIR}/etc/$PRODUCT/proxyarp"
    fi
else
    #
    # Install the Proxyndp file
    #
    run_install $OWNERSHIP -m 0644 proxyndp           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
    run_install $OWNERSHIP -m 0644 proxyndp.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/proxyndp ]; then
	run_install $OWNERSHIP -m 0600 proxyndp${suffix} ${DESTDIR}/etc/$PRODUCT/proxyndp
	echo "Proxyndp file installed as ${DESTDIR}/etc/$PRODUCT/proxyndp"
    fi
fi
#
# Install the Stopped Routing file
#
run_install $OWNERSHIP -m 0644 routestopped           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 routestopped.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/routestopped ]; then
    run_install $OWNERSHIP -m 0600 routestopped${suffix} ${DESTDIR}/etc/$PRODUCT/routestopped
    echo "Stopped Routing file installed as ${DESTDIR}/etc/$PRODUCT/routestopped"
fi
#
# Install the Mac List file
#
run_install $OWNERSHIP -m 0644 maclist           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 maclist.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/maclist ]; then
    run_install $OWNERSHIP -m 0600 maclist${suffix} ${DESTDIR}/etc/$PRODUCT/maclist
    echo "MAC list file installed as ${DESTDIR}/etc/$PRODUCT/maclist"
fi

if [ -f masq ]; then
    #
    # Install the Masq file
    #
    run_install $OWNERSHIP -m 0644 masq           ${DESTDIR}/usr/share/$PRODUCT/configfiles
    run_install $OWNERSHIP -m 0644 masq.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/masq ]; then
	run_install $OWNERSHIP -m 0600 masq${suffix} ${DESTDIR}/etc/$PRODUCT/masq
	echo "Masquerade file installed as ${DESTDIR}/etc/$PRODUCT/masq"
    fi
fi
#
# Install the Notrack file
#
run_install $OWNERSHIP -m 0644 notrack           ${DESTDIR}/usr/share/$PRODUCT/configfiles
run_install $OWNERSHIP -m 0644 notrack.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/notrack ]; then
    run_install $OWNERSHIP -m 0600 notrack${suffix} ${DESTDIR}/etc/$PRODUCT/notrack
    echo "Notrack file installed as ${DESTDIR}/etc/$PRODUCT/notrack"
fi

#
# Install the TC Rules file
#
run_install $OWNERSHIP -m 0644 tcrules           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcrules.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/tcrules ]; then
    run_install $OWNERSHIP -m 0600 tcrules${suffix} ${DESTDIR}/etc/$PRODUCT/tcrules
    echo "TC Rules file installed as ${DESTDIR}/etc/$PRODUCT/tcrules"
fi

#
# Install the TC Interfaces file
#
run_install $OWNERSHIP -m 0644 tcinterfaces           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcinterfaces.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/tcinterfaces ]; then
    run_install $OWNERSHIP -m 0600 tcinterfaces${suffix} ${DESTDIR}/etc/$PRODUCT/tcinterfaces
    echo "TC Interfaces file installed as ${DESTDIR}/etc/$PRODUCT/tcinterfaces"
fi

#
# Install the TC Priority file
#
run_install $OWNERSHIP -m 0644 tcpri           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcpri.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/tcpri ]; then
    run_install $OWNERSHIP -m 0600 tcpri${suffix} ${DESTDIR}/etc/$PRODUCT/tcpri
    echo "TC Priority file installed as ${DESTDIR}/etc/$PRODUCT/tcpri"
fi

#
# Install the TOS file
#
run_install $OWNERSHIP -m 0644 tos           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tos.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/tos ]; then
    run_install $OWNERSHIP -m 0600 tos${suffix} ${DESTDIR}/etc/$PRODUCT/tos
    echo "TOS file installed as ${DESTDIR}/etc/$PRODUCT/tos"
fi
#
# Install the Tunnels file
#
run_install $OWNERSHIP -m 0644 tunnels           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tunnels.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/tunnels ]; then
    run_install $OWNERSHIP -m 0600 tunnels${suffix} ${DESTDIR}/etc/$PRODUCT/tunnels
    echo "Tunnels file installed as ${DESTDIR}/etc/$PRODUCT/tunnels"
fi

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/blacklist ]; then
    run_install $OWNERSHIP -m 0600 blacklist${suffix} ${DESTDIR}/etc/$PRODUCT/blacklist
    echo "Blacklist file installed as ${DESTDIR}/etc/$PRODUCT/blacklist"
fi
#
# Install the blacklist rules file
#
run_install $OWNERSHIP -m 0644 blrules           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 blrules.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/blrules ]; then
    run_install $OWNERSHIP -m 0600 blrules${suffix} ${DESTDIR}/etc/$PRODUCT/blrules
    echo "Blrules file installed as ${DESTDIR}/etc/$PRODUCT/blrules"
fi

if [ -f findgw ]; then
    #
    # Install the findgw file
    #
    run_install $OWNERSHIP -m 0644 findgw ${DESTDIR}/usr/share/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/findgw ]; then
	run_install $OWNERSHIP -m 0600 findgw ${DESTDIR}/etc/$PRODUCT
	echo "Find GW file installed as ${DESTDIR}/etc/$PRODUCT/findgw"
    fi
fi

#
# Delete the Routes file
#
delete_file ${DESTDIR}/etc/$PRODUCT/routes
#
# Delete the tcstart file
#

delete_file ${DESTDIR}/usr/share/$PRODUCT/tcstart

#
# Delete the Limits Files
#
delete_file ${DESTDIR}/usr/share/$PRODUCT/action.Limit
delete_file ${DESTDIR}/usr/share/$PRODUCT/Limit
#
# Delete the xmodules file
#
delete_file ${DESTDIR}/usr/share/$PRODUCT/xmodules
#
# Install the Providers file
#
run_install $OWNERSHIP -m 0644 providers           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 providers.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/providers ]; then
    run_install $OWNERSHIP -m 0600 providers${suffix} ${DESTDIR}/etc/$PRODUCT/providers
    echo "Providers file installed as ${DESTDIR}/etc/$PRODUCT/providers"
fi

#
# Install the Route Rules file
#
run_install $OWNERSHIP -m 0644 rtrules           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 rtrules.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -f ${DESTDIR}/etc/$PRODUCT/route_rules -a ! ${DESTDIR}/etc/$PRODUCT/rtrules ]; then
    mv -f ${DESTDIR}/etc/$PRODUCT/route_rules ${DESTDIR}/etc/$PRODUCT/rtrules
    echo "${DESTDIR}/etc/$PRODUCT/route_rules has been renamed ${DESTDIR}/etc/$PRODUCT/rtrules"
elif [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/rtrules ]; then
    run_install $OWNERSHIP -m 0600 rtrules${suffix} ${DESTDIR}/etc/$PRODUCT/rtrules
    echo "Routing rules file installed as ${DESTDIR}/etc/$PRODUCT/rtrules"
fi

#
# Install the tcclasses file
#
run_install $OWNERSHIP -m 0644 tcclasses           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcclasses.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/tcclasses ]; then
    run_install $OWNERSHIP -m 0600 tcclasses${suffix} ${DESTDIR}/etc/$PRODUCT/tcclasses
    echo "TC Classes file installed as ${DESTDIR}/etc/$PRODUCT/tcclasses"
fi

#
# Install the tcdevices file
#
run_install $OWNERSHIP -m 0644 tcdevices           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcdevices.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/tcdevices ]; then
    run_install $OWNERSHIP -m 0600 tcdevices${suffix} ${DESTDIR}/etc/$PRODUCT/tcdevices
    echo "TC Devices file installed as ${DESTDIR}/etc/$PRODUCT/tcdevices"
fi

#
# Install the tcfilters file
#
run_install $OWNERSHIP -m 0644 tcfilters           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcfilters.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/tcfilters ]; then
    run_install $OWNERSHIP -m 0600 tcfilters${suffix} ${DESTDIR}/etc/$PRODUCT/tcfilters
    echo "TC Filters file installed as ${DESTDIR}/etc/$PRODUCT/tcfilters"
fi

#
# Install the secmarks file
#
run_install $OWNERSHIP -m 0644 secmarks           ${DESTDIR}/usr/share/$PRODUCT/configfiles
run_install $OWNERSHIP -m 0644 secmarks.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/secmarks ]; then
    run_install $OWNERSHIP -m 0600 secmarks${suffix} ${DESTDIR}/etc/$PRODUCT/secmarks
    echo "Secmarks file installed as ${DESTDIR}/etc/$PRODUCT/secmarks"
fi

#
# Install the init file
#
run_install $OWNERSHIP -m 0644 init ${DESTDIR}/usr/share/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/init ]; then
    run_install $OWNERSHIP -m 0600 init ${DESTDIR}/etc/$PRODUCT
    echo "Init file installed as ${DESTDIR}/etc/$PRODUCT/init"
fi

if [ -f initdone ]; then
    #
    # Install the initdone file
    #
    run_install $OWNERSHIP -m 0644 initdone ${DESTDIR}/usr/share/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/initdone ]; then
	run_install $OWNERSHIP -m 0600 initdone ${DESTDIR}/etc/$PRODUCT
	echo "Initdone file installed as ${DESTDIR}/etc/$PRODUCT/initdone"
    fi
fi
#
# Install the start file
#
run_install $OWNERSHIP -m 0644 start ${DESTDIR}/usr/share/$PRODUCT/configfiles/start

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/start ]; then
    run_install $OWNERSHIP -m 0600 start ${DESTDIR}/etc/$PRODUCT/start
    echo "Start file installed as ${DESTDIR}/etc/$PRODUCT/start"
fi
#
# Install the stop file
#
run_install $OWNERSHIP -m 0644 stop ${DESTDIR}/usr/share/$PRODUCT/configfiles/stop

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/stop ]; then
    run_install $OWNERSHIP -m 0600 stop ${DESTDIR}/etc/$PRODUCT/stop
    echo "Stop file installed as ${DESTDIR}/etc/$PRODUCT/stop"
fi
#
# Install the stopped file
#
run_install $OWNERSHIP -m 0644 stopped ${DESTDIR}/usr/share/$PRODUCT/configfiles/stopped

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/stopped ]; then
    run_install $OWNERSHIP -m 0600 stopped ${DESTDIR}/etc/$PRODUCT/stopped
    echo "Stopped file installed as ${DESTDIR}/etc/$PRODUCT/stopped"
fi

if [ -f ecn ]; then
    #
    # Install the ECN file
    #
    run_install $OWNERSHIP -m 0644 ecn           ${DESTDIR}/usr/share/$PRODUCT/configfiles
    run_install $OWNERSHIP -m 0644 ecn.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/ecn ]; then
	run_install $OWNERSHIP -m 0600 ecn${suffix} ${DESTDIR}/etc/$PRODUCT/ecn
	echo "ECN file installed as ${DESTDIR}/etc/$PRODUCT/ecn"
    fi
fi
#
# Install the Accounting file
#
run_install $OWNERSHIP -m 0644 accounting           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 accounting.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/accounting ]; then
    run_install $OWNERSHIP -m 0600 accounting${suffix} ${DESTDIR}/etc/$PRODUCT/accounting
    echo "Accounting file installed as ${DESTDIR}/etc/$PRODUCT/accounting"
fi
#
# Install the private library file
#
run_install $OWNERSHIP -m 0644 lib.private ${DESTDIR}/usr/share/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/lib.private ]; then
    run_install $OWNERSHIP -m 0600 lib.private ${DESTDIR}/etc/$PRODUCT
    echo "Private library file installed as ${DESTDIR}/etc/$PRODUCT/lib.private"
fi
#
# Install the Started file
#
run_install $OWNERSHIP -m 0644 started ${DESTDIR}/usr/share/$PRODUCT/configfiles/started

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/started ]; then
    run_install $OWNERSHIP -m 0600 started ${DESTDIR}/etc/$PRODUCT/started
    echo "Started file installed as ${DESTDIR}/etc/$PRODUCT/started"
fi
#
# Install the Restored file
#
run_install $OWNERSHIP -m 0644 restored ${DESTDIR}/usr/share/$PRODUCT/configfiles/restored

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/restored ]; then
    run_install $OWNERSHIP -m 0600 restored ${DESTDIR}/etc/$PRODUCT/restored
    echo "Restored file installed as ${DESTDIR}/etc/$PRODUCT/restored"
fi
#
# Install the Clear file
#
run_install $OWNERSHIP -m 0644 clear ${DESTDIR}/usr/share/$PRODUCT/configfiles/clear

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/clear ]; then
    run_install $OWNERSHIP -m 0600 clear ${DESTDIR}/etc/$PRODUCT/clear
    echo "Clear file installed as ${DESTDIR}/etc/$PRODUCT/clear"
fi
#
# Install the Isusable file
#
run_install $OWNERSHIP -m 0644 isusable ${DESTDIR}/usr/share/$PRODUCT/configfiles/isusable

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/isusable ]; then
    run_install $OWNERSHIP -m 0600 isusable ${DESTDIR}/etc/$PRODUCT/isusable
    echo "Isusable file installed as ${DESTDIR}/etc/$PRODUCT/isusable"
fi
#
# Install the Refresh file
#
run_install $OWNERSHIP -m 0644 refresh ${DESTDIR}/usr/share/$PRODUCT/configfiles/refresh

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/refresh ]; then
    run_install $OWNERSHIP -m 0600 refresh ${DESTDIR}/etc/$PRODUCT/refresh
    echo "Refresh file installed as ${DESTDIR}/etc/$PRODUCT/refresh"
fi
#
# Install the Refreshed file
#
run_install $OWNERSHIP -m 0644 refreshed ${DESTDIR}/usr/share/$PRODUCT/configfiles/refreshed

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/refreshed ]; then
    run_install $OWNERSHIP -m 0600 refreshed ${DESTDIR}/etc/$PRODUCT/refreshed
    echo "Refreshed file installed as ${DESTDIR}/etc/$PRODUCT/refreshed"
fi
#
# Install the Tcclear file
#
run_install $OWNERSHIP -m 0644 tcclear           ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/tcclear ]; then
    run_install $OWNERSHIP -m 0600 tcclear ${DESTDIR}/etc/$PRODUCT/tcclear
    echo "Tcclear file installed as ${DESTDIR}/etc/$PRODUCT/tcclear"
fi
#
# Install the Scfilter file
#
run_install $OWNERSHIP -m 0644 scfilter ${DESTDIR}/usr/share/$PRODUCT/configfiles/scfilter

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/scfilter ]; then
    run_install $OWNERSHIP -m 0600 scfilter ${DESTDIR}/etc/$PRODUCT/scfilter
    echo "Scfilter file installed as ${DESTDIR}/etc/$PRODUCT/scfilter"
fi

#
# Install the Actions file
#
run_install $OWNERSHIP -m 0644 actions           ${DESTDIR}/usr/share/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 actions.annotated ${DESTDIR}/usr/share/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}/etc/$PRODUCT/actions ]; then
    run_install $OWNERSHIP -m 0644 actions${suffix} ${DESTDIR}/etc/$PRODUCT/actions
    echo "Actions file installed as ${DESTDIR}/etc/$PRODUCT/actions"
fi

cd ..

#
# Install the Standard Actions file
#
install_file actions.std ${DESTDIR}/usr/share/$PRODUCT/actions.std 0644
echo "Standard actions file installed as ${DESTDIR}/usr/shared/$PRODUCT/actions.std"

#
# Install the  Makefiles
#
run_install $OWNERSHIP -m 0644 Makefile-lite ${DESTDIR}/usr/share/$PRODUCT/configfiles/Makefile

if [ -z "$SPARSE" ]; then
    run_install $OWNERSHIP -m 0600 Makefile ${DESTDIR}/etc/$PRODUCT
    echo "Makefile installed as ${DESTDIR}/etc/$PRODUCT/Makefile"
fi
#
# Install the Action files
#
for f in action.* ; do
    install_file $f ${DESTDIR}/usr/share/$PRODUCT/$f 0644
    echo "Action ${f#*.} file installed as ${DESTDIR}/usr/share/$PRODUCT/$f"
done

cd Macros

for f in macro.* ; do
    install_file $f ${DESTDIR}/usr/share/$PRODUCT/$f 0644
    echo "Macro ${f#*.} file installed as ${DESTDIR}/usr/share/$PRODUCT/$f"
done

cd ..

#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${DESTDIR}/usr/share/$PRODUCT/$f 0644
	echo "Library ${f#*.} file installed as ${DESTDIR}/usr/share/$PRODUCT/$f"
    fi
done

if [ $PRODUCT = shorewall6 ]; then
    #
    # Symbolically link 'functions' to lib.base
    #
    ln -sf lib.base ${DESTDIR}/usr/share/$PRODUCT/functions
fi

if [ -d Perl ]; then
    #
    # /usr/share/$PRODUCT/$Product if needed
    #
    mkdir -p ${DESTDIR}/usr/share/$PRODUCT/$Product
    chmod 755 ${DESTDIR}/usr/share/$PRODUCT/$Product
    #
    # Install the Compiler
    #
    cd Perl

    install_file compiler.pl ${DESTDIR}${LIBEXEC}/$PRODUCT/compiler.pl 0755

    echo
    echo "Compiler installed in ${DESTDIR}${LIBEXEC}/$PRODUCT/compiler.pl"
    #
    # Install the params file helper
    #
    install_file getparams ${DESTDIR}${LIBEXEC}/$PRODUCT/getparams 0755

    echo
    echo "Params file helper installed in ${DESTDIR}${LIBEXEC}/$PRODUCT/getparams"
    #
    # Install the Perl modules
    #
    for f in $Product/*.pm ; do
	install_file $f ${DESTDIR}${PERLLIB}/$f 0644
	echo "Module ${f%.*} installed as ${DESTDIR}${PERLLIB}/$f"
    done
    #
    # Install the program skeleton files
    #
    for f in prog.* ; do
        install_file $f ${DESTDIR}/usr/share/$PRODUCT/$f 0644
        echo "Program skeleton file ${f#*.} installed as ${DESTDIR}/usr/share/$PRODUCT/$f"
    done

    cd ..

    if [ -z "$DESTDIR" ]; then
	rm -rf /usr/share/$PRODUCT-perl
	rm -rf /usr/share/$PRODUCT-shell
	[ "$PERLLIB" != /usr/share/$PRODUCT ] && rm -rf /usr/share/$PRODUCT/$Product
    fi
fi
#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}/usr/share/$PRODUCT/version
chmod 644 ${DESTDIR}/usr/share/$PRODUCT/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$DESTDIR" ]; then
    rm -f /usr/share/$PRODUCT/init
    ln -s ${INITDIR}/${INITFILE} /usr/share/$PRODUCT/init
fi

#
# Install the Man Pages
#

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

if [ -d ${DESTDIR}/etc/logrotate.d ]; then
    run_install $OWNERSHIP -m 0644 logrotate ${DESTDIR}/etc/logrotate.d/$PRODUCT
    echo "Logrotate file installed as ${DESTDIR}/etc/logrotate.d/$PRODUCT"
fi

if [ -z "$DESTDIR" -a -n "$first_install" -a -z "${CYGWIN}${MAC}" ]; then
    if [ $HOST = DEBIAN ]; then
	run_install $OWNERSHIP -m 0644 default.debian /etc/default/$PRODUCT

	update-rc.d $PRODUCT defaults

	echo "$PRODUCT will start automatically at boot"
	echo "Set startup=1 in /etc/default/$PRODUCT to enable"
	touch /var/log/$PRODUCT-init.log
	perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' /etc/$PRODUCT/$PRODUCT.conf
    else
	if [ -n "$SYSTEMD" ]; then
	    if systemctl enable $PRODUCT; then
		echo "$Product will start automatically at boot"
	    fi
	elif [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
	    if insserv /etc/init.d/$PRODUCT ; then
		echo "$PRODUCT will start automatically at boot"
		echo "Set STARTUP_ENABLED=Yes in /etc/$PRODUCT/$PRODUCT.conf to enable"
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	    if chkconfig --add $PRODUCT ; then
		echo "$PRODUCT will start automatically in run levels as follows:"
		echo "Set STARTUP_ENABLED=Yes in /etc/$PRODUCT/$PRODUCT.conf to enable"
		chkconfig --list $PRODUCT
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/rc-update ]; then
	    if rc-update add $PRODUCT default; then
		echo "$PRODUCT will start automatically at boot"
		echo "Set STARTUP_ENABLED=Yes in /etc/$PRODUCT/$PRODUCT.conf to enable"
	    else
		cant_autostart
	    fi
	elif [ "$INITFILE" != rc.f ]; then #Slackware starts this automatically
	    cant_autostart
	fi
    fi
fi

#
#  Report Success
#
echo "$Product Version $VERSION Installed"
