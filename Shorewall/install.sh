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
    echo "usage: $ME [ <configuration-file> ]"
    echo "       $ME -v"
    echo "       $ME -h"
    echo "       $ME -s"
    echo "       $ME -a"
    exit $1
}

fatal_error() 
{
    echo "   ERROR: $@" >&2
    exit 1
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

require() 
{
    eval [ -n "\$$1" ] || fatal_error "Required option $1 not set"
}

cd "$(dirname $0)"

#
# Load packager's settings if any
#
if [ -f shorewall ]; then
    PRODUCT=shorewall
    Product=Shorewall
else
    PRODUCT=shorewall6
    Product=Shorewall6
fi

#
# Parse the run line
#
#
T="-T"
INSTALLD='-D'

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
	    finished=1
	    ;;
    esac
done

#
# Read the RC file
#
if [ $# -eq 0 ]; then
    if [ -f ./shorewallrc ]; then
	. ./shorewallrc
    elif [ -f ~/.shorewallrc ]; then
	. ~/.shorewallrc || exit 1
	file=./.shorewallrc
    elif [ -f /usr/share/shorewall/shorewallrc ]; then
	. /usr/share/shorewall/shorewallrc
    else
	fatal_error "No configuration file specified and /usr/share/shorewall/shorewallrc not found"
    fi
elif [ $# -eq 1 ]; then
    file=$1
    case $file in
	/*|.*)
	    ;;
	*)
	    file=./$file
	    ;;
    esac

    . $file
else
    usage 1
fi

for var in SHAREDIR LIBEXECDIR PERLLIBDIR CONFDIR SBINDIR VARDIR; do
    require $var
done

[ -n "${INITFILE}" ] && require INITSOURCE && require INITDIR

if [ -z "$BUILD" ]; then
    case $(uname) in
	cygwin*)
	    BUILD=cygwin
	    ;;
	Darwin)
	    BUILD=apple
	    ;;
	*)
	    if [ -f /etc/debian_version ]; then
		BUILD=debian
	    elif [ -f /etc/redhat-release ]; then
		BUILD=redhat
	    elif [ -f /etc/slackware-version ] ; then
		BUILD=slackware
	    elif [ -f /etc/SuSE-release ]; then
		BUILD=suse
	    elif [ -f /etc/arch-release ] ; then
		BUILD=archlinux
	    else
		BUILD=linux
	    fi
	    ;;
    esac
fi

case $BUILD in
    cygwin*)
	OWNER=$(id -un)
	GROUP=$(id -gn)
	;;
    apple)
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

#
# Determine where to install the firewall script
#

if [ $PRODUCT = shorewall -a -z "${DESTDIR}" ]; then
    #
    # Verify that Perl is installed
    #
    if ! perl -c Perl/compiler.pl; then
	echo "ERROR: $Product $VERSION requires Perl which either is not installed or is not able to compile the $Product Perl code" >&2
	echo "       Try perl -c $PWD/Perl/compiler.pl" >&2
	exit 1
    fi
fi

case "$HOST" in
    cygwin)
	echo "Installing Cygwin-specific configuration..."
	;;
    apple)
	echo "Installing Mac-specific configuration...";
	;;
    debian)
	echo "Installing Debian-specific configuration..."
	;;
    redhat)
	echo "Installing Redhat/Fedora-specific configuration..."
	;;
    suse)
	echo "Installing SuSE-specific configuration...";
	;;
    slackware)
	echo "Installing Slackware-specific configuration..."
	;;
    archlinux)
	echo "Installing ArchLinux-specific configuration..."
	;;
    linux)
	;;
    *)
	echo "ERROR: Unknown HOST \"$HOST\"" >&2
	exit 1;
	;;
esac

if [ $BUILD != cygwin ]; then
    if [ `id -u` != 0 ] ; then
	echo "Not setting file owner/group permissions, not running as root."
	OWNERSHIP=""
    fi
fi

install -d $OWNERSHIP -m 755 ${DESTDIR}${SBINDIR}
[ -n "${INITFILE}" ] && install -d $OWNERSHIP -m 755 ${DESTDIR}${INITDIR}
if [ -z "$DESTDIR" -a $PRODUCT != shorewall ]; then
    [ -x ${LIBEXECDIR}/shorewall/compiler.pl ] || \
	{ echo "   ERROR: Shorewall >= 4.5.0 is not installed" >&2; exit 1; }
fi

echo "Installing $Product Version $VERSION"

#
# Check for /sbin/$PRODUCT
#
if [ -f ${DESTDIR}${SBINDIR}/$PRODUCT ]; then
    first_install=""
else
    first_install="Yes"
fi

if [ -z "${DESTDIR}" -a $PRODUCT = shorewall -a ! -f ${SHAREDIR}/$PRODUCT/coreversion ]; then
    echo "Shorewall $VERSION requires Shorewall Core which does not appear to be installed"
    exit 1
fi

install_file $PRODUCT ${DESTDIR}${SBINDIR}/$PRODUCT 0755
[ $SHAREDIR = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}/${SBINDIR}/${PRODUCT}
echo "$PRODUCT control program installed in ${DESTDIR}${SBINDIR}/$PRODUCT"

#
# Install the Firewall Script
#
if [ -n "$INITFILE" ]; then
    install_file $INITSOURCE ${DESTDIR}${INITDIR}/$INITFILE 0544
    [ "${SHAREDIR}" = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}${INITDIR}/$INITFILE
  
    if [ -n "${AUXINITSOURCE}" ]; then
	install_file $INITSOURCE ${DESTDIR}${INITDIR}/$INITFILE 0544
    fi

    echo  "$Product script installed in ${DESTDIR}${INITDIR}/$INITFILE"
fi

#
# Create /etc/$PRODUCT and other directories
#
mkdir -p ${DESTDIR}/${CONFDIR}/$PRODUCT
mkdir -p ${DESTDIR}${LIBEXECDIR}/$PRODUCT
mkdir -p ${DESTDIR}${PERLLIBDIR}/Shorewall
mkdir -p ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles
mkdir -p ${DESTDIR}/var/lib/$PRODUCT

chmod 755 ${DESTDIR}${CONFDIR}/$PRODUCT
chmod 755 ${DESTDIR}${SHAREDIR}/$PRODUCT
chmod 755 ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

if [ -n "$DESTDIR" ]; then
    mkdir -p ${DESTDIR}${CONFDIR}/logrotate.d
    chmod 755 ${DESTDIR}${CONFDIR}/logrotate.d
fi

#
# Install the .service file
#
if [ -n "$SYSTEMD" ]; then
    mkdir -p ${DESTDIR}${SYSTEMD}
    run_install $OWNERSHIP -m 600 $PRODUCT.service ${DESTDIR}${SYSTEMD}/$PRODUCT.service
    echo "Service file installed as ${DESTDIR}${SYSTEMD}/$PRODUCT.service"
fi

#
# These use absolute path names since the files that they are removing existed
# prior to the use of directory variables
#
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
run_install $OWNERSHIP -m 0644 modules ${DESTDIR}${SHAREDIR}/$PRODUCT/modules
echo "Modules file installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/modules"

for f in modules.*; do
    run_install $OWNERSHIP -m 0644 $f ${DESTDIR}${SHAREDIR}/$PRODUCT/$f
    echo "Modules file $f installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/$f"
done

#
# Install the Module Helpers file
#
run_install $OWNERSHIP -m 0644 helpers ${DESTDIR}${SHAREDIR}/$PRODUCT/helpers
echo "Helper modules file installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/helpers"

#
# Install the default config path file
#
install_file configpath ${DESTDIR}${SHAREDIR}/$PRODUCT/configpath 0644
echo "Default config path file installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/configpath"
#
# Install the Standard Actions file
#
install_file actions.std ${DESTDIR}${SHAREDIR}/$PRODUCT/actions.std 0644
echo "Standard actions file installed as ${DESTDIR}${SHAREDIR}d/$PRODUCT/actions.std"

cd configfiles

if [ -n "$ANNOTATED" ]; then
    suffix=.annotated
else
    suffix=
fi

#
# Install the config file
#
run_install $OWNERSHIP -m 0644 $PRODUCT.conf           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 $PRODUCT.conf.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf ]; then
    run_install $OWNERSHIP -m 0644 ${PRODUCT}.conf${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf
    
    if [ "$SHAREDIR" != /usr/share -o "$CONFDIR" != /etc ]; then
	if [ $PRODUCT = shorewall ]; then
	    perl -p -w -i -e "s|^CONFIG_PATH=.*|CONFIG_PATH=${CONFDIR}/shorewall:${SHAREDIR}/shorewall|;" ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf
	else
	    perl -p -w -i -e "s|^CONFIG_PATH=.*|CONFIG_PATH=${CONFDIR}/shorewall:${SHAREDIR}/shorewall6:${SHAREDIR}/shorewall|;" ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf
	fi
    fi

    if [ $HOST = archlinux ] ; then
	sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf
    elif [ $HOST = debian ]; then
	perl -p -w -i -e 's|^STARTUP_ENABLED=.*|STARTUP_ENABLED=Yes|;' ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf${suffix}
    fi

    echo "Config file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf"
fi

#
# Install the init file
#
run_install $OWNERSHIP -m 0644 init ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/init

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/init ]; then
    run_install $OWNERSHIP -m 0600 init ${DESTDIR}${CONFDIR}/$PRODUCT/init
    echo "Init file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/init"
fi

#
# Install the zones file
#
run_install $OWNERSHIP -m 0644 zones           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 zones.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/zones ]; then
    run_install $OWNERSHIP -m 0644 zones${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/zones
    echo "Zones file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/zones"
fi

#
# Install the policy file
#
run_install $OWNERSHIP -m 0644 policy           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 policy.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/policy ]; then
    run_install $OWNERSHIP -m 0600 policy${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/policy
    echo "Policy file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/policy"
fi
#
# Install the interfaces file
#
run_install $OWNERSHIP -m 0644 interfaces           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 interfaces.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/interfaces ]; then
    run_install $OWNERSHIP -m 0600 interfaces${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/interfaces
    echo "Interfaces file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/interfaces"
fi

#
# Install the hosts file
#
run_install $OWNERSHIP -m 0644 hosts           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 hosts.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/hosts ]; then
    run_install $OWNERSHIP -m 0600 hosts${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/hosts
    echo "Hosts file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/hosts"
fi
#
# Install the rules file
#
run_install $OWNERSHIP -m 0644 rules           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 rules.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/rules ]; then
    run_install $OWNERSHIP -m 0600 rules${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/rules
    echo "Rules file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/rules"
fi

if [ -f nat ]; then
    #
    # Install the NAT file
    #
    run_install $OWNERSHIP -m 0644 nat           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles
    run_install $OWNERSHIP -m 0644 nat.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/nat ]; then
	run_install $OWNERSHIP -m 0600 nat${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/nat
	echo "NAT file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/nat"
    fi
fi

#
# Install the NETMAP file
#
run_install $OWNERSHIP -m 0644 netmap           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles
run_install $OWNERSHIP -m 0644 netmap.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/netmap ]; then
    run_install $OWNERSHIP -m 0600 netmap${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/netmap
    echo "NETMAP file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/netmap"
fi
#
# Install the Parameters file
#
run_install $OWNERSHIP -m 0644 params          ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 params.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -f ${DESTDIR}${CONFDIR}/$PRODUCT/params ]; then
    chmod 0644 ${DESTDIR}${CONFDIR}/$PRODUCT/params
else
    run_install $OWNERSHIP -m 0644 params${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/params
    echo "Parameter file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/params"
fi

if [ $PRODUCT = shorewall ]; then
    #
    # Install the proxy ARP file
    #
    run_install $OWNERSHIP -m 0644 proxyarp           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles
    run_install $OWNERSHIP -m 0644 proxyarp.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/proxyarp ]; then
	run_install $OWNERSHIP -m 0600 proxyarp${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/proxyarp
	echo "Proxy ARP file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/proxyarp"
    fi
else
    #
    # Install the Proxyndp file
    #
    run_install $OWNERSHIP -m 0644 proxyndp           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
    run_install $OWNERSHIP -m 0644 proxyndp.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/proxyndp ]; then
	run_install $OWNERSHIP -m 0600 proxyndp${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/proxyndp
	echo "Proxyndp file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/proxyndp"
    fi
fi
#
# Install the Stopped Routing file
#
run_install $OWNERSHIP -m 0644 routestopped           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 routestopped.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/routestopped ]; then
    run_install $OWNERSHIP -m 0600 routestopped${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/routestopped
    echo "Stopped Routing file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/routestopped"
fi
#
# Install the Mac List file
#
run_install $OWNERSHIP -m 0644 maclist           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 maclist.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/maclist ]; then
    run_install $OWNERSHIP -m 0600 maclist${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/maclist
    echo "mac list file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/maclist"
fi

if [ -f masq ]; then
    #
    # Install the Masq file
    #
    run_install $OWNERSHIP -m 0644 masq           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles
    run_install $OWNERSHIP -m 0644 masq.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/masq ]; then
	run_install $OWNERSHIP -m 0600 masq${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/masq
	echo "Masquerade file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/masq"
    fi
fi
#
# Install the Notrack file
#
run_install $OWNERSHIP -m 0644 notrack           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles
run_install $OWNERSHIP -m 0644 notrack.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/notrack ]; then
    run_install $OWNERSHIP -m 0600 notrack${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/notrack
    echo "Notrack file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/notrack"
fi

#
# Install the TC Rules file
#
run_install $OWNERSHIP -m 0644 tcrules           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcrules.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/tcrules ]; then
    run_install $OWNERSHIP -m 0600 tcrules${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/tcrules
    echo "TC Rules file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/tcrules"
fi

#
# Install the TC Interfaces file
#
run_install $OWNERSHIP -m 0644 tcinterfaces           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcinterfaces.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/tcinterfaces ]; then
    run_install $OWNERSHIP -m 0600 tcinterfaces${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/tcinterfaces
    echo "TC Interfaces file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/tcinterfaces"
fi

#
# Install the TC Priority file
#
run_install $OWNERSHIP -m 0644 tcpri           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcpri.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/tcpri ]; then
    run_install $OWNERSHIP -m 0600 tcpri${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/tcpri
    echo "TC Priority file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/tcpri"
fi

#
# Install the TOS file
#
run_install $OWNERSHIP -m 0644 tos           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tos.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/tos ]; then
    run_install $OWNERSHIP -m 0600 tos${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/tos
    echo "TOS file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/tos"
fi
#
# Install the Tunnels file
#
run_install $OWNERSHIP -m 0644 tunnels           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tunnels.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/tunnels ]; then
    run_install $OWNERSHIP -m 0600 tunnels${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/tunnels
    echo "Tunnels file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/tunnels"
fi

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/blacklist ]; then
    run_install $OWNERSHIP -m 0600 blacklist${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/blacklist
    echo "Blacklist file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/blacklist"
fi
#
# Install the blacklist rules file
#
run_install $OWNERSHIP -m 0644 blrules           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 blrules.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/blrules ]; then
    run_install $OWNERSHIP -m 0600 blrules${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/blrules
    echo "Blrules file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/blrules"
fi

if [ -f findgw ]; then
    #
    # Install the findgw file
    #
    run_install $OWNERSHIP -m 0644 findgw ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/findgw ]; then
	run_install $OWNERSHIP -m 0600 findgw ${DESTDIR}${CONFDIR}/$PRODUCT
	echo "Find GW file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/findgw"
    fi
fi

#
# Delete the Routes file
#
delete_file ${DESTDIR}${CONFDIR}/$PRODUCT/routes
#
# Delete the tcstart file
#

delete_file ${DESTDIR}${SHAREDIR}/$PRODUCT/tcstart

#
# Delete the Limits Files
#
delete_file ${DESTDIR}${SHAREDIR}/$PRODUCT/action.Limit
delete_file ${DESTDIR}${SHAREDIR}/$PRODUCT/Limit
#
# Delete the xmodules file
#
delete_file ${DESTDIR}${SHAREDIR}/$PRODUCT/xmodules
#
# Install the Providers file
#
run_install $OWNERSHIP -m 0644 providers           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 providers.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/providers ]; then
    run_install $OWNERSHIP -m 0600 providers${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/providers
    echo "Providers file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/providers"
fi

#
# Install the Route Rules file
#
run_install $OWNERSHIP -m 0644 rtrules           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 rtrules.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -f ${DESTDIR}${CONFDIR}/$PRODUCT/route_rules -a ! ${DESTDIR}${CONFDIR}/$PRODUCT/rtrules ]; then
    mv -f ${DESTDIR}${CONFDIR}/$PRODUCT/route_rules ${DESTDIR}${CONFDIR}/$PRODUCT/rtrules
    echo "${DESTDIR}${CONFDIR}/$PRODUCT/route_rules has been renamed ${DESTDIR}${CONFDIR}/$PRODUCT/rtrules"
elif [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/rtrules ]; then
    run_install $OWNERSHIP -m 0600 rtrules${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/rtrules
    echo "Routing rules file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/rtrules"
fi

#
# Install the tcclasses file
#
run_install $OWNERSHIP -m 0644 tcclasses           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcclasses.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/tcclasses ]; then
    run_install $OWNERSHIP -m 0600 tcclasses${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/tcclasses
    echo "TC Classes file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/tcclasses"
fi

#
# Install the tcdevices file
#
run_install $OWNERSHIP -m 0644 tcdevices           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcdevices.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/tcdevices ]; then
    run_install $OWNERSHIP -m 0600 tcdevices${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/tcdevices
    echo "TC Devices file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/tcdevices"
fi

#
# Install the tcfilters file
#
run_install $OWNERSHIP -m 0644 tcfilters           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 tcfilters.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/tcfilters ]; then
    run_install $OWNERSHIP -m 0600 tcfilters${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/tcfilters
    echo "TC Filters file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/tcfilters"
fi

#
# Install the secmarks file
#
run_install $OWNERSHIP -m 0644 secmarks           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles
run_install $OWNERSHIP -m 0644 secmarks.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/secmarks ]; then
    run_install $OWNERSHIP -m 0600 secmarks${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/secmarks
    echo "Secmarks file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/secmarks"
fi

#
# Install the init file
#
run_install $OWNERSHIP -m 0644 init ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/init ]; then
    run_install $OWNERSHIP -m 0600 init ${DESTDIR}${CONFDIR}/$PRODUCT
    echo "Init file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/init"
fi

if [ -f initdone ]; then
    #
    # Install the initdone file
    #
    run_install $OWNERSHIP -m 0644 initdone ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/initdone ]; then
	run_install $OWNERSHIP -m 0600 initdone ${DESTDIR}${CONFDIR}/$PRODUCT
	echo "Initdone file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/initdone"
    fi
fi
#
# Install the start file
#
run_install $OWNERSHIP -m 0644 start ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/start

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/start ]; then
    run_install $OWNERSHIP -m 0600 start ${DESTDIR}${CONFDIR}/$PRODUCT/start
    echo "Start file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/start"
fi
#
# Install the stop file
#
run_install $OWNERSHIP -m 0644 stop ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/stop

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/stop ]; then
    run_install $OWNERSHIP -m 0600 stop ${DESTDIR}${CONFDIR}/$PRODUCT/stop
    echo "Stop file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/stop"
fi
#
# Install the stopped file
#
run_install $OWNERSHIP -m 0644 stopped ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/stopped

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/stopped ]; then
    run_install $OWNERSHIP -m 0600 stopped ${DESTDIR}${CONFDIR}/$PRODUCT/stopped
    echo "Stopped file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/stopped"
fi

if [ -f ecn ]; then
    #
    # Install the ECN file
    #
    run_install $OWNERSHIP -m 0644 ecn           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles
    run_install $OWNERSHIP -m 0644 ecn.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

    if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/ecn ]; then
	run_install $OWNERSHIP -m 0600 ecn${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/ecn
	echo "ECN file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/ecn"
    fi
fi
#
# Install the Accounting file
#
run_install $OWNERSHIP -m 0644 accounting           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 accounting.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/accounting ]; then
    run_install $OWNERSHIP -m 0600 accounting${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/accounting
    echo "Accounting file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/accounting"
fi
#
# Install the private library file
#
run_install $OWNERSHIP -m 0644 lib.private ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/lib.private ]; then
    run_install $OWNERSHIP -m 0600 lib.private ${DESTDIR}${CONFDIR}/$PRODUCT
    echo "Private library file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/lib.private"
fi
#
# Install the Started file
#
run_install $OWNERSHIP -m 0644 started ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/started

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/started ]; then
    run_install $OWNERSHIP -m 0600 started ${DESTDIR}${CONFDIR}/$PRODUCT/started
    echo "Started file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/started"
fi
#
# Install the Restored file
#
run_install $OWNERSHIP -m 0644 restored ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/restored

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/restored ]; then
    run_install $OWNERSHIP -m 0600 restored ${DESTDIR}${CONFDIR}/$PRODUCT/restored
    echo "Restored file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/restored"
fi
#
# Install the Clear file
#
run_install $OWNERSHIP -m 0644 clear ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/clear

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/clear ]; then
    run_install $OWNERSHIP -m 0600 clear ${DESTDIR}${CONFDIR}/$PRODUCT/clear
    echo "Clear file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/clear"
fi
#
# Install the Isusable file
#
run_install $OWNERSHIP -m 0644 isusable ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/isusable
#
# Install the Refresh file
#
run_install $OWNERSHIP -m 0644 refresh ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/refresh

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/refresh ]; then
    run_install $OWNERSHIP -m 0600 refresh ${DESTDIR}${CONFDIR}/$PRODUCT/refresh
    echo "Refresh file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/refresh"
fi
#
# Install the Refreshed file
#
run_install $OWNERSHIP -m 0644 refreshed ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/refreshed

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/refreshed ]; then
    run_install $OWNERSHIP -m 0600 refreshed ${DESTDIR}${CONFDIR}/$PRODUCT/refreshed
    echo "Refreshed file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/refreshed"
fi
#
# Install the Tcclear file
#
run_install $OWNERSHIP -m 0644 tcclear           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/tcclear ]; then
    run_install $OWNERSHIP -m 0600 tcclear ${DESTDIR}${CONFDIR}/$PRODUCT/tcclear
    echo "Tcclear file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/tcclear"
fi
#
# Install the Scfilter file
#
run_install $OWNERSHIP -m 0644 scfilter ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/scfilter

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/scfilter ]; then
    run_install $OWNERSHIP -m 0600 scfilter ${DESTDIR}${CONFDIR}/$PRODUCT/scfilter
    echo "Scfilter file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/scfilter"
fi

#
# Install the Actions file
#
run_install $OWNERSHIP -m 0644 actions           ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/
run_install $OWNERSHIP -m 0644 actions.annotated ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/

if [ -z "$SPARSE" -a ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/actions ]; then
    run_install $OWNERSHIP -m 0644 actions${suffix} ${DESTDIR}${CONFDIR}/$PRODUCT/actions
    echo "Actions file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/actions"
fi

cd ..

#
# Install the Standard Actions file
#
install_file actions.std ${DESTDIR}${SHAREDIR}/$PRODUCT/actions.std 0644
echo "Standard actions file installed as ${DESTDIR}${SHAREDIR}d/$PRODUCT/actions.std"

#
# Install the  Makefiles
#
run_install $OWNERSHIP -m 0644 Makefile-lite ${DESTDIR}${SHAREDIR}/$PRODUCT/configfiles/Makefile

if [ -z "$SPARSE" ]; then
    run_install $OWNERSHIP -m 0600 Makefile ${DESTDIR}${CONFDIR}/$PRODUCT
    echo "Makefile installed as ${DESTDIR}${CONFDIR}/$PRODUCT/Makefile"
fi
#
# Install the Action files
#
for f in action.* ; do
    install_file $f ${DESTDIR}${SHAREDIR}/$PRODUCT/$f 0644
    echo "Action ${f#*.} file installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/$f"
done

cd Macros

for f in macro.* ; do
    install_file $f ${DESTDIR}${SHAREDIR}/$PRODUCT/$f 0644
    echo "Macro ${f#*.} file installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/$f"
done

cd ..

#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${DESTDIR}${SHAREDIR}/$PRODUCT/$f 0644
	echo "Library ${f#*.} file installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/$f"
    fi
done

if [ $PRODUCT = shorewall6 ]; then
    #
    # Symbolically link 'functions' to lib.base
    #
    ln -sf lib.base ${DESTDIR}${SHAREDIR}/$PRODUCT/functions
    [ $SHAREDIR = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}/${SHAREDIR}/${PRODUCT}/lib.base
fi

if [ -d Perl ]; then
    #
    # ${SHAREDIR}/$PRODUCT/$Product if needed
    #
    mkdir -p ${DESTDIR}${SHAREDIR}/$PRODUCT/$Product
    chmod 755 ${DESTDIR}${SHAREDIR}/$PRODUCT/$Product
    #
    # Install the Compiler
    #
    cd Perl

    install_file compiler.pl ${DESTDIR}${LIBEXECDIR}/$PRODUCT/compiler.pl 0755

    echo
    echo "Compiler installed in ${DESTDIR}${LIBEXECDIR}/$PRODUCT/compiler.pl"
    #
    # Install the params file helper
    #
    install_file getparams ${DESTDIR}${LIBEXECDIR}/$PRODUCT/getparams 0755
    [ $SHAREDIR = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}${LIBEXECDIR}/$PRODUCT/getparams

    echo
    echo "Params file helper installed in ${DESTDIR}${LIBEXECDIR}/$PRODUCT/getparams"
    #
    # Install the Perl modules
    #
    for f in $Product/*.pm ; do
	install_file $f ${DESTDIR}${PERLLIBDIR}/$f 0644
	echo "Module ${f%.*} installed as ${DESTDIR}${PERLLIBDIR}/$f"
    done
    #
    # Install the program skeleton files
    #
    for f in prog.* ; do
        install_file $f ${DESTDIR}${SHAREDIR}/$PRODUCT/$f 0644
        echo "Program skeleton file ${f#*.} installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/$f"
    done

    cd ..

    if [ -z "$DESTDIR" ]; then
	rm -rf ${SHAREDIR}/$PRODUCT-perl
	rm -rf ${SHAREDIR}/$PRODUCT-shell
	[ "$PERLLIBDIR" != ${SHAREDIR}/$PRODUCT ] && rm -rf ${SHAREDIR}/$PRODUCT/$Product
    fi
fi
#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}${SHAREDIR}/$PRODUCT/version
chmod 644 ${DESTDIR}${SHAREDIR}/$PRODUCT/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$DESTDIR" ]; then
    rm -f ${SHAREDIR}/$PRODUCT/init
    ln -s ${INITDIR}/${INITFILE} ${SHAREDIR}/$PRODUCT/init
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

if [ -d ${DESTDIR}${CONFDIR}/logrotate.d ]; then
    run_install $OWNERSHIP -m 0644 logrotate ${DESTDIR}${CONFDIR}/logrotate.d/$PRODUCT
    echo "Logrotate file installed as ${DESTDIR}${CONFDIR}/logrotate.d/$PRODUCT"
fi

if [ -n "$SYSCONFFILE" -a ! -f ${DESTDIR}${SYSCONFDIR}/${PRODUCT} ]; then
    if [ ${DESTDIR} ]; then
	mkdir -p ${DESTDIR}${SYSCONFDIR}
	chmod 755 ${DESTDIR}${SYSCONFDIR}
    fi

    run_install $OWNERSHIP -m 0644 default.debian ${DESTDIR}${SYSCONFDIR}/$PRODUCT
    echo "$SYSCONFFILE installed in ${DESTDIR}${SYSCONFDIR}/${PRODUCT}"
fi

if [ -z "$DESTDIR" -a -n "$first_install" -a -z "${cygwin}${mac}" ]; then
    if mywhich update-rc.d ; then
	echo "$PRODUCT will start automatically at boot"
	echo "Set startup=1 in ${CONFDIR}/default/$PRODUCT to enable"
	touch /var/log/$PRODUCT-init.log
	perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' ${CONFDIR}/$PRODUCT/$PRODUCT.conf
    elif [ -n "$SYSTEMD" ]; then
	if systemctl enable $PRODUCT; then
	    echo "$Product will start automatically at boot"
	fi
    elif mywhich insserv; then
	if insserv ${CONFDIR}/init.d/$PRODUCT ; then
	    echo "$PRODUCT will start automatically at boot"
	    echo "Set STARTUP_ENABLED=Yes in ${CONFDIR}/$PRODUCT/$PRODUCT.conf to enable"
	else
	    cant_autostart
	fi
    elif mywhich chkconfig; then
	if chkconfig --add $PRODUCT ; then
	    echo "$PRODUCT will start automatically in run levels as follows:"
	    echo "Set STARTUP_ENABLED=Yes in ${CONFDIR}/$PRODUCT/$PRODUCT.conf to enable"
	    chkconfig --list $PRODUCT
	else
	    cant_autostart
	fi
    elif mywhich rc-update ; then
	if rc-update add $PRODUCT default; then
	    echo "$PRODUCT will start automatically at boot"
	    echo "Set STARTUP_ENABLED=Yes in ${CONFDIR}/$PRODUCT/$PRODUCT.conf to enable"
	else
	    cant_autostart
	fi
    elif [ "$INITFILE" != rc.f ]; then #Slackware starts this automatically
	cant_autostart
    fi
fi

#
#  Report Success
#
echo "$Product Version $VERSION Installed"
