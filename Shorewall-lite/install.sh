#!/bin/sh
#
# Script to install Shoreline Firewall Lite
#
#     (c) 2000-2011,2014 - Tom Eastep (teastep@shorewall.net)
#
#       Shorewall documentation is available at http://shorewall.net
#
#       This program is part of Shorewall.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by the
#       Free Software Foundation, either version 2 of the license or, at your
#       option, any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, see <http://www.gnu.org/licenses/>.
#

VERSION=xxx #The Build script inserts the actual version

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME [ <configuration-file> ]"
    echo "       $ME -v"
    echo "       $ME -h"
    echo "       $ME -n"
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
    echo  "WARNING: Unable to configure $Product to start automatically at boot" >&2
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

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

if [ -f shorewall-lite ]; then
    PRODUCT=shorewall-lite
    Product="Shorewall Lite"
else
    PRODUCT=shorewall6-lite
    Product="Shorewall6 Lite"
fi

#
# Parse the run line
#
finished=0
configure=1

while [ $finished -eq 0 ] ; do

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
		    n*)
			configure=0
			option=${option#n}
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
	. ./shorewallrc || exit 1
	file=./shorewallrc
    elif [ -f ~/.shorewallrc ]; then
	. ~/.shorewallrc
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

if [ -z "${VARLIB}" ]; then
    VARLIB=${VARDIR}
    VARDIR=${VARLIB}/${PRODUCT}
elif [ -z "${VARDIR}" ]; then
    VARDIR=${VARLIB}/${PRODUCT}
fi

for var in SHAREDIR LIBEXECDIRDIRDIR CONFDIR SBINDIR VARLIB VARDIR; do
    require $var
done

[ -n "${INITFILE}" ] && require INITSOURCE && require INITDIR

PATH=${SBINDIR}:/bin:/usr${SBINDIR}:/usr/bin:/usr/local/bin:/usr/local${SBINDIR}

#
# Determine where to install the firewall script
#
cygwin=
INSTALLD='-D'
T='-T'

if [ -z "$BUILD" ]; then
    case $(uname) in
	cygwin*|CYGWIN*)
	    BUILD=cygwin
	    ;;
	Darwin)
	    BUILD=apple
	    ;;
	*)
	    if [ -f /etc/os-release ]; then
		eval $(cat /etc/os-release | grep ^ID)

		case $ID in
		    fedora|rhel|centos|foobar)
			BUILD=redhat
			;;
		    debian)
			BUILD=debian
			;;
		    gentoo)
			BUILD=gentoo
			;;
		    opensuse)
			BUILD=suse
			;;
		    *)
			BUILD="$ID"
			;;
		esac
	    elif [ -f ${CONFDIR}/debian_version ]; then
		BUILD=debian
	    elif [ -f /etc/gentoo-release ]; then
		BUILD=gentoo
	    elif [ -f ${CONFDIR}/redhat-release ]; then
		BUILD=redhat
	    elif [ -f ${CONFDIR}/SuSE-release ]; then
		BUILD=suse
	    elif [ -f ${CONFDIR}/slackware-version ] ; then
		BUILD=slackware
	    elif [ -f ${CONFDIR}/arch-release ] ; then
		BUILD=archlinux
	    else
		BUILD=linux
	    fi
	    ;;
    esac
fi

case $BUILD in
    cygwin*|CYGWIN*)
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

[ -n "$HOST" ] || HOST=$BUILD

case "$HOST" in
    cygwin)
	echo "$PRODUCT is not supported on Cygwin" >&2
	exit 1
	;;
    apple)
	echo "$PRODUCT is not supported on OS X" >&2
	exit 1
	;;
    debian)
	echo "Installing Debian-specific configuration..."
	;;
    gentoo)
	echo "Installing Gentoo-specific configuration..."
	;;
    redhat)
	echo "Installing Redhat/Fedora-specific configuration..."
	;;
    slackware)
	echo "Installing Slackware-specific configuration..."
	;;
    archlinux)
	echo "Installing ArchLinux-specific configuration..."
	;;
    suse)
	echo "Installing Suse-specific configuration..."
	;;
    linux)
	;;
    *)
	echo "ERROR: Unknown HOST \"$HOST\"" >&2
	exit 1;
	;;
esac

[ -z "$INITDIR" ] && INITDIR="${CONFDIR}/init.d"

if [ -n "$DESTDIR" ]; then
    if [ `id -u` != 0 ] ; then
	echo "Not setting file owner/group permissions, not running as root."
	OWNERSHIP=""
    fi

    install -d $OWNERSHIP -m 755 ${DESTDIR}/${SBINDIR}
    install -d $OWNERSHIP -m 755 ${DESTDIR}${INITDIR}
else
    if [ ! -f ${SHAREDIR}/shorewall/coreversion ]; then
	echo "$PRODUCT $VERSION requires Shorewall Core which does not appear to be installed" >&2
	exit 1
    fi
fi

echo "Installing $Product Version $VERSION"

#
# Check for ${CONFDIR}/$PRODUCT
#
if [ -z "$DESTDIR" -a -d ${CONFDIR}/$PRODUCT ]; then
    if [ ! -f ${SHAREDIR}/shorewall/coreversion ]; then
	echo "$PRODUCT $VERSION requires Shorewall Core which does not appear to be installed" >&2
	exit 1
    fi

    [ -f ${CONFDIR}/$PRODUCT/shorewall.conf ] && \
	mv -f ${CONFDIR}/$PRODUCT/shorewall.conf ${CONFDIR}/$PRODUCT/$PRODUCT.conf
else
    rm -rf ${DESTDIR}${CONFDIR}/$PRODUCT
    rm -rf ${DESTDIR}${SHAREDIR}/$PRODUCT
    rm -rf ${DESTDIR}${VARDIR}
    [ "$LIBEXECDIR" = /usr/share ] || rm -rf ${DESTDIR}/usr/share/$PRODUCT/wait4ifup ${DESTDIR}/usr/share/$PRODUCT/shorecap
fi

#
# Check for ${SBINDIR}/$PRODUCT
#
if [ -f ${DESTDIR}${SBINDIR}/$PRODUCT ]; then
    first_install=""
else
    first_install="Yes"
fi

delete_file ${DESTDIR}/usr/share/$PRODUCT/xmodules

install_file $PRODUCT ${DESTDIR}${SBINDIR}/$PRODUCT 0544
[ -n "${INITFILE}" ] && install -d $OWNERSHIP -m 755 ${DESTDIR}${INITDIR}

echo "$Product control program installed in ${DESTDIR}${SBINDIR}/$PRODUCT"

#
# Create ${CONFDIR}/$PRODUCT, /usr/share/$PRODUCT and /var/lib/$PRODUCT if needed
#
mkdir -p ${DESTDIR}${CONFDIR}/$PRODUCT
mkdir -p ${DESTDIR}${SHAREDIR}/$PRODUCT
mkdir -p ${DESTDIR}${LIBEXECDIR}/$PRODUCT
mkdir -p ${DESTDIR}${VARDIR}

chmod 755 ${DESTDIR}${CONFDIR}/$PRODUCT
chmod 755 ${DESTDIR}/usr/share/$PRODUCT

if [ -n "$DESTDIR" ]; then
    mkdir -p ${DESTDIR}${CONFDIR}/logrotate.d
    chmod 755 ${DESTDIR}${CONFDIR}/logrotate.d
    mkdir -p ${DESTDIR}${INITDIR}
    chmod 755 ${DESTDIR}${INITDIR}
fi

if [ -n "$INITFILE" ]; then
    if [ -f "${INITSOURCE}" ]; then
	initfile="${DESTDIR}/${INITDIR}/${INITFILE}"
	install_file ${INITSOURCE} "$initfile" 0544

	[ "${SHAREDIR}" = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' "$initfile"

	echo  "SysV init script $INITSOURCE installed in $initfile"
    fi
fi
#
# Install the .service file
#
if [ -n "$SYSTEMD" ]; then
    mkdir -p ${DESTDIR}${SYSTEMD}
    [ -z "$SERVICEFILE" ] && SERVICEFILE=$PRODUCT.service
    run_install $OWNERSHIP -m 644 $SERVICEFILE ${DESTDIR}${SYSTEMD}/$PRODUCT.service
    [ ${SBINDIR} != /sbin ] && eval sed -i \'s\|/sbin/\|${SBINDIR}/\|\' ${DESTDIR}${SYSTEMD}/$PRODUCT.service
    echo "Service file $SERVICEFILE installed as ${DESTDIR}${SYSTEMD}/$PRODUCT.service"
fi
#
# Install the config file
#
if [ ! -f ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf ]; then
   install_file $PRODUCT.conf ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf 0744
   echo "Config file installed as ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf"
fi

if [ $HOST = archlinux ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf
elif [ $HOST = gentoo ]; then
    # Adjust SUBSYSLOCK path (see https://bugs.gentoo.org/show_bug.cgi?id=459316)
    perl -p -w -i -e "s|^SUBSYSLOCK=.*|SUBSYSLOCK=/run/lock/$PRODUCT|;" ${DESTDIR}${CONFDIR}/$PRODUCT/$PRODUCT.conf
fi

#
# Install the  Makefile
#
run_install $OWNERSHIP -m 0600 Makefile ${DESTDIR}${CONFDIR}/$PRODUCT
[ $SHAREDIR = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}/${CONFDIR}/$PRODUCT/Makefile
[ $SBINDIR = /sbin ]       || eval sed -i \'s\|/sbin/\|${SBINDIR}/\|\'       ${DESTDIR}/${CONFDIR}/$PRODUCT/Makefile
echo "Makefile installed as ${DESTDIR}${CONFDIR}/$PRODUCT/Makefile"

#
# Install the default config path file
#
install_file configpath ${DESTDIR}${SHAREDIR}/$PRODUCT/configpath 0644
echo "Default config path file installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/configpath"

#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${DESTDIR}${SHAREDIR}/$PRODUCT/$f 0644
	echo "Library ${f#*.} file installed as ${DESTDIR}/${SHAREDIR}/$PRODUCT/$f"
    fi
done

ln -sf lib.base ${DESTDIR}${SHAREDIR}/$PRODUCT/functions

echo "Common functions linked through ${DESTDIR}${SHAREDIR}/$PRODUCT/functions"

#
# Install Shorecap
#

install_file shorecap ${DESTDIR}${LIBEXECDIR}/$PRODUCT/shorecap 0755
[ $SHAREDIR = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}/${LIBEXECDIR}/$PRODUCT/shorecap

echo
echo "Capability file builder installed in ${DESTDIR}${LIBEXECDIR}/$PRODUCT/shorecap"

#
# Install the Modules files
#

if [ -f modules ]; then
    run_install $OWNERSHIP -m 0600 modules ${DESTDIR}${SHAREDIR}/$PRODUCT
    echo "Modules file installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/modules"
fi

if [ -f helpers ]; then
    run_install $OWNERSHIP -m 0600 helpers ${DESTDIR}${SHAREDIR}/$PRODUCT
    echo "Helper modules file installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/helpers"
fi

for f in modules.*; do
    run_install $OWNERSHIP -m 0644 $f ${DESTDIR}${SHAREDIR}/$PRODUCT/$f
    echo "Module file $f installed as ${DESTDIR}${SHAREDIR}/$PRODUCT/$f"
done

#
# Install the Man Pages
#

if [ -d manpages ]; then
    cd manpages

    [ -n "$INSTALLD" ] || mkdir -p ${DESTDIR}${SHAREDIR}/man/man5/ ${DESTDIR}${SHAREDIR}/man/man8/

    for f in *.5; do
	gzip -c $f > $f.gz
	run_install $T $INSTALLD $OWNERSHIP -m 0644 $f.gz ${DESTDIR}${SHAREDIR}/man/man5/$f.gz
	echo "Man page $f.gz installed to ${DESTDIR}${SHAREDIR}/man/man5/$f.gz"
    done

    for f in *.8; do
	gzip -c $f > $f.gz
	run_install $T $INSTALLD $OWNERSHIP -m 0644 $f.gz ${DESTDIR}${SHAREDIR}/man/man8/$f.gz
	echo "Man page $f.gz installed to ${DESTDIR}${SHAREDIR}/man/man8/$f.gz"
    done

    cd ..

    echo "Man Pages Installed"
fi

if [ -d ${DESTDIR}${CONFDIR}/logrotate.d ]; then
    run_install $OWNERSHIP -m 0644 logrotate ${DESTDIR}${CONFDIR}/logrotate.d/$PRODUCT
    echo "Logrotate file installed as ${DESTDIR}${CONFDIR}/logrotate.d/$PRODUCT"
fi

#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}${SHAREDIR}/$PRODUCT/version
chmod 644 ${DESTDIR}${SHAREDIR}/$PRODUCT/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "${DESTDIR}" -a -n "${INITFILE}" ]; then
    rm -f ${SHAREDIR}/$PRODUCT/init
    ln -s ${INITDIR}/${INITFILE} ${SHAREDIR}/$PRODUCT/init
fi

delete_file ${DESTDIR}${SHAREDIR}/$PRODUCT/lib.common
delete_file ${DESTDIR}${SHAREDIR}/$PRODUCT/lib.cli
delete_file ${DESTDIR}${SHAREDIR}/$PRODUCT/wait4ifup

#
# Note -- not all packages will have the SYSCONFFILE so we need to check for its existance here
#
if [ -n "$SYSCONFFILE" -a -f "$SYSCONFFILE" -a ! -f ${DESTDIR}${SYSCONFDIR}/${PRODUCT} ]; then
    if [ ${DESTDIR} ]; then
	mkdir -p ${DESTDIR}${SYSCONFDIR}
	chmod 755 ${DESTDIR}${SYSCONFDIR}
    fi

    run_install $OWNERSHIP -m 0644 ${SYSCONFFILE} ${DESTDIR}${SYSCONFDIR}/${PRODUCT}
    echo "$SYSCONFFILE installed in ${DESTDIR}${SYSCONFDIR}/${PRODUCT}"
fi

if [ ${SHAREDIR} != /usr/share ]; then
    eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}/${SHAREDIR}/${PRODUCT}/lib.base
    eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}/${SBINDIR}/$PRODUCT
fi

if [ $configure -eq 1 -a -z "$DESTDIR" -a -n "$first_install" -a -z "${cygwin}${mac}" ]; then
    if [ -n "$SYSTEMD" ]; then
	if systemctl enable ${PRODUCT}.service; then
	    echo "$Product will start automatically at boot"
	fi
    elif mywhich insserv; then
	if insserv ${INITDIR}/${INITFILE} ; then
	    echo "$PRODUCT will start automatically at boot"
	    if [ $HOST = debian ]; then
		echo "Set startup=1 in ${CONFDIR}/default/$PRODUCT to enable"
		touch /var/log/$PRODUCT-init.log
		perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' ${CONFDIR}/$PRODUCT/$PRODUCT.conf
	    else
		echo "Set STARTUP_ENABLED=Yes in ${CONFDIR}/$PRODUCT/$PRODUCT.conf to enable"
	    fi
	else
	    cant_autostart
	fi
    elif mywhich chkconfig; then
	if chkconfig --add $PRODUCT ; then
	    echo "$PRODUCT will start automatically in run levels as follows:"
	    echo "Set STARTUP_ENABLED=Yes in ${CONFDIR}/$PRODUCT/${PRODUCT}.conf to enable"
	    chkconfig --list $PRODUCT
	else
	    cant_autostart
	fi
    elif mywhich update-rc.d ; then
	echo "$PRODUCT will start automatically at boot"
	echo "Set startup=1 in ${CONFDIR}/default/$PRODUCT to enable"
	touch /var/log/$PRODUCT-init.log
	perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' ${CONFDIR}/$PRODUCT/$PRODUCT.conf
	update-rc.d $PRODUCT enable
    elif mywhich rc-update ; then
	if rc-update add $PRODUCT default; then
	    echo "$PRODUCT will start automatically at boot"
	    if [ $HOST = debian ]; then
		echo "Set startup=1 in ${CONFDIR}/default/$PRODUCT to enable"
		touch /var/log/$PRODUCT-init.log
		perl -p -w -i -e 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/;s/^IP_FORWARDING=On/IP_FORWARDING=Keep/;s/^SUBSYSLOCK=.*/SUBSYSLOCK=/;' ${CONFDIR}/$PRODUCT/$PRODUCT.conf
	    else
		echo "Set STARTUP_ENABLED=Yes in ${CONFDIR}/$PRODUCT/$PRODUCT.conf to enable"
	    fi
	else
	    cant_autostart
	fi
    elif [ "$INITFILE" != rc.${PRODUCT} ]; then #Slackware starts this automatically
	cant_autostart
    fi
fi

#
#  Report Success
#
echo "$Product Version $VERSION Installed"
