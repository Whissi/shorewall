#!/bin/sh
#
# Script to install Shoreline Firewall Lite
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

VERSION=xxx #The Build script inserts the actual version

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

[ -n "$DESTDIR" ] || DESTDIR="$PREFIX"

#
# Parse the run line
#
while [ $# -gt 0 ] ; do
    case "$1" in
	-h|help|?)
	    usage 0
	    ;;
        -v)
	    echo "$Product Firewall Installer Version $VERSION"
	    exit 0
	    ;;
	*)
	    usage 1
	    ;;
    esac
    shift
done

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

[ -n "${LIBEXEC:=/usr/share}" ]

case "$LIBEXEC" in
    /*)
	;;
    *)
	echo "The LIBEXEC setting must be an absolute path name" >&2
	exit 1
	;;
esac

#
# Determine where to install the firewall script
#
CYGWIN=
INSTALLD='-D'
INITFILE=$PRODUCT
T='-T'

if [ -z "$HOST" ]; then
    case $(uname) in
	CYGWIN*)
	    HOST=CYGWIN
	    ;;
	Darwin)
	    HOST=MAC
	    ;;
	*)
	    if [ -f /etc/debian_version ]; then
		HOST=DEBIAN
	    elif [ -f /etc/redhat-release ]; then
		HOST=REDHAT
	    elif [ -f /etc/SuSE-release ]; then
		HOST=SUSE
	    elif [ -f /etc/slackware-version ] ; then
		HOST=SLACKWARE
	    elif [ -f /etc/arch-release ] ; then
		HOST=ARCHLINUX
	    else
		HOST=LINUX
	    fi
	    ;;
    esac
fi

case $HOST in
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

[ -n "$TARGET" ] || TARGET=$HOST

case "$TARGET" in
    CYGWIN)
	echo "$PRODUCT is not supported on Cygwin" >&2
	exit 1
	;;
    MAC)
	echo "$PRODUCT is not supported on OS X" >&2
	exit 1
	;;
    DEBIAN)
	echo "Installing Debian-specific configuration..."
	SPARSE=yes
	;;
    REDHAT)
	echo "Installing Redhat/Fedora-specific configuration..."
	INITDIR=/etc/rc.d/init.d
	;;
    SLACKWARE)
	echo "Installing Slackware-specific configuration..."
	INITDIR="/etc/rc.d"
	INITFILE="rc.firewall"
	MANDIR="/usr/man"
	;;
    ARCHLINUX)
	echo "Installing ArchLinux-specific configuration..."
	INITDIR="/etc/rc.d"
	INITFILE="$PRODUCT"
	;;
    LINUX|SUSE)
	;;
    *)
	echo "ERROR: Unknown TARGET \"$TARGET\"" >&2
	exit 1;
	;;
esac

[ -z "$INITDIR" ] && INITDIR="/etc/init.d"

if [ -n "$DESTDIR" ]; then
    if [ `id -u` != 0 ] ; then
	echo "Not setting file owner/group permissions, not running as root."
	OWNERSHIP=""
    fi
    
    install -d $OWNERSHIP -m 755 ${DESTDIR}/sbin
    install -d $OWNERSHIP -m 755 ${DESTDIR}${DESTFILE}

    if [ -n "$SYSTEMD" ]; then
	mkdir -p ${DESTDIR}/lib/systemd/system
    fi
else
    if [ ! -f /usr/share/shorewall/coreversion ]; then
	echo "$PRODUCT $VERSION requires Shorewall Core which does not appear to be installed" >&2
	exit 1
    fi

    if [ -f /lib/systemd/system ]; then
	SYSTEMD=Yes
    fi
fi

echo "Installing $Product Version $VERSION"

#
# Check for /etc/$PRODUCT
#
if [ -z "$DESTDIR" -a -d /etc/$PRODUCT ]; then
    if [ ! -f /usr/share/shorewall/coreversion ]; then
	echo "$PRODUCT $VERSION requires Shorewall Core which does not appear to be installed" >&2
	exit 1
    fi

    [ -f /etc/$PRODUCT/shorewall.conf ] && \
	mv -f /etc/$PRODUCT/shorewall.conf /etc/$PRODUCT/$PRODUCT.conf
else
    rm -rf ${DESTDIR}/etc/$PRODUCT
    rm -rf ${DESTDIR}/usr/share/$PRODUCT
    rm -rf ${DESTDIR}/var/lib/$PRODUCT
    [ "$LIBEXEC" = /usr/share ] || rm -rf ${DESTDIR}/usr/share/$PRODUCT/wait4ifup ${DESTDIR}/usr/share/$PRODUCT/shorecap
fi

#
# Check for /sbin/$PRODUCT
#
if [ -f ${DESTDIR}/sbin/$PRODUCT ]; then
    first_install=""
else
    first_install="Yes"
fi

delete_file ${DESTDIR}/usr/share/$PRODUCT/xmodules

install_file $PRODUCT ${DESTDIR}/sbin/$PRODUCT 0544

echo "$Product control program installed in ${DESTDIR}/sbin/$PRODUCT"

#
# Create /etc/$PRODUCT, /usr/share/$PRODUCT and /var/lib/$PRODUCT if needed
#
mkdir -p ${DESTDIR}/etc/$PRODUCT
mkdir -p ${DESTDIR}/usr/share/$PRODUCT
mkdir -p ${DESTDIR}${LIBEXEC}/$PRODUCT
mkdir -p ${DESTDIR}/var/lib/$PRODUCT

chmod 755 ${DESTDIR}/etc/$PRODUCT
chmod 755 ${DESTDIR}/usr/share/$PRODUCT

if [ -n "$DESTDIR" ]; then
    mkdir -p ${DESTDIR}/etc/logrotate.d
    chmod 755 ${DESTDIR}/etc/logrotate.d
    mkdir -p ${DESTDIR}${INITDIR}
    chmod 755 ${DESTDIR}${INITDIR}
fi

#
# Install the Firewall Script
#
install_file init.sh ${DESTDIR}${INITDIR}/$INITFILE 0544
echo  "$Product script installed in ${DESTDIR}${INITDIR}/$INITFILE"

#
# Install the .service file
#
if [ -n "$SYSTEMD" ]; then
    run_install $OWNERSHIP -m 600 $PRODUCT.service ${DESTDIR}/lib/systemd/system/$PRODUCT.service
    echo "Service file installed as ${DESTDIR}/lib/systemd/system/$PRODUCT.service"
fi

#
# Install the config file
#
if [ ! -f ${DESTDIR}/etc/$PRODUCT/$PRODUCT.conf ]; then
   install_file $PRODUCT.conf ${DESTDIR}/etc/$PRODUCT/$PRODUCT.conf 0744
   echo "Config file installed as ${DESTDIR}/etc/$PRODUCT/$PRODUCT.conf"
fi

if [ $TARGET = ARCHLINUX ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${DESTDIR}/etc/$PRODUCT/$PRODUCT.conf
fi

#
# Install the  Makefile
#
run_install $OWNERSHIP -m 0600 Makefile ${DESTDIR}/etc/$PRODUCT
echo "Makefile installed as ${DESTDIR}/etc/$PRODUCT/Makefile"

#
# Install the default config path file
#
install_file configpath ${DESTDIR}/usr/share/$PRODUCT/configpath 0644
echo "Default config path file installed as ${DESTDIR}/usr/share/$PRODUCT/configpath"

#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${DESTDIR}/usr/share/$PRODUCT/$f 0644
	echo "Library ${f#*.} file installed as ${DESTDIR}/usr/share/$PRODUCT/$f"
    fi
done

ln -sf lib.base ${DESTDIR}/usr/share/$PRODUCT/functions

echo "Common functions linked through ${DESTDIR}/usr/share/$PRODUCT/functions"

#
# Install Shorecap
#

install_file shorecap ${DESTDIR}${LIBEXEC}/$PRODUCT/shorecap 0755

echo
echo "Capability file builder installed in ${DESTDIR}${LIBEXEC}/$PRODUCT/shorecap"

#
# Install the Modules files
#

if [ -f modules ]; then
    run_install $OWNERSHIP -m 0600 modules ${DESTDIR}/usr/share/$PRODUCT
    echo "Modules file installed as ${DESTDIR}/usr/share/$PRODUCT/modules"
fi

if [ -f helpers ]; then
    run_install $OWNERSHIP -m 0600 helpers ${DESTDIR}/usr/share/$PRODUCT
    echo "Helper modules file installed as ${DESTDIR}/usr/share/$PRODUCT/helpers"
fi

for f in modules.*; do
    run_install $OWNERSHIP -m 0644 $f ${DESTDIR}/usr/share/$PRODUCT/$f
    echo "Module file $f installed as ${DESTDIR}/usr/share/$PRODUCT/$f"
done

#
# Install the Man Pages
#

if [ -d manpages ]; then
    cd manpages

    [ -n "$INSTALLD" ] || mkdir -p ${DESTDIR}/usr/share/man/man5/ ${DESTDIR}/usr/share/man/man8/

    for f in *.5; do
	gzip -c $f > $f.gz
	run_install $T $INSTALLD $OWNERSHIP -m 0644 $f.gz ${DESTDIR}/usr/share/man/man5/$f.gz
	echo "Man page $f.gz installed to ${DESTDIR}/usr/share/man/man5/$f.gz"
    done

    for f in *.8; do
	gzip -c $f > $f.gz
	run_install $T $INSTALLD $OWNERSHIP -m 0644 $f.gz ${DESTDIR}/usr/share/man/man8/$f.gz
	echo "Man page $f.gz installed to ${DESTDIR}/usr/share/man/man8/$f.gz"
    done

    cd ..

    echo "Man Pages Installed"
fi

if [ -d ${DESTDIR}/etc/logrotate.d ]; then
    run_install $OWNERSHIP -m 0644 logrotate ${DESTDIR}/etc/logrotate.d/$PRODUCT
    echo "Logrotate file installed as ${DESTDIR}/etc/logrotate.d/$PRODUCT"
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

delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.common
delete_file ${DESTDIR}/usr/share/$PRODUCT/lib.cli
delete_file ${DESTDIR}/usr/share/$PRODUCT/wait4ifup

if [ -z "$DESTDIR" ]; then
    touch /var/log/$PRODUCT-init.log

    if [ -n "$first_install" ]; then
	if [ $TARGET = DEBIAN ]; then
	    run_install $OWNERSHIP -m 0644 default.debian /etc/default/$PRODUCT

	    update-rc.d $PRODUCT defaults

	    if [ -x /sbin/insserv ]; then
		insserv /etc/init.d/$PRODUCT
	    else
		ln -s ../init.d/$PRODUCT /etc/rcS.d/S40$PRODUCT
	    fi

	    echo "$Product will start automatically at boot"
	else
	    if [ -n "$SYSTEMD" ]; then
		if systemctl enable $PRODUCT; then
		    echo "$Product will start automatically at boot"
		fi
	    elif [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
		if insserv /etc/init.d/$PRODUCT ; then
		    echo "$Product will start automatically at boot"
		else
		    cant_autostart
		fi
	    elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
		if chkconfig --add $PRODUCT ; then
		    echo "$Product will start automatically in run levels as follows:"
		    chkconfig --list $PRODUCT
		else
		    cant_autostart
		fi
	    elif [ -x /sbin/rc-update ]; then
		if rc-update add $PRODUCT default; then
		    echo "$Product will start automatically at boot"
		else
		    cant_autostart
		fi
	    elif [ "$INITFILE" != rc.firewall ]; then #Slackware starts this automatically
		cant_autostart
	    fi
	fi
    fi
fi

#
#  Report Success
#
echo "$Product Version $VERSION Installed"
