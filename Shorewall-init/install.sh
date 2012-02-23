#!/bin/sh
#
# Script to install Shoreline Firewall Init
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000-2011 - Tom Eastep (teastep@shorewall.net)
#     (c) 2010 - Roberto C. Sanchez (roberto@connexer.com)
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

VERSION=xxx #The Build script inserts the actual version.

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
    echo  "WARNING: Unable to configure shorewall init to start automatically at boot" >&2
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

#
# Load packager's settings if any
#
[ -f ../shorewall-pkg.config ] && . ../shorewall-pkg.config

[ -n "$DESTDIR" ] || DESTDIR="$PREFIX"

while [ $# -gt 0 ] ; do
    case "$1" in
	-h|help|?)
	    usage 0
	    ;;
        -v)
	    echo "Shorewall Init Installer Version $VERSION"
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

INITFILE="shorewall-init"

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
	    elif [ -f /etc/SuSE-release ]; then
		BUILD=suse
	    elif [ -f /etc/slackware-version ] ; then
		BUILD=slackware
	    elif [ -f /etc/arch-release ] ; then
		BUILD=archlinux
	    else
		BUILD=linux
	    fi
	    ;;
    esac
fi

[ -n "$OWNER" ] || OWNER=$(id -un)
[ -n "$GROUP" ] || GROUP=$(id -gn)

case $BUILD in
    apple)
	T=
	;;
    debian|redhat|suse|slackware|archlinux)
	;;
    *)
	[ -n "$BUILD" ] && echo "ERROR: Unknown BUILD environment ($BUILD)" >&2 || echo "ERROR: Unknown BUILD environment"
	exit 1
	;;
esac

OWNERSHIP="-o $OWNER -g $GROUP"

[ -n "$HOST" ] || HOST=$BUILD

case "$HOST" in
    debian)
	echo "Installing Debian-specific configuration..."
	SPARSE=yes
	;;
    redhat|redhat)
	echo "Installing Redhat/Fedora-specific configuration..."
	[ -n "$INITDIR" ] || INITDIR=/etc/rc.d/init.d
	;;
    slackware)
	echo "Shorewall-init is currently not supported on Slackware" >&2
	exit 1
	;;
    archlinux)
	echo "Shorewall-init is currently not supported on Arch Linux" >&2
	exit 1
	;;
    suse|suse)
	echo "Installing SuSE-specific configuration..."
	;;
    linux)
	echo "ERROR: Shorewall-init is not supported on this system" >&2
	;;
    *)
	echo "ERROR: Unsupported HOST distribution: \"$HOST\"" >&2
	exit 1;
	;;
esac

if [ -z "$INITDIR" -a -n "$INITFILE" ] ; then
    INITDIR="/etc/init.d"
fi

if [ -n "$DESTDIR" ]; then
    if [ `id -u` != 0 ] ; then
	echo "Not setting file owner/group permissions, not running as root."
	OWNERSHIP=""
    fi
    
    install -d $OWNERSHIP -m 755 ${DESTDIR}${INITDIR}
fi

if [ -z "$DESTDIR" ]; then
    if [ -f /lib/systemd/system ]; then
	SYSTEMD=Yes
	INITFILE=
    fi
elif [ -n "$SYSTEMD" ]; then
    mkdir -p ${DESTDIR}/lib/systemd/system
    INITFILE=
fi

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

echo "Installing Shorewall Init Version $VERSION"

#
# Check for /usr/share/shorewall-init/version
#
if [ -f ${DESTDIR}/usr/share/shorewall-init/version ]; then
    first_install=""
else
    first_install="Yes"
fi

if [ -n "$INITFILE" ]; then
    #
    # Install the Init Script
    #
    case $TARGET in
	debian)
	    install_file init.debian.sh ${DESTDIR}${INITDIR}/${INITFILE} 0544
	    ;;
	redhat)
	    install_file init.fedora.sh ${DESTDIR}${INITDIR}/${INITFILE} 0544
	    ;;
	*)
	    install_file init.sh ${DESTDIR}${INITDIR}/${INITFILE} 0544
	    ;;
    esac

    echo  "$Product script installed in ${DESTDIR}${INITDIR}/${INITFILE}"
fi
#
# Install the .service file
#
if [ -n "$SYSTEMD" ]; then
    run_install $OWNERSHIP -m 600 shorewall-init.service ${DESTDIR}/lib/systemd/system/shorewall-init.service
    echo "Service file installed as ${DESTDIR}/lib/systemd/system/shorewall-init.service"
fi

#
# Create /usr/share/shorewall-init if needed
#
mkdir -p ${DESTDIR}/usr/share/shorewall-init
chmod 755 ${DESTDIR}/usr/share/shorewall-init

#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}/usr/share/shorewall-init/version
chmod 644 ${DESTDIR}/usr/share/shorewall-init/version

#
# Remove and create the symbolic link to the init script
#
if [ -z "$DESTDIR" ]; then
    rm -f /usr/share/shorewall-init/init
    ln -s ${INITDIR}/${INITFILE} /usr/share/shorewall-init/init
fi

if [ $HOST = debian ]; then
    if [ -n "${DESTDIR}" ]; then
	mkdir -p ${DESTDIR}/etc/network/if-up.d/
	mkdir -p ${DESTDIR}/etc/network/if-post-down.d/
    fi

    if [ ! -f ${DESTDIR}/etc/default/shorewall-init ]; then
	if [ -n "${DESTDIR}" ]; then
	    mkdir ${DESTDIR}/etc/default
	fi

	install_file sysconfig ${DESTDIR}/etc/default/shorewall-init 0644
    fi
else
    if [ -n "$DESTDIR" ]; then
	mkdir -p ${DESTDIR}/etc/sysconfig

	if [ -z "$RPM" ]; then
	    if [ $HOST = suse ]; then
		mkdir -p ${DESTDIR}/etc/sysconfig/network/if-up.d
		mkdir -p ${DESTDIR}/etc/sysconfig/network/if-down.d
	    else
		mkdir -p ${DESTDIR}/etc/NetworkManager/dispatcher.d
	    fi
	fi
    fi

    if [ -d ${DESTDIR}/etc/sysconfig -a ! -f ${DESTDIR}/etc/sysconfig/shorewall-init ]; then
	install_file sysconfig ${DESTDIR}/etc/sysconfig/shorewall-init 0644
    fi 
fi

#
# Install the ifupdown script
#

mkdir -p ${DESTDIR}${LIBEXEC}/shorewall-init

install_file ifupdown.sh ${DESTDIR}${LIBEXEC}/shorewall-init/ifupdown 0544

if [ -d ${DESTDIR}/etc/NetworkManager ]; then
    install_file ifupdown.sh ${DESTDIR}/etc/NetworkManager/dispatcher.d/01-shorewall 0544
fi

case $HOST in
    debian)
	install_file ifupdown.sh ${DESTDIR}/etc/network/if-up.d/shorewall 0544
	install_file ifupdown.sh ${DESTDIR}/etc/network/if-post-down.d/shorewall 0544
	;;
    suse)
	if [ -z "$RPM" ]; then
	    install_file ifupdown.sh ${DESTDIR}/etc/sysconfig/network/if-up.d/shorewall 0544
	    install_file ifupdown.sh ${DESTDIR}/etc/sysconfig/network/if-down.d/shorewall 0544
	fi
	;;
    redhat)
	if [ -f ${DESTDIR}/sbin/ifup-local -o -f ${DESTDIR}/sbin/ifdown-local ]; then
	    echo "WARNING: /sbin/ifup-local and/or /sbin/ifdown-local already exist; up/down events will not be handled"
	elif [ -z "$DESTDIR" ]; then
	    install_file ifupdown.sh ${DESTDIR}/sbin/ifup-local 0544
	    install_file ifupdown.sh ${DESTDIR}/sbin/ifdown-local 0544
	fi
	;;
esac

if [ -z "$DESTDIR" ]; then
    if [ -n "$first_install" ]; then
	if [ $HOST = debian ]; then
	    
	    update-rc.d shorewall-init defaults

	    echo "Shorewall Init will start automatically at boot"
	else
	    if [ -n "$SYSTEMD" ]; then
		if systemctl enable shorewall-init; then
		    echo "Shorewall Init will start automatically at boot"
		fi
	    elif [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
		if insserv /etc/init.d/shorewall-init ; then
		    echo "Shorewall Init will start automatically at boot"
		else
		    cant_autostart
		fi
	    elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
		if chkconfig --add shorewall-init ; then
		    echo "Shorewall Init will start automatically in run levels as follows:"
		    chkconfig --list shorewall-init
		else
		    cant_autostart
		fi
	    elif [ -x /sbin/rc-update ]; then
		if rc-update add shorewall-init default; then
		    echo "Shorewall Init will start automatically at boot"
		else
		    cant_autostart
		fi
	    else
		cant_autostart
	    fi

	fi
    fi
else
    if [ -n "$first_install" ]; then
	if [ $HOST = debian ]; then
	    if [ -n "${DESTDIR}" ]; then
		mkdir -p ${DESTDIR}/etc/rcS.d
	    fi

	    ln -sf ../init.d/shorewall-init ${DESTDIR}/etc/rcS.d/S38shorewall-init
	    echo "Shorewall Init will start automatically at boot"
	fi
    fi
fi

if [ -f ${DESTDIR}/etc/ppp ]; then
    case $HOST in
	debian|suse)
	    for directory in ip-up.d ip-down.d ipv6-up.d ipv6-down.d; do
		mkdir -p ${DESTDIR}/etc/ppp/$directory #SuSE doesn't create the IPv6 directories
		cp -fp ${DESTDIR}${LIBEXEC}/shorewall-init/ifupdown ${DESTDIR}/etc/ppp/$directory/shorewall
	    done
	    ;;
	redhat)
	    #
	    # Must use the dreaded ip_xxx.local file
	    #
	    for file in ip-up.local ip-down.local; do
		FILE=${DESTDIR}/etc/ppp/$file
		if [ -f $FILE ]; then
		    if fgrep -q Shorewall-based $FILE ; then
			cp -fp ${DESTDIR}${LIBEXEC}/shorewall-init/ifupdown $FILE
		    else
			echo "$FILE already exists -- ppp devices will not be handled"
			break
		    fi
		else
		    cp -fp ${DESTDIR}${LIBEXEC}/shorewall-init/ifupdown $FILE
		fi
	    done
	    ;;
    esac
fi
#
#  Report Success
#
echo "shorewall Init Version $VERSION Installed"
