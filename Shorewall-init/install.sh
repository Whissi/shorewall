#!/bin/sh
#
# Script to install Shoreline Firewall Init
#
#     (c) 2000-2016 - Tom Eastep (teastep@shorewall.net)
#     (c) 2010 - Roberto C. Sanchez (roberto@connexer.com)
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
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

VERSION=xxx # The Build script inserts the actual version
PRODUCT=shorewall-init
Product="Shorewall Init"

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME [ <option> ] [ <shorewallrc file> ]"
    echo "where <option> is one of"
    echo "  -h"
    echo "  -v"
    echo "  -n"
    exit $1
}

install_file() # $1 = source $2 = target $3 = mode
{
    if cp -f $1 $2; then
	if chmod $3 $2; then
	    if [ -n "$OWNER" ]; then
		if chown $OWNER:$GROUP $2; then
		    return
		fi
	    else
		return 0
	    fi
	fi
    fi

    echo "ERROR: Failed to install $2" >&2
    exit 1
}

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

#
# Source common functions
#
. ./lib.installer || { echo "ERROR: Can not load common functions." >&2; exit 1; }

#
# Parse the run line
#

finished=0
configure=1

while [ $finished -eq 0 ] ; do
    option="$1"

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
	file=./shorewallrc
        . $file || fatal_error "Can not load the RC file: $file"
    elif [ -f ~/.shorewallrc ]; then
	file=~/.shorewallrc
        . $file || fatal_error "Can not load the RC file: $file"
    elif [ -f /usr/share/shorewall/shorewallrc ]; then
	file=/usr/share/shorewall/shorewallrc
        . $file || fatal_error "Can not load the RC file: $file"
    else
	fatal_error "No configuration file specified and /usr/share/shorewall/shorewallrc not found"
    fi
elif [ $# -eq 1 ]; then
    file=$1
    case $file in
	/*|.*)
	    ;;
	*)
	    file=./$file || exit 1
	    ;;
    esac

    . $file || fatal_error "Can not load the RC file: $file"
else
    usage 1
fi

if [ -z "${VARLIB}" ]; then
    VARLIB=${VARDIR}
    VARDIR=${VARLIB}/${PRODUCT}
elif [ -z "${VARDIR}" ]; then
    VARDIR=${VARLIB}/${PRODUCT}
fi

for var in SHAREDIR LIBEXECDIR CONFDIR SBINDIR VARLIB VARDIR; do
    require $var
done

[ -n "$SANDBOX" ] && configure=0

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

[ $configure -eq 1 ] && ETC=/etc || ETC="${CONFDIR}"

if [ -z "$BUILD" ]; then
    case $(uname) in
	cygwin*)
	    BUILD=cygwin
	    ;;
	Darwin)
	    BUILD=apple
	    ;;
	*)
	    if [ -f /etc/os-release ]; then
		eval $(cat /etc/os-release | grep ^ID=)

		case $ID in
		    fedora|rhel|centos|foobar)
			BUILD=redhat
			;;
		    debian|ubuntu)
			BUILD=debian
			;;
		    opensuse)
			BUILD=suse
			;;
		    *)
			BUILD="$ID"
			;;
		esac
	    elif [ -f /etc/debian_version ]; then
		BUILD=debian
	    elif [ -f /etc/ubuntu_version ]; then
		BUILD=debian
	    elif [ -f /etc/gentoo-release ]; then
		BUILD=gentoo
	    elif [ -f /etc/redhat-release ]; then
		BUILD=redhat
	    elif [ -f /etc/SuSE-release ]; then
		BUILD=suse
	    elif [ -f /etc/slackware-version ] ; then
		BUILD=slackware
	    elif [ -f /etc/arch-release ] ; then
		BUILD=archlinux
	    elif [ -f ${CONFDIR}/openwrt_release ]; then
		BUILD=openwrt
	    else
		BUILD=linux
	    fi
	    ;;
    esac
fi

case $BUILD in
    apple)
	[ -z "$OWNER" ] && OWNER=root
	[ -z "$GROUP" ] && GROUP=wheel
	;;
    cygwin*|CYGWIN*)
	OWNER=$(id -un)
	GROUP=$(id -gn)
 	;;
    *)
	if [ $(id -u) -eq 0 ]; then
	    [ -z "$OWNER" ] && OWNER=root
	    [ -z "$GROUP" ] && GROUP=root
	fi
	;;
esac

[ -n "$OWNER" ] && OWNERSHIP="$OWNER:$GROUP"

[ -n "$HOST" ] || HOST=$BUILD

case "$HOST" in
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
	echo "Shorewall-init is currently not supported on Slackware" >&2
	exit 1
	;;
    archlinux)
	echo "Shorewall-init is currently not supported on Arch Linux" >&2
	exit 1
	;;
    suse)
	echo "Installing SuSE-specific configuration..."
	;;
    openwrt)
	echo "Installing Openwrt-specific configuration..."
	;;
    linux)
	fatal_error "Shorewall-init is not supported on this system"
	;;
    *)
	fatal_error "Unsupported HOST distribution: \"$HOST\""
	;;
esac

[ -z "$TARGET" ] && TARGET=$HOST

if [ -n "$DESTDIR" ]; then
    if [ $(id -u) != 0 ] ; then
	echo "Not setting file owner/group permissions, not running as root."
	OWNERSHIP=""
    fi
    
    make_parent_directory ${DESTDIR}${INITDIR} 0755
fi

echo "Installing $Product Version $VERSION"

#
# Check for /usr/share/shorewall-init/version
#
if [ -f ${DESTDIR}${SHAREDIR}/$PRODUCT/version ]; then
    first_install=""
else
    first_install="Yes"
fi

[ -n "$DESTDIR" ] && make_parent_directory ${DESTDIR}${CONFDIR}/logrotate.d 0755

#
# Install the Firewall Script
#
if [ -n "$INITFILE" ]; then
    make_parent_directory ${DESTDIR}${INITDIR} 0755
    install_file $INITSOURCE ${DESTDIR}${INITDIR}/$INITFILE 0544
    [ "${SHAREDIR}" = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}${INITDIR}/$INITFILE
    
    if [ -n "${AUXINITSOURCE}" ]; then
	install_file $INITSOURCE ${DESTDIR}${INITDIR}/$AUXINITFILE 0544
    fi

    echo  "SysV init script $INITSOURCE installed in ${DESTDIR}${INITDIR}/$INITFILE"
fi

#
# Install the .service file
#
if [ -z "${SERVICEDIR}" ]; then
    SERVICEDIR="$SYSTEMD"
fi

if [ -n "$SERVICEDIR" ]; then
    make_parent_directory ${DESTDIR}${SERVICEDIR} 0755
    [ -z "$SERVICEFILE" ] && SERVICEFILE=$PRODUCT.service
    install_file $SERVICEFILE ${DESTDIR}${SERVICEDIR}/$PRODUCT.service 0644
    [ ${SBINDIR} != /sbin ] && eval sed -i \'s\|/sbin/\|${SBINDIR}/\|\' ${DESTDIR}${SERVICEDIR}/$PRODUCT.service
    echo "Service file $SERVICEFILE installed as ${DESTDIR}${SERVICEDIR}/$PRODUCT.service"
    [ -n "$DESTDIR" -o $configure -eq 0 ] && make_parent_directory ${DESTDIR}${SBINDIR} 0755
    install_file $PRODUCT ${DESTDIR}${SBINDIR}/$PRODUCT 0700
    [ "${SHAREDIR}" = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}${SBINDIR}/$PRODUCT
    echo "CLI installed as ${DESTDIR}${SBINDIR}/$PRODUCT"
fi

#
# Create /usr/share/shorewall-init if needed
#
make_parent_directory ${DESTDIR}${SHAREDIR}/$PRODUCT 0755

#
# Install logrotate file
#
if [ -d ${DESTDIR}${CONFDIR}/logrotate.d ]; then
    install_file logrotate ${DESTDIR}${CONFDIR}/logrotate.d/$PRODUCT 0644
    echo "Logrotate file installed as ${DESTDIR}${CONFDIR}/logrotate.d/$PRODUCT"
fi

#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}/${SHAREDIR}/$PRODUCT/version
chmod 0644 ${DESTDIR}${SHAREDIR}/$PRODUCT/version

#
# Remove and create the symbolic link to the init script
#
if [ -z "$DESTDIR" ]; then
    rm -f ${SHAREDIR}/$PRODUCT/init
    ln -s ${INITDIR}/${INITFILE} ${SHAREDIR}/$PRODUCT/init
fi

if [ $HOST = debian ]; then
    if [ -n "${DESTDIR}" ]; then
	make_parent_directory ${DESTDIR}${ETC}/network/if-up.d 0755
	make_parent_directory ${DESTDIR}${ETC}/network/if-down.d 0755
	make_parent_directory ${DESTDIR}${ETC}/network/if-post-down.d 0755
    elif [ $configure -eq 0 ]; then
	make_parent_directory ${DESTDIR}${CONFDIR}/network/if-up.d 0755
	make_parent_directory ${DESTDIR}${CONFDIR}/network/if-down.d 0755
	make_parent_directory ${DESTDIR}${CONFDIR}/network/if-post-down.d 0755
    fi

    if [ ! -f ${DESTDIR}${CONFDIR}/default/$PRODUCT ]; then
	[ -n "${DESTDIR}" ] && make_parent_directory ${DESTDIR}${ETC}/default 0755

	[ $configure -eq 1 ] || make_parent_directory ${DESTDIR}${CONFDIR}/default 0755
	install_file ${SYSCONFFILE} ${DESTDIR}${ETC}/default/$PRODUCT 0644
	echo "${SYSCONFFILE} file installed in ${DESTDIR}${SYSCONFDIR}/${PRODUCT}"
    fi

    IFUPDOWN=ifupdown.debian.sh
else
    if [ -n "$DESTDIR" ]; then
	make_parent_directory ${DESTDIR}${SYSCONFDIR} 0755

	if [ -z "$RPM" ]; then
	    if [ $HOST = suse ]; then
		make_parent_directory ${DESTDIR}${ETC}/sysconfig/network/if-up.d 0755
		make_parent_directory ${DESTDIR}${ETC}/sysconfig/network/if-down.d 0755
	    elif [ $HOST = gentoo ]; then
		# Gentoo does not support if-{up,down}.d
		/bin/true
	    elif [ $HOST = openwrt ]; then
		# Not implemented on OpenWRT
		/bin/true
	    else
		make_parent_directory ${DESTDIR}/${ETC}/NetworkManager/dispatcher.d 0755
	    fi
	fi
    fi

    if [ -n "$SYSCONFFILE" -a ! -f ${DESTDIR}${SYSCONFDIR}/${PRODUCT} ]; then
	install_file ${SYSCONFFILE} ${DESTDIR}${SYSCONFDIR}/$PRODUCT 0644
	echo "${SYSCONFFILE} file installed in ${DESTDIR}${SYSCONFDIR}/${PRODUCT}"
    fi

    [ $HOST = suse ] && IFUPDOWN=ifupdown.suse.sh || IFUPDOWN=ifupdown.fedora.sh
fi

#
# Install the ifupdown script
#

if [ $HOST != openwrt ]; then
    cp $IFUPDOWN ifupdown

    [ "${SHAREDIR}" = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ifupdown

    make_parent_directory ${DESTDIR}${LIBEXECDIR}/$PRODUCT 0755

    install_file ifupdown ${DESTDIR}${LIBEXECDIR}/$PRODUCT/ifupdown 0544
fi

if [ -d ${DESTDIR}/etc/NetworkManager ]; then
    [ $configure -eq 1 ] || make_parent_directory ${DESTDIR}${CONFDIR}/NetworkManager/dispatcher.d 0755
    install_file ifupdown ${DESTDIR}${ETC}/NetworkManager/dispatcher.d/01-shorewall 0544
fi

case $HOST in
    debian)
	if [ $configure -eq 1 ]; then
	    install_file ifupdown ${DESTDIR}/etc/network/if-up.d/shorewall 0544
	    install_file ifupdown ${DESTDIR}/etc/network/if-down.d/shorewall 0544
	    install_file ifupdown ${DESTDIR}/etc/network/if-post-down.d/shorewall 0544
	else
	    install_file ifupdown ${DESTDIR}${CONFDIR}/network/if-up.d/shorewall 0544
	    install_file ifupdown ${DESTDIR}${CONFDIR}/network/if-down.d/shorewall 0544
	    install_file ifupdown ${DESTDIR}${CONFDIR}/network/if-post-down.d/shorewall 0544
	fi
	;;
    suse)
	if [ -z "$RPM" ]; then
	    if [ $configure -eq 0 ]; then
		make_parent_directory ${DESTDIR}${SYSCONFDIR}/network/if-up.d 0755
		make_parent_directory ${DESTDIR}${SYSCONFDIR}/network/if-down.d 0755
	    fi

	    install_file ifupdown ${DESTDIR}${SYSCONFDIR}/network/if-up.d/shorewall 0544
	    install_file ifupdown ${DESTDIR}${SYSCONFDIR}/network/if-down.d/shorewall 0544
	fi
	;;
    redhat)
	if [ -z "$DESTDIR" ]; then
	    install_local=

	    if [ -f ${SBINDIR}/ifup-local -o -f ${SBINDIR}/ifdown-local ]; then
		if ! grep -qF Shorewall-based ${SBINDIR}/ifup-local || ! grep -qF Shorewall-based ${SBINDIR}/ifdown-local; then
		    echo "WARNING: ${SBINDIR}/ifup-local and/or ${SBINDIR}/ifdown-local already exist; up/down events will not be handled"
		else
		    install_local=Yes
		fi
	    else
		install_local=Yes
	    fi

	    if [ -n "$install_local" ]; then
		install_file ifupdown ${DESTDIR}${SBINDIR}/ifup-local 0544
		install_file ifupdown ${DESTDIR}${SBINDIR}/ifdown-local 0544
	    fi
	fi
	;;
esac

if [ -z "$DESTDIR" ]; then
    if [ $configure -eq 1 -a -n "first_install" ]; then
	if [ $HOST = debian ]; then
	    if [ -n "$SERVICEDIR" ]; then
		if systemctl enable ${PRODUCT}.service; then
                    echo "$Product will start automatically at boot"
		fi
	    elif mywhich insserv; then
		if insserv ${INITDIR}/$PRODUCT; then
                    echo "$Product will start automatically at boot"
		else
		    cant_autostart
		fi
	    elif mywhich update-rc.d ; then
		if update-rc.d $PRODUCT enable; then
                    echo "$Product will start automatically at boot"
		    echo "Set startup=1 in ${CONFDIR}/default/$PRODUCT to enable"
		else
		    cant_autostart
		fi
	    else
		cant_autostart
	    fi
	elif [ $HOST = openwrt -a -f ${CONFDIR}/rc.common ]; then
	    /etc/init.d/$PRODUCT enable
	    if /etc/init.d/$PRODUCT enabled; then
		echo "$Product will start automatically at boot"
	    else
		cant_autostart
	    fi
	elif [ $HOST = gentoo ]; then
	    # On Gentoo, a service must be enabled manually by the user,
	    # not by the installer
	    /bin/true
	else
	    if [ -n "$SERVICEDIR" ]; then
		if systemctl enable ${PRODUCT}.service; then
		    echo "$Product will start automatically at boot"
		fi
	    elif [ -x ${SBINDIR}/insserv -o -x /usr${SBINDIR}/insserv ]; then
		if insserv ${INITDIR}/$PRODUCT ; then
		    echo "$Product will start automatically at boot"
		else
		    cant_autostart
		fi
	    elif [ -x ${SBINDIR}/chkconfig -o -x /usr${SBINDIR}/chkconfig ]; then
		if chkconfig --add $PRODUCT ; then
		    echo "$Product will start automatically at boot"
		    chkconfig --list $PRODUCT
		else
		    cant_autostart
		fi
	    elif [ -x ${SBINDIR}/rc-update ]; then
		if rc-update add $PRODUCT default; then
		    echo "$Product will start automatically at boot"
		else
		    cant_autostart
		fi
	    elif [ $HOST = openwrt -a -f ${CONFDIR}/rc.common ]; then
		/etc/init.d/$PRODUCT enable
		if /etc/init.d/$PRODUCT enabled; then
		    echo "$Product will start automatically at boot"
		else
		    cant_autostart
		fi
	    else
		cant_autostart
	    fi
	fi
    fi
else
    if [ $configure -eq 1 -a -n "$first_install" ]; then
	if [ $HOST = debian -a -z "$SERVICEDIR" ]; then
	    if [ -n "${DESTDIR}" ]; then
		make_parent_directory ${DESTDIR}/etc/rcS.d 0755
	    fi

	    ln -sf ../init.d/$PRODUCT ${DESTDIR}${CONFDIR}/rcS.d/S38${PRODUCT}
	    echo "$Product will start automatically at boot"
	fi
    fi
fi

[ -z "${DESTDIR}" ] && [ ! -f ~/.shorewallrc ] && cp ${SHAREDIR}/shorewall/shorewallrc .

if [ -d ${DESTDIR}/etc/ppp ]; then
    case $HOST in
	debian|suse)
	    for directory in ip-up.d ip-down.d ipv6-up.d ipv6-down.d; do
		make_parent_directory ${DESTDIR}/etc/ppp/$directory 0755 #SuSE doesn't create the IPv6 directories
		cp -fp ${DESTDIR}${LIBEXECDIR}/$PRODUCT/ifupdown ${DESTDIR}${CONFDIR}/ppp/$directory/shorewall
	    done
	    ;;
	redhat)
	    #
	    # Must use the dreaded ip_xxx.local file
	    #
	    for file in ip-up.local ip-down.local; do
		FILE=${DESTDIR}/etc/ppp/$file
		if [ -f $FILE ]; then
		    if grep -qF Shorewall-based $FILE ; then
			cp -fp ${DESTDIR}${LIBEXECDIR}/$PRODUCT/ifupdown $FILE
		    else
			echo "$FILE already exists -- ppp devices will not be handled"
			break
		    fi
		else
		    cp -fp ${DESTDIR}${LIBEXECDIR}/$PRODUCT/ifupdown $FILE
		fi
	    done
	    ;;
    esac
fi
#
# Report Success
#
echo "shorewall Init Version $VERSION Installed"
