#!/bin/sh
#
# Script to install Shoreline Firewall Init
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010 - Tom Eastep (teastep@shorewall.net)
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

VERSION=4.4.18-Beta2

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
	INIT="shorewall-init"
fi

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
    ARGS="yes"
done

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

#
# Determine where to install the firewall script
#

case $(uname) in
    Darwin)
	[ -z "$OWNER" ] && OWNER=root
	[ -z "$GROUP" ] && GROUP=wheel
	T=
	;;	
    *)
	[ -z "$OWNER" ] && OWNER=root
	[ -z "$GROUP" ] && GROUP=root
	;;
esac

OWNERSHIP="-o $OWNER -g $GROUP"

if [ -n "$DESTDIR" ]; then
    if [ `id -u` != 0 ] ; then
	echo "Not setting file owner/group permissions, not running as root."
	OWNERSHIP=""
    fi
    
    install -d $OWNERSHIP -m 755 ${DESTDIR}${DEST}
elif [ -f /etc/debian_version ]; then
    DEBIAN=yes
elif [ -f /etc/SuSE-release ]; then
    SUSE=Yes
elif [ -f /etc/slackware-version ] ; then
    echo "Shorewall-init is currently not supported on Slackware" >&2
    exit 1
#   DEST="/etc/rc.d"
#   INIT="rc.firewall"
elif [ -f /etc/arch-release ] ; then
    echo "Shorewall-init is currently not supported on Arch Linux" >&2
    exit 1
#   DEST="/etc/rc.d"
#   INIT="shorewall-init"
#   ARCHLINUX=yes
elif [ -d /etc/sysconfig/network-scripts/ ]; then
    #
    # Assume RedHat-based
    #
    REDHAT=Yes
else
    echo "Unknown distribution: Shorewall-init support is not available" >&2
    exit 1
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

#
# Install the Init Script
#
if [ -n "$DEBIAN" ]; then
    install_file init.debian.sh ${DESTDIR}/etc/init.d/shorewall-init 0544
#elif [ -n "$ARCHLINUX" ]; then
#    install_file init.archlinux.sh ${DESTDIR}${DEST}/$INIT 0544
else
    install_file init.sh ${DESTDIR}${DEST}/$INIT 0544
fi

echo  "Shorewall Init script installed in ${DESTDIR}${DEST}/$INIT"

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
    ln -s ${DEST}/${INIT} /usr/share/shorewall-init/init
fi

if [ -n "$DEBIAN" ]; then
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
	    if [ -n "$SUSE" ]; then
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

mkdir -p ${DESTDIR}/usr/share/shorewall-init

install_file ifupdown.sh ${DESTDIR}/usr/share/shorewall-init/ifupdown 0544

if [ -d ${DESTDIR}/etc/NetworkManager ]; then
    install_file ifupdown.sh ${DESTDIR}/etc/NetworkManager/dispatcher.d/01-shorewall 0544
fi

if [ -n "$DEBIAN" ]; then
    install_file ifupdown.sh ${DESTDIR}/etc/network/if-up.d/shorewall 0544
    install_file ifupdown.sh ${DESTDIR}/etc/network/if-post-down.d/shorewall 0544
elif [ -n "$SUSE" ]; then
    install_file ifupdown.sh ${DESTDIR}/etc/sysconfig/network/if-up.d/shorewall 0544
    install_file ifupdown.sh ${DESTDIR}/etc/sysconfig/network/if-down.d/shorewall 0544
elif [ -n "$REDHAT" ]; then
    if [ -f ${DESTDIR}/sbin/ifup-local -o -f ${DESTDIR}/sbin/ifdown-local ]; then
	echo "WARNING: /sbin/ifup-local and/or /sbin/ifdown-local already exist; up/down events will not be handled"
    else
	install_file ifupdown.sh ${DESTDIR}/sbin/ifup-local 0544
	install_file ifupdown.sh ${DESTDIR}/sbin/ifdown-local 0544
    fi
fi

if [ -z "$DESTDIR" ]; then
    if [ -n "$first_install" ]; then
	if [ -n "$DEBIAN" ]; then
	    
	    update-rc.d shorewall-init defaults

	    echo "Shorewall Init will start automatically at boot"
	else
	    if [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
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
	    elif [ "$INIT" != rc.firewall ]; then #Slackware starts this automatically
		cant_autostart
	    fi

	fi
    fi
else
    if [ -n "$first_install" ]; then
	if [ -n "$DEBIAN" ]; then
	    if [ -n "${DESTDIR}" ]; then
		mkdir -p ${DESTDIR}/etc/rcS.d
	    fi

	    ln -sf ../init.d/shorewall-init ${DESTDIR}/etc/rcS.d/S38shorewall-init
	    echo "Shorewall Init will start automatically at boot"
	fi
    fi
fi

if [ -f ${DESTDIR}/etc/ppp ]; then
    if [ -n "$DEBIAN" ] -o -n "$SUSE" ]; then
	for directory in ip-up.d ip-down.d ipv6-up.d ipv6-down.d; do
	    mkdir -p ${DESTDIR}/etc/ppp/$directory #SuSE doesn't create the IPv6 directories
	    cp -fp ${DESTDIR}/usr/share/shorewall-init/ifupdown ${DESTDIR}/etc/ppp/$directory/shorewall
	done
    elif [ -n "$REDHAT" ]; then
	#
	# Must use the dreaded ip_xxx.local file
	#
	for file in ip-up.local ip-down.local; do
	    FILE=${DESTDIR}/etc/ppp/$file
	    if [ -f $FILE ]; then
		if fgrep -q Shorewall-based $FILE ; then
		    cp -fp ${DESTDIR}/usr/share/shorewall-init/ifupdown $FILE
		else
		    echo "$FILE already exists -- ppp devices will not be handled"
		    break
		fi
	    else
		cp -fp ${DESTDIR}/usr/share/shorewall-init/ifupdown $FILE
	    fi
	done
    fi
fi

#
#  Report Success
#
echo "shorewall Init Version $VERSION Installed"
