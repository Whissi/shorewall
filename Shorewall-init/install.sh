#!/bin/sh
#
# Script to install Shoreline Firewall Init
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010 - Tom Eastep (teastep@shorewall.net)
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

VERSION=4.4.10-Beta1

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
	INIT="shorewall-init"
fi

if [ -z "$RUNLEVELS" ] ; then
	RUNLEVELS=""
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
DEBIAN=

case $(uname) in
    *)
	[ -z "$OWNER" ] && OWNER=root
	[ -z "$GROUP" ] && GROUP=root
	;;
esac

OWNERSHIP="-o $OWNER -g $GROUP"

if [ -n "$PREFIX" ]; then
    if [ `id -u` != 0 ] ; then
	echo "Not setting file owner/group permissions, not running as root."
	OWNERSHIP=""
    fi
    
    install -d $OWNERSHIP -m 755 ${PREFIX}${DEST}
elif [ -f /etc/debian_version ]; then
    DEBIAN=yes
elif [ -f /etc/slackware-version ] ; then
    DEST="/etc/rc.d"
    INIT="rc.firewall"
elif [ -f /etc/arch-release ] ; then
      DEST="/etc/rc.d"
      INIT="shorewall-init"
      ARCHLINUX=yes
fi

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

echo "Installing Shorewall Init Version $VERSION"

#
# Check for /usr/share/shorewall-init/version
#
if [ -f ${PREFIX}/usr/share/shorewall-init/version ]; then
    first_install=""
else
    first_install="Yes"
fi

#
# Install the Init Script
#
if [ -n "$DEBIAN" ]; then
    install_file init.debian.sh /etc/init.d/shorewall-init 0544
elif [ -n "$ARCHLINUX" ]; then
    install_file init.archlinux.sh ${PREFIX}${DEST}/$INIT 0544
else
    install_file init.sh ${PREFIX}${DEST}/$INIT 0544
fi

echo  "Shorewall Init script installed in ${PREFIX}${DEST}/$INIT"

#
# Create /usr/share/shorewall-init if needed
#
mkdir -p ${PREFIX}/usr/share/shorewall-init
chmod 755 ${PREFIX}/usr/share/shorewall-init

#
# Create the version file
#
echo "$VERSION" > ${PREFIX}/usr/share/shorewall-init/version
chmod 644 ${PREFIX}/usr/share/shorewall-init/version

#
# Remove and create the symbolic link to the init script
#
if [ -z "$PREFIX" ]; then
    rm -f /usr/share/shorewall-init/init
    ln -s ${DEST}/${INIT} /usr/share/shorewall-init/init
fi

#
# Install the ifupdown script
#
if [ -n "$DEBIAN" ]; then
    run_install $OWNERSHIP -m 744 ifupdown.debian.sh ${PREFIX}/usr/share/shorewall-init/ifupdown
else
    if [ -n "$PREFIX" ]; then
	mkdir -p ${PREFIX}/etc/sysconfig
    fi

    if [ -d ${PREFIX}/etc/sysconfig ]; then
	run_install $OWNERSHIP -m 0644 sysconfig /etc/default/shorewall-init
    fi 
fi

if [ -z "$PREFIX" ]; then
    if [ -n "$first_install" ]; then
	if [ -n "$DEBIAN" ]; then
	    run_install $OWNERSHIP -m 0644 sysconfig /etc/default/shorewall-init
	    ln -sf ../init.d/shorewall-init /etc/rcS.d/S09shorewall-init
	    ln -sf /usr/share/shorewall-init/ifupdown /etc/network/if-up.d/shorewall
	    ln -sf /usr/share/shorewall-init/ifupdown /etc/network/if-post-down.d/shorewall
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
fi

#
#  Report Success
#
echo "shorewall Init Version $VERSION Installed"
