#!/bin/sh
#
# Script to install Shoreline Firewall Lite
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

VERSION=4.4.6-Beta2

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
    echo  "WARNING: Unable to configure shorewall to start automatically at boot" >&2
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
	INIT="shorewall-lite"
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
	    echo "Shorewall Lite Firewall Installer Version $VERSION"
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
CYGWIN=

case $(uname) in
    CYGWIN*)
	if [ -z "$PREFIX" ]; then
	    DEST=
	    INIT=
	fi

	OWNER=$(id -un)
	GROUP=$(id -gn)
	;;
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
    
    install -d $OWNERSHIP -m 755 ${PREFIX}/sbin
    install -d $OWNERSHIP -m 755 ${PREFIX}${DEST}
elif [ -d /etc/apt -a -e /usr/bin/dpkg ]; then
    DEBIAN=yes
elif [ -f /etc/slackware-version ] ; then
    DEST="/etc/rc.d"
    INIT="rc.firewall"
elif [ -f /etc/arch-release ] ; then
      DEST="/etc/rc.d"
      INIT="shorewall-lite"
      ARCHLINUX=yes
fi

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

echo "Installing Shorewall Lite Version $VERSION"

#
# Check for /etc/shorewall-lite
#
if [ -z "$PREFIX" -a -d /etc/shorewall-lite ]; then
    first_install=""
    [ -f /etc/shorewall-lite/shorewall.conf ] && \
	mv -f /etc/shorewall-lite/shorewall.conf /etc/shorewall-lite/shorewall-lite.conf
else
    first_install="Yes"
    rm -rf ${PREFIX}/etc/shorewall-lite
    rm -rf ${PREFIX}/usr/share/shorewall-lite
    rm -rf ${PREFIX}/var/lib/shorewall-lite
fi

delete_file ${PREFIX}/usr/share/shorewall-lite/xmodules

install_file shorewall-lite ${PREFIX}/sbin/shorewall-lite 0544 ${PREFIX}/var/lib/shorewall-lite-${VERSION}.bkout

echo "Shorewall Lite control program installed in ${PREFIX}/sbin/shorewall-lite"

#
# Install the Firewall Script
#
if [ -n "$DEBIAN" ]; then
    install_file init.debian.sh /etc/init.d/shorewall-lite 0544 ${PREFIX}/usr/share/shorewall-lite-${VERSION}.bkout
elif [ -n "$ARCHLINUX" ]; then
    install_file init.archlinux.sh ${PREFIX}${DEST}/$INIT 0544 ${PREFIX}/usr/share/shorewall-lite-${VERSION}.bkout

else
    install_file init.sh ${PREFIX}${DEST}/$INIT 0544 ${PREFIX}/usr/share/shorewall-lite-${VERSION}.bkout
fi

echo  "Shorewall Lite script installed in ${PREFIX}${DEST}/$INIT"

#
# Create /etc/shorewall-lite, /usr/share/shorewall-lite and /var/lib/shorewall-lite if needed
#
mkdir -p ${PREFIX}/etc/shorewall-lite
mkdir -p ${PREFIX}/usr/share/shorewall-lite
mkdir -p ${PREFIX}/var/lib/shorewall-lite

chmod 755 ${PREFIX}/etc/shorewall-lite
chmod 755 ${PREFIX}/usr/share/shorewall-lite

if [ -n "$PREFIX" ]; then
    mkdir -p ${PREFIX}/etc/logrotate.d
    chmod 755 ${PREFIX}/etc/logrotate.d
fi

#
# Install the config file
#
if [ ! -f ${PREFIX}/etc/shorewall-lite/shorewall-lite.conf ]; then
   run_install $OWNERSHIP -m 0744 shorewall-lite.conf ${PREFIX}/etc/shorewall-lite/shorewall-lite.conf
   echo "Config file installed as ${PREFIX}/etc/shorewall-lite/shorewall-lite.conf"
fi

if [ -n "$ARCHLINUX" ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${PREFIX}/etc/shorewall-lite/shorewall.conf
fi

#
# Install the  Makefile
#
run_install $OWNERSHIP -m 0600 Makefile ${PREFIX}/etc/shorewall-lite/Makefile
echo "Makefile installed as ${PREFIX}/etc/shorewall-lite/Makefile"

#
# Install the default config path file
#
install_file configpath ${PREFIX}/usr/share/shorewall-lite/configpath 0644
echo "Default config path file installed as ${PREFIX}/usr/share/shorewall-lite/configpath"

#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${PREFIX}/usr/share/shorewall-lite/$f 0644
	echo "Library ${f#*.} file installed as ${PREFIX}/usr/share/shorewall-lite/$f"
    fi
done

ln -sf lib.base ${PREFIX}/usr/share/shorewall-lite/functions

echo "Common functions linked through ${PREFIX}/usr/share/shorewall-lite/functions"

#
# Install Shorecap
#

install_file shorecap ${PREFIX}/usr/share/shorewall-lite/shorecap 0755

echo
echo "Capability file builder installed in ${PREFIX}/usr/share/shorewall-lite/shorecap"

#
# Install wait4ifup
#

install_file wait4ifup ${PREFIX}/usr/share/shorewall-lite/wait4ifup 0755

echo
echo "wait4ifup installed in ${PREFIX}/usr/share/shorewall-lite/wait4ifup"

#
# Install the Modules file
#
run_install $OWNERSHIP -m 0600 modules ${PREFIX}/usr/share/shorewall-lite/modules
echo "Modules file installed as ${PREFIX}/usr/share/shorewall-lite/modules"

#
# Install the Man Pages
#

cd manpages

for f in *.5; do
    gzip -c $f > $f.gz
    run_install -D -m 644 $f.gz ${PREFIX}/usr/share/man/man5/$f.gz
    echo "Man page $f.gz installed to ${PREFIX}/usr/share/man/man5/$f.gz"
done

for f in *.8; do
    gzip -c $f > $f.gz
    run_install -D -m 644 $f.gz ${PREFIX}/usr/share/man/man8/$f.gz
    echo "Man page $f.gz installed to ${PREFIX}/usr/share/man/man8/$f.gz"
done

cd ..

echo "Man Pages Installed"

if [ -d ${PREFIX}/etc/logrotate.d ]; then
    run_install $OWNERSHIP -m 0644 logrotate ${PREFIX}/etc/logrotate.d/shorewall-lite
    echo "Logrotate file installed as ${PREFIX}/etc/logrotate.d/shorewall-lite"
fi


#
# Create the version file
#
echo "$VERSION" > ${PREFIX}/usr/share/shorewall-lite/version
chmod 644 ${PREFIX}/usr/share/shorewall-lite/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$PREFIX" ]; then
    rm -f /usr/share/shorewall-lite/init
    ln -s ${DEST}/${INIT} /usr/share/shorewall-lite/init
fi

if [ -z "$PREFIX" -a -n "$first_install" ]; then
    if [ -n "$DEBIAN" ]; then
	run_install $OWNERSHIP -m 0644 default.debian /etc/default/shorewall-lite
	ln -s ../init.d/shorewall-lite /etc/rcS.d/S40shorewall-lite
	echo "Shorewall Lite will start automatically at boot"
	touch /var/log/shorewall-init.log
    else
	if [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
	    if insserv /etc/init.d/shorewall-lite ; then
		echo "Shorewall Lite will start automatically at boot"
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	    if chkconfig --add shorewall-lite ; then
		echo "Shorewall Lite will start automatically in run levels as follows:"
		chkconfig --list shorewall-lite
	    else
		cant_autostart
	    fi
	elif [ -x /sbin/rc-update ]; then
	    if rc-update add shorewall-lite default; then
		echo "Shorewall Lite will start automatically at boot"
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
echo "shorewall Lite Version $VERSION Installed"
