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

VERSION=4.4.17-Beta1

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
	INIT="shorewall-lite"
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
INSTALLD='-D'
T='-T'

case $(uname) in
    CYGWIN*)
	if [ -z "$DESTDIR" ]; then
	    DEST=
	    INIT=
	fi

	OWNER=$(id -un)
	GROUP=$(id -gn)
	;;
    Darwin)
	INSTALLD=
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
    
    install -d $OWNERSHIP -m 755 ${DESTDIR}/sbin
    install -d $OWNERSHIP -m 755 ${DESTDIR}${DEST}
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
if [ -z "$DESTDIR" -a -d /etc/shorewall-lite ]; then
    [ -f /etc/shorewall-lite/shorewall.conf ] && \
	mv -f /etc/shorewall-lite/shorewall.conf /etc/shorewall-lite/shorewall-lite.conf
else
    rm -rf ${DESTDIR}/etc/shorewall-lite
    rm -rf ${DESTDIR}/usr/share/shorewall-lite
    rm -rf ${DESTDIR}/var/lib/shorewall-lite
fi

#
# Check for /sbin/shorewall-lite
#
if [ -f ${DESTDIR}/sbin/shorewall-lite ]; then
    first_install=""
else
    first_install="Yes"
fi

delete_file ${DESTDIR}/usr/share/shorewall-lite/xmodules

install_file shorewall-lite ${DESTDIR}/sbin/shorewall-lite 0544

echo "Shorewall Lite control program installed in ${DESTDIR}/sbin/shorewall-lite"

#
# Install the Firewall Script
#
if [ -n "$DEBIAN" ]; then
    install_file init.debian.sh /etc/init.d/shorewall-lite 0544
elif [ -n "$ARCHLINUX" ]; then
    install_file init.archlinux.sh ${DESTDIR}${DEST}/$INIT 0544

else
    install_file init.sh ${DESTDIR}${DEST}/$INIT 0544
fi

echo  "Shorewall Lite script installed in ${DESTDIR}${DEST}/$INIT"

#
# Create /etc/shorewall-lite, /usr/share/shorewall-lite and /var/lib/shorewall-lite if needed
#
mkdir -p ${DESTDIR}/etc/shorewall-lite
mkdir -p ${DESTDIR}/usr/share/shorewall-lite
mkdir -p ${DESTDIR}/var/lib/shorewall-lite

chmod 755 ${DESTDIR}/etc/shorewall-lite
chmod 755 ${DESTDIR}/usr/share/shorewall-lite

if [ -n "$DESTDIR" ]; then
    mkdir -p ${DESTDIR}/etc/logrotate.d
    chmod 755 ${DESTDIR}/etc/logrotate.d
fi

#
# Install the config file
#
if [ ! -f ${DESTDIR}/etc/shorewall-lite/shorewall-lite.conf ]; then
   run_install $OWNERSHIP -m 0744 shorewall-lite.conf ${DESTDIR}/etc/shorewall-lite
   echo "Config file installed as ${DESTDIR}/etc/shorewall-lite/shorewall-lite.conf"
fi

if [ -n "$ARCHLINUX" ] ; then
   sed -e 's!LOGFILE=/var/log/messages!LOGFILE=/var/log/messages.log!' -i ${DESTDIR}/etc/shorewall-lite/shorewall.conf
fi

#
# Install the  Makefile
#
run_install $OWNERSHIP -m 0600 Makefile ${DESTDIR}/etc/shorewall-lite
echo "Makefile installed as ${DESTDIR}/etc/shorewall-lite/Makefile"

#
# Install the default config path file
#
install_file configpath ${DESTDIR}/usr/share/shorewall-lite/configpath 0644
echo "Default config path file installed as ${DESTDIR}/usr/share/shorewall-lite/configpath"

#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${DESTDIR}/usr/share/shorewall-lite/$f 0644
	echo "Library ${f#*.} file installed as ${DESTDIR}/usr/share/shorewall-lite/$f"
    fi
done

ln -sf lib.base ${DESTDIR}/usr/share/shorewall-lite/functions

echo "Common functions linked through ${DESTDIR}/usr/share/shorewall-lite/functions"

#
# Install Shorecap
#

install_file shorecap ${DESTDIR}/usr/share/shorewall-lite/shorecap 0755

echo
echo "Capability file builder installed in ${DESTDIR}/usr/share/shorewall-lite/shorecap"

#
# Install wait4ifup
#

if [ -f wait4ifup ]; then
    install_file wait4ifup ${DESTDIR}/usr/share/shorewall-lite/wait4ifup 0755

    echo
    echo "wait4ifup installed in ${DESTDIR}/usr/share/shorewall-lite/wait4ifup"
fi

#
# Install the Modules file
#

if [ -f modules ]; then
    run_install $OWNERSHIP -m 0600 modules ${DESTDIR}/usr/share/shorewall-lite
    echo "Modules file installed as ${DESTDIR}/usr/share/shorewall-lite/modules"
fi

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
    run_install $OWNERSHIP -m 0644 logrotate ${DESTDIR}/etc/logrotate.d/shorewall-lite
    echo "Logrotate file installed as ${DESTDIR}/etc/logrotate.d/shorewall-lite"
fi


#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}/usr/share/shorewall-lite/version
chmod 644 ${DESTDIR}/usr/share/shorewall-lite/version
#
# Remove and create the symbolic link to the init script
#

if [ -z "$DESTDIR" ]; then
    rm -f /usr/share/shorewall-lite/init
    ln -s ${DEST}/${INIT} /usr/share/shorewall-lite/init
fi

if [ -z "$DESTDIR" ]; then
    touch /var/log/shorewall-lite-init.log

    if [ -n "$first_install" ]; then
	if [ -n "$DEBIAN" ]; then
	    run_install $OWNERSHIP -m 0644 default.debian /etc/default/shorewall-lite

	    update-rc.d shorewall-lite defaults

	    if [ -x /sbin/insserv ]; then
		insserv /etc/init.d/shorewall-lite
	    else
		ln -s ../init.d/shorewall-lite /etc/rcS.d/S40shorewall-lite
	    fi

	    echo "Shorewall Lite will start automatically at boot"
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
fi

#
#  Report Success
#
echo "shorewall Lite Version $VERSION Installed"
