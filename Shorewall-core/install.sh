#!/bin/sh
#
# Script to install Shoreline Firewall Core Modules
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
# ARGS is "yes" if we've already parsed an argument
#
T="-T"

[ -n "${LIBEXEC:=/usr/share}" ]
[ -n "${PERLLIB:=/usr/share/shorewall}" ]
MACHOST=

case "$LIBEXEC" in
    /*)
	;;
    *)
	LIBEXEC=/usr/${LIBEXEC}
	;;
esac

case "$PERLLIB" in
    /*)
	;;
    *)
	PERLLIB=/usr/${PERLLIB}
	;;
esac

INSTALLD='-D'

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
		if [ -d /etc/sysconfig/network-scripts/ ]; then
		    BUILD=REDHAT
		else
		    BUILD=FEDORA
		fi
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
	if [ -z "$DESTDIR" ]; then
	    DEST=
	    INIT=
	fi

	OWNER=$(id -un)
	GROUP=$(id -gn)
	;;
    MAC)
	if [ -z "$DESTDIR" ]; then
	    DEST=
	    INIT=
	    SPARSE=Yes
	fi

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
			echo "Shorewall Firewall Installer Version $VERSION"
			exit 0
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

[ -n "$HOST" ] || HOST=$BUILD

case "$HOST" in
    CYGWIN)
	echo "Installing Cygwin-specific configuration..."
	;;
    MAC)
	echo "Installing Mac-specific configuration...";
	;;
    DEBIAN)
	echo "Installing Debian-specific configuration..."
	SPARSE=yes
	;;
    FEDORA|REDHAT|SLACKWARE|ARCHLINUX|LINUX)
	;;
    *)
	echo "ERROR: Unknown HOST \"$HOST\"" >&2
	exit 1;
	;;
esac

if [ -n "$DESTDIR" ]; then
    if [ $BUILD != CYGWIN ]; then
	if [ `id -u` != 0 ] ; then
	    echo "Not setting file owner/group permissions, not running as root."
	    OWNERSHIP=""
	fi
    fi
fi

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

echo "Installing Shorewall Core Version $VERSION"

#
# Create /usr/share/shorewall
#
mkdir -p ${DESTDIR}${LIBEXEC}/shorewall
chmod 755 ${DESTDIR}/usr/share/shorewall
#
# Install wait4ifup
#
install_file wait4ifup ${DESTDIR}${LIBEXEC}/shorewall/wait4ifup 0755

echo
echo "wait4ifup installed in ${DESTDIR}${LIBEXEC}/shorewall/wait4ifup"

#
# Install the libraries
#
for f in lib.* ; do
    install_file $f ${DESTDIR}/usr/share/shorewall/$f 0644
    echo "Library ${f#*.} file installed as ${DESTDIR}/usr/share/shorewall/$f"
done

if [ -z "$MACHOST" ]; then
    eval sed -i \'s\|g_libexec=.\*\|g_libexec=$LIBEXEC\|\' ${DESTDIR}/usr/share/shorewall/lib.cli
    eval sed -i \'s\|g_perllib=.\*\|g_perllib=$PERLLIB\|\' ${DESTDIR}/usr/share/shorewall/lib.cli
else
    eval sed -i \'\' -e \'s\|g_libexec=.\*\|g_libexec=$LIBEXEC\|\' ${DESTDIR}/usr/share/shorewall/lib.cli
    eval sed -i \'\' -e \'s\|g_perllib=.\*\|g_perllib=$PERLLIB\|\' ${DESTDIR}/usr/share/shorewall/lib.cli
fi

#
# Symbolically link 'functions' to lib.base
#
ln -sf lib.base ${DESTDIR}/usr/share/shorewall/functions
#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}/usr/share/shorewall/coreversion
chmod 644 ${DESTDIR}/usr/share/shorewall/coreversion
#
#  Report Success
#
echo "Shorewall Core Version $VERSION Installed"
