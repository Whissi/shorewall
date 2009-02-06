#!/bin/sh
#
# Script to install Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000,2001,2002,2003,2004,2005 - Tom Eastep (teastep@shorewall.net)
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

VERSION=4.3.6

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME"
    echo "       $ME -v"
    echo "       $ME -h"
    echo "       $ME -n"
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

backup_directory() # $1 = directory to backup
{
    if [ -d $1 ]; then
	if cp -a $1  ${1}-${VERSION}.bkout ; then
	    echo
	    echo "$1 saved to ${1}-${VERSION}.bkout"
	else
	    exit 1
	fi
    fi
}

backup_file() # $1 = file to backup, $2 = (optional) Directory in which to create the backup
{
    if [ -z "${PREFIX}{NOBACKUP}" ]; then
	if [ -f $1 -a ! -f ${1}-${VERSION}.bkout ]; then
	    if [ -n "$2" ]; then
		if [ -d $2 ]; then
		    if cp -f $1 $2 ; then
			echo
			echo "$1 saved to $2/$(basename $1)"
		    else
			exit 1
		    fi
		fi
	    elif cp $1 ${1}-${VERSION}.bkout; then
		echo
		echo "$1 saved to ${1}-${VERSION}.bkout"
	    else
		exit 1
	    fi
	fi
    fi
}

delete_file() # $1 = file to delete
{
    rm -f $1
}

install_file() # $1 = source $2 = target $3 = mode
{
    run_install $OWNERSHIP -m $3 $1 ${2}
}

install_file_with_backup() # $1 = source $2 = target $3 = mode $4 = (optional) backup directory
{
    backup_file $2 $4
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
	INIT="shorewall"
fi

if [ -z "$RUNLEVELS" ] ; then
	RUNLEVELS=""
fi

case $(uname) in
    CYGWIN*)
	DEST=
	INIT=
	[ -z "$OWNER" ] && OWNER=$(id -un)
	[ -z "$GROUP" ] && GROUP=$(id -gn)
	;;
    *)
	[ -z "$OWNER" ] && OWNER=root
	[ -z "$GROUP" ] && GROUP=root
	;;
esac

NOBACKUP=

while [ $# -gt 0 ] ; do
    case "$1" in
	-h|help|?)
	    usage 0
	    ;;
        -v)
	    echo "Shorewall Firewall Installer Version $VERSION"
	    exit 0
	    ;;
	-n)
	    NOBACKUP=Yes
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

OWNERSHIP="-o $OWNER -g $GROUP"

if [ -n "$PREFIX" ]; then
    if [ `id -u` != 0 ] ; then
	echo "Not setting file owner/group permissions, not running as root."
	OWNERSHIP=""
    fi
fi

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

echo "Installing Shorewall-shell Version $VERSION"

#
# Check for /usr/share/shorewall-shell
#
if [ -d ${PREFIX}/usr/share/shorewall-shell ]; then
    first_install=""
    if [ -z "$NOBACKUP" ]; then
	backup_directory ${PREFIX}/usr/share/shorewall-shell
    fi
else
    first_install="Yes"
fi

#
# Create /etc/shorewall, /usr/share/shorewall-shell and /var/shorewall if needed
#
mkdir -p ${PREFIX}/usr/share/shorewall-shell

chmod 755 ${PREFIX}/usr/share/shorewall-shell

#
# Install the Compiler
#

install_file compiler ${PREFIX}/usr/share/shorewall-shell/compiler 0755

echo
echo "Compiler installed in ${PREFIX}/usr/share/shorewall-shell/compiler"

#
#
# Install the libraries
#
for f in lib.* ; do
    if [ -f $f ]; then
	install_file $f ${PREFIX}/usr/share/shorewall-shell/$f 0644
	echo "Library ${f#*.} file installed as ${PREFIX}/usr/share/shorewall-shell/$f"
    fi
done

#
# Install the program skeleton files
#
for f in prog.* ; do
    install_file $f ${PREFIX}/usr/share/shorewall-shell/$f 0644
    echo "Program skeleton file ${f#*.} installed as ${PREFIX}/usr/share/shorewall-shell/$f"
done

echo $VERSION > ${PREFIX}/usr/share/shorewall-shell/version
#
#  Report Success
#
echo "shorewall-shell Version $VERSION Installed"
