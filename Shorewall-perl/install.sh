#!/bin/sh
#
# Script to install Shorewall-perl.
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2007 - Tom Eastep (teastep@shorewall.net)
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
#       Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#

VERSION=4.0.0-Beta5

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
    local ifs=$IFS
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
	INIT="shorewall"
fi

if [ -z "$RUNLEVELS" ] ; then
	RUNLEVELS=""
fi

if [ -z "$OWNER" ] ; then
	OWNER=root
fi

if [ -z "$GROUP" ] ; then
	GROUP=root
fi

NOBACKUP=

while [ $# -gt 0 ] ; do
    case "$1" in
	-h|help|?)
	    usage 0
	    ;;
        -v)
	    echo "Shorewall-perl Installer Version $VERSION"
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

OWNERSHIP="-o $OWNER -g $GROUP"

if [ -n "$PREFIX" ]; then
	if [ `id -u` != 0 ] ; then
	    echo "Not setting file owner/group permissions, not running as root."
	    OWNERSHIP=""
	fi

	install -d $OWNERSHIP -m 755 ${PREFIX}/sbin
	install -d $OWNERSHIP -m 755 ${PREFIX}${DEST}
fi

#
# Change to the directory containing this script
#
cd "$(dirname $0)"

echo "Installing Shorewall-perl Version $VERSION"

#
# /usr/share/shorewall-perl if needed
#
mkdir -p ${PREFIX}/usr/share/shorewall-perl/Shorewall

chmod 755 ${PREFIX}/usr/share/shorewall-perl
chmod 755 ${PREFIX}/usr/share/shorewall-perl/Shorewall

#
# Install the Compiler
#

install_file compiler.pl ${PREFIX}/usr/share/shorewall-perl/compiler.pl 0555

echo
echo "Compiler installed in ${PREFIX}/usr/share/shorewall-perl/compiler.pl"

#
# Install the libraries
#
for f in Shorewall/*.pm ; do
    install_file $f ${PREFIX}/usr/share/shorewall-perl/$f 0644
    echo "Library ${f%.*} file installed as ${PREFIX}/usr/share/shorewall-perl/$f"
done

#
# Install the program skeleton files
#
for f in prog.* ; do
    install_file $f ${PREFIX}/usr/share/shorewall-perl/$f 0644
    echo "Program skeleton file ${f#*.} installed as ${PREFIX}/usr/share/shorewall-perl/$f"
done

echo $VERSION > ${PREFIX}/usr/share/shorewall-perl/version
#
#  Report Success
#
echo "Shorewall-perl Version $VERSION Installed"
