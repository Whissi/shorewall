#!/bin/sh
#
# Script to install Shoreline Firewall Core Modules
#
#     (c) 2000-2011,2014 - Tom Eastep (teastep@shorewall.net)
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

VERSION=xxx #The Build script inserts the actual version

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME [ <configuration-file> ] "
    echo "       $ME -v"
    echo "       $ME -h"
    exit $1
}

fatal_error()
{
    echo "   ERROR: $@" >&2
    exit 1
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

require()
{
    eval [ -n "\$$1" ] || fatal_error "Required option $1 not set"
}

cd "$(dirname $0)"

#
# Parse the run line
#
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
	    finished=1
	    ;;
    esac
done

#
# Read the RC file
#
if [ $# -eq 0 ]; then
    if [ -f ./shorewallrc ]; then
	. ./shorewallrc
	file=./shorewallrc
    elif [ -f ~/.shorewallrc ]; then
	. ~/.shorewallrc || exit 1
	file=~/.shorewallrc
    elif [ -f /usr/share/shorewall/shorewallrc ]; then
	. /usr/share/shorewall/shorewallrc
	file=/usr/share/shorewall/shorewallrc
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

    . $file
else
    usage 1
fi

update=0

if [ -z "${VARLIB}" ]; then
    VARLIB=${VARDIR}
    VARDIR="${VARLIB}/${PRODUCT}"
    update=1
elif [ -z "${VARDIR}" ]; then
    VARDIR="${VARLIB}/${PRODUCT}"
    update=2
fi

for var in SHAREDIR LIBEXECDIR PERLLIBDIR CONFDIR SBINDIR VARLIB VARDIR; do
    require $var
done

[ "${INITFILE}" != 'none/' ] && require INITSOURCE && require INITDIR

T="-T"

INSTALLD='-D'

if [ -z "$BUILD" ]; then
    case $(uname) in
	cygwin*|CYGWIN*)
	    BUILD=cygwin
	    ;;
	Darwin)
	    BUILD=apple
	    ;;
	*)
	    if [ -f /etc/os-release ]; then
		eval $(cat /etc/os-release | grep ^ID)

		case $ID in
		    fedora|rhel|centos|foobar)
			BUILD=redhat
			;;
		    debian)
			BUILD=debian
			;;
		    gentoo)
			BUILD=gentoo
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
	    elif [ -f /etc/gentoo-release ]; then
		BUILD=gentoo
	    elif [ -f /etc/redhat-release ]; then
		BUILD=redhat
	    elif [ -f /etc/slackware-version ] ; then
		BUILD=slackware
	    elif [ -f /etc/SuSE-release ]; then
		BUILD=suse
	    elif [ -f /etc/arch-release ] ; then
		BUILD=archlinux
	    else
		BUILD=linux
	    fi
	    ;;
    esac
fi

case $BUILD in
    cygwin*)
	if [ -z "$DESTDIR" ]; then
	    DEST=
	    INIT=
	fi

	OWNER=$(id -un)
	GROUP=$(id -gn)
	;;
    apple)
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

#
# Determine where to install the firewall script
#

[ -n "$HOST" ] || HOST=$BUILD

case "$HOST" in
    cygwin)
	echo "Installing Cygwin-specific configuration..."
	;;
    apple)
	echo "Installing Mac-specific configuration...";
	;;
    debian|gentoo|redhat|slackware|archlinux|linux|suse)
	;;
    *)
	echo "ERROR: Unknown HOST \"$HOST\"" >&2
	exit 1;
	;;
esac

if [ -z "$file" ]; then
    if $HOST = linux; then
	file=shorewallrc.default
    else
	file=shorewallrc.${HOST}
    fi

    echo "You have not specified a configuration file and ~/.shorewallrc does not exist" >&2
    echo "Shorewall-core $VERSION has determined that the $file configuration is appropriate for your system" >&2
    echo "Please review the settings in that file. If you wish to change them, make a copy and modify the copy" >&2
    echo "Then re-run install.sh passing either $file or the name of your modified copy" >&2
    echo "" >&2
    echo "Example:" >&2
    echo "" >&2
    echo "   ./install.sh $file" &>2
fi

if [ -n "$DESTDIR" ]; then
    if [ $BUILD != cygwin ]; then
	if [ `id -u` != 0 ] ; then
	    echo "Not setting file owner/group permissions, not running as root."
	    OWNERSHIP=""
	fi
    fi
fi

echo "Installing Shorewall Core Version $VERSION"

#
# Create directories
#
mkdir -p ${DESTDIR}${LIBEXECDIR}/shorewall
chmod 755 ${DESTDIR}${LIBEXECDIR}/shorewall

mkdir -p ${DESTDIR}${SHAREDIR}/shorewall
chmod 755 ${DESTDIR}${SHAREDIR}/shorewall

mkdir -p ${DESTDIR}${CONFDIR}
chmod 755 ${DESTDIR}${CONFDIR}

if [ -n "${SYSCONFDIR}" ]; then
    mkdir -p ${DESTDIR}${SYSCONFDIR}
    chmod 755 ${DESTDIR}${SYSCONFDIR}
fi

if [ -z "${SERVICEDIR}" ]; then
    SERVICEDIR="$SYSTEMD"
fi

if [ -n "${SERVICEDIR}" ]; then
    mkdir -p ${DESTDIR}${SERVICEDIR}
    chmod 755 ${DESTDIR}${SERVICEDIR}
fi

mkdir -p ${DESTDIR}${SBINDIR}
chmod 755 ${DESTDIR}${SBINDIR}

mkdir -p ${DESTDIR}${MANDIR}
chmod 755 ${DESTDIR}${MANDIR}

if [ -n "${INITFILE}" ]; then
    mkdir -p ${DESTDIR}${INITDIR}
    chmod 755 ${DESTDIR}${INITDIR}

    if [ -n "$AUXINITSOURCE" -a -f "$AUXINITSOURCE" ]; then
	install_file $AUXINITSOURCE ${DESTDIR}${INITDIR}/$AUXINITFILE 0544
	[ "${SHAREDIR}" = /usr/share ] || eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}${INITDIR}/$AUXINITFILE
	echo  "SysV init script $AUXINITSOURCE installed in ${DESTDIR}${INITDIR}/$AUXINITFILE"
    fi
fi
#
# Note: ${VARDIR} is created at run-time since it has always been
#       a relocatable directory on a per-product basis
#
# Install wait4ifup
#
install_file wait4ifup ${DESTDIR}${LIBEXECDIR}/shorewall/wait4ifup 0755

echo
echo "wait4ifup installed in ${DESTDIR}${LIBEXECDIR}/shorewall/wait4ifup"

#
# Install the libraries
#
for f in lib.* ; do
    install_file $f ${DESTDIR}${SHAREDIR}/shorewall/$f 0644
    echo "Library ${f#*.} file installed as ${DESTDIR}${SHAREDIR}/shorewall/$f"
done

#
# Symbolically link 'functions' to lib.base
#
ln -sf lib.base ${DESTDIR}${SHAREDIR}/shorewall/functions
#
# Create the version file
#
echo "$VERSION" > ${DESTDIR}${SHAREDIR}/shorewall/coreversion
chmod 644 ${DESTDIR}${SHAREDIR}/shorewall/coreversion

if [ -z "${DESTDIR}" ]; then
    if [ $update -ne 0 ]; then
	echo "Updating $file - original saved in $file.bak"

	cp $file $file.bak

	echo '#'                                             >> $file
	echo "# Updated by Shorewall-core $VERSION -" `date` >> $file
	echo '#'                                             >> $file

	[ $update -eq 1 ] && sed -i 's/VARDIR/VARLIB/' $file

	echo 'VARDIR=${VARLIB}/${PRODUCT}' >> $file
    fi
fi

[ $file != "${DESTDIR}${SHAREDIR}/shorewall/shorewallrc" ] && cp $file ${DESTDIR}${SHAREDIR}/shorewall/shorewallrc


[ -z "${DESTDIR}" ] && [ ! -f ~/.shorewallrc ] && cp ${SHAREDIR}/shorewall/shorewallrc ~/.shorewallrc

if [ ${SHAREDIR} != /usr/share ]; then
    for f in lib.*; do
	if [ $BUILD != apple ]; then
	    eval sed -i \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}/${SHAREDIR}/shorewall/$f
	else
	    eval sed -i \'\' -e \'s\|/usr/share/\|${SHAREDIR}/\|\' ${DESTDIR}/${SHAREDIR}/shorewall/$f
	fi
    done
fi
#
#  Report Success
#
echo "Shorewall Core Version $VERSION Installed"
