#!/bin/sh
#
# Script to back uninstall Shoreline Firewall 6
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2000,2001,2002,2003,2004,2005,2008,2009,2010 - Tom Eastep (teastep@shorewall.net)
#
#       Shorewall documentation is available at http://www.shorewall.net
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
#    Usage:
#
#       You may only use this script to uninstall the version
#       shown below. Simply run this script to remove Shorewall Firewall

VERSION=4.4.19-Beta1

usage() # $1 = exit status
{
    ME=$(basename $0)
    echo "usage: $ME"
    exit $1
}

qt()
{
    "$@" >/dev/null 2>&1
}

restore_file() # $1 = file to restore
{
    if [ -f ${1}-shorewall.bkout ]; then
	if (mv -f ${1}-shorewall.bkout $1); then
	    echo
	    echo "$1 restored"
        else
	    exit 1
        fi
    fi
}

remove_file() # $1 = file to restore
{
    if [ -f $1 -o -L $1 ] ; then
	rm -f $1
	echo "$1 Removed"
    fi
}

if [ -n "$BASE" ]; then
    if [ -n "$DESTDIR" ]; then
	echo "   ERROR: DESTDIR and BASE may not be specified together" >&2
	exit 1
    fi

    case "$BASE" in
	/*)
	    ;;
	*)
	    echo "   ERROR: BASE must contain an absolute path name" >&2
	    exit 1;
	    ;;
    esac

    mkdir -p "$BASE"

    [ -n ${ETC:=${BASE}/etc/} ]
    [ -n ${SBIN:=${BASE}/sbin/} ]
    [ -n ${SHARE:=${BASE}/share/} ]
    [ -n ${VAR:=${BASE}/var/lib/} ]
    [ -n ${MANDIR:=${BASE}/share/man} ]
else
    [ -n ${ETC:=/etc/} ]
    [ -n ${SBIN:=/sbin/} ]
    [ -n ${SHARE:=/usr/share/} ]
    [ -n ${VAR:=/var/lib/} ]
    [ -n ${MANDIR:=/usr/share/man} ]
fi


case "$ETC" in
    /*/)
	;;
    /*)
	ETC=$ETC/
	;;
    *)
	if [ -n "$BASE" ]; THEN
	    ETC=$BASE/$ETC/
	else
	    echo "ERROR: ETC must contain an absolute path name" >&2
	    exit 1
	fi
	;;
esac

case "$SBIN" in
    /*/)
	;;
    /*)
	SBIN=$SBIN/
	;;
    *)
	if [ -n "$BASE" ]; THEN
	    SBIN=$BASE/$SBIN/
	else
	    echo "ERROR: SBIN must contain an absolute path name" >&2
	    exit 1
	fi
	;;
esac

case "$SHARE" in
    /*/)
	;;
    /*)
	SHARE=$SHARE/
	;;
    *)
	if [ -n "$BASE" ]; THEN
	    SHARE=$BASE/$SHARE/
	else
	    echo "ERROR: SHARE must contain an absolute path name" >&2
	    exit 1
	fi
	;;
esac

case "$VAR" in
    /*/)
	;;
    /*)
	VAR=$VAR/
	;;
    *)
	if [ -n "$BASE" ]; THEN
	    VAR=$BASE/$VAR/
	else
	    echo "ERROR: VAR must contain an absolute path name" >&2
	    exit 1
	fi
	;;
esac

if [ -f ${SHARE}shorewall6/version ]; then
    INSTALLED_VERSION="$(cat ${SHARE}shorewall6/version)"
    if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
	echo "WARNING: Shorewall6 Version $INSTALLED_VERSION is installed"
	echo "         and this is the $VERSION uninstaller."
	VERSION="$INSTALLED_VERSION"
    fi
else
    echo "WARNING: Shorewall6 Version $VERSION is not installed"
    VERSION=""
fi

echo "Uninstalling shorewall6 $VERSION"

if [ `id -u` = 0 ] ; then
    if qt ip6tables -L shorewall6 -n && [ ! -f ${SBIN}shorewall6-lite ]; then
	${SBIN}shorewall6 clear
    fi

    if [ -L ${SHARE}shorewall6/init ]; then
	FIREWALL=$(readlink -m -q ${SHARE}shorewall6/init)
    else
	FIREWALL=${ETC}init.d/shorewall6
    fi

    if [ -n "$FIREWALL" ]; then
	if [ -x /usr${SBIN}updaterc.d ]; then
	    updaterc.d shorewall6 remove
	elif [ -x ${SBIN}insserv -o -x /usr${SBIN}insserv ]; then
            insserv -r $FIREWALL
	elif [ -x ${SBIN}chkconfig -o -x /usr${SBIN}chkconfig ]; then
	    chkconfig --del $(basename $FIREWALL)
	else
	    rm -f ${ETC}rc*.d/*$(basename $FIREWALL)
	fi

	remove_file $FIREWALL
	rm -f ${FIREWALL}-*.bkout
    fi
fi

rm -f ${SBIN}shorewall6
rm -f ${SBIN}shorewall6-*.bkout

rm -rf ${ETC}shorewall6
rm -rf ${ETC}shorewall6-*.bkout
rm -rf ${VAR}/shorewall6
rm -rf ${VAR}/shorewall6-*.bkout
rm -rf ${SHARE}shorewall6
rm -rf ${SHARE}shorewall6-*.bkout
rm -rf ${SHARE}man/man5/shorewall6*
rm -rf ${SHARE}man/man8/shorewall6*
rm -f  ${ETC}logrotate.d/shorewall6

echo "Shorewall6 Uninstalled"


