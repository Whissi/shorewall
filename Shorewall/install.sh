#!/bin/sh
#
# Script to install Shoreline Firewall
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]         
#
#     (c) 2000,2001,2002 - Tom Eastep (teastep@shorewall.net)
#
#       Seawall documentation is available at http://seawall.sourceforge.net
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
#    Usage:
#
#        If you are running a distribution that has a directory called /etc/rc.d/init.d or one
#        called /etc/init.d or you are running Slackware then simply cd to the directory 
#        containing this script and run it.
#
#            ./install.sh
#
#        If you don't have either of those directories, you will need to determine where the
#        SysVInit scripts are kept on your system and pass the name of that directory.
#
#            ./install.sh /etc/rc.d/scripts
#
#        The default is that the firewall will be started in run levels 2-5 starting at
#        position 15 and stopping at position 90. This is correct RedHat/Mandrake, Debian, 
#        Caldera and Corel.
#
#        If you wish to change that, you can pass -r "<levels startpos stoppos>".
#
#        Example 1: You wish to start your firewall in runlevels 2 and three, start at position
#                   15 and stop at position 90
#
#            ./install.sh -r "23 15 90"
#
#       Example 2: You wish to start your firewall only in run level 3, start at position 5 
#                  and stop at position 95.
#
#            ./install.sh -r "3 5 95" /etc/rc.d/scripts
#
#        For distributions that don't include chkconfig (Slackware, for example), the
#        /etc/rc.d/rc.local file is modified to start the firewall.
#

VERSION=1.3.5

usage() # $1 = exit status
{
    ME=`basename $0`
    echo "usage: $ME [ -r \"<chkconfig parameters>\" ] [ <init scripts directory> ]"
    echo "       $ME [ -v ]"
    echo "       $ME [ -h ]"
    exit $1
}

run_install()
{
    if ! install $*; then
	echo -e "\nERROR: Failed to install $*"
	exit 1
    fi
}

cant_autostart()
{
    echo -e "\nWARNING: Unable to configure Shorewall to start"
echo    "           automatically at boot"
}

backup_file() # $1 = file to backup
{
    if [ -z "$PREFIX" -a -f $1 -a ! -f ${1}-${VERSION}.bkout ]; then
	if (cp $1 ${1}-${VERSION}.bkout); then
	    echo
	    echo "$1 saved to ${1}-${VERSION}.bkout"
        else
	    exit 1
        fi
    fi
}

modify_rclocal()
{
    if [ -f /etc/rc.d/rc.local ]; then
	if [ -z "`grep shorewall /etc/rc.d/rc.local`" ]; then
	    cp -f /etc/rc.d/rc.local /etc/rc.d/rc.local-shorewall.bkout
	    echo >> /etc/rc.d/rc.local
	    echo "/sbin/shorewall start" >> /etc/rc.d/rc.local
	    echo "/etc/rc.d/rc.local modified to start Shorewall"
	fi
    else
	cant_autostart
    fi	
}

install_file_with_backup() # $1 = source $2 = target $3 = mode
{    
    backup_file $2
    run_install -o $OWNER -g $GROUP -m $3 $1 ${2}
}

#
# Parse the run line
#
# DEST is the SysVInit script directory
# RUNLEVELS is the chkconfig parmeters for firewall
# ARGS is "yes" if we've already parsed an argument
#
DEST=""
RUNLEVELS=""
ARGS=""

if [ -z "$OWNER" ] ; then
	OWNER=root
fi

if [ -z "$GROUP" ] ; then
	GROUP=root
fi

while [ $# -gt 0 ] ; do
    case "$1" in
	-h|help|?)
	    if [ -n "$ARGS" ]; then
		usage 1
            fi

	    usage 0
	    ;;
	-r)
	    if [ -n "$RUNLEVELS" -o $# -eq 1 ]; then
		usage 1
	    fi

	    RUNLEVELS="$2";
	    shift
	    ;;
        -v)
	    if [ -n "$ARGS" ]; then
		usage 1
            fi

	    echo "Shorewall Firewall Installer Version $VERSION"
	    exit 0
	    ;;
	*)
	    if [ -n "$DEST" ]; then
		usage 1
            fi

	    DEST="$1"
	    ;;
    esac
    shift
    ARGS="yes"
done
    
#
# Determine where to install the firewall script
#
if [ -n "$PREFIX" ]; then
	install -d -o $OWNER -g $GROUP -m 755 ${PREFIX}/sbin
	install -d -o $OWNER -g $GROUP -m 755 ${PREFIX}${DEST}
fi

FIREWALL="shorewall"

if [ -z "$DEST" ]; then
    #
    # We make this first test so that on RedHat systems that have Seawall installed,
    # we can still use PREFIX (the code that reads the existing symbolic link
    # fails dreadfully if the link is relative and PREFIX is non-null).
    #
    if [ -x /etc/rc.d/init.d/firewall ]; then
	DEST=/etc/rc.d/init.d
    elif [ -L /etc/shorewall/firewall ]; then
	TEMP=`ls -l /etc/shorewall/firewall | sed 's/^.*> //'`
	DEST=`dirname $TEMP`
	FIREWALL=`basename $TEMP`
    elif [ -d /etc/rc.d/init.d ]; then
	DEST=/etc/rc.d/init.d
    elif [ -d /etc/init.d ]; then
	DEST=/etc/init.d
    elif [ -f /etc/rc.d/rc.local ]; then
	DEST=/etc/rc.d
	FIREWALL="rc.shorewall"
    else
	echo "ERROR: Can't determine where to install the firewall script"
	echo "       Rerun $0 passing the name of the SysVInit script directory"
	echo "       on your system"
	exit 1
    fi
fi

#
# Change to the directory containing this script
#
cd "`dirname $0`"
    
echo "Installing Shorewall Version $VERSION"

#
# Check for /etc/shorewall
#
if [ -d ${PREFIX}/etc/shorewall ]; then
    first_install=""
else
    first_install="Yes"
fi

install_file_with_backup shorewall ${PREFIX}/sbin/shorewall 0544

echo -e "\nShorewall control program installed in ${PREFIX}/sbin/shorewall"

#
# Install the Firewall Script
#
if [ -n "$RUNLEVELS" ]; then
    #
    # User specified chkconfig parameters -- build an awk script to install them
    # in the firewall script
    #
    echo "/# chkconfig/ { print \"# chkconfig: $RUNLEVELS\" ; next }" > awk.temp
    echo "{ print }" >> awk.temp

    awk -f awk.temp firewall > firewall.temp

    if [ $? -ne 0 ]; then
	echo -e "\nERROR: Error running awk."
	echo    "         You must run `basename $0` without the "-r" option then edit"
	echo    "         $DEST/$FIREWALL  manually (line beginning '# chkconfig:')"
	exit 1
    fi

    install_file_with_backup firewall.temp ${PREFIX}${DEST}/$FIREWALL 0544
    
    rm -f firewall.temp awk.tmp
else
    install_file_with_backup firewall ${PREFIX}${DEST}/$FIREWALL 0544
fi
    
echo -e "\nShorewall script installed in ${PREFIX}${DEST}/$FIREWALL"

#
# Create /etc/shorewall and /var/shorewall if needed
#
mkdir -p ${PREFIX}/etc/shorewall
mkdir -p ${PREFIX}/var/lib/shorewall
#
# Install the config file
#
if [ -f ${PREFIX}/etc/shorewall/shorewall.conf ]; then
   backup_file /etc/shorewall/shorewall.conf
else
   run_install -o $OWNER -g $GROUP -m 0744 shorewall.conf ${PREFIX}/etc/shorewall/shorewall.conf
   echo -e "\nConfig file installed as ${PREFIX}/etc/shorewall/shorewall.conf"
fi
#
# Install the zones file
#
if [ -f ${PREFIX}/etc/shorewall/zones ]; then
    backup_file /etc/shorewall/zones
else
    run_install -o $OWNER -g $GROUP -m 0744 zones ${PREFIX}/etc/shorewall/zones
    echo -e "\nZones file installed as ${PREFIX}/etc/shorewall/policy"
fi

#
# Install the functions file
#
install_file_with_backup functions ${PREFIX}/var/lib/shorewall/functions 0444

echo -e "\nCommon functions installed in ${PREFIX}/var/lib/shorewall/functions"
#
# Install the common.def file
#
install_file_with_backup common.def ${PREFIX}/etc/shorewall/common.def 0444

echo -e "\nCommon rules installed in ${PREFIX}/etc/shorewall/common.def"
#
# Install the icmp.def file
#
install_file_with_backup icmp.def ${PREFIX}/etc/shorewall/icmp.def 0444

echo -e "\nCommon ICMP rules installed in ${PREFIX}/etc/shorewall/icmp.def"

#
# Install the policy file
#
if [ -f ${PREFIX}/etc/shorewall/policy ]; then
    backup_file /etc/shorewall/policy
else
    run_install -o $OWNER -g $GROUP -m 0600 policy ${PREFIX}/etc/shorewall/policy
    echo -e "\nPolicy file installed as ${PREFIX}/etc/shorewall/policy"
fi
#
# Install the interfaces file
#
if [ -f ${PREFIX}/etc/shorewall/interfaces ]; then
    backup_file /etc/shorewall/interfaces
else
    run_install -o $OWNER -g $GROUP -m 0600 interfaces ${PREFIX}/etc/shorewall/interfaces
    echo -e "\nInterfaces file installed as ${PREFIX}/etc/shorewall/interfaces"
fi
#
# Install the hosts file
#
if [ -f ${PREFIX}/etc/shorewall/hosts ]; then
    backup_file /etc/shorewall/hosts
else
    run_install -o $OWNER -g $GROUP -m 0600 hosts ${PREFIX}/etc/shorewall/hosts
    echo -e "\nHosts file installed as ${PREFIX}/etc/shorewall/hosts"
fi
#
# Install the rules file
#
if [ -f ${PREFIX}/etc/shorewall/rules ]; then
    backup_file /etc/shorewall/rules
else
    run_install -o $OWNER -g $GROUP -m 0600 rules ${PREFIX}/etc/shorewall/rules
    echo -e "\nRules file installed as ${PREFIX}/etc/shorewall/rules"
fi
#
# Install the NAT file
#
if [ -f ${PREFIX}/etc/shorewall/nat ]; then
    backup_file /etc/shorewall/nat
else
    run_install -o $OWNER -g $GROUP -m 0600 nat ${PREFIX}/etc/shorewall/nat
    echo -e "\nNAT file installed as ${PREFIX}/etc/shorewall/nat"
fi
# 
# Install the Parameters file
#
if [ -f ${PREFIX}/etc/shorewall/params ]; then
    backup_file /etc/shorewall/params
else
    run_install -o $OWNER -g $GROUP -m 0600 params ${PREFIX}/etc/shorewall/params   
    echo -e "\nParameter file installed as ${PREFIX}/etc/shorewall/params"
fi
#
# Install the proxy ARP file
#
if [ -f ${PREFIX}/etc/shorewall/proxyarp ]; then
    backup_file /etc/shorewall/proxyarp
else
    run_install -o $OWNER -g $GROUP -m 0600 proxyarp ${PREFIX}/etc/shorewall/proxyarp
    echo -e "\nProxy ARP file installed as ${PREFIX}/etc/shorewall/proxyarp"
fi
#
# Install the Stopped Routing file
#
if [ -f ${PREFIX}/etc/shorewall/routestopped ]; then
    backup_file /etc/shorewall/routestopped
else
    run_install -o $OWNER -g $GROUP -m 0600 routestopped ${PREFIX}/etc/shorewall/routestopped
    echo -e "\nStopped Routing file installed as ${PREFIX}/etc/shorewall/routestopped"
fi
#
# Install the Masq file
#
if [ -f ${PREFIX}/etc/shorewall/masq ]; then
    backup_file /etc/shorewall/masq
else
    run_install -o $OWNER -g $GROUP -m 0600 masq ${PREFIX}/etc/shorewall/masq
    echo -e "\nMasquerade file installed as ${PREFIX}/etc/shorewall/masq"
fi
#
# Install the Modules file
#
if [ -f ${PREFIX}/etc/shorewall/modules ]; then
    backup_file /etc/shorewall/modules
else
    run_install -o $OWNER -g $GROUP -m 0600 modules ${PREFIX}/etc/shorewall/modules
    echo -e "\nModules file installed as ${PREFIX}/etc/shorewall/modules"
fi
#
# Install the TC Rules file
#
if [ -f ${PREFIX}/etc/shorewall/tcrules ]; then
    backup_file /etc/shorewall/tcrules
else
    run_install -o $OWNER -g $GROUP -m 0600 tcrules ${PREFIX}/etc/shorewall/tcrules
    echo -e "\nTC Rules file installed as ${PREFIX}/etc/shorewall/tcrules"
fi

#
# Install the TOS file
#
if [ -f ${PREFIX}/etc/shorewall/tos ]; then
    backup_file /etc/shorewall/tos
else
    run_install -o $OWNER -g $GROUP -m 0600 tos ${PREFIX}/etc/shorewall/tos
    echo -e "\nTOS file installed as ${PREFIX}/etc/shorewall/tos"
fi
#
# Install the Tunnels file
#
if [ -f ${PREFIX}/etc/shorewall/tunnels ]; then
    backup_file /etc/shorewall/tunnels
else
    run_install -o $OWNER -g $GROUP -m 0600 tunnels ${PREFIX}/etc/shorewall/tunnels
    echo -e "\nTunnels file installed as ${PREFIX}/etc/shorewall/tunnels"
fi
#
# Install the blacklist file
#
if [ -f ${PREFIX}/etc/shorewall/blacklist ]; then
    backup_file /etc/shorewall/blacklist
else
    run_install -o $OWNER -g $GROUP -m 0600 blacklist ${PREFIX}/etc/shorewall/blacklist
    echo -e "\nBlacklist file installed as ${PREFIX}/etc/shorewall/blacklist"
fi
#
# Backup and remove the whitelist file
#
if [ -f ${PREFIX}/etc/shorewall/whitelist ]; then
    backup_file /etc/shorewall/whitelist
    rm -f ${PREFIX}/etc/shorewall/whitelist
fi
#
# Install the rfc1918 file
#
if [ -f ${PREFIX}/etc/shorewall/rfc1918 ]; then
    backup_file /etc/shorewall/rfc1918
else
    run_install -o $OWNER -g $GROUP -m 0600 rfc1918 ${PREFIX}/etc/shorewall/rfc1918
    echo -e "\nRFC 1918 file installed as ${PREFIX}/etc/shorewall/rfc1918"
fi
#
# Backup the version file
#
if [ -z "$PREFIX" ]; then
    if [ -f /var/lib/shorewall/version ]; then
	backup_file /var/lib/shorewall/version
    elif [ -n "$oldversion" ]; then
	echo $oldversion > /var/lib/shorewall/version-${VERSION}.bkout
    else
	echo "Unknown" > /var/lib/shorewall/version-${VERSION}.bkout
    fi
fi
#
# Create the version file
#
echo "$VERSION" > ${PREFIX}/var/lib/shorewall/version
chmod 644 ${PREFIX}/var/lib/shorewall/version
#
# Remove and create the symbolic link to the firewall script
#

if [ -z "$PREFIX" ]; then
    rm -f /etc/shorewall/firewall
    rm -f /var/lib/shorewall/firewall
    ln -s ${DEST}/${FIREWALL} /var/lib/shorewall/firewall
else
    pushd ${PREFIX}/var/lib/shorewall/ >> /dev/null && ln -s ../../..${DEST}/${FIREWALL} firewall && popd >> /dev/null
fi

echo -e "\n${PREFIX}/var/lib/shorewall/firewall linked to ${PREFIX}$DEST/$FIREWALL"

if [ -z "$PREFIX" -a -n "$first_install" ]; then
    if [ -x /sbin/insserv -o -x /usr/sbin/insserv ]; then
    	if insserv /etc/init.d/shorewall ; then
	    echo -e "\nFirewall will start automatically at boot"
	else
	    cant_autostart
	fi
    elif [ -x /sbin/chkconfig -o -x /usr/sbin/chkconfig ]; then
	if chkconfig --add $FIREWALL ; then
	    echo -e "\nFirewall will automatically start in run levels as follows:"
	    chkconfig --list $FIREWALL
	else
	    cant_autostart
	fi
    else
       modify_rclocal
    fi
fi
#
#  Report Success
#
echo -e "\nShorewall Version $VERSION Installed"
