#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Proc.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010,2011,2012 - Tom Eastep (teastep@shorewall.net)
#
#       Complete documentation is available at http://shorewall.net
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
#   This module contains the code that deals with entries in /proc.
#
#   Note: The /proc/sys/net/ipv4/conf/x/proxy_arp flag is handled
#         in the Proxyarp module.
#
package Shorewall::Proc;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		 setup_arp_filtering
		 setup_route_filtering
		 setup_martian_logging
		 setup_source_routing
		 setup_forwarding
		 );
our @EXPORT_OK = qw( setup_interface_proc );
our $VERSION = 'MODULEVERSION';

#
# ARP Filtering
#
sub setup_arp_filtering() {
    my $interfaces  = find_interfaces_by_option 'arp_filter';
    my $interfaces1 = find_interfaces_by_option 'arp_ignore';

    if ( @$interfaces || @$interfaces1 ) {
	progress_message2 "$doing ARP Filtering...";

	save_progress_message "Setting up ARP filtering...";

	for my $interface ( @$interfaces ) {
	    my $value = get_interface_option $interface, 'arp_filter';
	    my $optional = interface_is_optional $interface;

	    $interface = get_physical $interface;

	    my $file = "/proc/sys/net/ipv4/conf/$interface/arp_filter";

	    emit ( '',
		   "if [ -f $file ]; then",
		   "    echo $value > $file");
	    emit ( 'else',
		   "    error_message \"WARNING: Cannot set ARP filtering on $interface\"" ) unless $optional;
	    emit   "fi\n";
	}

	for my $interface ( @$interfaces1 ) {
	    my $value = get_interface_option $interface, 'arp_ignore';
	    my $optional = interface_is_optional $interface;

	    $interface = get_physical $interface;

	    my $file  = "/proc/sys/net/ipv4/conf/$interface/arp_ignore";

	    assert( defined $value );

	    emit ( "if [ -f $file ]; then",
		   "    echo $value > $file");
	    emit ( 'else',
		   "    error_message \"WARNING: Cannot set ARP filtering on $interface\"" ) unless $optional;
	    emit   "fi\n";
	}
    }
}

#
# Route Filtering
#
sub setup_route_filtering() {

    my $interfaces = find_interfaces_by_option 'routefilter';
    my $config     = $config{ROUTE_FILTER};

    if ( @$interfaces || $config ) {

	progress_message2 "$doing Kernel Route Filtering...";

	save_progress_message "Setting up Route Filtering...";

	my $val = '';

	if ( $config ne '' ) {
	    $val = $config eq 'on' ? 1 : $config eq 'off' ? 0 : $config;

	    emit ( 'for file in /proc/sys/net/ipv4/conf/*; do',
		   "    [ -f \$file/rp_filter ] && echo $val > \$file/rp_filter",
		   'done',
		   '' );
	}

	for my $interface ( @$interfaces ) {
	    my $value = get_interface_option $interface, 'routefilter';
	    my $optional = interface_is_optional $interface;

	    $interface = get_physical $interface;

	    my $file = "/proc/sys/net/ipv4/conf/$interface/rp_filter";

	    emit ( "if [ -f $file ]; then" ,
		   "    echo $value > $file" );
	    emit ( 'else' ,
		   "    error_message \"WARNING: Cannot set route filtering on $interface\"" ) unless $optional;
	    emit   "fi\n";
	}

	if ( have_capability( 'KERNELVERSION' ) < 20631 ) {
	    emit 'echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter';
	} elsif ( $val ne '' ) {
	    emit "echo $val > /proc/sys/net/ipv4/conf/all/rp_filter";
	}

	emit "echo $val > /proc/sys/net/ipv4/conf/default/rp_filter" if $val ne '';

	emit "[ -n \"\$g_noroutes\" ] || \$IP -4 route flush cache";
    }
}

#
# Martian Logging
#

sub setup_martian_logging() {
    my $interfaces = find_interfaces_by_option 'logmartians';

    if ( @$interfaces || $config{LOG_MARTIANS} ) {

	progress_message2 "$doing Martian Logging...";

	save_progress_message "Setting up Martian Logging...";

	if ( $config{LOG_MARTIANS} ) {
	    my $val = $config{LOG_MARTIANS} eq 'on' ? 1 : 0;

	    emit ( 'for file in /proc/sys/net/ipv4/conf/*; do',
		   "    [ -f \$file/log_martians ] && echo $val > \$file/log_martians",
		   'done',
		   '' );

	    emit( 'echo 0 > /proc/sys/net/ipv4/conf/all/log_martians','' ) if $val == 1;
	}

	for my $interface ( @$interfaces ) {
	    my $value = get_interface_option $interface, 'logmartians';
	    my $optional = interface_is_optional $interface;

	    $interface = get_physical $interface;

	    my $file = "/proc/sys/net/ipv4/conf/$interface/log_martians";

	    emit ( "if [ -f $file ]; then" ,
		   "    echo $value > $file" );

	    emit ( 'else' ,
		   "    error_message \"WARNING: Cannot set Martian logging on $interface\"") unless $optional;
	    emit   "fi\n";
	}
    }
}

#
# Source Routing
#
sub setup_source_routing( $ ) {
    my $family = shift;

    my $interfaces = find_interfaces_by_option 'sourceroute';

    if ( @$interfaces ) {
	progress_message2 "$doing Accept Source Routing...";

	save_progress_message 'Setting up Accept Source Routing...';

	for my $interface ( @$interfaces ) {
	    my $value = get_interface_option $interface, 'sourceroute';
	    my $optional = interface_is_optional $interface;

	    $interface = get_physical $interface;

	    my $file = "/proc/sys/net/ipv$family/conf/$interface/accept_source_route";

	    emit ( "if [ -f $file ]; then" ,
		   "    echo $value > $file" );
	    emit ( 'else' ,
		   "    error_message \"WARNING: Cannot set Accept Source Routing on $interface\"" ) unless $optional;
	    emit   "fi\n";
	}
    }
}

sub setup_forwarding( $$ ) {
    my ( $family, $first ) = @_;

    if ( $family == F_IPV4 ) {
	if ( $config{IP_FORWARDING} eq 'on' ) {
	    emit '        echo 1 > /proc/sys/net/ipv4/ip_forward';
	    emit '        progress_message2 IPv4 Forwarding Enabled';
	} elsif ( $config{IP_FORWARDING} eq 'off' ) {
	    emit '        echo 0 > /proc/sys/net/ipv4/ip_forward';
	    emit '        progress_message2 IPv4 Forwarding Disabled!';
	}

	emit '';

	emit ( '        echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables' ,
	       ''
	     ) if have_bridges;
    } else {
	if ( $config{IP_FORWARDING} eq 'on' ) {
	    emit '        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding';
	    emit '        progress_message2 IPv6 Forwarding Enabled';
	} elsif ( $config{IP_FORWARDING} eq 'off' ) {
	    emit '        echo 0 > /proc/sys/net/ipv6/conf/all/forwarding';
	    emit '        progress_message2 IPv6 Forwarding Disabled!';
	}

	emit '';

	emit ( '        echo 1 > /proc/sys/net/bridge/bridge-nf-call-ip6tables' ,
	       ''
	     ) if have_bridges;

	my $interfaces = find_interfaces_by_option 'forward';

	if ( @$interfaces ) {
	    progress_message2 "$doing Interface forwarding..." if $first;

	    push_indent;
	    push_indent;

	    save_progress_message 'Setting up IPv6 Interface Forwarding...';

	    for my $interface ( @$interfaces ) {
		my $value = get_interface_option $interface, 'forward';
		my $optional = interface_is_optional $interface;

		$interface = get_physical $interface;

		my $file = "/proc/sys/net/ipv6/conf/$interface/forwarding";

		emit ( "if [ -f $file ]; then" ,
		       "    echo $value > $file" );
		emit ( 'else' ,
		       "    error_message \"WARNING: Cannot set IPv6 forwarding on $interface\"" ) unless $optional;
		emit   "fi\n";
	    }

	    pop_indent;
	    pop_indent;
	}
    }
}

sub setup_interface_proc( $ ) {
    my $interface = shift;
    my $physical  = get_physical $interface;
    my $value;
    my @emitted;

    if ( interface_has_option( $interface, 'arp_filter' , $value ) ) {
	push @emitted, "echo $value > /proc/sys/net/ipv4/conf/$physical/arp_filter";
    }
	 
    if ( interface_has_option( $interface, 'arp_ignore' , $value ) ) {
	push @emitted, "echo $value > /proc/sys/net/ipv4/conf/$physical/arp_ignore";
    }

    if ( interface_has_option( $interface, 'routefilter' , $value ) ) {
	push @emitted, "echo $value > /proc/sys/net/ipv4/conf/$physical/rp_filter";
    }

    if ( interface_has_option( $interface, 'logmartians' , $value ) ) {
	push @emitted, "echo $value > /proc/sys/net/ipv4/conf/$physical/log_martians";
    }

    if ( interface_has_option( $interface, 'sourceroute' , $value ) ) {
	push @emitted, "echo $value > /proc/sys/net/ipv4/conf/$physical/accept_source_route";
    }

    if ( interface_has_option( $interface, 'sourceroute' , $value ) ) {
	push @emitted, "echo $value > /proc/sys/net/ipv4/conf/$physical/accept_source_route";
    }

    if ( @emitted ) {
	emit( 'if [ $COMMAND = enable ]; then' );
	push_indent;
	emit "$_" for @emitted;
	pop_indent;
	emit "fi\n";
    }
}
	 

1;
