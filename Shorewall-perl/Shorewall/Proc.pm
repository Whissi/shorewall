#
# Shorewall 4.0 -- /usr/share/shorewall-perl/Shorewall/Proc.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007 - Tom Eastep (teastep@shorewall.net)
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
our @EXPORT_OK = qw( );
our $VERSION = 4.0.6;

#
# ARP Filtering
#
sub setup_arp_filtering() {
    save_progress_message "Setting up ARP filtering...";

    my $interfaces  = find_interfaces_by_option 'arp_filter';
    my $interfaces1 = find_interfaces_by_option 'arp_ignore';

    if ( @$interfaces || @$interfaces1 ) {
	progress_message2 "$doing ARP Filtering...";

	for my $interface ( @$interfaces ) {
	    my $file = "/proc/sys/net/ipv4/conf/$interface/arp_filter";
	    my $value = get_interface_option $interface, 'arp_filter';

	    emit ( '',
		   "if [ -f $file ]; then",
		   "    echo $value > $file");
	    emit ( 'else',
		   "    error_message \"WARNING: Cannot set ARP filtering on $interface\"" ) unless interface_is_optional( $interface );
	    emit   "fi\n";
	}

	for my $interface ( @$interfaces1 ) {
	    my $file  = "/proc/sys/net/ipv4/conf/$interface/arp_ignore";
	    my $value = get_interface_option $interface, 'arp_ignore';

	    fatal_error "Internal Error in setup_arp_filtering()" unless defined $value;

	    emit ( "if [ -f $file ]; then",
		   "    echo $value > $file");
	    emit ( 'else',
		   "    error_message \"WARNING: Cannot set ARP filtering on $interface\"" ) unless interface_is_optional( $interface );
	    emit   "fi\n";
	}
    }
}

#
# Route Filtering
#
sub setup_route_filtering() {

    my $interfaces = find_interfaces_by_option 'routefilter';

    if ( @$interfaces || $config{ROUTE_FILTER} ) {

	progress_message2 "$doing Kernel Route Filtering...";

	save_progress_message "Setting up Route Filtering...";


	if ( $config{ROUTE_FILTER} ) {
	    my $val = $config{ROUTE_FILTER} eq 'on' ? 1 : 0;

	    emit ( 'for file in /proc/sys/net/ipv4/conf/*; do',
		   "    [ -f \$file/rp_filter ] && echo $val > \$file/rp_filter",
		   'done' );
	}

	for my $interface ( @$interfaces ) {
	    my $file = "/proc/sys/net/ipv4/conf/$interface/rp_filter";
	    my $value = get_interface_option $interface, 'routefilter';

	    emit ( "if [ -f $file ]; then" ,
		   "    echo $value > $file" );
	    emit ( 'else' ,
		   "    error_message \"WARNING: Cannot set route filtering on $interface\"" ) unless interface_is_optional( $interface);
	    emit   "fi\n";
	}

	emit 'echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter';

	if ( $config{ROUTE_FILTER} eq 'on' ) {
	    emit 'echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter';
	} elsif (  $config{ROUTE_FILTER} eq 'off' ) {
	    emit 'echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter';
	}

	emit "[ -n \"\$NOROUTES\" ] || ip route flush cache";
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
		   'done' );
	}

	for my $interface ( @$interfaces ) {
	    my $file = "/proc/sys/net/ipv4/conf/$interface/log_martians";
	    my $value = get_interface_option $interface, 'logmartians';

	    emit ( "if [ -f $file ]; then" ,
		   "    echo $value > $file" );

	    emit ( 'else' ,
		   "    error_message \"WARNING: Cannot set Martian logging on $interface\"") unless interface_is_optional( $interface);
	    emit   "fi\n";
	}

	if ( $config{LOG_MARTIANS} eq 'on' ) {
	    emit 'echo 1 > /proc/sys/net/ipv4/conf/all/log_martians';
	    emit 'echo 1 > /proc/sys/net/ipv4/conf/default/log_martians';
	} elsif ( $config{LOG_MARTIANS} eq 'off' ) {
	    emit 'echo 0 > /proc/sys/net/ipv4/conf/all/log_martians';
	    emit 'echo 0 > /proc/sys/net/ipv4/conf/default/log_martians';
	}
    }
}

#
# Source Routing
#
sub setup_source_routing() {

    save_progress_message 'Setting up Accept Source Routing...';

    my $interfaces = find_interfaces_by_option 'sourceroute';

    if ( @$interfaces ) {
	progress_message2 "$doing Accept Source Routing...";

	save_progress_message 'Setting up Source Routing...';

	for my $interface ( @$interfaces ) {
	    my $file = "/proc/sys/net/ipv4/conf/$interface/accept_source_route";
	    my $value = get_interface_option $interface, 'sourceroute';

	    emit ( "if [ -f $file ]; then" ,
		   "    echo $value > $file" );
	    emit ( 'else' ,
		   "    error_message \"WARNING: Cannot set Accept Source Routing on $interface\"" ) unless interface_is_optional( $interface);
	    emit   "fi\n";
	}
    }
}

sub setup_forwarding() {
    if ( $config{IP_FORWARDING} eq 'on' ) {
	emit 'echo 1 > /proc/sys/net/ipv4/ip_forward';
	emit 'progress_message2 IP Forwarding Enabled';
    } elsif ( $config{IP_FORWARDING} eq 'off' ) {
	emit 'echo 0 > /proc/sys/net/ipv4/ip_forward';
	emit 'progress_message2 IP Forwarding Disabled!';
    }

    emit '';
}

1;
