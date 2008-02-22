#
# Shorewall-perl 4.1 -- /usr/share/shorewall-perl/Shorewall/Proxyarp.pm
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
#
package Shorewall::Proxyarp;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		  setup_proxy_arp
		  dump_proxy_arp
		  );

our @EXPORT_OK = qw( initialize );
our $VERSION = 4.0.6;

our @proxyarp;

#
# Initialize globals -- we take this novel approach to globals initialization to allow
#                       the compiler to run multiple times in the same process. The
#                       initialize() function does globals initialization for this
#                       module and is called from an INIT block below. The function is
#                       also called by Shorewall::Compiler::compiler at the beginning of
#                       the second and subsequent calls to that function.
#

sub initialize() {
    @proxyarp = ();
}

INIT {
    initialize;
}

sub setup_one_proxy_arp( $$$$$ ) {
    my ( $address, $interface, $external, $haveroute, $persistent) = @_;

    if ( "\L$haveroute" eq 'no' || $haveroute eq '-' ) {
	$haveroute = '';
    } elsif ( "\L$haveroute" eq 'yes' ) {
	$haveroute = 'yes';
    } else {
	fatal_error "Invalid value ($haveroute) for HAVEROUTE";
    }

    if ( "\L$persistent" eq 'no' || $persistent eq '-' ) {
	$persistent = '';
    } elsif ( "\L$persistent" eq 'yes' ) {
	$persistent = 'yes';
    } else {
	fatal_error "Invalid value ($persistent) for PERSISTENT";
    }

    unless ( $haveroute ) {

	if ( $config{BROKEN_ROUTING} ) {
	    emit "[ -n \"\$NOROUTES\" ] || qt ip route del $address";
	    emit "[ -n \"\$NOROUTES\" ] || run_ip route add $address dev $interface";
	} else {
	    emit "[ -n \"\$NOROUTES\" ] || run_ip route replace $address dev $interface";
	}

	$haveroute = 1 if $persistent;
    }

    emit ( "if ! arp -i $external -Ds $address $external pub; then",
	   "    fatal_error \"Command 'arp -i $external -Ds $address $external pub' failed\"" ,
	   'fi' ,
	   '',
	   "progress_message \"   Host $address connected to $interface added to ARP on $external\"\n" );

    push @proxyarp, "$address $interface $external $haveroute";

    progress_message "   Host $address connected to $interface added to ARP on $external";
}

#
# Setup Proxy ARP
#
sub setup_proxy_arp() {

    my $interfaces= find_interfaces_by_option 'proxyarp';
    my $fn = open_file 'proxyarp';

    if ( @$interfaces || $fn ) {

	my $first_entry = 1;

	save_progress_message "Setting up Proxy ARP...";

	my ( %set, %reset );

	while ( read_a_line ) {

	    my ( $address, $interface, $external, $haveroute, $persistent ) = split_line 3, 5, 'proxyarp file';

	    if ( $first_entry ) {
		progress_message2 "$doing $fn...";
		$first_entry = 0;
	    }

	    $set{$interface}  = 1;
	    $reset{$external} = 1 unless $set{$external};

	    setup_one_proxy_arp( $address, $interface, $external, $haveroute, $persistent );
	}

	emit '';

	for my $interface ( keys %reset ) {
	    unless ( $set{interface} ) {
		emit  ( "if [ -f /proc/sys/net/ipv4/conf/$interface/proxy_arp ]; then" ,
			"    echo 0 > /proc/sys/net/ipv4/conf/$interface/proxy_arp" );
		emit    "fi\n";
	    }
	}

	for my $interface ( keys %set ) {
	    emit  ( "if [ -f /proc/sys/net/ipv4/conf/$interface/proxy_arp ]; then" ,
		    "    echo 1 > /proc/sys/net/ipv4/conf/$interface/proxy_arp" );
	    emit  ( 'else' ,
		    "    error_message \"    WARNING: Cannot set the 'proxy_arp' option for interface $interface\"" ) unless interface_is_optional( $interface );
	    emit    "fi\n";
	}

	for my $interface ( @$interfaces ) {
	    my $value = get_interface_option $interface, 'proxyarp';
	    emit ( "if [ -f /proc/sys/net/ipv4/conf/$interface/proxy_arp ] ; then" ,
		   "    echo $value > /proc/sys/net/ipv4/conf/$interface/proxy_arp" );
	    emit ( 'else' ,
		   "    error_message \"WARNING: Unable to set/reset proxy ARP on $interface\"" ) unless interface_is_optional( $interface );
	    emit   "fi\n";
	}
    }
}

sub dump_proxy_arp() {
    for ( @proxyarp ) {
	emit_unindented $_;
    }
}

1;
