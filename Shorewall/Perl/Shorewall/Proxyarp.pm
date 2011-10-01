#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Proxyarp.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2011,2011 - Tom Eastep (teastep@shorewall.net)
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
our $VERSION = 'MODULEVERSION';

our @proxyarp;

our $family;

#
# Rather than initializing globals in an INIT block or during declaration,
# we initialize them in a function. This is done for two reasons:
#
#   1. Proper initialization depends on the address family which isn't
#      known until the compiler has started.
#
#   2. The compiler can run multiple times in the same process so it has to be
#      able to re-initialize its dependent modules' state.
#
sub initialize( $ ) {
    $family = shift;
    @proxyarp = ();
}

sub setup_one_proxy_arp( $$$$$$$ ) {
    my ( $address, $interface, $physical, $external, $extphy, $haveroute, $persistent) = @_;

    my $proto = $family == F_IPV4 ? 'ARP' : 'NDP';

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
	fatal_error "HAVEROUTE=No requires an INTERFACE" if $interface eq '-';

	if ( $family == F_IPV4 ) {
	    emit "[ -n \"\$g_noroutes\" ] || run_ip route replace $address/32 dev $physical";
	} else {
	    emit( 'if [ -z "$g_noroutes" ]; then',
		  "    qt \$IP -6 route del $address/128 dev $physical".
		  "    run_ip route add $address/128 dev $physical",
		  'fi'
		);
	}

	$haveroute = 1 if $persistent;
    }

    emit ( "run_ip neigh add proxy $address nud permanent dev $extphy" ,
	   qq(progress_message "   Host $address connected to $interface added to $proto on $extphy"\n) );

    push @proxyarp, "$address $interface $external $haveroute";

    progress_message "   Host $address connected to $interface added to $proto on $external";
}

#
# Setup Proxy ARP/NDP
#
sub setup_proxy_arp() {
    my $proto      = $family == F_IPV4 ? 'arp' : 'ndp';   # Protocol
    my $file_opt   = 'proxy' . $proto;                    # Name of config file and of the interface option
    my $proc_file  = 'proxy_' . $proto;                   # Name of the corresponding file in /proc

    my $interfaces= find_interfaces_by_option $file_opt;
    my $fn = open_file $file_opt;

    if ( @$interfaces || $fn ) {

	my $first_entry = 1;

	save_progress_message 'Setting up Proxy ' . uc($proto) . '...';

	my ( %set, %reset );

	while ( read_a_line ) {

	    my ( $address, $interface, $external, $haveroute, $persistent ) =
		split_line $file_opt . 'file ', { address => 0, interface => 1, external => 2, haveroute => 3, persistent => 4 };

	    if ( $first_entry ) {
		progress_message2 "$doing $fn...";
		$first_entry = 0;
	    }

	    fatal_error 'EXTERNAL must be specified' if $external eq '-';
	    fatal_error "Unknown interface ($external)" unless known_interface $external;
	    fatal_error "Wildcard interface ($external) not allowed" if $external =~ /\+$/;
	    $reset{$external} = 1 unless $set{$external};

	    my $extphy   = get_physical $external;
	    my $physical = '-';

	    if ( $interface ne '-' ) {
		fatal_error "Unknown interface ($interface)" unless known_interface $interface;
		fatal_error "Wildcard interface ($interface) not allowed" if $interface =~ /\+$/;
		$physical = physical_name $interface;
		$set{$interface}  = 1;
	    }

	    setup_one_proxy_arp( $address, $interface, $physical, $external, $extphy, $haveroute, $persistent );
	}

	emit '';

	for my $interface ( keys %reset ) {
	    unless ( $set{interface} ) {
		my $physical = get_physical $interface;
		emit  ( "if [ -f /proc/sys/net/ipv$family/conf/$physical/$proc_file ]; then" ,
			"    echo 0 > /proc/sys/net/ipv$family/conf/$physical/$proc_file" );
		emit    "fi\n";
	    }
	}

	for my $interface ( keys %set ) {
	    my $physical = get_physical $interface;
	    emit  ( "if [ -f /proc/sys/net/ipv$family/conf/$physical/$proc_file ]; then" ,
		    "    echo 1 > /proc/sys/net/ipv$family/conf/$physical/$proc_file" );
	    emit  ( 'else' ,
		    "    error_message \"    WARNING: Cannot set the '$file_opt' option for interface $physical\"" ) unless interface_is_optional( $interface );
	    emit    "fi\n";
	}

	for my $interface ( @$interfaces ) {
	    my $value = get_interface_option $interface, $file_opt;
	    my $optional = interface_is_optional $interface;

	    $interface = get_physical $interface;

	    emit ( "if [ -f /proc/sys/net/ipv$family/conf/$interface/$proc_file ] ; then" ,
		   "    echo $value > /proc/sys/net/ipv$family/conf/$interface/$proc_file" );
	    emit ( 'else' ,
		   "    error_message \"WARNING: Unable to set/reset the '$file_opt' option on $interface\"" ) unless $optional;
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
