#
# Shorewall 3.9 -- /usr/share/shorewall/Shorewall/Interfaces.pm
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
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
#       Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#
#
package Shorewall::Interfaces;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( add_group_to_zone 
		  validate_interfaces_file
		  dump_interface_info 
		  known_interface 
		  find_interfaces_by_option
		  get_interface_option

		  @interfaces  );
our @EXPORT_OK = ();
our @VERSION = 1.00;

#
#     Interface Table.
#
#     @interfaces lists the interface names in the order that they appear in the interfaces file.
#
#     %interfaces { <interface1> => { root        => <name without trailing '+'>
#                                     broadcast   => [ <bcast1>, ... ]
#                                     options     => { <option1> = <val1> ,
#                                                      ...
#                                                    }
#                                     zone        => <zone name>
#                 }
#
our @interfaces;
our %interfaces;

sub add_group_to_zone($$$$$)
{
    my ($zone, $type, $interface, $networks, $options) = @_;
    my $typeref;
    my $interfaceref;
    my $arrayref;
    my $zoneref  = $zones{$zone};
    my $zonetype = $zoneref->{type};
    my $ifacezone = $interfaces{$interface}{zone};

    $zoneref->{interfaces}{$interface} = 1;

    my @newnetworks;
    my @exclusions;
    my $new = \@newnetworks;
    my $switched = 0;

    $ifacezone = '' unless defined $ifacezone;

    for my $host ( @$networks ) {
	if ( $host =~ /^!.*/ ) {
	    fatal_error "Invalid host group: @$networks" if $switched;
	    $switched = 1;
	    $new = \@exclusions;
	}

	unless ( $switched ) {
	    if ( $type eq $zonetype ) {
		fatal_error "Duplicate Host Group ($interface:$host) in zone $zone" if $ifacezone eq $zone;
		$ifacezone = $zone if $host eq ALLIPv4;
	    }
	}
	    
	push @$new, $switched ? "$interface:$host" : $host;
    }

    $zoneref->{options}{in_out}{routeback} = 1 if $options->{routeback};

    $typeref      = ( $zoneref->{hosts}           || ( $zoneref->{hosts} = {} ) );
    $interfaceref = ( $typeref->{$type}           || ( $interfaceref = $typeref->{$type} = {} ) );
    $arrayref     = ( $interfaceref->{$interface} || ( $interfaceref->{$interface} = [] ) );

    $zoneref->{options}{complex} = 1 if @$arrayref || ( @newnetworks > 1 );

    my %h;

    $h{options} = $options;
    $h{hosts}   = \@newnetworks;
    $h{ipsec}   = $type eq 'ipsec' ? 'ipsec' : 'none';

    push @{$zoneref->{exclusions}}, @exclusions;
    push @{$arrayref}, \%h;
}

#
# Parse the interfaces file.
#	 
sub validate_interfaces_file()
{
    my %validoptions = (arp_filter => 1,
			arp_ignore => 1,
			blacklist => 1,
			detectnets => 1,
			dhcp => 1,
			maclist => 1,
			logmartians => 1,
			norfc1918 => 1,
			nosmurfs => 1,
			proxyarp => 1,
			routeback => 1,		
			routefilter => 1,
			sourceroute => 1,
			tcpflags => 1,
			upnp => 1,
			);

    open INTERFACES, "$ENV{TMP_DIR}/interfaces" or fatal_error "Unable to open stripped interfaces file: $!";

    while ( $line = <INTERFACES> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ($zone, $interface, $networks, $options, $extra) = split /\s+/, $line;
	my $zoneref;

	fatal_error "Invalid interfaces entry: $line" if $extra;

	if ( $zone eq '-' ) {
	    $zone = '';
	} else {
	    $zoneref = $zones{$zone};

	    fatal_error "Unknown zone ($zone)" unless $zoneref;
	    fatal_error "Firewall zone not allowed in ZONE column of interface record" if $zoneref->{type} eq 'firewall';
	}

	$networks = '' if $networks eq '-';
	$options  = '' if $networks eq '-';

	fatal_error "Duplicate Interface ($interface)" if $interfaces{$interface};

	fatal_error "Invalid Interface Name: $interface" if $interface =~ /:|^\+$/;

	( $interfaces{$interface}{root} = $interface ) =~ s/\+$// ;

	if ( $networks && $networks ne '-' )
	{
	    my @broadcast = split ',', $networks; 
	    $interfaces{$interface}{broadcast} = \@broadcast;
	}

	my $optionsref = {};

	if ( $options )
	{
	    my %options;

	    for my $option (split ',', $options )
	    {
		next if $option eq '-';

		if ( $validoptions{$option} ) {
		    $options{$option} = 1;
		} elsif ( $option =~ /^arp_filter=([1-3,8])$/ ) {
		    $options{arp_filter} = $1;
		} else {
		    warning_message("Invalid Interface option ($option) ignored");
		}
	    }

	    $zoneref->{options}{in_out}{routeback} = 1 if $options{routeback};

	    $interfaces{$interface}{options} = $optionsref = \%options;
	}

	push @interfaces, $interface;

	add_group_to_zone( $zone, $zoneref->{type}, $interface, \@allipv4, $optionsref ) if $zone;
	
    	$interfaces{$interface}{zone} = $zone; #Must follow the call to add_group_to_zone()

	progress_message "   Interface \"$line\" Validated";

    }		
		
    close INTERFACES;
}

#
# Dump the tables built by validate_interface_file
#
sub dump_interface_info()
{
    print "\n";

    for my $interface ( @interfaces ) {
	my $interfaceref = $interfaces{$interface};
	print "Interface: $interface\n";
	my $root = $interfaceref->{root};
	print "   Root = $root\n";
	my $bcastref = $interfaceref->{broadcast};
	if ( $bcastref ) {
	    my $spaces = '';
	    print '   Broadcast: ';
	    for my $addr (@$bcastref) {
		print "${spaces}${addr}\n";
		$spaces = '              ';
	    }
	}

	my $options = $interfaceref->{options};

	if ( $options ) {
	    print '     Options: ';
	    my $spaces = '';
	    for my $option ( keys %$options ) {
		my $val = ${$options}{$option};
		print "${spaces}${option} = $val\n";
		$spaces = '              ';
	    }
	}

	my $zone = $interfaceref->{zone};
	print "        zone: $zone\n" if $zone;
    }

    print "\n";
}

#
# Returns true if passed interface matches an entry in /etc/shorewall/interfaces
#
# If the passed name matches a wildcard, a entry for the name is added in %interfaces to speed up validation of other references to that name.
#
sub known_interface($)
{
    my $interface = $_[0];

    return 1 if exists $interfaces{$interface};

    for my $i ( @interfaces ) {
	my $val = $interfaces{$i}{root};
	next if $val eq $i;
	my $len = length $val;
	if ( substr( $interface, 0, $len ) eq $val ) {
	    #
	    # Cache this result for future reference
	    #
	    $interfaces{$interface} = undef;
	    return 1;
	}
    }

    0;
}

#
# Returns reference to array of interfaces with the passed option
#
sub find_interfaces_by_option( $ ) {
    my $option = $_[0];
    my @ints = ();

    for my $interface ( @interfaces ) {
	my $optionsref = $interfaces{$interface}{options};
	if ( $optionsref && $optionsref->{$option} ) {
	    push @ints , $interface;
	}
    }

    \@ints;
}

#
# Return the value of an option for an interface
#
sub get_interface_option( $$ ) {
    my ( $interface, $option ) = @_;

    $interfaces{$interface}{options}{$option};
}

1;
