#
# Shorewall-perl 3.9 -- /usr/share/shorewall-perl/Shorewall/Hosts.pm
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
#  This module contains the code for dealing with the /etc/shorewall/hosts
#  file.
#
package Shorewall::Hosts;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Interfaces;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( validate_hosts_file find_hosts_by_option );
our @EXPORT_OK = ();
our @VERSION = 1.00;

#
# Validates the hosts file. Generates entries in %zone{..}{hosts}
#
sub validate_hosts_file()
{
    my %validoptions = (
			blacklist => 1,
			maclist => 1,
			norfc1918 => 1,
			nosmurfs => 1,
			routeback => 1,
			routefilter => 1,
			tcpflags => 1,
			);

    my $ipsec = 0;
    my $first_entry = 1;

    my $fn = open_file 'hosts';

    while ( read_a_line ) {

	my ($zone, $hosts, $options ) = split_line 2, 3, 'hosts file';

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	my $zoneref = $zones{$zone};
	my $type    = $zoneref->{type};

	fatal_error "Unknown ZONE ($zone)" unless $type;
	fatal_error 'Firewall zone not allowed in ZONE column of hosts record' if $type eq 'firewall';

	my $interface;

	if ( $hosts =~ /^([\w.@%-]+\+?):(.*)$/ ) {
	    $interface = $1;
	    $hosts = $2;
	    $zoneref->{options}{complex} = 1 if $hosts =~ /^\+/;
	    fatal_error "Unknown interface ($interface)" unless $interfaces{$interface}{root};
	} else {
	    fatal_error "Invalid HOST(S) column contents: $hosts";
	}

	my $optionsref = {};

	if ( $options ne '-' ) {
	    my @options = split ',', $options;
	    my %options;

	    for my $option ( @options )
	    {
		if ( $option eq 'ipsec' ) {
		    $type = 'ipsec';
		    $zoneref->{options}{complex} = 1;
		    $ipsec = 1;
		} elsif ( $validoptions{$option}) {
		    $options{$option} = 1;
		} else {
		    fatal_error "Invalid option ($option)";
		}
	    }

	    $optionsref = \%options;
	}

	#
	# Looking for the '!' at the beginning of a list element is more straight-foward than looking for it in the middle.
	#
	# Be sure we don't have a ',!' in the original
	#
	fatal_error "Invalid hosts list" if $hosts =~ /,!/;
	#
	# Now add a comma before '!'. Do it globally - add_group_to_zone() correctly checks for multiple exclusions
	#
	$hosts =~ s/!/,!/g;  
	#
	# Take care of case where the hosts list begins with '!'
	#
	$hosts = join( '', ALLIPv4 , $hosts ) if substr($hosts, 0, 2 ) eq ',!';

	add_group_to_zone( $zone, $type , $interface, [ split( ',', $hosts ) ] , $optionsref);

	progress_message "   Host \"$line\" validated";
    }

    $capabilities{POLICY_MATCH} = '' unless $ipsec or $zones{ipsec};
}
#
# Returns a reference to a array of host entries. Each entry is a
# reference to an array containing ( interface , group type {ipsec|none} , network );
#
sub find_hosts_by_option( $ ) {
    my $option = $_[0];
    my @hosts;

    for my $zone ( grep $zones{$_}{type} ne 'firewall' , @zones ) {
	while ( my ($type, $interfaceref) = each %{$zones{$zone}{hosts}} ) {
	    while ( my ( $interface, $arrayref) = ( each %{$interfaceref} ) ) {
		for my $host ( @{$arrayref} ) {
		    if ( $host->{options}{$option} ) {
			for my $net ( @{$host->{hosts}} ) {
			    push @hosts, [ $interface, $type eq 'ipsec4' ? 'ipsec' : 'none' , $net ];
			}
		    }
		}
	    }
	}
    }

    for my $interface ( @interfaces ) {
	if ( ! $interfaces{$interface}{zone} && $interfaces{$interface}{options}{$option} ) {
	    push @hosts, [ $interface, 'none', ALLIPv4 ];
	}
    }

    \@hosts;
}

1;
