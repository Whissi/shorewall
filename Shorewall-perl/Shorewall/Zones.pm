#
# Shorewall-perl 3.9 -- /usr/share/shorewall-perl/Shorewall/Zones.pm
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
#   This module contains the code which deals with /etc/shorewall/zones.
#
package Shorewall::Zones;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( NOTHING
		  NUMERIC
		  NETWORK
		  IPSECPROTO
		  IPSECMODE

		  determine_zones
		  zone_report
		  dump_zone_contents
		  ipseczones

		  @zones
		  %zones
		  $firewall_zone
		  %interfaces );

our @EXPORT_OK = ();
our @VERSION = 1.00;

#
# IPSEC Option types
#
use constant { NOTHING    => 'NOTHING',
	       NUMERIC    => '0x[\da-fA-F]+|\d+',
	       NETWORK    => '\d+.\d+.\d+.\d+(\/\d+)?',
	       IPSECPROTO => 'ah|esp|ipcomp',
	       IPSECMODE  => 'tunnel|transport'
	       };

#
# Zone Table.
#
#     @zones contains the ordered list of zones with sub-zones appearing before their parents.
#
#     %zones{<zone1> => {type = >      <zone type>       'firewall', 'ipv4', 'ipsec4';
#                        options =>    { complex => 0|1
#                                        in_out  => < policy match string >
#                                        in      => < policy match string >
#                                        out     => < policy match string >
#                                      }
#                        parents =>    [ <parents> ]     Parents, Children and interfaces are listed by name
#                        children =>   [ <children> ]
#                        interfaces => [ <interfaces> ]
#                        hosts { <type> } => [ { <interface1> => { ipsec   => 'ipsec'|'none'
#                                                                  options => { <option1> => <value1>
#                                                                               ...
#                                                                             }
#                                                                  hosts   => [ <net1> , <net2> , ... ]
#                                                                }
#                                                <interface2> => ...
#                                              }
#                                            ]
#                       }
#             <zone2> => ...
#           }
#
#     $firewall_zone names the firewall zone.
#
our @zones;
our %zones;
our $firewall_zone;

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
our %interfaces;

my %reservedName = ( all => 1,
		     none => 1,
		     SOURCE => 1,
		     DEST => 1 );

#
# Parse the passed option list and return a reference to a hash as follows:
#
# => mss   = <MSS setting>
# => ipsec = <-m policy arguments to match options>
#
sub parse_zone_option_list($$)
{
    my %validoptions = ( mss          => NUMERIC,
			 strict       => NOTHING,
			 next         => NOTHING,
			 reqid        => NUMERIC,
			 spi          => NUMERIC,
			 proto        => IPSECPROTO,
			 mode         => IPSECMODE,
			 "tunnel-src" => NETWORK,
			 "tunnel-dst" => NETWORK,
		       );

    #
    # Hash of options that have their own key in the returned hash.
    #
    my %key = ( mss => "mss" );

    my ( $list, $zonetype ) = @_;
    my %h;
    my $options = '';
    my $fmt;

    if ( $list ne '-' ) {
	for my $e ( split ',' , $list ) {
	    my $val    = undef;
	    my $invert = '';

	    if ( $e =~ /([\w-]+)!=(.+)/ ) {
		$val    = $2;
		$e      = $1;
		$invert = '! ';
	    } elsif ( $e =~ /([\w-]+)=(.+)/ ) {
		$val = $2;
		$e   = $1;
	    }

	    $fmt = $validoptions{$e};

	    fatal_error "Invalid Option ($e)" unless $fmt;

	    if ( $fmt eq NOTHING ) {
		fatal_error "Option \"$e\" does not take a value" if defined $val;
	    } else {
		fatal_error "Missing value for option \"$e\""        unless defined $val;
		fatal_error "Invalid value ($val) for option \"$e\"" unless $val =~ /^($fmt)$/;
	    }

	    if ( $key{$e} ) {
		$h{$e} = $val;
	    } else {
		fatal_error "The \"$e\" option may only be specified for ipsec zones" unless $zonetype eq 'ipsec4';
		$options .= $invert;
		$options .= "--$e ";
		$options .= "$val "if defined $val;
	    }
	}
    }

    $h{ipsec} = $options ? "$options " : '';

    \%h;
}

#
# Parse the zones file.
#
sub determine_zones()
{
    my @z;

    my $fn = open_file 'zones';

    my $first_entry = 1;

    while ( read_a_line ) {

	my @parents;

	my ($zone, $type, $options, $in_options, $out_options ) = split_line 1, 5, 'zones file';

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	if ( $zone =~ /(\w+):([\w,]+)/ ) {
	    $zone = $1;
	    @parents = split ',', $2;

	    for my $p ( @parents ) {
		fatal_error "Invalid Parent List ($2)" unless $p;
		fatal_error "Unknown parent zone ($p)" unless $zones{$p};
		fatal_error 'Subzones of firewall zone not allowed' if $zones{$p}{type} eq 'firewall';
		push @{$zones{$p}{children}}, $zone;
	    }
	}

	fatal_error "Invalid zone name: $zone" unless "\L$zone" =~ /^[a-z]\w*$/ && length $zone <= $globals{MAXZONENAMELENGTH};
	fatal_error "Invalid zone name: $zone"        if $reservedName{$zone} || $zone =~ /^all2|2all$/;
	fatal_error( "Duplicate zone name: $zone\n" ) if $zones{$zone};

	my $zoneref = $zones{$zone} = {};
	$zoneref->{parents}    = \@parents;
	$zoneref->{exclusions} = [];

	$type = "ipv4" unless $type;

	if ( $type =~ /ipv4/i ) {
	    $zoneref->{type} = 'ipv4';
	} elsif ( $type =~ /^ipsec4?$/i ) {
	    $zoneref->{type} = 'ipsec4';
	} elsif ( $type eq 'firewall' ) {
	    fatal_error 'Firewall zone may not be nested' if @parents;
	    fatal_error "Only one firewall zone may be defined: $zone" if $firewall_zone;
	    $firewall_zone = $zone;
	    $ENV{FW} = $zone;
	    $zoneref->{type} = "firewall";
	} elsif ( $type eq '-' ) {
	    $type = $zoneref->{type} = 'ipv4';
	} else {
	    fatal_error "Invalid zone type ($type)" ;
	}

	my %zone_hash;

	$options      = '' if $options     eq '-';
	$in_options   = '' if $in_options  eq '-';
	$out_options  = '' if $out_options eq '-';

	$zone_hash{in_out}   = parse_zone_option_list( $options || '',$zoneref->{type} );
	$zone_hash{in}       = parse_zone_option_list( $in_options || '', $zoneref->{type} );
	$zone_hash{out}      = parse_zone_option_list( $out_options || '', $zoneref->{type} );
	$zone_hash{complex}  = ($type eq 'ipsec4' || $options || $in_options || $out_options ? 1 : 0);

	$zoneref->{options}    = \%zone_hash;
	$zoneref->{interfaces} = {};
	$zoneref->{children}   = [];
	$zoneref->{hosts}      = {};

	push @z, $zone;
    }

    fatal_error "No firewall zone defined" unless $firewall_zone;
    
    my $pushed = 1;
    my %ordered;

    while ( $pushed )
    {
	$pushed = 0;
      ZONE:
	for my $zone ( @z ) {
	    unless ( $ordered{$zone} ) {
		for my $child ( @{$zones{$zone}{children}} ) {
		    next ZONE unless $ordered{$child};
		}
		$ordered{$zone} = 1;
		push @zones, $zone;
		$pushed = 1;
	    }
	}
    }
}

#
# Return true of we have any ipsec zones
#
sub ipseczones() {
    for my $zoneref ( values %zones ) {
	return 1 if $zoneref->{type} eq 'ipsec4';
    }

    0;
}

#
# Report about zones.
#
sub zone_report()
{
    for my $zone ( @zones )
    {
	my $zoneref   = $zones{$zone};
	my $hostref   = $zoneref->{hosts};
	my $type      = $zoneref->{type};
	my $optionref = $zoneref->{options};

	progress_message "   $zone ($type)";

	my $printed = 0;

	if ( $hostref ) {
	    for my $type ( sort keys %$hostref ) {
		my $interfaceref = $hostref->{$type};

		for my $interface ( sort keys %$interfaceref ) {
		    my $arrayref = $interfaceref->{$interface};
		    for my $groupref ( @$arrayref ) {
			my $hosts     = $groupref->{hosts};
			if ( $hosts ) {
			    my $grouplist = join ',', ( @$hosts );
			    progress_message "      $interface:$grouplist";
			    $printed = 1;
			}
		    }

		}
	    }
	}

	warning_message "*** $zone is an EMPTY ZONE ***" unless $printed || $type eq 'firewall';
    }
}

sub dump_zone_contents()
{
    for my $zone ( @zones )
    {
	my $zoneref    = $zones{$zone};
	my $hostref    = $zoneref->{hosts};
	my $type       = $zoneref->{type};
	my $optionref  = $zoneref->{options};
	my $exclusions = $zoneref->{exclusions};
	my $entry      =  "$zone $type";

	if ( $hostref ) {
	    for my $type ( sort keys %$hostref ) {
		my $interfaceref = $hostref->{$type};

		for my $interface ( sort keys %$interfaceref ) {
		    my $arrayref = $interfaceref->{$interface};
		    for my $groupref ( @$arrayref ) {
			my $hosts     = $groupref->{hosts};
			if ( $hosts ) {
			    my $grouplist = join ',', ( @$hosts );
			    $entry .= " $interface:$grouplist";
			}
		    }

		}
	    }
	}

	if ( @$exclusions ) {
	    $entry .= ' exclude';

	    for my $host ( @$exclusions ) {
		$entry .= " $host";
	    }
	}

	emit_unindented $entry;
    }
}

1;
