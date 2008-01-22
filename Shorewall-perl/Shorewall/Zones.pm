#
# Shorewall-perl 4.1 -- /usr/share/shorewall-perl/Shorewall/Zones.pm
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
#   This module contains the code which deals with /etc/shorewall/zones,
#   /etc/shorewall/interfaces and /etc/shorewall/hosts.
#
package Shorewall::Zones;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;

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
		  find_zone
		  firewall_zone
		  defined_zone
		  zone_type
		  all_zones
		  complex_zones
		  non_firewall_zones
		  single_interface
		  validate_interfaces_file
		  all_interfaces
		  find_interface
		  known_interface
		  have_bridges
		  port_to_bridge
		  source_port_to_bridge
		  interface_is_optional
		  find_interfaces_by_option
		  get_interface_option
		  set_interface_option
		  validate_hosts_file
		  find_hosts_by_option
		 );

our @EXPORT_OK = qw( initialize );
our $VERSION = 4.1.2;

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
#     %zones{<zone1> => {type = >      <zone type>       'firewall', 'ipv4', 'ipsec4', 'bport4';
#                        options =>    { complex => 0|1
#                                        nested  => 0|1
#                                        in_out  => < policy match string >
#                                        in      => < policy match string >
#                                        out     => < policy match string >
#                                      }
#                        parents =>    [ <parents> ]     Parents, Children and interfaces are listed by name
#                        children =>   [ <children> ]
#                        interfaces => [ <interfaces> ]
#                        bridge =>     <bridge>
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

our %reservedName = ( all => 1,
		      none => 1,
		      SOURCE => 1,
		      DEST => 1 );

#
#     Interface Table.
#
#     @interfaces lists the interface names in the order that they appear in the interfaces file.
#
#     %interfaces { <interface1> => { name        => <name of interface>
#                                     root        => <name without trailing '+'>
#                                     options     => { <option1> = <val1> ,
#                                                      ...
#                                                    }
#                                     zone        => <zone name>
#                                     bridge      => <bridge>
#                                     broadcasts  => 'none', 'detect' or [ <addr1>, <addr2>, ... ]
#                                   }
#                 }
#
our @interfaces;
our %interfaces;
our @bport_zones;

#
# Initialize globals -- we take this novel approach to globals initialization to allow
#                       the compiler to run multiple times in the same process. The
#                       initialize() function does globals initialization for this
#                       module and is called from an INIT block below. The function is
#                       also called by Shorewall::Compiler::compiler at the beginning of
#                       the second and subsequent calls to that function.
#

sub initialize() {
    @zones = ();
    %zones = ();
    $firewall_zone = '';

    @interfaces = ();
    %interfaces = ();
    @bport_zones = ();
}

INIT {
    initialize;
}

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

    my $ipv4 = 0;

    my $fn = open_file 'zones';

    first_entry "$doing $fn...";

    while ( read_a_line ) {

	my @parents;

	my ($zone, $type, $options, $in_options, $out_options ) = split_line 1, 5, 'zones file';

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

	fatal_error "Invalid zone name ($zone)" unless "\L$zone" =~ /^[a-z]\w*$/ && length $zone <= $globals{MAXZONENAMELENGTH};
	fatal_error "Invalid zone name ($zone)"        if $reservedName{$zone} || $zone =~ /^all2|2all$/;
	fatal_error( "Duplicate zone name ($zone)" ) if $zones{$zone};

	$type = "ipv4" unless $type;

	if ( $type =~ /ipv4/i ) {
	    $type = 'ipv4';
	    $ipv4 = 1;
	} elsif ( $type =~ /^ipsec4?$/i ) {
	    $type = 'ipsec4';
	} elsif ( $type =~ /^bport4?$/i ) {
	    warning_message "Bridge Port zones should have a parent zone" unless @parents;
	    $type = 'bport4';
	    push @bport_zones, $zone;
	} elsif ( $type eq 'firewall' ) {
	    fatal_error 'Firewall zone may not be nested' if @parents;
	    fatal_error "Only one firewall zone may be defined ($zone)" if $firewall_zone;
	    $firewall_zone = $zone;
	    $ENV{FW} = $zone;
	    $type = "firewall";
	} elsif ( $type eq '-' ) {
	    $type = 'ipv4';
	    $ipv4 = 1;
	} else {
	    fatal_error "Invalid zone type ($type)" ;
	}

	for ( $options, $in_options, $out_options ) {
	    $_ = '' if $_ eq '-';
	}

	$zones{$zone} = { type       => $type,
			  parents    => \@parents,
			  exclusions => [],
			  bridge     => '',
			  options    => { in_out  => parse_zone_option_list( $options || '', $type ) ,
					  in      => parse_zone_option_list( $in_options || '', $type ) ,
					  out     => parse_zone_option_list( $out_options || '', $type ) ,
					  complex => ($type eq 'ipsec4' || $options || $in_options || $out_options ? 1 : 0) ,
					  nested  => @parents > 0 } ,
			  interfaces => {} ,
			  children   => [] ,
			  hosts      => {}
			};
	push @z, $zone;
    }

    fatal_error "No firewall zone defined" unless $firewall_zone;
    fatal_error "No IPv4 zones defined" unless $ipv4;

    my %ordered;

  PUSHED:
    {
      ZONE:
	for my $zone ( @z ) {
	    unless ( $ordered{$zone} ) {
		for ( @{$zones{$zone}{children}} ) {
		    next ZONE unless $ordered{$_};
		}
		$ordered{$zone} = 1;
		push @zones, $zone;
		redo PUSHED;
	    }
	}
    }

    fatal_error "Internal error in determine_zones()" unless scalar @zones == scalar @z;

}

#
# Return true of we have any ipsec zones
#
sub haveipseczones() {
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
    progress_message2 "Determining Hosts in Zones...";

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

	unless ( $printed ) {
	    fatal_error "No bridge has been associated with zone $zone" if $type eq 'bport4' && ! $zoneref->{bridge};
	    warning_message "*** $zone is an EMPTY ZONE ***" unless $type eq 'firewall';
	}

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

	$entry .= ":$zoneref->{bridge}" if $type eq 'bport4';

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

#
# If the passed zone is associated with a single interface, the name of the interface is returned. Otherwise, the funtion returns '';
#
sub single_interface( $ ) {
    my $zone = $_[0];
    my $zoneref = $zones{$zone};
  
    fatal_error "Internal Error in single_zone()" unless $zoneref;

    my @keys = keys( %{$zoneref->{interfaces}} );

    @keys == 1 ? $keys[0] : '';
}

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
	fatal_error "Invalid Host List" unless defined $host and $host ne '';

	if ( substr( $host, 0, 1 ) eq '!' ) {
	    fatal_error "Only one exclusion allowed in a host list" if $switched;
	    $switched = 1;
	    $host = substr( $host, 1 );
	    $new = \@exclusions;
	}

	unless ( $switched ) {
	    if ( $type eq $zonetype ) {
		fatal_error "Duplicate Host Group ($interface:$host) in zone $zone" if $ifacezone eq $zone;
		$ifacezone = $zone if $host eq ALLIPv4;
	    }
	}

	if ( substr( $host, 0, 1 ) eq '+' ) {
	    fatal_error "Invalid ipset name ($host)" unless $host =~ /^\+[a-zA-Z]\w*$/;
	} else {
	    validate_host $host;
	}

	push @$new, $switched ? "$interface:$host" : $host;
    }

    $zoneref->{options}{in_out}{routeback} = 1 if $options->{routeback};

    $typeref      = ( $zoneref->{hosts}           || ( $zoneref->{hosts} = {} ) );
    $interfaceref = ( $typeref->{$type}           || ( $interfaceref = $typeref->{$type} = {} ) );
    $arrayref     = ( $interfaceref->{$interface} || ( $interfaceref->{$interface} = [] ) );

    $zoneref->{options}{complex} = 1 if @$arrayref || ( @newnetworks > 1 ) || ( @exclusions );

    push @{$zoneref->{exclusions}}, @exclusions;

    push @{$arrayref}, { options => $options,
			 hosts   => \@newnetworks,
			 ipsec   => $type eq 'ipsec4' ? 'ipsec' : 'none' };
}

#
# Verify that the passed zone name represents a declared zone. Return a
# reference to its zone table entry.
#
sub find_zone( $ ) {
    my $zone = $_[0];

    my $zoneref = $zones{$zone};

    fatal_error "Unknown zone" unless $zoneref;

    $zoneref;
}

sub zone_type( $ ) {
    find_zone( $_[0] )->{type};
}

sub defined_zone( $ ) {
    $zones{$_[0]};
}

sub all_zones() {
    @zones;
}

sub non_firewall_zones() {
   grep ( $zones{$_}{type} ne 'firewall'  ,  @zones );
}

sub complex_zones() {
    grep( $zones{$_}{options}{complex} , @zones );
}

sub firewall_zone() {
    $firewall_zone;
}

#
# Parse the interfaces file.
#

sub validate_interfaces_file( $ )
{
    my $export = shift;

    use constant { SIMPLE_IF_OPTION   => 1,
		   BINARY_IF_OPTION   => 2,
		   ENUM_IF_OPTION     => 3,
		   NUMERIC_IF_OPTION  => 4,
		   OBSOLETE_IF_OPTION => 5,
	           MASK_IF_OPTION     => 7,

	           IF_OPTION_ZONEONLY => 8 };

    my %validoptions = (arp_filter  => BINARY_IF_OPTION,
			arp_ignore  => ENUM_IF_OPTION,
			blacklist   => SIMPLE_IF_OPTION,
			bridge      => SIMPLE_IF_OPTION,
			detectnets  => OBSOLETE_IF_OPTION,
			dhcp        => SIMPLE_IF_OPTION,
			maclist     => SIMPLE_IF_OPTION,
			logmartians => BINARY_IF_OPTION,
			norfc1918   => SIMPLE_IF_OPTION,
			nosmurfs    => SIMPLE_IF_OPTION,
			optional    => SIMPLE_IF_OPTION,
			proxyarp    => BINARY_IF_OPTION,
			routeback   => SIMPLE_IF_OPTION + IF_OPTION_ZONEONLY,
			routefilter => BINARY_IF_OPTION,
			sourceroute => BINARY_IF_OPTION,
			tcpflags    => SIMPLE_IF_OPTION,
			upnp        => SIMPLE_IF_OPTION,
			mss         => NUMERIC_IF_OPTION,
			);

    my $fn = open_file 'interfaces';

    my $first_entry = 1;

    my @ifaces;

    while ( read_a_line ) {

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	my ($zone, $interface, $networks, $options ) = split_line 2, 4, 'interfaces file';
	my $zoneref;
	my $bridge = '';

	if ( $zone eq '-' ) {
	    $zone = '';
	} else {
	    $zoneref = $zones{$zone};

	    fatal_error "Unknown zone ($zone)" unless $zoneref;
	    fatal_error "Firewall zone not allowed in ZONE column of interface record" if $zoneref->{type} eq 'firewall';
	}

	$networks = '' if $networks eq '-';
	$options  = '' if $options  eq '-';

	( $interface, my ($port, $extra) ) = split /:/ , $interface, 3;

	fatal_error "Invalid INTERFACE" if defined $extra || ! $interface;

	fatal_error "Invalid Interface Name ($interface)" if $interface eq '+';

	if ( defined $port ) {
	    fatal_error qq("Virtual" interfaces are not supported -- see http://www.shorewall.net/Shorewall_and_Aliased_Interfaces.html) if $port =~ /^\d+$/;
	    require_capability( 'PHYSDEV_MATCH', 'Bridge Ports', '');
	    require_capability( 'KLUDGEFREE', 'Bridge Ports', '');
	    fatal_error "Duplicate Interface ($port)" if $interfaces{$port};
	    fatal_error "$interface is not a defined bridge" unless $interfaces{$interface} && $interfaces{$interface}{options}{bridge};
	    fatal_error "Bridge Ports may only be associated with 'bport' zones" if $zone && $zoneref->{type} ne 'bport4';

	    if ( $zone ) {
		if ( $zoneref->{bridge} ) {
		    fatal_error "Bridge Port zones may only be associated with a single bridge" if $zoneref->{bridge} ne $interface;
		} else {
		    $zoneref->{bridge} = $interface;
		}
	    }

	    fatal_error "Bridge Ports may not have options" if $options && $options ne '-';

	    next if $port eq '';

	    fatal_error "Invalid Interface Name ($interface:$port)" unless $port =~ /^[\w.@%-]+\+?$/;

	    $interfaces{$port}{bridge} = $bridge = $interface;
	    $interface = $port;
	} else {
	    fatal_error "Duplicate Interface ($interface)" if $interfaces{$interface};
	    fatal_error "Zones of type 'bport' may only be associated with bridge ports" if $zone && $zoneref->{type} eq 'bport4';
	    $interfaces{$interface}{bridge} = $interface;
	}

	$interfaces{$interface}{name} = $interface;
	
	my $wildcard = 0;

	if ( $interface =~ /\+$/ ) {
	    $wildcard = 1;
	    $interfaces{$interface}{root} = substr( $interface, 0, -1 );
	} else {
	    $interfaces{$interface}{root} = $interface;
	}

	unless ( $networks eq '' || $networks eq 'detect' ) {
	    my @broadcasts = split /,/, $networks;

	    for my $address ( @broadcasts ) {
		fatal_error 'Invalid BROADCAST address' unless $address =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
	    }

	    if ( $capabilities{ADDRTYPE} ) {
		warning_message 'Shorewall no longer uses broadcast addresses in rule generation when Address Type Match is available';
	    } else {
		$interfaces{$interface}{broadcasts} = \@broadcasts;
	    }
	}

	my $optionsref = {};

	my %options;

	if ( $options ) {

	    for my $option (split ',', $options ) {
		next if $option eq '-';

		( $option, my $value ) = split /=/, $option;

		fatal_error "Invalid Interface option ($option)" unless my $type = $validoptions{$option};

		fatal_error "The \"$option\" option may not be specified on a multi-zone interface" if $type & IF_OPTION_ZONEONLY && ! $zone;

		$type &= MASK_IF_OPTION;

		if ( $type == SIMPLE_IF_OPTION ) {
		    fatal_error "Option $option does not take a value" if defined $value;
		    $options{$option} = 1;
		} elsif ( $type == BINARY_IF_OPTION ) {
		    $value = 1 unless defined $value;
		    fatal_error "Option value for $option must be 0 or 1" unless ( $value eq '0' || $value eq '1' );
		    fatal_error "The $option option may not be used with a wild-card interface name" if $wildcard;
		    $options{$option} = $value;
		} elsif ( $type == ENUM_IF_OPTION ) {
		    fatal_error "The $option option may not be used with a wild-card interface name" if $wildcard;
		    if ( $option eq 'arp_ignore' ) {
			if ( defined $value ) {
			    if ( $value =~ /^[1-3,8]$/ ) {
				$options{arp_ignore} = $value;
			    } else {
				fatal_error "Invalid value ($value) for arp_ignore";
			    }
			} else {
			    $options{arp_ignore} = 1;
			}
		    } else {
			fatal_error "Internal Error in validate_interfaces_file";
		    }
		} elsif ( $type == NUMERIC_IF_OPTION ) {
		    fatal_error "The $option option requires a value" unless defined $value;
		    my $numval = numeric_value $value;
		    fatal_error "Invalid value ($value) for option $option" unless defined $numval;
		    $options{$option} = $numval;
		} else {
		    warning_message "Support for the $option interface option has been removed from Shorewall-perl";
		}
	    }

	    $zoneref->{options}{in_out}{routeback} = 1 if $zoneref && $options{routeback};

	    if ( $options{bridge} ) {
		require_capability( 'PHYSDEV_MATCH', 'The "bridge" option', 's');
		fatal_error "Bridges may not have wildcard names" if $wildcard;
	    }
	} elsif ( $port ) {
	    $options{port} = 1;
	}

	$interfaces{$interface}{options} = $optionsref = \%options;

	push @ifaces, $interface;

	my @networks = allipv4;

	add_group_to_zone( $zone, $zoneref->{type}, $interface, \@networks, $optionsref ) if $zone && @networks;

    	$interfaces{$interface}{zone} = $zone; #Must follow the call to add_group_to_zone()

	progress_message "   Interface \"$currentline\" Validated";

    }

    #
    # We now assemble the @interfaces array such that bridge ports immediately precede their associated bridge
    #
    for my $interface ( @ifaces ) {
	my $interfaceref = $interfaces{$interface};

	if ( $interfaceref->{options}{bridge} ) {
	    my @ports = grep $interfaces{$_}{options}{port} && $interfaces{$_}{bridge} eq $interface, @ifaces;

	    if ( @ports ) {
		push @interfaces, @ports;
	    } else {
		$interfaceref->{options}{routeback} = 1; #so the bridge will work properly
	    }
	}

	push @interfaces, $interface unless $interfaceref->{options}{port};
    }
    #
    # Be sure that we have at least one interface
    #
    fatal_error "No network interfaces defined" unless @interfaces;
}

#
# Returns true if passed interface matches an entry in /etc/shorewall/interfaces
#
# If the passed name matches a wildcard, a entry for the name is added in %interfaces to speed up validation of other references to that name.
#
sub known_interface($)
{
    my $interface = $_[0];
    my $interfaceref = $interfaces{$interface};
    
    return $interfaceref if $interfaceref;

    for my $i ( @interfaces ) {
	$interfaceref = $interfaces{$i};
	my $val = $interfaceref->{root};
	next if $val eq $i;
	if ( substr( $interface, 0, length $val ) eq $val ) {
	    #
	    # Cache this result for future reference. We set the 'name' to the name of the entry that appears in /etc/shorewall/interfaces.
	    #
	    return $interfaces{$interface} = { options => $interfaceref->{options}, bridge => $interfaceref->{bridge} , name => $i };
	}
    }

    0;
}

#
# Return the interfaces list
#
sub all_interfaces() {
    @interfaces;
}

#
# Return a reference to the interfaces table entry for an interface
#
sub find_interface( $ ) {
    my $interface    = $_[0];
    my $interfaceref = $interfaces{ $interface };
    
    fatal_error "Unknown Interface ($interface)" unless $interfaceref;

    $interfaceref;
}

#
# Returns true if there are bridge port zones defined in the config
#
sub have_bridges() {
    @bport_zones > 0;
}

#
# Return the bridge associated with the passed interface. If the interface is not a bridge port,
# return ''
#
sub port_to_bridge( $ ) {
    my $portref = $interfaces{$_[0]};
    return $portref && $portref->{options}{port} ? $portref->{bridge} : '';
}

#
# Return the bridge associated with the passed interface.
#
sub source_port_to_bridge( $ ) {
    my $portref = $interfaces{$_[0]};
    return $portref ? $portref->{bridge} : '';
}

#
# Return the 'optional' setting of the passed interface
#
sub interface_is_optional($) {
    my $optionsref = $interfaces{$_[0]}{options};
    $optionsref && $optionsref->{optional};
}

#
# Returns reference to array of interfaces with the passed option
#
sub find_interfaces_by_option( $ ) {
    my $option = $_[0];
    my @ints = ();

    for my $interface ( @interfaces ) {
	my $optionsref = $interfaces{$interface}{options};
	if ( $optionsref && defined $optionsref->{$option} ) {
	    push @ints , $interface
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

#
# Set an option for an interface
#
sub set_interface_option( $$$ ) {
    my ( $interface, $option, $value ) = @_;

    $interfaces{$interface}{options}{$option} = $value;
}

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
			broadcast => 1,
			destonly => 1,
			sourceonly => 1,
			);

    my $ipsec = 0;
    my $first_entry = 1;

    my $fn = open_file 'hosts';

    while ( read_a_line ) {

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	my ($zone, $hosts, $options ) = split_line 2, 3, 'hosts file';

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

	if ( $type eq 'bport4' ) {
	    if ( $zoneref->{bridge} eq '' ) {
		fatal_error 'Bridge Port Zones may only be associated with bridge ports' unless $interfaces{$interface}{options}{port};
		$zoneref->{bridge} = $interfaces{$interface}{bridge};
	    } elsif ( $zoneref->{bridge} ne $interfaces{$interface}{bridge} ) {
		fatal_error "Interface $interface is not a port on bridge $zoneref->{bridge}";
	    }
	}

	my $optionsref = {};

	if ( $options ne '-' ) {
	    my @options = split ',', $options;
	    my %options;

	    for my $option ( @options )
	    {
		if ( $option eq 'ipsec' ) {
		    $type = 'ipsec4';
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

	progress_message "   Host \"$currentline\" validated";
    }

    $capabilities{POLICY_MATCH} = '' unless $ipsec || haveipseczones;
}

#
# Returns a reference to a array of host entries. Each entry is a
# reference to an array containing ( interface , polciy match type {ipsec|none} , network );
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
			    push @hosts, [ $interface, $host->{ipsec} , $net ];
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
