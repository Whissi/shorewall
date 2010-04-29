#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Zones.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010 - Tom Eastep (teastep@shorewall.net)
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
		  FIREWALL
		  IP
		  BPORT
		  IPSEC

		  determine_zones
		  zone_report
		  dump_zone_contents
		  find_zone
		  firewall_zone
		  defined_zone
		  zone_type
		  zone_interfaces
		  all_zones
		  all_parent_zones
		  complex_zones
		  non_firewall_zones
		  single_interface
		  validate_interfaces_file
		  all_interfaces
		  all_bridges
		  interface_number
		  find_interface
		  known_interface
		  get_physical
		  physical_name
		  have_bridges
		  port_to_bridge
		  source_port_to_bridge
		  interface_is_optional
		  find_interfaces_by_option
		  get_interface_option
		  set_interface_option
		  validate_hosts_file
		  find_hosts_by_option
		  all_ipsets
		  have_ipsec
		 );

our @EXPORT_OK = qw( initialize );
our $VERSION = '4.4_9';

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
#     %zones{<zone1> => {type = >      <zone type>       FIREWALL, IP, IPSEC, BPORT;
#                        options =>    { complex => 0|1
#                                        nested  => 0|1
#                                        super   => 0|1
#                                        in_out  => < policy match string >
#                                        in      => < policy match string >
#                                        out     => < policy match string >
#                                      }
#                        parents =>    [ <parents> ]      Parents, Children and interfaces are listed by name
#                        children =>   [ <children> ]
#                        interfaces => { <interfaces1> => 1, ... }
#                        bridge =>     <bridge>
#                        hosts { <type> } => [ { <interface1> => { ipsec   => 'ipsec'|'none'
#                                                                  options => { <option1> => <value1>
#                                                                               ...
#                                                                             }
#                                                                  hosts   => [ <net1> , <net2> , ... ]
#                                                                  exclusions => [ <net1>, <net2>, ... ]
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
		      any => 1,
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
#                                     options     => { port => undef|1
#                                                      <option1> = <val1> ,          #See %validinterfaceoptions
#                                                      ...
#                                                    }
#                                     zone        => <zone name>
#                                     nets        => <number of nets in interface/hosts records referring to this interface>
#                                     bridge      => <bridge>
#                                     broadcasts  => 'none', 'detect' or [ <addr1>, <addr2>, ... ]
#                                     number      => <ordinal position in the interfaces file>
#                                     physical    => <physical interface name>
#                                   }
#                 }
#
our @interfaces;
our %interfaces;
our @bport_zones;
our %ipsets;
our %physical;
our $family;
our $have_ipsec;

use constant { FIREWALL => 1,
	       IP       => 2,
	       BPORT    => 3,
	       IPSEC    => 4 };

use constant { SIMPLE_IF_OPTION   => 1,
	       BINARY_IF_OPTION   => 2,
	       ENUM_IF_OPTION     => 3,
	       NUMERIC_IF_OPTION  => 4,
	       OBSOLETE_IF_OPTION => 5,
	       IPLIST_IF_OPTION   => 6,
	       STRING_IF_OPTION   => 7,

	       MASK_IF_OPTION     => 7,

	       IF_OPTION_ZONEONLY => 8,
	       IF_OPTION_HOST     => 16,
	   };

our %validinterfaceoptions;

our %defaultinterfaceoptions = ( routefilter => 1 );

our %maxoptionvalue = ( routefilter => 2, mss => 100000 );

our %validhostoptions;

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
    @zones = ();
    %zones = ();
    $firewall_zone = '';
    $have_ipsec = undef;

    @interfaces = ();
    %interfaces = ();
    @bport_zones = ();
    %ipsets = ();
    %physical = ();

    if ( $family == F_IPV4 ) {
	%validinterfaceoptions = (arp_filter  => BINARY_IF_OPTION,
				  arp_ignore  => ENUM_IF_OPTION,
				  blacklist   => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				  bridge      => SIMPLE_IF_OPTION,
				  detectnets  => OBSOLETE_IF_OPTION,
				  dhcp        => SIMPLE_IF_OPTION,
				  maclist     => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				  logmartians => BINARY_IF_OPTION,
				  nets        => IPLIST_IF_OPTION + IF_OPTION_ZONEONLY,
				  norfc1918   => OBSOLETE_IF_OPTION,
				  nosmurfs    => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				  optional    => SIMPLE_IF_OPTION,
				  proxyarp    => BINARY_IF_OPTION,
				  routeback   => SIMPLE_IF_OPTION + IF_OPTION_ZONEONLY + IF_OPTION_HOST,
				  routefilter => NUMERIC_IF_OPTION ,
				  sourceroute => BINARY_IF_OPTION,
				  tcpflags    => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				  upnp        => SIMPLE_IF_OPTION,
				  upnpclient  => SIMPLE_IF_OPTION,
				  mss         => NUMERIC_IF_OPTION,
				  physical    => STRING_IF_OPTION + IF_OPTION_HOST,
				 );
	%validhostoptions = (
			     blacklist => 1,
			     maclist => 1,
			     nosmurfs => 1,
			     routeback => 1,
			     tcpflags => 1,
			     broadcast => 1,
			     destonly => 1,
			     sourceonly => 1,
			    );
    } else {
	%validinterfaceoptions = (  blacklist   => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				    bridge      => SIMPLE_IF_OPTION,
				    dhcp        => SIMPLE_IF_OPTION,
				    maclist     => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				    nets        => IPLIST_IF_OPTION + IF_OPTION_ZONEONLY,
				    nosmurfs    => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				    optional    => SIMPLE_IF_OPTION,
				    proxyndp    => BINARY_IF_OPTION,
				    routeback   => SIMPLE_IF_OPTION + IF_OPTION_ZONEONLY + IF_OPTION_HOST,
				    sourceroute => BINARY_IF_OPTION,
				    tcpflags    => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				    mss         => NUMERIC_IF_OPTION,
				    forward     => BINARY_IF_OPTION,
				    physical    => STRING_IF_OPTION + IF_OPTION_HOST,
				 );
	%validhostoptions = (
			     blacklist => 1,
			     maclist => 1,
			     routeback => 1,
			     tcpflags => 1,
			    );
    }
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
    my %key = ( mss => 'mss' );

    my ( $list, $zonetype ) = @_;
    my %h;
    my $options = '';
    my $fmt;

    if ( $list ne '-' ) {
	for my $e ( split_list $list, 'option' ) {
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
		fatal_error "The \"$e\" option may only be specified for ipsec zones" unless $zonetype == IPSEC;
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
# Set the super option on the passed zoneref and propagate to its parents
#
sub set_super( $ );

sub set_super( $ ) {
    my $zoneref = shift;

    unless ( $zoneref->{options}{super} ) {
	$zoneref->{options}{super} = 1;
	set_super( $zones{$_} ) for @{$zoneref->{parents}};
    }
}

#
# Process a record in the zones file
#
sub process_zone( \$ ) {
    my $ip = $_[0];

    my @parents;

    my ($zone, $type, $options, $in_options, $out_options ) = split_line 1, 5, 'zones file';

    if ( $zone =~ /(\w+):([\w,]+)/ ) {
	$zone = $1;
	@parents = split_list $2, 'zone';

	for my $p ( @parents ) {
	    fatal_error "Invalid Parent List ($2)" unless $p;
	    fatal_error "Unknown parent zone ($p)" unless $zones{$p};
	    fatal_error 'Subzones of firewall zone not allowed' if $zones{$p}{type} == FIREWALL;
	    push @{$zones{$p}{children}}, $zone;
	}
    }

    fatal_error "Invalid zone name ($zone)"      unless $zone =~ /^[a-z]\w*$/i && length $zone <= $globals{MAXZONENAMELENGTH};
    fatal_error "Invalid zone name ($zone)"      if $reservedName{$zone} || $zone =~ /^all2|2all$/;
    fatal_error( "Duplicate zone name ($zone)" ) if $zones{$zone};

    if ( $type =~ /^ip(v([46]))?$/i ) {
	fatal_error "Invalid zone type ($type)" if $1 && $2 != $family;
	$type = IP;
	$$ip = 1;
    } elsif ( $type =~ /^ipsec([46])?$/i ) {
	fatal_error "Invalid zone type ($type)" if $1 && $1 != $family;
	$type = IPSEC;
    } elsif ( $type =~ /^bport([46])?$/i ) {
	fatal_error "Invalid zone type ($type)" if $1 && $1 != $family;
	warning_message "Bridge Port zones should have a parent zone" unless @parents;
	$type = BPORT;
	push @bport_zones, $zone;
    } elsif ( $type eq 'firewall' ) {
	fatal_error 'Firewall zone may not be nested' if @parents;
	fatal_error "Only one firewall zone may be defined ($zone)" if $firewall_zone;
	$firewall_zone = $zone;
	$ENV{FW} = $zone;
	$type = FIREWALL;
    } elsif ( $type eq '-' ) {
	$type = IP;
	$$ip = 1;
    } else {
	fatal_error "Invalid zone type ($type)" ;
    }

    if ( $type eq IPSEC ) {
	require_capability 'POLICY_MATCH' , 'IPSEC zones', '';
	for ( @parents ) {
	    set_super( $zones{$_} ) unless $zones{$_}{type} == IPSEC;
	}
    }

    for ( $options, $in_options, $out_options ) {
	$_ = '' if $_ eq '-';
    }

    $zones{$zone} = { type       => $type,
		      parents    => \@parents,
		      bridge     => '',
		      options    => { in_out  => parse_zone_option_list( $options || '', $type ) ,
				      in      => parse_zone_option_list( $in_options || '', $type ) ,
				      out     => parse_zone_option_list( $out_options || '', $type ) ,
				      complex => ( $type == IPSEC || $options || $in_options || $out_options ) ,
				      nested  => @parents > 0 ,
				      super   => 0 ,
				    } ,
		      interfaces => {} ,
		      children   => [] ,
		      hosts      => {}
		    };

    return $zone;

}
#
# Parse the zones file.
#
sub determine_zones()
{
    my @z;
    my $ip = 0;

    my $fn = open_file 'zones';

    first_entry "$doing $fn...";

    push @z, process_zone( $ip ) while read_a_line;

    fatal_error "No firewall zone defined" unless $firewall_zone;
    fatal_error "No IP zones defined" unless $ip;
    #
    # Topological sort to place sub-zones before all of their parents
    #
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

    assert( scalar @zones == scalar @z );

}

#
# Return true of we have any ipsec zones
#
sub haveipseczones() {
    for my $zoneref ( values %zones ) {
	return 1 if $zoneref->{type} == IPSEC;
    }

    0;
}

#
# Report about zones.
#
sub zone_report()
{
    progress_message2 "Determining Hosts in Zones...";

    my @translate;

    if ( $family == F_IPV4 ) {
	@translate = ( undef, 'firewall', 'ipv4', 'bport4', 'ipsec4' );
    } else {
	@translate = ( undef, 'firewall', 'ipv6', 'bport6', 'ipsec6' );
    }

    for my $zone ( @zones )
    {
	my $zoneref   = $zones{$zone};
	my $hostref   = $zoneref->{hosts};
	my $type      = $zoneref->{type};
	my $optionref = $zoneref->{options};

	progress_message_nocompress "   $zone ($translate[$type])";

	my $printed = 0;

	if ( $hostref ) {
	    for my $type ( sort keys %$hostref ) {
		my $interfaceref = $hostref->{$type};

		for my $interface ( sort keys %$interfaceref ) {
		    my $iref     = $interfaces{$interface};
		    my $arrayref = $interfaceref->{$interface};
		    for my $groupref ( @$arrayref ) {
			my $hosts      = $groupref->{hosts};
			if ( $hosts ) {
			    my $grouplist  = join ',', ( @$hosts );
			    my $exclusions = join ',', @{$groupref->{exclusions}};
			    $grouplist = join '!', ( $grouplist, $exclusions) if $exclusions;
		
			    if ( $family == F_IPV4 ) {
				progress_message_nocompress "      $iref->{physical}:$grouplist";
			    } else {
				progress_message_nocompress "      $iref->{physical}:<$grouplist>";
			    }
			    $printed = 1;
			}
		    }

		}
	    }
	}

	unless ( $printed ) {
	    fatal_error "No bridge has been associated with zone $zone" if $type == BPORT && ! $zoneref->{bridge};
	    warning_message "*** $zone is an EMPTY ZONE ***" unless $type == FIREWALL;
	}

    }
}

#
# This function is called to create the contents of the ${VARDIR}/zones file
#
sub dump_zone_contents()
{
    my @xlate;

    if ( $family == F_IPV4 ) {
	@xlate = ( undef, 'firewall', 'ipv4', 'bport4', 'ipsec4' );
    } else {
	@xlate = ( undef, 'firewall', 'ipv6', 'bport6', 'ipsec6' );
    }

    for my $zone ( @zones )
    {
	my $zoneref    = $zones{$zone};
	my $hostref    = $zoneref->{hosts};
	my $type       = $zoneref->{type};
	my $optionref  = $zoneref->{options};

	my $entry      =  "$zone $xlate[$type]";

	$entry .= ":$zoneref->{bridge}" if $type == BPORT;

	if ( $hostref ) {
	    for my $type ( sort keys %$hostref ) {
		my $interfaceref = $hostref->{$type};

		for my $interface ( sort keys %$interfaceref ) {
		    my $iref     = $interfaces{$interface};
		    my $arrayref = $interfaceref->{$interface};
		    for my $groupref ( @$arrayref ) {
			my $hosts     = $groupref->{hosts};

			if ( $hosts ) {
			    my $grouplist  = join ',', ( @$hosts );
			    my $exclusions = join ',', @{$groupref->{exclusions}};

			    $grouplist = join '!', ( $grouplist, $exclusions ) if $exclusions;

			    if ( $family == F_IPV4 ) {
				$entry .= " $iref->{physical}:$grouplist";
			    } else {
				$entry .= " $iref->{physical}:<$grouplist>";
			    }
			}
		    }
		}
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

    assert( $zoneref );

    my @keys = keys( %{$zoneref->{interfaces}} );

    @keys == 1 ? $keys[0] : '';
}

sub add_group_to_zone($$$$$)
{
    my ($zone, $type, $interface, $networks, $options) = @_;
    my $hostsref;
    my $typeref;
    my $interfaceref;
    my $zoneref  = $zones{$zone};
    my $zonetype = $zoneref->{type};

    $zoneref->{interfaces}{$interface} = 1;

    my @newnetworks;
    my @exclusions = ();
    my $new = \@newnetworks;
    my $switched = 0;
    my $allip    = 0;

    for my $host ( @$networks ) {
	$interfaces{$interface}{nets}++;

	fatal_error "Invalid Host List" unless defined $host and $host ne '';

	if ( substr( $host, 0, 1 ) eq '!' ) {
	    fatal_error "Only one exclusion allowed in a host list" if $switched;
	    $switched = 1;
	    $host = substr( $host, 1 );
	    $new = \@exclusions;
	}

	unless ( $switched ) {
	    if ( $type == $zonetype ) {
		fatal_error "Duplicate Host Group ($interface:$host) in zone $zone" if $interfaces{$interface}{zone} eq $zone;
		if ( $host eq ALLIP ) {
		    fatal_error "Duplicate Host Group ($interface:$host) in zone $zone" if @newnetworks;
		    $interfaces{$interface}{zone} = $zone;
		    $allip = 1;
		}
	    }
	}

	if ( substr( $host, 0, 1 ) eq '+' ) {
	    fatal_error "Invalid ipset name ($host)" unless $host =~ /^\+[a-zA-Z]\w*$/;
	    require_capability( 'IPSET_MATCH', 'Ipset names in host lists', '');
	} else {
	    validate_host $host, 0;
	}

	push @$new, $host;
    }

    $zoneref->{options}{in_out}{routeback} = 1 if $options->{routeback};

    my $gtype = $type == IPSEC ? 'ipsec' : 'ip';

    $hostsref     = ( $zoneref->{hosts}           || ( $zoneref->{hosts} = {} ) );
    $typeref      = ( $hostsref->{$gtype}         || ( $hostsref->{$gtype} = {} ) );
    $interfaceref = ( $typeref->{$interface}      || ( $typeref->{$interface} = [] ) );

    fatal_error "Duplicate Host Group ($interface:" . ALLIP . ") in zone $zone" if $allip && @$interfaceref;

    $zoneref->{options}{complex} = 1 if @$interfaceref || ( @newnetworks > 1 ) || ( @exclusions ) || $options->{routeback};

    push @{$interfaceref}, { options => $options,
			     hosts   => \@newnetworks,
			     ipsec   => $type == IPSEC ? 'ipsec' : 'none' ,
			     exclusions => \@exclusions };
}

#
# Verify that the passed zone name represents a declared zone. Return a
# reference to its zone table entry.
#
sub find_zone( $ ) {
    my $zone = $_[0];

    my $zoneref = $zones{$zone};

    fatal_error "Unknown zone ($zone)" unless $zoneref;

    $zoneref;
}

sub zone_type( $ ) {
    find_zone( $_[0] )->{type};
}

sub zone_interfaces( $ ) {
    find_zone( $_[0] )->{interfaces};
}

sub defined_zone( $ ) {
    $zones{$_[0]};
}

sub all_zones() {
    @zones;
}

sub non_firewall_zones() {
   grep ( $zones{$_}{type} != FIREWALL ,  @zones );
}

sub all_parent_zones() {
   grep ( ! @{$zones{$_}{parents}} ,  @zones );
}

sub complex_zones() {
    grep( $zones{$_}{options}{complex} , @zones );
}

sub firewall_zone() {
    $firewall_zone;
}

#
# Determine if the passed physical device is a bridge
#
sub is_a_bridge( $ ) {
    which 'brctl' && qt( "brctl show | tail -n+2 | grep -q '^$_[0]\[\[:space:\]\]'" );
} 

#
# Process a record in the interfaces file
#
sub process_interface( $$ ) {
    my ( $nextinum, $export ) = @_;
    my $netsref = '';
    my ($zone, $originalinterface, $bcasts, $options ) = split_line 2, 4, 'interfaces file';
    my $zoneref;
    my $bridge = '';

    if ( $zone eq '-' ) {
	$zone = '';
    } else {
	$zoneref = $zones{$zone};

	fatal_error "Unknown zone ($zone)" unless $zoneref;
	fatal_error "Firewall zone not allowed in ZONE column of interface record" if $zoneref->{type} == FIREWALL;
    }

    my ($interface, $port, $extra) = split /:/ , $originalinterface, 3;

    fatal_error "Invalid INTERFACE ($originalinterface)" if ! $interface || defined $extra;

    if ( defined $port && $port ne '' ) {
	fatal_error qq("Virtual" interfaces are not supported -- see http://www.shorewall.net/Shorewall_and_Aliased_Interfaces.html) if $port =~ /^\d+$/;
	require_capability( 'PHYSDEV_MATCH', 'Bridge Ports', '');
	fatal_error "Your iptables is not recent enough to support bridge ports" unless have_capability( 'KLUDGEFREE' );

	fatal_error "Invalid Interface Name ($interface:$port)" unless $port =~ /^[\w.@%-]+\+?$/;
	fatal_error "Duplicate Interface ($port)" if $interfaces{$port};

	fatal_error "$interface is not a defined bridge" unless $interfaces{$interface} && $interfaces{$interface}{options}{bridge};
	fatal_error "Bridge Ports may only be associated with 'bport' zones" if $zone && $zoneref->{type} != BPORT;

	if ( $zone ) {
	    if ( $zoneref->{bridge} ) {
		fatal_error "Bridge Port zones may only be associated with a single bridge" if $zoneref->{bridge} ne $interface;
	    } else {
		$zoneref->{bridge} = $interface;
	    }
	}

	$bridge = $interface;
	$interface = $port;
    } else {
	fatal_error "Duplicate Interface ($interface)" if $interfaces{$interface};
	fatal_error "Zones of type 'bport' may only be associated with bridge ports" if $zone && $zoneref->{type} == BPORT;
	$bridge = $interface;
    }

    my $wildcard = 0;
    my $root;

    if ( $interface =~ /\+$/ ) {
	$wildcard = 1;
	$root = substr( $interface, 0, -1 );
    } else {
	$root = $interface;
    }

    my $physical = $interface;
    my $broadcasts;

    unless ( $bcasts eq '-' || $bcasts eq 'detect' ) {
	my @broadcasts = split_list $bcasts, 'address';

	for my $address ( @broadcasts ) {
	    fatal_error 'Invalid BROADCAST address' unless $address =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
	}

	if ( have_capability( 'ADDRTYPE' ) ) {
	    warning_message 'Shorewall no longer uses broadcast addresses in rule generation when Address Type Match is available';
	} else {
	    $broadcasts = \@broadcasts;
	}
    }

    my %options;

    $options{port} = 1 if $port;

    my $hostoptionsref = {};

    if ( $options ne '-' ) {

	my %hostoptions = ( dynamic => 0 );

	for my $option (split_list1 $options, 'option' ) {
	    next if $option eq '-';

	    ( $option, my $value ) = split /=/, $option;

	    fatal_error "Invalid Interface option ($option)" unless my $type = $validinterfaceoptions{$option};

	    fatal_error "The \"$option\" option may not be specified on a multi-zone interface" if $type & IF_OPTION_ZONEONLY && ! $zone;

	    my $hostopt = $type & IF_OPTION_HOST;

	    fatal_error "The \"$option\" option is not allowed on a bridge port" if $port && ! $hostopt;

	    $type &= MASK_IF_OPTION;

	    if ( $type == SIMPLE_IF_OPTION ) {
		fatal_error "Option $option does not take a value" if defined $value;
		$options{$option} = 1;
		$hostoptions{$option} = 1 if $hostopt;
	    } elsif ( $type == BINARY_IF_OPTION ) {
		$value = 1 unless defined $value;
		fatal_error "Option value for '$option' must be 0 or 1" unless ( $value eq '0' || $value eq '1' );
		fatal_error "The '$option' option may not be used with a wild-card interface name" if $wildcard;
		$options{$option} = $value;
		$hostoptions{$option} = $value if $hostopt;
	    } elsif ( $type == ENUM_IF_OPTION ) {
		fatal_error "The '$option' option may not be used with a wild-card interface name" if $wildcard;
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
		    assert( 0 );
		}
	    } elsif ( $type == NUMERIC_IF_OPTION ) {
		$value = $defaultinterfaceoptions{$option} unless defined $value;
		fatal_error "The '$option' option requires a value" unless defined $value;
		my $numval = numeric_value $value;
		fatal_error "Invalid value ($value) for option $option" unless defined $numval && $numval <= $maxoptionvalue{$option};
		$options{$option} = $numval;
		$hostoptions{$option} = $numval if $hostopt;
	    } elsif ( $type == IPLIST_IF_OPTION ) {
		fatal_error "The '$option' option requires a value" unless defined $value;
		#
		# Remove parentheses from address list if present
		#
		$value =~ s/\)$// if $value =~ s/^\(//;
		#
		# Add all IP to the front of a list if the list begins with '!'
		#
		$value = join ',' , ALLIP , $value if $value =~ /^!/;

		if ( $option eq 'nets' ) {
		    fatal_error q("nets=" may not be specified for a multi-zone interface) unless $zone;
		    fatal_error "Duplicate $option option" if $netsref;
		    if ( $value eq 'dynamic' ) {
			require_capability( 'IPSET_MATCH', 'Dynamic nets', '');
			$hostoptions{dynamic} = 1;
			#
			# Defer remaining processing until we have the final physical interface name
			#
			$netsref = 'dynamic';
		    } else {
			$hostoptions{multicast} = 1;
			#
			# Convert into a Perl array reference
			#
			$netsref = [ split_list $value, 'address' ];
		    }
		    #
		    # Assume 'broadcast'
		    #
		    $hostoptions{broadcast} = 1;
		} else {
		    assert(0);
		}
	    } elsif ( $type == STRING_IF_OPTION ) {
		fatal_error "The '$option' option requires a value" unless defined $value;

		if ( $option eq 'physical' ) {
		    fatal_error "Invalid Physical interface name ($value)" unless $value =~ /^[\w.@%-]+\+?$/;

		    fatal_error "Duplicate physical interface name ($value)" if ( $physical{$value} && ! $port );

		    fatal_error "The type of 'physical' name ($value) doesn't match the type of interface name ($interface)" if $wildcard && ! $value =~ /\+$/;
		    $physical = $value;
		} else {
		    assert(0);
		}
	    } else {
		warning_message "Support for the $option interface option has been removed from Shorewall";
	    }
	}

	if ( $netsref eq 'dynamic' ) {
	    my $ipset = "${zone}_" . chain_base $physical;
	    $netsref = [ "+$ipset" ];
	    $ipsets{$ipset} = 1;
	}

	if ( $options{bridge} ) {
	    require_capability( 'PHYSDEV_MATCH', 'The "bridge" option', 's');
	    fatal_error "Bridges may not have wildcard names" if $wildcard;
	    $hostoptions{routeback} = $options{routeback} = 1;
	}

	$hostoptions{routeback} = $options{routeback} = is_a_bridge( $physical ) unless $export || $options{routeback};

	$hostoptionsref = \%hostoptions;
    } else {
	#
	# No options specified -- auto-detect bridge
	#
	$hostoptionsref->{routeback} = $options{routeback} = is_a_bridge( $physical ) unless $export;
    }	

    $physical{$physical} = $interfaces{$interface} = { name       => $interface ,
						       bridge     => $bridge ,
						       nets       => 0 ,
						       number     => $nextinum ,
						       root       => $root ,
						       broadcasts => $broadcasts ,
						       options    => \%options ,
						       zone       => '',
						       physical   => $physical
						     };

    if ( $zone ) {
	$netsref ||= [ allip ];
	add_group_to_zone( $zone, $zoneref->{type}, $interface, $netsref, $hostoptionsref );
	add_group_to_zone( $zone, 
			   $zoneref->{type}, 
			   $interface, 
			   [ IPv4_MULTICAST ], 
			   { destonly => 1 } ) if $hostoptionsref->{multicast} && $interfaces{$interface}{zone} ne $zone;
    } 

    progress_message "  Interface \"$currentline\" Validated";

    return $interface;
}

#
# Parse the interfaces file.
#
sub validate_interfaces_file( $ ) {
    my $export = shift;

    my $fn = open_file 'interfaces';

    my @ifaces;

    my $nextinum = 1;

    first_entry "$doing $fn...";

    push @ifaces, process_interface( $nextinum++, $export ) while read_a_line;

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
# Map the passed name to the corresponding physical name in the passed interface
#
sub map_physical( $$ ) {
    my ( $name, $interfaceref ) = @_;
    my $physical = $interfaceref->{physical};
    
    return $physical if $name eq $interfaceref->{name};

    $physical =~ s/\+$//;

    $physical . substr( $name, length  $interfaceref->{root} );
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
	my $root = $interfaceref->{root};
	if ( $i ne $root && substr( $interface, 0, length $root ) eq $root ) {
	    #
	    # Cache this result for future reference. We set the 'name' to the name of the entry that appears in /etc/shorewall/interfaces and we do not set the root;
	    #
	    return $interfaces{$interface} = { options  => $interfaceref->{options}, 
					       bridge   => $interfaceref->{bridge} , 
					       name     => $i , 
					       number   => $interfaceref->{number} ,
					       physical => map_physical( $interface, $interfaceref )
					     };
	}
    }

    0;
}

#
# Return interface number
#
sub interface_number( $ ) {
    $interfaces{$_[0]}{number} || 256;
}

#
# Return the interfaces list
#
sub all_interfaces() {
    @interfaces;
}

#
# Return a list of bridges
#
sub all_bridges() {
    grep ( $interfaces{$_}{options}{bridge} , @interfaces );
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
# Returns the physical interface associated with the passed logical name
#
sub get_physical( $ ) {
    $interfaces{ $_[0] }->{physical};
}

#
# This one doesn't insist that the passed name be the name of a configured interface
#
sub physical_name( $ ) {
    my $device = shift;
    my $devref = known_interface $device;

    $devref ? $devref->{physical} : $device;
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
	my $interfaceref = $interfaces{$interface};
	
	next unless $interfaceref->{root};

	my $optionsref = $interfaceref->{options};
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
# Process a record in the hosts file
#
sub process_host( ) {
    my $ipsec = 0;
    my ($zone, $hosts, $options ) = split_line 2, 3, 'hosts file';

    my $zoneref = $zones{$zone};
    my $type    = $zoneref->{type};

    fatal_error "Unknown ZONE ($zone)" unless $type;
    fatal_error 'Firewall zone not allowed in ZONE column of hosts record' if $type == FIREWALL;

    my $interface;

    if ( $family == F_IPV4 ) {
	if ( $hosts =~ /^([\w.@%-]+\+?):(.*)$/ ) {
	    $interface = $1;
	    $hosts = $2;
	    $zoneref->{options}{complex} = 1 if $hosts =~ /^\+/;
	    fatal_error "Unknown interface ($interface)" unless $interfaces{$interface}{root};
	} else {
	    fatal_error "Invalid HOST(S) column contents: $hosts";
	}
    } elsif ( $hosts =~ /^([\w.@%-]+\+?):<(.*)>\s*$/ || $hosts =~ /^([\w.@%-]+\+?):\[(.*)\]\s*$/   ) {
	$interface = $1;
	$hosts = $2;
	$zoneref->{options}{complex} = 1 if $hosts =~ /^\+/;
	fatal_error "Unknown interface ($interface)" unless $interfaces{$interface}{root};
    } else {
	fatal_error "Invalid HOST(S) column contents: $hosts";
    }

    if ( $type == BPORT ) {
	if ( $zoneref->{bridge} eq '' ) {
	    fatal_error 'Bridge Port Zones may only be associated with bridge ports' unless $interfaces{$interface}{options}{port};
	    $zoneref->{bridge} = $interfaces{$interface}{bridge};
	} elsif ( $zoneref->{bridge} ne $interfaces{$interface}{bridge} ) {
	    fatal_error "Interface $interface is not a port on bridge $zoneref->{bridge}";
	}
    }

    my $optionsref = { dynamic => 0 };

    if ( $options ne '-' ) {
	my @options = split_list $options, 'option';
	my %options = ( dynamic => 0 );

	for my $option ( @options ) {
	    if ( $option eq 'ipsec' ) {
		require_capability 'POLICY_MATCH' , q(The 'ipsec' option), 's';
		$type = IPSEC;
		$zoneref->{options}{complex} = 1;
		$ipsec = 1;
	    } elsif ( $option eq 'norfc1918' ) {
		warning_message "The 'norfc1918' option is no longer supported"
	    } elsif ( $validhostoptions{$option}) {
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
    $hosts = join( '', ALLIP , $hosts ) if substr($hosts, 0, 2 ) eq ',!';

    if ( $hosts eq 'dynamic' ) {
	require_capability( 'IPSET_MATCH', 'Dynamic nets', '');
	my $physical = physical_name $interface;
	$hosts = "+${zone}_${physical}";
	$optionsref->{dynamic} = 1;
	$ipsets{"${zone}_${physical}"} = 1;

    }

    add_group_to_zone( $zone, $type , $interface, [ split_list( $hosts, 'host' ) ] , $optionsref);

    progress_message "   Host \"$currentline\" validated";

    return $ipsec;
}

#
# Validates the hosts file. Generates entries in %zone{..}{hosts}
#
sub validate_hosts_file()
{
    my $ipsec = 0;

    my $fn = open_file 'hosts';

    first_entry "$doing $fn...";

    $ipsec |= process_host while read_a_line;

    $have_ipsec = $ipsec || haveipseczones;

}

#
# Return an indication of whether IPSEC is present
#
sub have_ipsec() {
    return defined $have_ipsec ? $have_ipsec : have_capability 'POLICY_MATCH';
}

#
# Returns a reference to a array of host entries. Each entry is a
# reference to an array containing ( interface , polciy match type {ipsec|none} , network , exclusions );
#
sub find_hosts_by_option( $ ) {
    my $option = $_[0];
    my @hosts;

    for my $zone ( grep $zones{$_}{type} != FIREWALL , @zones ) {
	while ( my ($type, $interfaceref) = each %{$zones{$zone}{hosts}} ) {
	    while ( my ( $interface, $arrayref) = ( each %{$interfaceref} ) ) {
		for my $host ( @{$arrayref} ) {
		    if ( $host->{options}{$option} ) {
			for my $net ( @{$host->{hosts}} ) {
			    push @hosts, [ $interface, $host->{ipsec} , $net , $host->{exclusions}];
			}
		    }
		}
	    }
	}
    }

    for my $interface ( @interfaces ) {
	if ( ! $interfaces{$interface}{zone} && $interfaces{$interface}{options}{$option} ) {
	    push @hosts, [ $interface, 'none', ALLIP , [] ];
	}
    }

    \@hosts;
}

sub all_ipsets() {
    sort keys %ipsets;
}

1;
