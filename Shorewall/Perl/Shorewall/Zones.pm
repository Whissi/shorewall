#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Zones.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010,2011 - Tom Eastep (teastep@shorewall.net)
#
#       Complete documentation is available at http://shorewall.net
#
#       This program is part of Shorewall.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by the
#       Free Software Foundation, either version 2 of the license or, at your
#       option, any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, see <http://www.gnu.org/licenses/>.
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
our @EXPORT = ( qw( NOTHING
		    NUMERIC
		    NETWORK
		    IPSECPROTO
		    IPSECMODE
		    FIREWALL
		    VSERVER
		    LOOPBACK
		    LOCAL
		    IP
		    BPORT
		    IPSEC
		    GROUP
		    NO_UPDOWN
		    NO_SFILTER

		    determine_zones
		    zone_report
		    dump_zone_contents
		    find_zone
		    firewall_zone
		    loopback_zones
		    local_zones
		    defined_zone
		    zone_type
		    zone_interfaces
		    zone_mark
		    all_zones
		    all_parent_zones
		    complex_zones
		    vserver_zones
		    on_firewall_zones
		    off_firewall_zones
		    non_firewall_zones
		    single_interface
		    var_base
		    validate_interfaces_file
		    all_interfaces
		    all_real_interfaces
		    all_plain_interfaces
		    all_bridges
		    managed_interfaces
		    unmanaged_interfaces
		    interface_number
		    interface_origin
		    find_interface
		    known_interface
		    get_physical
		    physical_name
		    have_bridges
		    port_to_bridge
		    source_port_to_bridge
		    interface_is_optional
		    interface_is_required
		    find_interfaces_by_option
		    find_interfaces_by_option1
		    get_interface_option
		    interface_has_option
		    set_interface_option
		    set_interface_provider
		    interface_zone
		    interface_zones
		    verify_required_interfaces
		    validate_hosts_file
		    find_hosts_by_option
		    find_zone_hosts_by_option
		    find_zones_by_option
		    all_ipsets
		    have_ipsec
		 ),
	      );

our @EXPORT_OK = qw( initialize );
our $VERSION = 'MODULEVERSION';

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
# Option columns
#
use constant { IN_OUT     => 1,
	       IN         => 2,
	       OUT        => 3 };

#
# Zone Table.
#
#     @zones contains the ordered list of zones with sub-zones appearing before their parents.
#
#     %zones{<zone1> => {name =>       <name>,
#                        type =>       <zone type>       FIREWALL, IP, IPSEC, BPORT;
#                        complex =>    0|1
#                        super   =>    0|1
#                        options =>    { in_out  => < policy match string >
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
our %zonetypes;
our $firewall_zone;
our @loopback_zones;
our @local_zones;

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
#                                                    { <option1> } => <val1> ,          #See %validinterfaceoptions
#                                                      ...
#                                                    }
#                                     zone        => <zone name>
#                                     multizone   => undef|1   #More than one zone interfaces through this interface
#                                     nets        => <number of nets in interface/hosts records referring to this interface>
#                                     bridge      => <bridge name> # Same as ->{name} if not a bridge port.
#                                     ports       => <number of port on this bridge>
#                                     ipsec       => undef|1 # Has an ipsec host group
#                                     broadcasts  => 'none', 'detect' or [ <addr1>, <addr2>, ... ]
#                                     number      => <ordinal position in the interfaces file>
#                                     physical    => <physical interface name>
#                                     base        => <shell variable base representing this interface>
#                                     provider    => <Provider Name, if interface is associated with a provider>
#                                     wildcard    => undef|1 # Wildcard Name
#                                     zones       => { zone1 => 1, ... }
#                                   }
#                 }
#
#    The purpose of the 'base' member is to ensure that the base names associated with the physical interfaces are assigned in
#    the same order as the interfaces are encountered in the configuration files.
#
our @interfaces;
our %interfaces;
our %roots;
our @bport_zones;
our %ipsets;
our %physical;
our %basemap;
our %basemap1;
our %mapbase;
our %mapbase1;
our $family;
our $upgrade;
our $have_ipsec;
our $baseseq;
our $minroot;
our $zonemark;
our $zonemarkincr;
our $zonemarklimit;

use constant { FIREWALL => 1,
	       IP       => 2,
	       BPORT    => 4,
	       IPSEC    => 8,
	       VSERVER  => 16,
	       LOOPBACK => 32,
	       LOCAL    => 64,
	   };

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
	       IF_OPTION_VSERVER  => 32,
	       IF_OPTION_WILDOK   => 64
	   };

use constant { NO_UPDOWN   => 1, 
	       NO_SFILTER  => 2 };

our %validinterfaceoptions;

our %prohibitunmanaged = (
			  blacklist      => 1,
			  bridge         => 1,
			  destonly       => 1,
			  detectnets     => 1,
			  dhcp           => 1,
			  maclist        => 1,
			  nets           => 1,
			  norfc1918      => 1,
			  nosmurfs       => 1,
			  optional       => 1,
			  routeback      => 1,
			  rpfilter       => 1,
			  sfilter        => 1,
			  tcpflags       => 1,
			  upnp           => 1,
			  upnpclient     => 1,
			 );

our %defaultinterfaceoptions = ( routefilter => 1 , wait => 60, accept_ra => 1 , ignore => 3, routeback => 1 );

our %maxoptionvalue = ( routefilter => 2, mss => 100000 , wait => 120 , ignore => NO_UPDOWN | NO_SFILTER, accept_ra => 2 );

our %validhostoptions;

our %validzoneoptions = ( mss            => NUMERIC,
			  nomark         => NOTHING,
			  blacklist      => NOTHING,
			  dynamic_shared => NOTHING,
			  strict         => NOTHING,
			  next           => NOTHING,
			  reqid          => NUMERIC,
			  spi            => NUMERIC,
			  proto          => IPSECPROTO,
			  mode           => IPSECMODE,
			 "tunnel-src"   => NETWORK,
			 "tunnel-dst"   => NETWORK,
		       );

use constant { UNRESTRICTED => 1, NOFW => 2 , COMPLEX => 8, IN_OUT_ONLY => 16 };
#
# Hash of options that have their own key in the returned hash.
#
our %zonekey = ( mss            => UNRESTRICTED | COMPLEX ,
		 blacklist      => NOFW, 
		 nomark         => NOFW | IN_OUT_ONLY,
		 dynamic_shared => IN_OUT_ONLY );

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
sub initialize( $$ ) {
    ( $family , $upgrade ) = @_;
    @zones = ();
    %zones = ();
    @loopback_zones = ();
    @local_zones = ();
    $firewall_zone = '';
    $have_ipsec = undef;

    @interfaces = ();
    %roots = ();
    %interfaces = ();
    @bport_zones = ();
    %ipsets = ();
    %physical = ();
    %basemap = ();
    %basemap1 = ();
    %mapbase = ();
    %mapbase1 = ();
    $baseseq = 0;
    $minroot = 0;

    if ( $family == F_IPV4 ) {
	%validinterfaceoptions = (arp_filter  => BINARY_IF_OPTION,
				  arp_ignore  => ENUM_IF_OPTION,
				  blacklist   => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				  bridge      => SIMPLE_IF_OPTION,
				  destonly    => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				  detectnets  => OBSOLETE_IF_OPTION,
				  dhcp        => SIMPLE_IF_OPTION,
				  ignore      => NUMERIC_IF_OPTION + IF_OPTION_WILDOK,
				  maclist     => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				  logmartians => BINARY_IF_OPTION,
				  nets        => IPLIST_IF_OPTION + IF_OPTION_ZONEONLY + IF_OPTION_VSERVER,
				  norfc1918   => OBSOLETE_IF_OPTION,
				  nosmurfs    => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				  optional    => SIMPLE_IF_OPTION,
				  proxyarp    => BINARY_IF_OPTION,
				  required    => SIMPLE_IF_OPTION,
				  routeback   => BINARY_IF_OPTION + IF_OPTION_ZONEONLY + IF_OPTION_HOST + IF_OPTION_VSERVER,
				  routefilter => NUMERIC_IF_OPTION ,
				  rpfilter    => SIMPLE_IF_OPTION,
				  sfilter     => IPLIST_IF_OPTION,
				  sourceroute => BINARY_IF_OPTION,
				  tcpflags    => BINARY_IF_OPTION + IF_OPTION_HOST,
				  upnp        => SIMPLE_IF_OPTION,
				  upnpclient  => SIMPLE_IF_OPTION,
				  mss         => NUMERIC_IF_OPTION + IF_OPTION_WILDOK,
				  physical    => STRING_IF_OPTION  + IF_OPTION_HOST,
				  unmanaged   => SIMPLE_IF_OPTION,
				  wait        => NUMERIC_IF_OPTION + IF_OPTION_WILDOK,
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
			     mss => 1,
			    );

	%zonetypes = ( 1   => 'firewall',
		       2   => 'ipv4',
		       4   => 'bport4',
		       8   => 'ipsec4',
		       16  => 'vserver',
		       32  => 'loopback',
		       64  => 'local' );
    } else {
	%validinterfaceoptions = (  accept_ra   => NUMERIC_IF_OPTION,
				    blacklist   => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				    bridge      => SIMPLE_IF_OPTION,
				    destonly    => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				    dhcp        => SIMPLE_IF_OPTION,
				    ignore      => NUMERIC_IF_OPTION + IF_OPTION_WILDOK,
				    maclist     => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				    nets        => IPLIST_IF_OPTION + IF_OPTION_ZONEONLY + IF_OPTION_VSERVER,
				    nosmurfs    => SIMPLE_IF_OPTION + IF_OPTION_HOST,
				    optional    => SIMPLE_IF_OPTION,
				    optional    => SIMPLE_IF_OPTION,
				    proxyndp    => BINARY_IF_OPTION,
				    required    => SIMPLE_IF_OPTION,
				    routeback   => BINARY_IF_OPTION + IF_OPTION_ZONEONLY + IF_OPTION_HOST + IF_OPTION_VSERVER,
				    rpfilter    => SIMPLE_IF_OPTION,
				    sfilter     => IPLIST_IF_OPTION,
				    sourceroute => BINARY_IF_OPTION,
				    tcpflags    => BINARY_IF_OPTION + IF_OPTION_HOST,
				    mss         => NUMERIC_IF_OPTION + IF_OPTION_WILDOK,
				    forward     => BINARY_IF_OPTION,
				    physical    => STRING_IF_OPTION + IF_OPTION_HOST,
				    unmanaged   => SIMPLE_IF_OPTION,
				    wait        => NUMERIC_IF_OPTION + IF_OPTION_WILDOK,
				 );
	%validhostoptions = (
			     blacklist => 1,
			     maclist => 1,
			     routeback => 1,
			     tcpflags => 1,
			     mss => 1,
			    );

	%zonetypes = ( 1   => 'firewall',
		       2   => 'ipv6',
		       4   => 'bport6',
		       8   => 'ipsec4',
		       16  => 'vserver',
		       32  => 'loopback',
		       64  => 'local' );
    }
}

#
# Parse the passed option list and return a reference to a hash as follows:
#
# => mss   = <MSS setting>
# => ipsec = <-m policy arguments to match options>
#
sub parse_zone_option_list($$\$$)
{
    my ( $list, $zonetype, $complexref, $column ) = @_;
    my %h;
    my $options = '';
    my $fmt;

    if ( $list ne '-' ) {
	fatal_error "The 'loopback' zone may not have $column OPTIONS" if $zonetype == LOOPBACK;

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

	    $fmt = $validzoneoptions{$e};

	    fatal_error "Invalid Option ($e)" unless $fmt;

	    if ( $fmt eq NOTHING ) {
		fatal_error "Option \"$e\" does not take a value" if defined $val;
	    } else {
		fatal_error "Missing value for option \"$e\""        unless defined $val;
		fatal_error "Invalid value ($val) for option \"$e\"" unless $val =~ /^($fmt)$/;
	    }

	    my $key = $zonekey{$e};

	    if ( $key ) {
		fatal_error "Option '$e' not permitted with this zone type " if $key & NOFW && ($zonetype & ( FIREWALL | VSERVER) );
		fatal_error "Option '$e' is only permitted in the OPTIONS columns" if $key & IN_OUT_ONLY && $column != IN_OUT;
		$$complexref = 1 if $key & COMPLEX;
		$h{$e} = $val || 1;
	    } else {
		fatal_error "The \"$e\" option may only be specified for ipsec zones" unless $zonetype & IPSEC;
		$options .= $invert;
		$options .= "--$e ";
		$options .= "$val "if defined $val;
		$$complexref = 1;
	    }
	}
    }

    $h{ipsec} = $options ? "$options " : '';

    \%h;
}

#
# Set the super option on the passed zoneref and propagate to its parents
#
sub set_super( $ ); #required for recursion

sub set_super( $ ) {
    my $zoneref = shift;

    unless ( $zoneref->{super} ) {
	$zoneref->{super} = 1;
	set_super( $zones{$_} ) for @{$zoneref->{parents}};
    }
}

#
# Process a record in the zones file
#
sub process_zone( \$ ) {
    my $ip = $_[0];

    my @parents;

    my ($zone, $type, $options, $in_options, $out_options ) =
	split_line( 'zones file',
		    { zone => 0, type => 1, options => 2, in_options => 3, out_options => 4 } );

    fatal_error 'ZONE must be specified' if $zone eq '-';

    if ( $zone =~ /(\w+):([\w,]+)/ ) {
	$zone = $1;
	@parents = split_list $2, 'zone';
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
	require_capability 'POLICY_MATCH' , 'IPSEC zones', '';
	$type = IPSEC;
    } elsif ( $type =~ /^bport([46])?$/i ) {
	fatal_error "Invalid zone type ($type)" if $1 && $1 != $family;
	warning_message "Bridge Port zones should have a parent zone" unless @parents || $config{ZONE_BITS};
	$type = BPORT;
	push @bport_zones, $zone;
    } elsif ( $type eq 'firewall' ) {
	fatal_error 'Firewall zone may not be nested' if @parents;
	fatal_error "Only one firewall zone may be defined ($zone)" if $firewall_zone;
	$firewall_zone = $zone;
	add_param( FW => $zone );
	$type = FIREWALL;
    } elsif ( $type eq 'vserver' ) {
	fatal_error 'Vserver zones may not be nested' if @parents;
	$type = VSERVER;
    } elsif ( $type eq '-' ) {
	$type = IP;
	$$ip = 1;
    } elsif ( $type eq 'local' ) {
	push @local_zones, $zone;
	$type = LOCAL;
	$$ip  = 1;
    } elsif ( $type eq 'loopback' ) {
	push @loopback_zones, $zone;
	$type = LOOPBACK;
    } else {
	fatal_error "Invalid zone type ($type)";
    }

    for my $p ( @parents ) {
	fatal_error "Invalid Parent List ($2)" unless $p;
	fatal_error "Unknown parent zone ($p)" unless $zones{$p};

	my $ptype = $zones{$p}{type};

	fatal_error 'Subzones of a Vserver zone not allowed' if $ptype & VSERVER;
	fatal_error 'Subzones of firewall zone not allowed'  if $ptype & FIREWALL;
	fatal_error 'Loopback zones may only be subzones of other loopback zones' if ( $type | $ptype ) & LOOPBACK && $type != $ptype;
	fatal_error 'Local zones may only be subzones of other local zones'       if ( $type | $ptype ) & LOCAL    && $type != $ptype;

	set_super( $zones{$p} ) if $type & IPSEC && ! ( $ptype & IPSEC );

	push @{$zones{$p}{children}}, $zone;
    }

    my $complex = 0;

    my $zoneref = $zones{$zone} = { name       => $zone,
				    type       => $type,
				    parents    => \@parents,
				    bridge     => '',
				    options    => { in_out  => parse_zone_option_list( $options , $type, $complex , IN_OUT ) ,
						    in      => parse_zone_option_list( $in_options , $type , $complex , IN ) ,
						    out     => parse_zone_option_list( $out_options , $type , $complex , OUT ) ,
						  } ,
				    super      => 0 ,
				    complex    => ( $type & IPSEC || $complex ) ,
				    interfaces => {} ,
				    children   => [] ,
				    hosts      => {}
				  };

    if ( $config{ZONE_BITS} ) {
	my $mark;

	if ( $type == FIREWALL ) {
	    $mark = 0;
	} else {
	    unless ( $zoneref->{options}{in_out}{nomark} ) {
		fatal_error "Zone mark overflow - please increase the setting of ZONE_BITS" if $zonemark >= $zonemarklimit;
		$mark      = $zonemark;
		$zonemark += $zonemarkincr;
		$zoneref->{complex} = 1;
	    }
	}

	if ( $zoneref->{options}{in_out}{nomark} ) {
	    progress_message_nocompress "   Zone $zone:\tmark value not assigned";
	} else {
	    progress_message_nocompress "   Zone $zone:\tmark value " . in_hex( $zoneref->{mark} = $mark );
	}
    }

    if ( $zoneref->{options}{in_out}{blacklist} ) {
	warning_message q(The 'blacklist' option is deprecated);
	for ( qw/in out/ ) {
	    unless ( $zoneref->{options}{$_}{blacklist} ) {
		$zoneref->{options}{$_}{blacklist} = 1;
	    } else {
		warning_message( "Redundant 'blacklist' in " . uc( $_ ) . '_OPTIONS' );
	    }
	}
    } else {
	for ( qw/in out/ ) {
	    warning_message q(The 'blacklist' option is deprecated), last if  $zoneref->{options}{$_}{blacklist};
	}
    }

    return $zone;

}
#
# Parse the zones file.
#
sub vserver_zones();

sub determine_zones()
{
    my @z;
    my $ip = 0;

    $zonemark      = 1 << $globals{ZONE_OFFSET};
    $zonemarkincr  = $zonemark;
    $zonemarklimit = $zonemark << $config{ZONE_BITS};

    if ( my $fn = open_file 'zones' ) {
	first_entry "$doing $fn...";
	push @z, process_zone( $ip ) while read_a_line( NORMAL_READ );
    } else {
	fatal_error q(The 'zones' file does not exist or has zero size);
    }

    fatal_error "No firewall zone defined" unless $firewall_zone;
    fatal_error "No IP zones defined" unless $ip;
    fatal_error "Loopback zones and vserver zones are mutually exclusive" if @loopback_zones && vserver_zones;
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

    assert( @zones == @z );

}

#
# Return true of we have any ipsec zones
#
sub haveipseczones() {
    for my $zoneref ( values %zones ) {
	return 1 if $zoneref->{type} & IPSEC;
    }

    0;
}

#
# Report about zones.
#
sub zone_report()
{
    progress_message2 "Determining Hosts in Zones...";

    for my $zone ( @zones ) {
	my $zoneref   = $zones{$zone};
	my $hostref   = $zoneref->{hosts};
	my $type      = $zoneref->{type};
	my $optionref = $zoneref->{options};

	progress_message_nocompress "   $zone ($zonetypes{$type})";

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
	    fatal_error "No bridge has been associated with zone $zone" if $type & BPORT && ! $zoneref->{bridge};
	    warning_message "*** $zone is an EMPTY ZONE ***" unless $type == FIREWALL;
	}

    }
}

#
# This function is called to create the contents of the ${VARDIR}/zones file
#
sub dump_zone_contents() {
    for my $zone ( @zones )
    {
	my $zoneref    = $zones{$zone};
	my $hostref    = $zoneref->{hosts};
	my $type       = $zoneref->{type};
	my $optionref  = $zoneref->{options};

	my $entry      =  "$zone $zonetypes{$type}";

	$entry .= ":$zoneref->{bridge}" if $type & BPORT;
	$entry .= ( " mark=" . in_hex( $zoneref->{mark} ) ) if exists $zoneref->{mark};

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

sub add_group_to_zone($$$$$$)
{
    my ($zone, $type, $interface, $networks, $options, $inherit_options) = @_;
    my $hostsref;
    my $typeref;
    my $interfaceref;
    my $zoneref  = $zones{$zone};
    my $zonetype = $zoneref->{type};

    $interfaceref = $interfaces{$interface};
    $zoneref->{interfaces}{$interface} = 1;
    $zoneref->{destonly} ||= $interfaceref->{options}{destonly};
    $options->{destonly} ||= $interfaceref->{options}{destonly};

    if ( $inherit_options && $type== $zonetype && $type != IPSEC ) {
	#
	# Make 'find_hosts_by_option()' work correctly for this zone
	#
	for ( qw/blacklist maclist nosmurfs tcpflags/ ) {
	    $options->{$_} = $interfaceref->{options}{$_} if $interfaceref->{options}{$_} && ! exists $options->{$_}; 
	}
    }

    $interfaceref->{zones}{$zone} = 1;

    my @newnetworks;
    my @exclusions = ();
    my $new = \@newnetworks;
    my $switched = 0;
    my $allip    = 0;

    for my $host ( @$networks ) {
	$interfaceref->{nets}++;

	fatal_error "Invalid Host List" unless supplied $host;

	if ( substr( $host, 0, 1 ) eq '!' ) {
	    fatal_error "Only one exclusion allowed in a host list" if $switched;
	    $switched = 1;
	    $host = substr( $host, 1 );
	    $new = \@exclusions;
	}

	if ( substr( $host, 0, 1 ) eq '+' ) {
	    fatal_error "Invalid ipset name ($host)" unless $host =~ /^\+(6_)?[a-zA-Z][-\w]*$/;
	    require_capability( 'IPSET_MATCH', 'Ipset names in host lists', '');
	} else {
	    $host = validate_host $host, 0;
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

	push @$new, $host;
    }

    $zoneref->{options}{in_out}{routeback} = 1 if $options->{routeback};

    my $gtype = $type & IPSEC ? 'ipsec' : 'ip';

    $hostsref     = ( $zoneref->{hosts}      ||= {} );
    $typeref      = ( $hostsref->{$gtype}    ||= {} );
    $interfaceref = ( $typeref->{$interface} ||= [] );

    fatal_error "Duplicate Host Group ($interface:" . ALLIP . ") in zone $zone" if $allip && @$interfaceref;

    $zoneref->{complex} = 1 if @$interfaceref || @newnetworks > 1 || @exclusions || $options->{routeback};

    push @{$interfaceref}, { options => $options,
			     hosts   => \@newnetworks,
			     ipsec   => $type & IPSEC ? 'ipsec' : 'none' ,
			     exclusions => \@exclusions };

    if ( $type != IPSEC ) {
	my $optref = $interfaces{$interface}{options};
	$optref->{routeback} ||= $options->{routeback};
	$optref->{allip}     ||= $allip;
    }
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

sub zone_mark( $ ) {
    my $zoneref = find_zone( $_[0] );
    fatal_error "Zone $_[0] has no assigned mark" unless exists $zoneref->{mark};
    $zoneref->{mark};
}

sub defined_zone( $ ) {
    $zones{$_[0]};
}

sub all_zones() {
    @zones;
}

sub on_firewall_zones() {
   grep ( ( $zones{$_}{type} & ( FIREWALL | VSERVER ) )  ,  @zones );
}

sub off_firewall_zones() {
   grep ( ! ( $zones{$_}{type} & ( FIREWALL | VSERVER ) )  ,  @zones );
}

sub non_firewall_zones() {
   grep ( ! ( $zones{$_}{type} & FIREWALL ) ,  @zones );
}

sub all_parent_zones() {
    #
    # Although the firewall zone is technically a parent zone, we let the caller decide
    # if it is to be included or not.
    #
    grep ( ! @{$zones{$_}{parents}} , off_firewall_zones );
}

sub complex_zones() {
    grep( $zones{$_}{complex} , @zones );
}

sub vserver_zones() {
    grep ( $zones{$_}{type} & VSERVER, @zones );
}

sub firewall_zone() {
    $firewall_zone;
}

sub loopback_zones() {
    @loopback_zones;
}

sub local_zones() {
    @local_zones;
}

#
# Determine if the passed physical device is a bridge
#
sub is_a_bridge( $ ) {
    which 'brctl' && system( "brctl show < /dev/null | tail -n+2 | grep -q '^$_[0]\[\[:space:\]\]' > /dev/null" ) == 0;
}

#
# Transform the passed interface name into a legal shell variable name.
#
sub var_base($) {
    my $var = $_[0];
    my $name  = $basemap{$var};
    #
    # Return existing mapping, if any
    #
    return $name if $name;
    #
    # Remember initial value
    #
    my $key = $var;
    #
    # Handle VLANs and wildcards
    #
    $var =~ s/\+$/_plus/;
    $var =~ tr/./_/;

    if ( $var eq '' || $var =~ /^[0-9]/ || $var =~ /[^\w]/ ) {
	#
	# Must map. Remove all illegal characters
	#
	$var =~ s/[^\w]//g;
	#
	# Prefix with if_ if it begins with a digit
	#
	$var = join( '' , 'if_', $var ) if $var =~ /^[0-9]/;
	#
	# Create a new unique name
	#
	1 while $mapbase{$name = join ( '_', $var, ++$baseseq )};
    } else {
	#
	# We'll store the identity mapping if it is unique
	#
	$var = join( '_', $key , ++$baseseq ) while $mapbase{$name = $var};
    }
    #
    # Store the reverse mapping
    #
    $mapbase{$name} = $key;
    #
    # Store the mapping
    #
    $basemap{$key} = $name;
}

#
# This is a slightly relaxed version of the above that allows '-' in the generated name.
#
sub var_base1($) {
    my $var = $_[0];
    my $name  = $basemap1{$var};
    #
    # Return existing mapping, if any
    #
    return $name if $name;
    #
    # Remember initial value
    #
    my $key = $var;
    #
    # Handle VLANs and wildcards
    #
    $var =~ s/\+$//;
    $var =~ tr/./_/;

    if ( $var eq '' || $var =~ /^[0-9]/ || $var =~ /[^-\w]/ ) {
	#
	# Must map. Remove all illegal characters
	#
	$var =~ s/[^\w]//g;
	#
	# Prefix with if_ if it begins with a digit
	#
	$var = join( '' , 'if_', $var ) if $var =~ /^[0-9]/;
	#
	# Create a new unique name
	#
	1 while $mapbase1{$name = join ( '_', $var, ++$baseseq )};
    } else {
	#
	# We'll store the identity mapping if it is unique
	#
	$var = join( '_', $key , ++$baseseq ) while $mapbase1{$name = $var};
    }
    #
    # Store the reverse mapping
    #
    $mapbase1{$name} = $key;
    #
    # Store the mapping
    #
    $basemap1{$key} = $name;
}

#
# Process a record in the interfaces file
#
sub process_interface( $$ ) {
    my ( $nextinum, $export ) = @_;
    my $netsref   = '';
    my $filterref = [];
    my ($zone, $originalinterface, $bcasts, $options );
    my $zoneref;
    my $bridge = '';

    if ( $file_format == 1 ) {
	($zone, $originalinterface, $bcasts, $options ) =
	    split_line1( 'interfaces file',
			 { zone => 0, interface => 1, broadcast => 2, options => 3 } );
    } else {
	($zone, $originalinterface, $options ) = split_line1( 'interfaces file',
							      { zone => 0, interface => 1, options => 2 } );
	$bcasts = '-';
    }

    if ( $zone eq '-' ) {
	$zone = '';
    } else {
	$zoneref = $zones{$zone};

	fatal_error "Unknown zone ($zone)" unless $zoneref;
	fatal_error "Firewall zone not allowed in ZONE column of interface record" if $zoneref->{type} == FIREWALL;
    }

    fatal_error 'INTERFACE must be specified' if $originalinterface eq '-';

    my ($interface, $port, $extra) = split /:/ , $originalinterface, 3;

    fatal_error "Invalid INTERFACE ($originalinterface)" if ! $interface || defined $extra;

    if ( supplied $port ) {
	fatal_error qq("Virtual" interfaces are not supported -- see http://www.shorewall.net/Shorewall_and_Aliased_Interfaces.html) if $port =~ /^\d+$/;
	require_capability( 'PHYSDEV_MATCH', 'Bridge Ports', '');
	fatal_error "Your iptables is not recent enough to support bridge ports" unless $globals{KLUDGEFREE};

	fatal_error "Invalid Interface Name ($interface:$port)" unless $port =~ /^[\w.@%-]+\+?$/;
	fatal_error "Duplicate Interface ($port)" if $interfaces{$port};

	fatal_error "$interface is not a defined bridge" unless $interfaces{$interface} && $interfaces{$interface}{options}{bridge};
	$interfaces{$interface}{ports}++;
	fatal_error "Bridge Ports may only be associated with 'bport' zones" if $zone && ! ( $zoneref->{type} & BPORT );

	if ( $zone ) {
	    if ( $zoneref->{bridge} ) {
		fatal_error "Bridge Port zones may only be associated with a single bridge" if $zoneref->{bridge} ne $interface;
	    } else {
		$zoneref->{bridge} = $interface;
	    }

	    fatal_error "Vserver zones may not be associated with bridge ports" if $zoneref->{type} & VSERVER;
	}

	$bridge = $interface;
	$interface = $port;
    } else {
	fatal_error "Duplicate Interface ($interface)" if $interfaces{$interface};
	fatal_error "Zones of type 'bport' may only be associated with bridge ports" if $zone && $zoneref->{type} & BPORT;
	fatal_error "Vserver zones may not be associated with interfaces" if $zone && $zoneref->{type} & VSERVER;

	$bridge = $interface;
    }

    my $wildcard = 0;
    my $root;

    if ( $interface =~ /\+$/ ) {
	$wildcard = 1;
	$root = substr( $interface, 0, -1 );
	$roots{$root} = $interface;
	my $len = length $root;

	if ( $minroot ) {
	    $minroot = $len if $minroot > $len;
	} else {
	    $minroot = $len;
	}
    } else {
	$root = $interface;
    }

    fatal_error "Invalid interface name ($interface)" if $interface =~ /\*/;

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

    if ( $options eq 'ignore' ) {
	fatal_error "Ignored interfaces may not be associated with a zone" if $zone;
	$options{ignore} = NO_UPDOWN | NO_SFILTER;
	$options = '-';
    }

    if ( $options ne '-' ) {

	my %hostoptions = ( dynamic => 0 );

	for my $option (split_list1 $options, 'option' ) {
	    next if $option eq '-';

	    ( $option, my $value ) = split /=/, $option;

	    fatal_error "Invalid Interface option ($option)" unless my $type = $validinterfaceoptions{$option};

	    if ( $zone ) {
		fatal_error qq(The "$option" option may not be specified for a Vserver zone") if $zoneref->{type} & VSERVER && ! ( $type & IF_OPTION_VSERVER );
	    } else {
		fatal_error "The \"$option\" option may not be specified on a multi-zone interface" if $type & IF_OPTION_ZONEONLY;
	    }

	    my $hostopt = $type & IF_OPTION_HOST;

	    fatal_error "The \"$option\" option is not allowed on a bridge port" if $port && ! $hostopt;

	    $type &= MASK_IF_OPTION;

	    if ( $type == SIMPLE_IF_OPTION ) {
		fatal_error "Option $option does not take a value" if defined $value;
		if ( $option eq 'blacklist' ) {
		    if ( $zone ) {
			$zoneref->{options}{in}{blacklist} = 1;
		    } else {
			warning_message "The 'blacklist' option is ignored on multi-zone interfaces";
		    }
		} else {
		    $options{$option} = 1;
		    $hostoptions{$option} = 1 if $hostopt;
		}
	    } elsif ( $type == BINARY_IF_OPTION ) {
		$value = 1 unless defined $value;
		fatal_error "Option value for '$option' must be 0 or 1" unless ( $value eq '0' || $value eq '1' );
		fatal_error "The '$option' option may not be used with a wild-card interface name" if $wildcard && ! $type && IF_OPTION_WILDOK;
		$options{$option} = $value;
		$hostoptions{$option} = $value if $hostopt;
	    } elsif ( $type == ENUM_IF_OPTION ) {
		if ( $option eq 'arp_ignore' ) {
		    fatal_error q(The 'arp_ignore' option may not be used with a wild-card interface name) if $wildcard;
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
		fatal_error "The '$option' option may not be specified on a wildcard interface" if $wildcard && ! $type && IF_OPTION_WILDOK;
		$value = $defaultinterfaceoptions{$option} unless defined $value;
		fatal_error "The '$option' option requires a value" unless defined $value;
		my $numval = numeric_value $value;
		fatal_error "Invalid value ($value) for option $option" unless defined $numval && $numval <= $maxoptionvalue{$option};
		$options{$option} = $numval;
		$hostoptions{$option} = $numval if $hostopt;
	    } elsif ( $type == IPLIST_IF_OPTION ) {
		fatal_error "The '$option' option requires a value" unless defined $value;
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
		} elsif ( $option eq 'sfilter' ) {
		    $filterref = [ split_list $value, 'address' ];
		    validate_net( $_, 0) for @{$filterref}
		} else {
		    assert(0);
		}
	    } elsif ( $type == STRING_IF_OPTION ) {
		fatal_error "The '$option' option requires a value" unless defined $value;

		if ( $option eq 'physical' ) {
		    fatal_error "Invalid Physical interface name ($value)" unless $value && $value !~ /%/;
		    fatal_error "Virtual interfaces ($value) are not supported" if $value =~ /:\d+$/;

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

	fatal_error q(The 'required', 'optional' and 'ignore' options are mutually exclusive)
	    if ( ( $options{required} && $options{optional} ) ||
		 ( $options{required} && $options{ignore}   ) ||
		 ( $options{optional} && $options{ignore}   ) );

	if ( $options{rpfilter} ) {
	    require_capability( 'RPFILTER_MATCH', q(The 'rpfilter' option), 's' ) ;
	    fatal_error q(The 'routefilter', 'sfilter' and 'rpfilter' options are mutually exclusive) if $options{routefilter} || @$filterref;
	} else {
	    fatal_error q(The 'routefilter', 'sfilter' and 'rpfilter' options are mutually exclusive) if $options{routefilter} && @$filterref;
	}

	if ( supplied( my $ignore = $options{ignore} ) ) {
	    fatal_error "Invalid value ignore=0" if ! $ignore;
	} else {
	    $options{ignore} = 0;
	}

	if ( $netsref eq 'dynamic' ) {
	    my $ipset = $family == F_IPV4 ? "${zone}" : "6_${zone}";
	    $ipset = join( '_', $ipset, var_base1( $physical ) ) unless $zoneref->{options}{in_out}{dynamic_shared};	    
	    $netsref = [ "+$ipset" ];
	    $ipsets{$ipset} = 1;
	}

	if ( $options{bridge} ) {
	    require_capability( 'PHYSDEV_MATCH', 'The "bridge" option', 's');
	    fatal_error "Bridges may not have wildcard names" if $wildcard;
	    $hostoptions{routeback} = $options{routeback} = 1 unless supplied $options{routeback};
	}

	$hostoptions{routeback} = $options{routeback} = is_a_bridge( $physical ) unless $export || supplied $options{routeback} || $options{unmanaged};

	$hostoptionsref = \%hostoptions;
    } else {
	#
	# No options specified -- auto-detect bridge
	#
	$hostoptionsref->{routeback} = $options{routeback} = is_a_bridge( $physical ) unless $export;
	#
	# And give the 'ignore' option a defined value
	#
	$options{ignore} ||= 0;
    }

    if ( $options{unmanaged} ) {
	fatal_error "The 'lo' interface may not be unmanaged when there are vserver zones" if $physical eq 'lo' && vserver_zones;

	while ( my ( $option, $value ) = each( %options ) ) {
	    fatal_error "The $option option may not be specified with 'unmanaged'" if $prohibitunmanaged{$option};
	}
    } else {
	$options{tcpflags} = $hostoptionsref->{tcpflags} = 1 unless exists $options{tcpflags};
    }

    $physical{$physical} = $interfaces{$interface} = { name       => $interface ,
						       bridge     => $bridge ,
						       filter     => $filterref ,
						       nets       => 0 ,
						       number     => $nextinum ,
						       root       => $root ,
						       broadcasts => $broadcasts ,
						       options    => \%options ,
						       zone       => '',
						       physical   => $physical ,
						       base       => var_base( $physical ),
						       zones      => {},
						       origin     => shortlineinfo(''),
						       wildcard   => $wildcard,
						     };

    if ( $zone ) {
	fatal_error "Unmanaged interfaces may not be associated with a zone" if $options{unmanaged};

	if ( $physical eq 'lo' ) {
	    fatal_error "Only a loopback zone may be assigned to 'lo'" unless $zoneref->{type} == LOOPBACK;
	    fatal_error "Invalid definition of 'lo'"                   if $bridge ne $interface;
	    
	    for ( qw/arp_filter
		     arp_ignore
		     blacklist
		     bridge
		     detectnets
		     dhcp
		     maclist
		     logmartians
		     norfc1918
		     nosmurts
		     proxyarp
		     routeback
		     routefilter
		     rpfilter
		     sfilter
		     sourceroute
		     upnp
		     upnpclient
		     mss
		    / ) {
		fatal_error "The 'lo' interface may not specify the '$_' option" if supplied $options{$_};
	    }
	} else {
	    fatal_error "A loopback zone may only be assigned to 'lo'" if $zoneref->{type} == LOOPBACK;
	}

	$netsref ||= [ allip ];
	add_group_to_zone( $zone, $zoneref->{type}, $interface, $netsref, $hostoptionsref , 1);
	add_group_to_zone( $zone,
			   $zoneref->{type},
			   $interface,
			   $family == F_IPV4 ? [ IPv4_MULTICAST ] : [ IPv6_MULTICAST ] ,
			   { destonly => 1 },
			   0) if $hostoptionsref->{multicast} && $interfaces{$interface}{zone} ne $zone;
    }

    progress_message "  Interface \"$currentline\" Validated";

    return $interface;
}

#
# Parse the interfaces file.
#
sub validate_interfaces_file( $ ) {
    my  $export = shift;

    my @ifaces;
    my $nextinum = 1;

    if ( my $fn = open_file 'interfaces', 2 ) {
	first_entry "$doing $fn...";
	push @ifaces, process_interface( $nextinum++, $export ) while read_a_line( NORMAL_READ );
    } else {
	fatal_error q(The 'interfaces' file does not exist or has zero size);
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

    if ( vserver_zones ) {
	#
	# While the user thinks that vservers are associated with a particular interface, they really are not.
	# We create an interface to associated them with.
	#
	my $interface = '%vserver%';

	$interfaces{$interface} = { name       => $interface ,
				    bridge     => $interface ,
				    nets       => 0 ,
				    number     => $nextinum ,
				    root       => $interface ,
				    broadcasts => undef ,
				    options    => {} ,
				    zone       => '',
				    physical   => 'lo',
				  };

	push @interfaces, $interface;
    }
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
# If the passed name matches a wildcard, an entry for the name is added to %interfaces.
#
sub known_interface($)
{
    my $interface = shift;
    my $interfaceref = $interfaces{$interface};

    return $interfaceref if $interfaceref;

    fatal_error "Invalid interface ($interface)" if $interface =~ /\*/;

    my $iface = $interface;

    if ( $minroot ) {
	while ( length $iface > $minroot ) {
	    chop $iface;

	    if ( my $i = $roots{$iface} ) {
		$interfaceref = $interfaces{$i};

		my $physical = map_physical( $interface, $interfaceref );

		return $interfaces{$interface} = { options  => $interfaceref->{options} ,
						   bridge   => $interfaceref->{bridge} ,
						   name     => $i ,
						   number   => $interfaceref->{number} ,
						   physical => $physical ,
						   base     => var_base( $physical ) ,
						   wildcard => $interfaceref->{wildcard} ,
						   zones    => $interfaceref->{zones} ,
						 };
	    }
	}
    }

    $physical{$interface} || 0;
}

#
# Return interface number
#
sub interface_number( $ ) {
    $interfaces{$_[0]}{number} || 256;
}

#
# Return interface origin
#
sub interface_origin( $ ) {
    $interfaces{$_[0]}->{origin};
}

#
# Return the interfaces list
#
sub all_interfaces() {
    @interfaces;
}

#
# Return all managed non-vserver interfaces
#
sub all_real_interfaces() {
    grep $_ ne '%vserver%' && ! $interfaces{$_}{options}{unmanaged}, @interfaces;
}

#
# Return a list of bridges
#
sub all_bridges() {
    grep ( $interfaces{$_}{options}{bridge} , @interfaces );
}

#
# Return a list of managed interfaces
#
sub managed_interfaces() {
    grep (! $interfaces{$_}{options}{unmanaged} , @interfaces );
}

#
# Return a list of unmanaged interfaces (skip 'lo' since it is implicitly unmanaged when there are no loopback zones).
#
sub unmanaged_interfaces() {
    grep ( $interfaces{$_}{options}{unmanaged} && $_ ne 'lo', @interfaces );
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
# Returns a hash reference for the zones interface through the interface
#
sub interface_zones( $ ) {
    my $interfaceref = known_interface( $_[0] );

    fatal_error "Unknown interface(@_)" unless $interfaceref;
    $interfaceref->{zones} || {};
}

#
# Returns the 'zone' member of the passed interface, if any
#
sub interface_zone( $ ) {
    my $interfaceref = known_interface( $_[0] );

    $interfaceref ? $interfaceref->{zone} : '';
}

#
# Return the 'optional' setting of the passed interface
#
sub interface_is_optional($) {
    my $optionsref = $interfaces{$_[0]}{options};
    $optionsref && $optionsref->{optional};
}

#
# Return the 'required' setting of the passed interface
#
sub interface_is_required($) {
    my $optionsref = $interfaces{$_[0]}{options};
    $optionsref && $optionsref->{required};
}

#
# Return true if the interface is 'plain'
#
sub interface_is_plain($) {
    my $interfaceref = $interfaces{$_[0]};
    my $optionsref   = $interfaceref->{options};

    $interfaceref->{bridge} eq $interfaceref->{name} && ! ( $optionsref && ( $optionsref->{required} || $optionsref->{optional} || $optionsref->{ignore} ) )
}

#
# Return a minimal list of physical interfaces that are neither ignored, optional, required nor a bridge port.
#
sub all_plain_interfaces() {
    my @plain1 = map get_physical($_), grep $_ ne '%vserver%' && interface_is_plain( $_ ), @interfaces;
    my @plain2;
    my @wild1;
    my @wild2;
   
    for ( @plain1 ) {
	if ( /\+$/ ) {
	    return ( '+' ) if $_ eq '+';
	    push @wild1, $_;
	    chop;
	    push @wild2, $_;
	} else {
	    push @plain2, $_;
	}
    }

    return @plain2 unless @wild1;

    @plain1 = ();

NAME:
    for my $name ( @plain2) {
	for ( @wild2 ) {
	    next NAME if substr( $name, 0, length( $_ ) ) eq $_;
	}

	push @plain1, $name;
    }

    ( @plain1, @wild1 );
}

#
# Returns reference to array of interfaces with the passed option
#
sub find_interfaces_by_option( $;$ ) {
    my ( $option , $nonzero ) = @_;
    my @ints = ();

    for my $interface ( @interfaces ) {
	my $interfaceref = $interfaces{$interface};

	next unless $interfaceref->{root};

	my $optionsref = $interfaceref->{options};
	if ( $nonzero ) {
	    if ( $optionsref && $optionsref->{$option} ) {
		push @ints , $interface
	    }
	} elsif ( $optionsref && defined $optionsref->{$option} ) {
	    push @ints , $interface
	}
    }

    \@ints;
}

#
# Returns reference to array of interfaces with the passed option. Unlike the preceding function, this one:
#
# - All entries in %interfaces are searched.
# - Returns a two-element list; the second element indicates whether any members of the list have wildcard physical names
#
sub find_interfaces_by_option1( $ ) {
    my $option = $_[0];
    my @ints = ();
    my $wild = 0;

    for my $interface ( sort { $interfaces{$a}->{number} <=> $interfaces{$b}->{number} } keys %interfaces ) {
	my $interfaceref = $interfaces{$interface};

	next unless defined $interfaceref->{physical};

	my $optionsref = $interfaceref->{options};

	if ( $optionsref && defined $optionsref->{$option} ) {
	    $wild ||= $interfaceref->{wildcard};
	    push @ints , $interface
	}
    }

    return unless defined wantarray;

    wantarray ? ( \@ints, $wild ) : \@ints;
}

#
# Return the value of an option for an interface
#
sub get_interface_option( $$ ) {
    my ( $interface, $option ) = @_;

    my $ref = $interfaces{$interface};

    return $ref->{options}{$option} if $ref;

    assert( $ref = known_interface( $interface ) );

    $ref->{options}{$option};

}

#
# Return the value of an option for an interface
#
sub interface_has_option( $$\$ ) {
    my ( $interface, $option, $value ) = @_;

    my $ref = $interfaces{$interface};

    $ref = known_interface( $interface ) unless $ref;

    if ( exists $ref->{options}{$option} ) {
	$$value = $ref->{options}{$option};
	1;
    }
}

#
# Set an option for an interface
#
sub set_interface_option( $$$ ) {
    my ( $interface, $option, $value ) = @_;

    $interfaces{$interface}{options}{$option} = $value;
}

#
# Verify that all required interfaces are available after waiting for any that specify the 'wait' option.
#
sub verify_required_interfaces( $ ) {

    my $generate_case = shift;

    my $returnvalue = 0;

    my $interfaces = find_interfaces_by_option 'wait';

    if ( @$interfaces ) {
	my $first = 1;

	emit( "local waittime\n" );

	emit( 'case "$COMMAND" in' );

	push_indent;

	emit( 'start|restart|restore)' );

	push_indent;

	for my $interface (@$interfaces ) {
	    my $wait = $interfaces{$interface}{options}{wait};

	    emit q() unless $first-- > 0;

	    if ( $wait ) {
		my $physical = get_physical $interface;

		if ( $physical =~ /\+$/ ) {
		    $physical =~ s/\+$/*/;

		    emit( "waittime=$wait",
			  '',
			  'for interface in $(find_all_interfaces); do',
			  '    case $interface in',
			  "        $physical)",
			  '            while [ $waittime -gt 0 ]; do',
			  '                interface_is_usable $interface && break',
			  '                sleep 1',
			  '                waittime=$(($waittime - 1))',
			  '            done',
			  '            ;;',
			  '    esac',
			  'done',
			  '',
			);
		} else {
		    emit qq(if ! interface_is_usable $physical; then);
		    emit qq(    waittime=$wait);
		    emit  '';
		    emit  q(    while [ $waittime -gt 0 ]; do);
		    emit  q(        sleep 1);
		    emit qq(        interface_is_usable $physical && break);
		    emit   '        waittime=$(($waittime - 1))';
		    emit  q(    done);
		    emit  q(fi);
		}

		$returnvalue = 1;
	    }
	}

	emit( ";;\n" );

	pop_indent;
	pop_indent;

	emit( "esac\n" );

    }

    $interfaces = find_interfaces_by_option 'required';

    if ( @$interfaces ) {

	if ( $generate_case ) {
	    emit( 'case "$COMMAND" in' );
	    push_indent;
	    emit( 'start|restart|restore|refresh)' );
	    push_indent;
	}

	for my $interface (@$interfaces ) {
	    my $physical = get_physical $interface;

	    if ( $physical =~ /\+$/ ) {
		my $base = uc var_base $physical;

		$physical =~ s/\+$/*/;

		emit( "SW_${base}_IS_UP=\n",
		      'for interface in $(find_all_interfaces); do',
		      '    case $interface in',
		      "        $physical)",
		      "            interface_is_usable \$interface && SW_${base}_IS_UP=Yes && break",
		      '            ;;',
		      '    esac',
		      'done',
		      '',
		      "if [ -z \"\$SW_${base}_IS_UP\" ]; then",
		      "    startup_error \"None of the required interfaces $physical are available\"",
		      "fi\n"
		    );
	    } else {
		emit qq(if ! interface_is_usable $physical; then);
		emit qq(    startup_error "Required interface $physical not available");
		emit qq(fi\n);
	    }
	}

	if ( $generate_case ) {
	    emit( ';;' );
	    pop_indent;
	    pop_indent;
	    emit( 'esac' );
	}

	$returnvalue = 1;
    }

    $returnvalue;
}

#
# Process a record in the hosts file
#
sub process_host( ) {
    my $ipsec = 0;
    my ($zone, $hosts, $options ) = split_line1( 'hosts file',
						 { zone => 0, host => 1, hosts => 1, options => 2 },
						 {},
						 3 );

    fatal_error 'ZONE must be specified'  if $zone eq '-';
    fatal_error 'HOSTS must be specified' if $hosts eq '-';

    my $zoneref = $zones{$zone};
    my $type    = $zoneref->{type};

    fatal_error "Unknown ZONE ($zone)" unless $type;
    fatal_error 'Firewall zone not allowed in ZONE column of hosts record' if $type == FIREWALL;

    my ( $interface, $interfaceref );

    if ( $family == F_IPV4 ) {
	if ( $hosts =~ /^([\w.@%-]+\+?):(.*)$/ ) {
	    $interface = $1;
	    $hosts = $2;
	    fatal_error "Unknown interface ($interface)" unless ($interfaceref = $interfaces{$interface}) && $interfaceref->{root};
	} else {
	    fatal_error "Invalid HOST(S) column contents: $hosts";
	}
    } elsif ( $hosts =~ /^([\w.@%-]+\+?):<(.*)>$/               ||
	      $hosts =~ /^([\w.@%-]+\+?)\[(.*)\]$/              ||
	      $hosts =~ /^([\w.@%-]+\+?):(!?\[.+\](?:\/\d+)?)$/ ||
	      $hosts =~ /^([\w.@%-]+\+?):(!?\+.*)$/             ||
	      $hosts =~ /^([\w.@%-]+\+?):(dynamic)$/ ) {
	$interface = $1;
	$hosts = $2;

	fatal_error "Unknown interface ($interface)" unless ($interfaceref = $interfaces{$interface}) && $interfaceref->{root};
	fatal_error "Unmanaged interfaces may not be associated with a zone" if $interfaceref->{unmanaged};

	if ( $interfaceref->{name} eq 'lo' ) {
	    fatal_error "Only a loopback zone may be associated with the loopback interface (lo)" if $type != LOOPBACK;
	} else {
	    fatal_error "Loopback zones may only be associated with the loopback interface (lo)" if $type == LOOPBACK;
	}
    } else {
	fatal_error "Invalid HOST(S) column contents: $hosts"
    }

    if ( $hosts =~ /^!?\+/ ) {
       $zoneref->{complex} = 1;
       fatal_error "ipset name qualification is disallowed in this file" if $hosts =~ /[\[\]]/;
       fatal_error "Invalid ipset name ($hosts)" unless $hosts =~ /^!?\+[a-zA-Z][-\w]*$/;
    }

    if ( $type & BPORT ) {
	if ( $zoneref->{bridge} eq '' ) {
	    fatal_error 'Bridge Port Zones may only be associated with bridge ports' unless $interfaceref->{options}{port};
	    $zoneref->{bridge} = $interfaces{$interface}{bridge};
	} elsif ( $zoneref->{bridge} ne $interfaceref->{bridge} ) {
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
		$zoneref->{complex} = 1;
		$ipsec = $interfaceref->{ipsec} = 1;
	    } elsif ( $option eq 'norfc1918' ) {
		warning_message "The 'norfc1918' host option is no longer supported"
	    } elsif ( $option eq 'blacklist' ) {
		warning_message "The 'blacklist' option is deprecated";
		$zoneref->{options}{in}{blacklist} = 1;
	    } elsif ( $option =~ /^mss=(\d+)$/ ) {
		fatal_error "Invalid mss ($1)" unless $1 >= 500;
		$options{mss} = $1;
		$zoneref->{options}{complex} = 1;
	    } elsif ( $validhostoptions{$option}) {
		fatal_error qq(The "$option" option is not allowed with Vserver zones) if $type & VSERVER && ! ( $validhostoptions{$option} & IF_OPTION_VSERVER );
		$options{$option} = 1;
	    } else {
		fatal_error "Invalid option ($option)";
	    }
	}

	fatal_error q(A host entry for a Vserver zone may not specify the 'ipsec' option) if $ipsec && $zoneref->{type} & VSERVER;

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
	fatal_error "Vserver zones may not be dynamic" if $type & VSERVER;
	require_capability( 'IPSET_MATCH', 'Dynamic nets', '');

	my $set = $family == F_IPV4 ? "${zone}" : "6_${zone}";
	
	unless ( $zoneref->{options}{in_out}{dynamic_shared} ) {
	    my $physical = var_base1( physical_name $interface );
	    $set = join( '_', $set, $physical );
	}

	$hosts = "+$set";
	$optionsref->{dynamic} = 1;
	$ipsets{$set} = 1;
    }

    #
    # We ignore the user's notion of what interface vserver addresses are on and simply invent one for all of the vservers.
    #
    $interface = '%vserver%' if $type & VSERVER;

    add_group_to_zone( $zone, $type , $interface, [ split_list( $hosts, 'host' ) ] , $optionsref, 1 );

    progress_message "   Host \"$currentline\" validated";

    return $ipsec;
}

#
# Validates the hosts file. Generates entries in %zone{..}{hosts}
#
sub validate_hosts_file()
{
    my $ipsec = 0;

    if ( my $fn = open_file 'hosts' ) {
	first_entry "$doing $fn...";
	$ipsec |= process_host while read_a_line( NORMAL_READ );
    }

    $have_ipsec = $ipsec || haveipseczones;

    $_->{complex} ||= ( keys %{$_->{interfaces}} > 1 ) for values %zones;
}

#
# Return an indication of whether IPSEC is present
#
sub have_ipsec() {
    return defined $have_ipsec ? $have_ipsec : have_capability 'POLICY_MATCH';
}

#
# Returns a reference to a array of host entries. Each entry is a
# reference to an array containing ( interface , polciy match type {ipsec|none} , network , exclusions, value );
#
sub find_hosts_by_option( $ ) {
    my $option = $_[0];
    my @hosts;

    for my $zone ( grep ! ( $zones{$_}{type} & FIREWALL ) , @zones ) {
	while ( my ($type, $interfaceref) = each %{$zones{$zone}{hosts}} ) {
	    while ( my ( $interface, $arrayref) = ( each %{$interfaceref} ) ) {
		for my $host ( @{$arrayref} ) {
		    if ( my $value = $host->{options}{$option} ) {
			for my $net ( @{$host->{hosts}} ) {
			    push @hosts, [ $interface, $host->{ipsec} , $net , $host->{exclusions}, $value ];
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

#
# As above but for a single zone
#
sub find_zone_hosts_by_option( $$ ) {
    my ($zone, $option ) = @_;
    my @hosts;

    unless ( $zones{$zone}{type} & FIREWALL ) {
	while ( my ($type, $interfaceref) = each %{$zones{$zone}{hosts}} ) {
	    while ( my ( $interface, $arrayref) = ( each %{$interfaceref} ) ) {
		for my $host ( @{$arrayref} ) {
		    if ( my $value = $host->{options}{$option} ) {
			for my $net ( @{$host->{hosts}} ) {
			    push @hosts, [ $interface, $host->{ipsec} , $net , $host->{exclusions}, $value ];
			}
		    }
		}
	    }
	}
    }

    \@hosts;
}

#
# Returns a reference to a list of zones with the passed in/out option
#

sub find_zones_by_option( $$ ) {
    my ($option, $in_out ) = @_;
    my @zns;

    for my $zone ( @zones ) {
	push @zns, $zone if $zones{$zone}{options}{$in_out}{$option};
    }

    \@zns;
}

sub all_ipsets() {
    sort keys %ipsets;
}

1;
