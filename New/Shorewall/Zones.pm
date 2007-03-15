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
		  dump_zone_info
		  zone_report

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

#
# Parse the passed option list and return a reference to a hash as follows:
#
# => mss   = <MSS setting>
# => ipsec = <-m policy arguments to match options>
#
sub parse_zone_option_list($)
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

    my $list=$_[0];
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
		fatal_error "Option $e does not take a value: Zone \"$line\"" if defined $val;
	    } else {
		fatal_error "Invalid value ($val) for option \"$e\" in Zone \"$line\"" unless $val =~ /^($fmt)$/;
	    }
	    
	    if ( $key{$e} ) {
		$h{$e} = $val;
	    } else {
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

    open ZONES, "$ENV{TMP_DIR}/zones" or fatal_error "Unable to open stripped zones file: $!";

    while ( $line = <ZONES> ) {
	chomp $line;
	$line =~ s/\s+/ /g;
	
	my @parents;

	my ($zone, $type, $options, $in_options, $out_options, $extra) = split /\s+/, $line;

	fatal_error("Invalid zone file entry: $line") if $extra;
	
	fatal_error( "Duplicate zone name: $zone\n" ) if $zones{$zone};

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

	fatal_error "Invalid zone name: $zone" unless "\L$zone" =~ /^[a-z]\w*$/ && length $zone <= $env{MAXZONENAMELENGTH};
	fatal_error "Invalid zone name: $zone" if $zone =~ /^all2|2all$/;

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
	    $zoneref->{type} = "firewall";
	} elsif ( $type eq '-' ) {
	    $type = $zoneref->{type} = 'ipv4';
	} else {
	    fatal_error "Invalid zone type ($type)" ;
	}

	my %zone_hash;

	$zone_hash{in_out}   = parse_zone_option_list( $options || '');
	$zone_hash{in}       = parse_zone_option_list( $in_options || '');
	$zone_hash{out}      = parse_zone_option_list( $out_options || '');
	$zone_hash{complex}  = ($type eq 'ipsec4' || $options || $in_options || $out_options ? 1 : 0);

	$zoneref->{options}    = \%zone_hash;
	$zoneref->{interfaces} = {};
	$zoneref->{children}   = [];
	$zoneref->{hosts}      = {};

	push @z, $zone;
    }

    close ZONES;

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
# Dump out all information about zones.
#
sub dump_zone_info() 
{
    print "\n";

    for my $zone ( @zones )
    {
	my $zoneref   = $zones{$zone};
	my $typeref   = $zoneref->{hosts};
	my $optionref = $zoneref->{options};
	my $zonetype  = $zoneref->{type};

	print "Zone: $zone\n";

	print "   Type: $zonetype\n";
	print "   Parents:\n";

	my $parentsref = $zoneref->{parents};

	for my $parent ( @$parentsref ) {
	    print "      $parent\n";
	}

	if ( %$optionref ) {
	    print "   Options:\n";

	    for my $opttype ( keys %$optionref ) {
		if ( $opttype eq 'complex' ) {
		    print "      Complex: $optionref->{$opttype}\n";
		} else {
		    print "      $opttype:\n";
		    while ( my ( $option, $val ) = each %{$optionref->{$opttype}} ) { print "         $option=$val\n"; }
		}
	    }
	}
	
	if ( $typeref ) {
	    print "   Host Groups:\n";
	    while ( my ( $type, $interfaceref ) =  ( each %$typeref ) ) {
		print "      Type: $type\n";
	
		for my $interface ( sort keys %$interfaceref ) {
		    my $arrayref = $interfaceref->{$interface};
		    
		    print "         Interface: $interface\n";
		    
		    for my $groupref ( @$arrayref ) {
			my $hosts     = $groupref->{hosts};
			my $options   = $groupref->{options};
			my $ipsec     = $groupref->{ipsec};
			
			if ( $ipsec ) {
			    print "            Ipsec: $ipsec\n" ;
			}

			if ( $hosts ) {
			    my $space = '';
			    print "            Hosts: " ;
			    for my $host ( @{$hosts} ) {
				print "${space}${host}\n";
				$space = '            ';
			    }
			}       
			
			if ( $options ) {
			    print "            Options: ";
			    for my $option (sort keys %$options ) {
				print "$option ";
			    }
			    print "\n";
			}
		    }
		}
	    }
	} else {
	    #
	    # Empty ?
	    #
	    print "   ***Empty***\n" if $zonetype ne 'firewall';
	}
    }

    print "\n";
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
    
	print STDERR "      *** $zone is an EMPTY ZONE ***\n" unless $printed || $type eq 'firewall';
    }
}

1;
