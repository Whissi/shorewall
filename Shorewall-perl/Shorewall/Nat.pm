#
# Shorewall-perl 4.1 -- /usr/share/shorewall-perl/Shorewall/Nat.pm
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
#   This module contains code for dealing with the /etc/shorewall/masq,
#   /etc/shorewall/nat and /etc/shorewall/netmap files.
#
package Shorewall::Nat;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Providers qw( lookup_provider );

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_masq setup_nat setup_netmap add_addresses );
our @EXPORT_OK = ();
our $VERSION = 4.0.6;

our @addresses_to_add;
our %addresses_to_add;

#
# Initialize globals -- we take this novel approach to globals initialization to allow
#                       the compiler to run multiple times in the same process. The
#                       initialize() function does globals initialization for this
#                       module and is called from an INIT block below. The function is
#                       also called by Shorewall::Compiler::compiler at the beginning of
#                       the second and subsequent calls to that function.
#

sub initialize() {
    @addresses_to_add = ();
    %addresses_to_add = ();
}

INIT {
    initialize;
}

#
# Handle IPSEC Options in a masq record
#
sub do_ipsec_options($)
{
    my %validoptions = ( strict       => NOTHING,
			 next         => NOTHING,
			 reqid        => NUMERIC,
			 spi          => NUMERIC,
			 proto        => IPSECPROTO,
			 mode         => IPSECMODE,
			 "tunnel-src" => NETWORK,
			 "tunnel-dst" => NETWORK,
		       );
    my $list=$_[0];
    my $options = '-m policy --pol ipsec --dir out ';
    my $fmt;

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

	$options .= $invert;
	$options .= "--$e ";
	$options .= "$val " if defined $val;
    }

    $options;
}

#
# Process a single rule from the the masq file
#
sub setup_one_masq($$$$$$$)
{
    my ($interfacelist, $networks, $addresses, $proto, $ports, $ipsec, $mark) = @_;

    my $pre_nat;
    my $add_snat_aliases = $config{ADD_SNAT_ALIASES};
    my $destnets = '';

    #
    # Leading '+'
    #
    $pre_nat = 1 if $interfacelist =~ s/^\+//;
    #
    # Parse the remaining part of the INTERFACE column
    #
    if ( $interfacelist =~ /^([^:]+)::([^:]*)$/ ) {
	$add_snat_aliases = 0;
	$destnets = $2;
	$interfacelist = $1;
    } elsif ( $interfacelist =~ /^([^:]+:[^:]+):([^:]+)$/ ) {
	$destnets = $2;
	$interfacelist = $1;
    } elsif ( $interfacelist =~ /^([^:]+):$/ ) {
	$add_snat_aliases = 0;
	$interfacelist = $1;
    } elsif ( $interfacelist =~ /^([^:]+):([^:]*)$/ ) {
	my ( $one, $two ) = ( $1, $2 );
	if ( $2 =~ /\./ ) {
	    $interfacelist = $one;
	    $destnets = $two;
	}
    }
    #
    # If there is no source or destination then allow all addresses
    #
    $networks = ALLIPv4 if $networks eq '-';
    $destnets = ALLIPv4 if $destnets eq '-';

    for my $fullinterface (split /,/, $interfacelist ) {
	my $rule = '';
	my $target = '-j MASQUERADE ';
	#
	# Isolate and verify the interface part
	#
	( my $interface = $fullinterface ) =~ s/:.*//;

	if ( $interface =~ /(.*)[(](\w*)[)]$/ ) {
	    $interface = $1;
	    my $realm  = $2;
	    $fullinterface =~ s/[(]\w*[)]//;
	    $realm = lookup_provider( $realm ) unless $realm =~ /^\d+$/;
	    
	    $rule .= "-m realm --realm $realm ";
	}

	fatal_error "Unknown interface ($interface)" unless find_interface( $interface )->{root};

	my $chainref = ensure_chain('nat', $pre_nat ? snat_chain $interface : masq_chain $interface);
	#
	# Handle IPSEC options, if any
	#
	if ( $ipsec ne '-' ) {
	    fatal_error "Non-empty IPSEC column requires policy match support in your kernel and iptables"  unless $globals{ORIGINAL_POLICY_MATCH};
	    
	    if ( $ipsec =~ /^yes$/i ) {
		$rule .= '-m policy --pol ipsec --dir out ';
	    } elsif ( $ipsec =~ /^no$/i ) {
		$rule .= '-m policy --pol none --dir out ';
	    } else {
		$rule .= do_ipsec_options $ipsec;
	    }
	} elsif ( $capabilities{POLICY_MATCH} ) {
	    $rule .= '-m policy --pol none --dir out ';
	}
	
	#
	# Handle Protocol and Ports
	#
	$rule .= do_proto $proto, $ports, '';
	#
	# Handle Mark
	#
	$rule .= do_test( $mark, 0xFF) if $mark ne '-';
	
	my $detectaddress = 0;
	my $exceptionrule = '';
	my $randomize     = '';
	#
	# Parse the ADDRESSES column
	#
	if ( $addresses ne '-' ) {
	    if ( $addresses eq 'random' ) {
		$randomize = '--random ';
	    } else {
		$addresses =~ s/:random$// and $randomize = '--random ';
		
		if ( $addresses =~ /^SAME:nodst:/ ) {
		    fatal_error "':random' is not supported by the SAME target" if $randomize;
		    $target = '-j SAME --nodst ';
		    $addresses =~ s/.*://;
		    for my $addr ( split /,/, $addresses ) {
			$target .= "--to $addr ";
		    }
		} elsif ( $addresses =~ /^SAME:/ ) {
		    fatal_error "':random' is not supported by the SAME target" if $randomize;
		    $target = '-j SAME ';
		    $addresses =~ s/.*://;
		    for my $addr ( split /,/, $addresses ) {
			$target .= "--to $addr ";
		    }
		} elsif ( $addresses eq 'detect' ) {
		    my $variable = get_interface_address $interface;
		    $target = "-j SNAT --to-source $variable";
		    
		    if ( interface_is_optional $interface ) {
			add_commands( $chainref,
				      '',
				      "if [ \"$variable\" != 0.0.0.0 ]; then" );
			incr_cmd_level( $chainref );
			$detectaddress = 1;
		    }
		} else {
		    my $addrlist = '';
		    for my $addr ( split /,/, $addresses ) {
			if ( $addr =~ /^.*\..*\..*\./ ) {
			    $target = '-j SNAT ';
			    $addrlist .= "--to-source $addr ";
			    $exceptionrule = do_proto( $proto, '', '' ) if $addr =~ /:/;
			} else {
			    $addr =~ s/^://;
			    $addrlist .= "--to-ports $addr ";
			    $exceptionrule = do_proto( $proto, '', '' );
			}
		    }
		    
		    $target .= $addrlist;
		}
	    }
	    
	    $target .= $randomize;
	} else {
	    $add_snat_aliases = 0;
	}
	#
	# And Generate the Rule(s)
	#
	expand_rule( $chainref ,
		     POSTROUTE_RESTRICT ,
		     $rule ,
		     $networks ,
		     $destnets ,
		     '' ,
		     $target ,
		     '' ,
		     '' ,
		     $exceptionrule );
	
	if ( $detectaddress ) {
	    decr_cmd_level( $chainref );
	    add_command( $chainref , 'fi' );
	}
	
	if ( $add_snat_aliases ) {
	    my ( $interface, $alias , $remainder ) = split( /:/, $fullinterface, 3 );
	    fatal_error "Invalid alias ($alias:$remainder)" if defined $remainder;
	    for my $address ( split /,/, $addresses ) {
		my ( $addrs, $port ) = split /:/, $address;
		next unless $addrs;
		next if $addrs eq 'detect';
		for my $addr ( ip_range_explicit $addrs ) {
		    unless ( $addresses_to_add{$addr} ) {
			emit "del_ip_addr $addr $interface" unless $config{RETAIN_ALIASES};
			$addresses_to_add{$addr} = 1;
			if ( defined $alias ) {
			    push @addresses_to_add, $addr, "$interface:$alias";
			    $alias++;
			} else {
			    push @addresses_to_add, $addr, $interface;
			}
		    }
		}
	    }
	}
    }
	
    progress_message "   Masq record \"$currentline\" $done";

}

#
# Process the masq file
#
sub setup_masq()
{
    my $fn = open_file 'masq';

    first_entry( sub { progress_message2 "$doing $fn..."; require_capability 'NAT_ENABLED' , 'a non-empty masq file' , 's'; } );
    
    while ( read_a_line ) {

	my ($fullinterface, $networks, $addresses, $proto, $ports, $ipsec, $mark ) = split_line1 2, 7, 'masq file';

	if ( $fullinterface eq 'COMMENT' ) {
	    process_comment;
	} else {
	    setup_one_masq $fullinterface, $networks, $addresses, $proto, $ports, $ipsec, $mark;
	}
    }

    clear_comment;

}

#
# Validate the ALL INTERFACES or LOCAL column in the NAT file
#
sub validate_nat_column( $$ ) {
    my $ref = $_[1];
    my $val = $$ref;

    if ( defined $val ) {
	unless ( ( $val = "\L$val" ) eq 'yes' ) {
	    if ( ( $val eq 'no' ) || ( $val eq '-' ) ) {
		$$ref = '';
	    } else {
		fatal_error "Invalid value ($val) for $_[0]";
	    }
	}
    } else {
	$$ref = '';
    }
}

#
# Process a record from the NAT file
#
sub do_one_nat( $$$$$ )
{
    my ( $external, $fullinterface, $internal, $allints, $localnat ) = @_;

    my ( $interface, $alias, $remainder ) = split( /:/, $fullinterface, 3 );

    fatal_error "Invalid alias ($alias:$remainder)" if defined $remainder;

    sub add_nat_rule( $$ ) {
	add_rule ensure_chain( 'nat', $_[0] ) , $_[1];
    }

    my $add_ip_aliases = $config{ADD_IP_ALIASES};

    my $policyin = '';
    my $policyout = '';

    if ( $capabilities{POLICY_MATCH} ) {
	$policyin = ' -m policy --pol none --dir in';
	$policyout =  '-m policy --pol none --dir out';
    }

    fatal_error "Invalid nat file entry" unless defined $interface && defined $internal;

    if ( $add_ip_aliases ) {
	if ( defined( $alias ) && $alias eq '' ) {
	    $add_ip_aliases = '';
	} else {
	    emit "del_ip_addr $external $interface" unless $config{RETAIN_ALIASES};
	}
    }

    validate_nat_column 'ALL INTERFACES', \$allints;
    validate_nat_column 'LOCAL'         , \$localnat;

    if ( $allints ) {
	add_nat_rule 'nat_in' ,  "-d $external $policyin  -j DNAT --to-destination $internal";
	add_nat_rule 'nat_out' , "-s $internal $policyout -j SNAT --to-source $external";
    } else {
	add_nat_rule input_chain( $interface ) ,  "-d $external $policyin -j DNAT --to-destination $internal";
	add_nat_rule output_chain( $interface ) , "-s $internal $policyout -j SNAT --to-source $external";
    }

    add_nat_rule 'OUTPUT' , "-d $external $policyout -j DNAT --to-destination $internal " if $localnat;

    if ( $add_ip_aliases ) {
	unless ( $addresses_to_add{$external} ) {
	    $addresses_to_add{$external} = 1;
	    push @addresses_to_add, ( $external , $fullinterface );
	}
    }

}

#
# Process NAT file
#
sub setup_nat() {

    my $fn = open_file 'nat';

    first_entry( sub { progress_message2 "$doing $fn..."; require_capability 'NAT_ENABLED' , 'a non-empty nat file' , 's'; } );
    
    while ( read_a_line ) {

	my ( $external, $interfacelist, $internal, $allints, $localnat ) = split_line1 3, 5, 'nat file';

	if ( $external eq 'COMMENT' ) {
	    process_comment;
	} else {
	    ( $interfacelist, my $digit ) = split /:/, $interfacelist;

	    $digit = defined $digit ? ":$digit" : '';

	    for my $interface ( split /,/, $interfacelist ) {
		do_one_nat $external, "${interface}${digit}", $internal, $allints, $localnat;
	    }

	    progress_message "   NAT entry \"$currentline\" $done";
	}

    }

    clear_comment;
}

#
# Setup Network Mapping
#
sub setup_netmap() {

    my $fn = open_file 'netmap';

    first_entry( sub { progress_message2 "$doing $fn..."; require_capability 'NAT_ENABLED' , 'a non-empty netmap file' , 's'; } );

    while ( read_a_line ) {

	my ( $type, $net1, $interface, $net2 ) = split_line 4, 4, 'netmap file';

	fatal_error "Unknown Interface ($interface)" unless known_interface $interface;

	if ( $type eq 'DNAT' ) {
	    add_rule ensure_chain( 'nat' , input_chain $interface )  , "-d $net1 -j NETMAP --to $net2";
	} elsif ( $type eq 'SNAT' ) {
	    add_rule ensure_chain( 'nat' , output_chain $interface ) , "-s $net1 -j NETMAP --to $net2";
	} else {
	    fatal_error "Invalid type ($type)";
	}

	progress_message "   Network $net1 on $interface mapped to $net2 ($type)";

    }

}

sub add_addresses () {
    if ( @addresses_to_add ) {
	my $arg = '';

	while ( @addresses_to_add ) {
	    my $addr      = shift @addresses_to_add;
	    my $interface = shift @addresses_to_add;
	    $arg = "$arg $addr $interface";
	}

	emit "add_ip_aliases $arg";
    }
}

1;
