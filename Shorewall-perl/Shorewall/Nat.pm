#
# Shorewall-perl 3.9 -- /usr/share/shorewall-perl/Shorewall/Nat.pm
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
#   This module contains code for dealing with the /etc/shorewall/masq,
#   /etc/shorewall/nat and /etc/shorewall/netmap files.
#
package Shorewall::Nat;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Interfaces;
use Shorewall::Chains;
use Shorewall::IPAddrs;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_masq setup_nat setup_netmap add_addresses );
our @EXPORT_OK = ();
our @VERSION = 1.00;

my @addresses_to_add;
my %addresses_to_add;

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
    my ($fullinterface, $networks, $addresses, $proto, $ports, $ipsec, $mark) = @_;

    my $rule = '';
    my $pre_nat;
    my $add_snat_aliases = $config{ADD_SNAT_ALIASES};
    my $destnets = '';
    my $target = '-j MASQUERADE ';

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
    }

    #
    # Leading '+'
    #
    if ( $fullinterface =~ /^\+/ ) {
	$pre_nat = 1;
	$fullinterface =~ s/\+//;
    }

    #
    # Parse the remaining part of the INTERFACE column
    #
    if ( $fullinterface =~ /^([^:]+)::([^:]*)$/ ) {
	$add_snat_aliases = 0;
	$destnets = $2;
	$fullinterface = $1;
    } elsif ( $fullinterface =~ /^([^:]+:[^:]+):([^:]+)$/ ) {
	$destnets = $2;
	$fullinterface = $1;
    } elsif ( $fullinterface =~ /^([^:]+):$/ ) {
	$add_snat_aliases = 0;
	$fullinterface = $1;
    } elsif ( $fullinterface =~ /^([^:]+):([^:]*)$/ ) {
	my ( $one, $two ) = ( $1, $2 );
	if ( $2 =~ /\./ ) {
	    $fullinterface = $one;
	    $destnets = $two;
	}
    }

    #
    # Isolate and verify the interface part
    #
    ( my $interface = $fullinterface ) =~ s/:.*//;

    fatal_error "Unknown interface ($interface)" unless $interfaces{$interface}{root};

    my $chainref = ensure_chain('nat', $pre_nat ? snat_chain $interface : masq_chain $interface);
    #
    # If there is no source or destination then allow all addresses
    #
    $networks = ALLIPv4 if $networks eq '-';
    $destnets = ALLIPv4 if $destnets eq '-';
    #
    # Handle Protocol and Ports
    #
    $rule .= do_proto $proto, $ports, '';
    #
    # Handle Mark
    #
    $rule .= do_test( $mark, 0xFF) if $mark ne '-';

    my $detectaddress = 0;
    #
    # Parse the ADDRESSES column
    #
    if ( $addresses ne '-' ) {
	if ( $addresses =~ /^SAME:nodst:/ ) {
	    $target = '-j SAME --nodst ';
	    $addresses =~ s/.*://;
	    for my $addr ( split /,/, $addresses ) {
		$target .= "--to $addr ";
	    }
	} elsif ( $addresses =~ /^SAME:/ ) {
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
		push_cmd_mode( $chainref );
		$detectaddress = 1;
	    }
	} else {
	    my $addrlist = '';
	    for my $addr ( split /,/, $addresses ) {
		if ( $addr =~ /^.*\..*\..*\./ ) {
		    $target = '-j SNAT ';
		    $addrlist .= "--to-source $addr ";
		} else {
		    $addr =~ s/^://;
		    $addrlist .= "--to-ports $addr ";
		}
	    }

	    $target .= $addrlist;
	}
    } else {
	$add_snat_aliases = 0;
    }
    #
    # And Generate the Rule(s)
    #
    expand_rule $chainref , POSTROUTE_RESTRICT , $rule, $networks, $destnets, '', $target, '', '' , '';

    if ( $detectaddress ) {
	pop_cmd_mode( $chainref );
	add_command( $chainref , 'fi' );
    }

    if ( $add_snat_aliases ) {
	my ( $interface, $alias ) = split /:/, $fullinterface;
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

    progress_message "   Masq record \"$line\" $done";

}

#
# Process the masq file
#
sub setup_masq()
{
    my $first_entry = 1;

    my $fn = open_file 'masq';

    while ( read_a_line ) {

	my ($fullinterface, $networks, $addresses, $proto, $ports, $ipsec, $mark ) = split_line 2, 7, 'masq file';

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    require_capability( 'NAT_ENABLED' , 'a non-empty masq file' , 's' );
	    $first_entry = 0;
	}

	if ( $fullinterface eq 'COMMENT' ) {
	    process_comment;
	} else {
	    setup_one_masq $fullinterface, $networks, $addresses, $proto, $ports, $ipsec, $mark;
	}
    }

    $comment = '';

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

    my ( $interface, $alias ) = split /:/, $fullinterface;

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
	if ( $interface =~ s/:$// ) {
	    $add_ip_aliases = '';
	} else {
	    my ( $iface , undef ) = split /:/, $interface;
	    emit "del_ip_addr $external $iface" unless $config{RETAIN_ALIASES};
	}
    } else {
	$interface =~ s/:$//;
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

    add_nat_rule 'OUTPUT' , "-d $external$policyout -j DNAT --to-destination $internal " if $localnat;

    if ( $add_ip_aliases ) {
	unless ( $addresses_to_add{$external} ) {
	    $addresses_to_add{$external} = 1;
	    push @addresses_to_add, ( $external , $fullinterface );
	}
    }

    progress_message "   NAT entry \"$line\" $done";
}

#
# Process NAT file
#
sub setup_nat() {

    my $first_entry = 1;

    my $fn = open_file 'nat';

    while ( read_a_line ) {

	my ( $external, $interface, $internal, $allints, $localnat ) = split_line 3, 5, 'nat file';

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    require_capability( 'NAT_ENABLED' , 'a non-empty nat file', 's' );
	    $first_entry = 0;
	}

	if ( $external eq 'COMMENT' ) {
	    process_comment;
	} else {
	    do_one_nat $external, $interface, $internal, $allints, $localnat;
	}

    }

    $comment = '';
}

#
# Setup Network Mapping
#
sub setup_netmap() {

    my $first_entry = 1;

    my $fn = open_file 'netmap';

    while ( read_a_line ) {

	my ( $type, $net1, $interface, $net2 ) = split_line 4, 4, 'netmap file';

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    require_capability( 'NAT_ENABLED' , 'a non-empty netmap file' , 's' );
	    $first_entry = 0;
	}

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
