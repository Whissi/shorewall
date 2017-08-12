#
# Shorewall 5.0 -- /usr/share/shorewall/Shorewall/Nat.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007-2016 - Tom Eastep (teastep@shorewall.net)
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
#   This module contains code for dealing with the /etc/shorewall/masq,
#   /etc/shorewall/nat and /etc/shorewall/netmap files.
#
package Shorewall::Nat;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::Providers qw( provider_realm );

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_nat setup_netmap add_addresses );
our %EXPORT_TAGS = ( rules => [ qw ( handle_nat_rule handle_nonat_rule process_one_masq convert_masq @addresses_to_add %addresses_to_add ) ] );
our @EXPORT_OK = ();

Exporter::export_ok_tags('rules');

our $VERSION = 'MODULEVERSION';

our @addresses_to_add;
our %addresses_to_add;
our $family;

#
# Called by the compiler
#
sub initialize($) {
    $family = shift;
    @addresses_to_add = ();
    %addresses_to_add = ();
}

#
# Process a single rule from the the masq file
#
sub process_one_masq1( $$$$$$$$$$$ )
{
    my ( $interfacelist, $networks, $addresses, $proto, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) = @_;

    my $pre_nat;
    my $add_snat_aliases = $family == F_IPV4 && $config{ADD_SNAT_ALIASES};
    my $destnets = '';
    my $baserule = '';
    my $inlinematches = '';
    my $prerule       = '';
    my $savelist;
    #
    # Leading '+'
    #
    $pre_nat = 1 if $interfacelist =~ s/^\+//;

    #
    # Check for INLINE
    #
    if ( $interfacelist =~ /^INLINE\((.+)\)$/ ) {
	$interfacelist = $1;
	$inlinematches = get_inline_matches(0);
    } else {
	$inlinematches = get_inline_matches(0);
    }

    $savelist = $interfacelist;
    #
    # Handle early matches
    #
    if ( $inlinematches =~ s/s*\+// ) {
	$prerule = $inlinematches;
	$inlinematches = '';
    }
    #
    # Parse the remaining part of the INTERFACE column
    #
    if ( $family == F_IPV4 ) {
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
	    if ( $2 =~ /\./ || $2 =~ /^%/ ) {
		$interfacelist = $one;
		$destnets = $two;
	    }
	}
    } elsif ( $interfacelist =~ /^(.+?):(.+)$/ ) {
	$interfacelist = $1;
	$destnets      = $2;
    }
    #
    # If there is no source or destination then allow all addresses
    #
    $networks = ALLIP if $networks eq '-';
    $destnets = ALLIP if $destnets eq '-';

    #
    # Handle IPSEC options, if any
    #
    if ( $ipsec ne '-' ) {
	fatal_error "Non-empty IPSEC column requires policy match support in your kernel and iptables"  unless have_capability( 'POLICY_MATCH' );

	if ( $ipsec =~ /^yes$/i ) {
	    $baserule .= do_ipsec_options 'out', 'ipsec', '';
	} elsif ( $ipsec =~ /^no$/i ) {
	    $baserule .= do_ipsec_options 'out', 'none', '';
	} else {
	    $baserule .= do_ipsec_options 'out', 'ipsec', $ipsec;
	}
    } elsif ( have_ipsec ) {
	$baserule .= '-m policy --pol none --dir out ';
    }

    #
    # Handle Protocol, Ports and Condition
    #
    $baserule .= do_proto( $proto, $ports, '' );
    #
    # Handle Mark
    #
    $baserule .= do_test( $mark, $globals{TC_MASK} ) if $mark ne '-';
    $baserule .= do_user( $user )                    if $user ne '-';
    $baserule .= do_probability( $probability )      if $probability ne '-';

    my $target;

    for my $fullinterface (split_list $interfacelist, 'interface' ) {
	my $rule = '';

	$target = 'MASQUERADE ';
	#
	# Isolate and verify the interface part
	#
	( my $interface = $fullinterface ) =~ s/:.*//;

	if ( $interface =~ /(.*)[(](\w*)[)]$/ ) {
	    $interface = $1;
	    my $provider  = $2;

	    fatal_error "Missing Provider ($fullinterface)" unless supplied $provider;

	    $fullinterface =~ s/[(]\w*[)]//;
	    my $realm = provider_realm( $provider );

	    fatal_error "$provider is not a shared-interface provider" unless $realm;

	    $rule .= "-m realm --realm $realm ";
	}

	fatal_error "Unknown interface ($interface)" unless my $interfaceref = known_interface( $interface );

	if ( $interfaceref->{root} ) {
	    $interface = $interfaceref->{name} if $interface eq $interfaceref->{physical};
	} else {
	    $rule .= match_dest_dev( $interface );
	    $interface = $interfaceref->{name};
	}

	my $chainref = ensure_chain('nat', $pre_nat ? snat_chain $interface : masq_chain $interface);

	$baserule .= do_condition( $condition , $chainref->{name} );

	my $detectaddress = 0;
	my $exceptionrule = '';
	my $randomize     = '';
	my $persistent    = '';
	my $conditional   = 0;
	#
	# Parse the ADDRESSES column
	#
	if ( $addresses ne '-' ) {
	    my $saveaddresses = $addresses;
	    if ( $addresses eq 'random' ) {
		require_capability( 'MASQUERADE_TGT', 'Masquerade rules', '') if $family == F_IPV6;
		$randomize = '--random ';
	    } else {
		$addresses =~ s/:persistent$// and $persistent = ' --persistent ';
		$addresses =~ s/:random$//     and $randomize  = ' --random ';

		require_capability 'PERSISTENT_SNAT', ':persistent', 's' if $persistent;

		if ( $addresses =~ /^SAME/ ) {
		    fatal_error "The SAME target is no longer supported";
		} elsif ( $addresses eq 'detect' ) {
		    my $variable = get_interface_address $interface;
		    $target = "SNAT --to-source $variable";

		    if ( interface_is_optional $interface ) {
			add_commands( $chainref,
				      '',
				      "if [ \"$variable\" != 0.0.0.0 ]; then" );
			incr_cmd_level( $chainref );
			$detectaddress = 1;
		    }
		} elsif ( $addresses eq 'NONAT' ) {
		    fatal_error "'persistent' may not be specified with 'NONAT'" if $persistent;
		    fatal_error "'random' may not be specified with 'NONAT'"     if $randomize;
		    $target = 'RETURN';
		    $add_snat_aliases = 0;
		} elsif ( $addresses ) {
		    my $addrlist = '';
		    my @addrs = split_list $addresses, 'address';

		    fatal_error "Only one ADDRESS may be specified" if @addrs > 1;

		    for my $addr ( @addrs ) {
			if ( $addr =~ /^([&%])(.+)$/ ) {
			    my ( $type, $interface ) = ( $1, $2 );

			    my $ports = '';

			    if ( $interface =~ s/:(.+)$// ) {
				validate_portpair1( $proto, $1 );
				$ports = ":$1";
			    }
			    #
			    # Address Variable
			    #
			    $target = 'SNAT ';

			    if ( $interface =~ /^{([a-zA-Z_]\w*)}$/ ) {
				#
				# User-defined address variable
				#
				$conditional = conditional_rule( $chainref, $addr );
				$addrlist .= '--to-source ' . "\$${1}${ports} ";
			    } else {
				if ( $conditional = conditional_rule( $chainref, $addr ) ) {
				    #
				    # Optional Interface -- rule is conditional
				    #
				    $addr = get_interface_address $interface;
				} else {
				    #
				    # Interface is not optional
				    #
				    $addr = record_runtime_address( $type, $interface );
				}

				if ( $ports ) {
				    $addr =~ s/ $//;
				    $addr = $family == F_IPV4 ? "${addr}${ports} " : "[$addr]$ports ";
				}

				$addrlist .= '--to-source ' . $addr;
			    }
			} elsif ( $family == F_IPV4 ) {
			    if ( $addr =~ /^.*\..*\..*\./ ) {
				$target = 'SNAT ';
				my ($ipaddr, $rest) = split ':', $addr, 2;
				if ( $ipaddr =~ /^(.+)-(.+)$/ ) {
				    validate_range( $1, $2 );
				} else {
				    validate_address $ipaddr, 0;
				}

				if ( supplied $rest ) {
				    validate_portpair1( $proto, $rest );
				    $addrlist .= "--to-source $addr ";
				} else {
				    $addrlist .= "--to-source $ipaddr";
				}

				$exceptionrule = do_proto( $proto, '', '' ) if $addr =~ /:/;
			    } else {
				my $ports = $addr;
				$ports =~ s/^://;
				validate_portpair1( $proto, $ports );
				$addrlist .= "--to-ports $ports ";
				$exceptionrule = do_proto( $proto, '', '' );
			    }
			} else {
			    $target = 'SNAT ';

			    if ( $addr =~ /^\[/ ) {
				#
				# Can have ports specified
				#
				my $ports;

				if ( $addr =~ s/:([^]:]+)$// ) {
				    $ports = $1;
				}

				fatal_error "Invalid IPv6 Address ($addr)" unless $addr =~ /^\[(.+)\]$/;

				$addr = $1;

				if ( $addr =~ /^(.+)-(.+)$/ ) {
				    fatal_error "Correct address range syntax is '[<addr1>-<addr2>]'" if $addr =~ /]-\[/;
				    validate_range( $1, $2 );
				} else {
				    validate_address $addr, 0;
				}

				if ( supplied $ports ) {
				    validate_portpair1( $proto, $ports );
				    $exceptionrule = do_proto( $proto, '', '' );
				    $addr = "[$addr]:$ports";
				}

				$addrlist .= "--to-source $addr ";
			    } else {
				if ( $addr =~ /^(.+)-(.+)$/ ) {
				    validate_range( $1, $2 );
				} else {
				    validate_address $addr, 0;
				}

				$addrlist .= "--to-source $addr ";
			    }
			}
		    }

		    $target .= $addrlist;
		} else {
		    fatal_error( "':persistent' is not allowed in a MASQUERADE rule" ) if $persistent;
		    require_capability( 'MASQUERADE_TGT', 'Masquerade rules', '' )     if $family == F_IPV6;
		}
	    }

	    $target .= $randomize;
	    $target .= $persistent;
	    $addresses = $saveaddresses;
	} else {
	    require_capability( 'MASQUERADE_TGT', 'Masquerade rules', '' )  if $family == F_IPV6;
	    $add_snat_aliases = 0;
	}
	#
	# And Generate the Rule(s)
	#
	expand_rule( $chainref ,
		     POSTROUTE_RESTRICT ,
		     $prerule ,
		     $baserule . $inlinematches . $rule ,
		     $networks ,
		     $destnets ,
		     $origdest ,
		     $target ,
		     '' ,
		     '' ,
		     $exceptionrule ,
		     '' )
	    unless unreachable_warning( 0, $chainref );

	conditional_rule_end( $chainref ) if $detectaddress || $conditional;

	if ( $add_snat_aliases ) {
	    my ( $interface, $alias , $remainder ) = split( /:/, $fullinterface, 3 );
	    fatal_error "Invalid alias ($alias:$remainder)" if defined $remainder;
	    for my $address ( split_list $addresses, 'address' ) {
		my ( $addrs, $port ) = split /:/, $address;
		next unless $addrs;
		next if $addrs eq 'detect';
		for my $addr ( ip_range_explicit $addrs ) {
		    unless ( $addresses_to_add{$addr} ) {
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

sub convert_one_masq1( $$$$$$$$$$$$ )
{
    my ( $snat, $interfacelist, $networks, $addresses, $proto, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) = @_;

    my $pre_nat;
    my $destnets = '';
    my $savelist;
    #
    # Leading '+'
    #
    $pre_nat = ( $interfacelist =~ s/^\+// );
    #
    # Check for INLINE
    #
    if ( $interfacelist =~ /^INLINE\((.+)\)$/ ) {
	$interfacelist = $1;
    }

    $savelist = $interfacelist;
    #
    # Parse the remaining part of the INTERFACE column
    #
    if ( $family == F_IPV4 ) {
	if ( $interfacelist =~ /^([^:]+)::([^:]*)$/ ) {
	    $destnets = $2;
	    $interfacelist = $1;
	} elsif ( $interfacelist =~ /^([^:]+:[^:]+):([^:]+)$/ ) {
	    $destnets = $2;
	    $interfacelist = $1;
	} elsif ( $interfacelist =~ /^([^:]+):$/ ) {
	    $interfacelist = $1;
	} elsif ( $interfacelist =~ /^([^:]+):([^:]*)$/ ) {
	    my ( $one, $two ) = ( $1, $2 );
	    if ( $2 =~ /\./ || $2 =~ /^%/ ) {
		$interfacelist = $one;
		$destnets = $two;
	    }
	}
    } elsif ( $interfacelist =~ /^(.+?):(.+)$/ ) {
	$interfacelist = $1;
	$destnets      = $2;
    }
    #
    # If there is no source or destination then allow all addresses
    #
    $networks = ALLIP if $networks eq '-';
    $destnets = ALLIP if $destnets eq '-';

    my $target;
    #
    # Parse the ADDRESSES column
    #
    if ( $addresses ne '-' ) {
	my $saveaddresses = $addresses;
	if ( $addresses ne 'random' ) {
	    $addresses =~ s/:persistent$//;
	    $addresses =~ s/:random$//;

	    if ( $addresses eq 'detect' ) {
		$target = 'SNAT';
	    } elsif ( $addresses eq 'NONAT' ) {
		$target = 'CONTINUE';
	    } elsif ( $addresses ) {
		if ( $addresses =~ /^:/ ) {
		    $target = 'MASQUERADE';
		} else {
		    $target = 'SNAT';
		}
	    }
	}

	$addresses = $saveaddresses;
    } else {
	$target = 'MASQUERADE';
    }

    if ( $snat ) {
	$target .= '+' if $pre_nat;

	if ( $addresses ne '-' && $addresses ne 'NONAT' ) {
	    $addresses =~ s/^://;
	    $target .= '(' . $addresses . ')';
	}

	my $line = "$target\t$networks\t$savelist\t$proto\t$ports\t$ipsec\t$mark\t$user\t$condition\t$origdest\t$probability";
	#
	# Supress superfluous trailing dashes
	#
	$line =~ s/(?:\t-)+$//;

	my $raw_matches = fetch_inline_matches;

	$line .= join( '', ' ;;', $raw_matches ) if $raw_matches ne ' ';

	print $snat "$line\n";
    }

    progress_message "   Masq record \"$rawcurrentline\" Converted";

}

sub process_one_masq( $ )
{
    my ( $snat ) = @_;

    if ( $snat ) {
	unless ( $rawcurrentline =~ /^\s*(?:#.*)?$/ ) {
	    #
	    # Line was not blank or all comment
	    #
	    my ($interfacelist, $networks, $addresses, $protos, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) =
		split_rawline2( 'masq file',
				{ interface => 0, source => 1, address => 2, proto => 3, port => 4, ipsec => 5, mark => 6, user => 7, switch => 8, origdest => 9, probability => 10 },
				{},    #Nopad
				undef, #Columns
				1 );   #Allow inline matches

	    if ( $interfacelist ne '-' ) { 
		for my $proto ( split_list $protos, 'Protocol' ) {
		    convert_one_masq1( $snat, $interfacelist, $networks, $addresses, $proto, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability );
		}
	    }
	}
    } else {
	my ($interfacelist, $networks, $addresses, $protos, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) =
	    split_line2( 'masq file',
			 { interface => 0, source => 1, address => 2, proto => 3, port => 4, ipsec => 5, mark => 6, user => 7, switch => 8, origdest => 9, probability => 10 },
			 {},    #Nopad
			 undef, #Columns
			 1 );   #Allow inline matches

	fatal_error 'INTERFACE must be specified' if $interfacelist eq '-';

	for my $proto ( split_list $protos, 'Protocol' ) {
	    process_one_masq1( $interfacelist, $networks, $addresses, $proto, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability );
	}
    }
}

sub open_snat_for_output( $ ) {
    my ($fn ) = @_;
    my ( $snat, $fn1 );

    if ( -f ( $fn1 = find_writable_file( 'snat' ) ) ) {
	open( $snat , '>>', $fn1 ) || fatal_error "Unable to open $fn1:$!";
    } else {
	open( $snat , '>', $fn1 ) || fatal_error "Unable to open $fn1:$!";
	#
	# Transfer permissions from the existing masq file to the new snat file
	#
	transfer_permissions( $fn, $fn1 );

	if ( $family == F_IPV4 ) {
	    print $snat <<'EOF';
#
# Shorewall - SNAT/Masquerade File
#
# For information about entries in this file, type "man shorewall-snat"
#
# See http://shorewall.net/manpages/shorewall-snat.html for additional information
EOF
	} else {
	    print $snat <<'EOF';
#
# Shorewall6 - SNAT/Masquerade File
#
# For information about entries in this file, type "man shorewall6-snat"
#
# See http://shorewall.net/manpages6/shorewall6-snat.html for additional information
EOF
	}

	print $snat <<'EOF';
###################################################################################################################
#ACTION         SOURCE          DEST            PROTO   PORT   IPSEC  MARK   USER    SWITCH  ORIGDEST   PROBABILITY
EOF
    }

    return ( $snat, $fn1 );
}

#
# Convert a masq file into the equivalent snat file
#
sub convert_masq() {
    if ( my $fn = open_file( 'masq', 1, 1 ) ) {
	my ( $snat, $fn1 ) = open_snat_for_output( $fn );

	my $have_masq_rules;

	directive_callback(
	    sub ()
	    {
		if ( $_[0] eq 'OMITTED' ) {
		    #
		    # Convert the raw rule
		    #
		    process_one_masq( $snat) if $snat;
		} else {
		    print $snat "$_[1]\n"; 0;
		}
	    }
	    );

	first_entry(
	    sub {
		my $date = compiletime;
		progress_message2 "Converting $fn...";
		print( $snat
		       "#\n" ,
		       "# Rules generated from masq file $fn by Shorewall $globals{VERSION} - $date\n" ,
		       "#\n" );
	    }
	    );

	while ( read_a_line( NORMAL_READ ) ) {
	    #
	    # Process the file normally
	    #
	    process_one_masq(0);
	    #
	    # Now Convert it
	    #
	    process_one_masq($snat);

	    $have_masq_rules++;
	}

	if ( $have_masq_rules ) {
	    progress_message2 "Converted $fn to $fn1";
	    if ( rename $fn, "$fn.bak" ) {
		progress_message2 "$fn renamed $fn.bak";
	    } else {
		fatal_error "Cannot Rename $fn to $fn.bak: $!";
	    }
	} else {
	    if ( unlink $fn ) {
		warning_message "Empty masq file ($fn) removed";
	    } else {
		warning_message "Unable to remove empty masq file $fn: $!";
	    }
	}

	close $snat, directive_callback( 0 );
    }
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
    my $rulein = '';
    my $ruleout = '';

    fatal_error "Unknown interface ($interface)" unless my $interfaceref = known_interface( $interface );

    if ( $interfaceref->{root} ) {
	$interface = $interfaceref->{name} if $interface eq $interfaceref->{physical};
    } else {
	$rulein  = match_source_dev $interface;
	$ruleout = match_dest_dev $interface;
	$interface = $interfaceref->{name};
    }

    if ( have_ipsec ) {
	$policyin = ' -m policy --pol none --dir in';
	$policyout =  '-m policy --pol none --dir out';
    }

    fatal_error "Invalid nat file entry" unless defined $interface && defined $internal;

    if ( $add_ip_aliases ) {
	$add_ip_aliases = '' if defined( $alias ) && $alias eq '';
    }

    validate_nat_column 'ALL INTERFACES', \$allints;
    validate_nat_column 'LOCAL'         , \$localnat;

    if ( $allints ) {
	add_nat_rule 'nat_in' ,  "-d $external $policyin  -j DNAT --to-destination $internal";
	add_nat_rule 'nat_out' , "-s $internal $policyout -j SNAT --to-source $external";
    } else {
	add_nat_rule input_chain( $interface ) ,  $rulein  . "-d $external $policyin -j DNAT --to-destination $internal";
	add_nat_rule output_chain( $interface ) , $ruleout . "-s $internal $policyout -j SNAT --to-source $external";
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

    if ( my $fn = open_file( 'nat', 1, 1 ) ) {

	first_entry( sub { progress_message2 "$doing $fn..."; require_capability 'NAT_ENABLED' , 'a non-empty nat file' , 's'; } );

	while ( read_a_line( NORMAL_READ ) ) {

	    my ( $external, $interfacelist, $internal, $allints, $localnat ) =
		split_line1( 'nat file',
			     { external => 0, interface => 1, internal => 2, allints => 3, local => 4 } );

	    ( $interfacelist, my $digit ) = split /:/, $interfacelist;

	    $digit = defined $digit ? ":$digit" : '';

	    fatal_error 'EXTERNAL must be specified' if $external eq '-';
	    fatal_error 'INTERNAL must be specified' if $interfacelist eq '-';

	    for my $interface ( split_list $interfacelist , 'interface' ) {
		fatal_error "Invalid Interface List ($interfacelist)" unless supplied $interface;
		do_one_nat $external, "${interface}${digit}", $internal, $allints, $localnat;
	    }

	    progress_message "   NAT entry \"$currentline\" $done";
	}
    }
}

#
# Setup Network Mapping
#
sub setup_netmap() {

    if ( my $fn = open_file 'netmap', 1, 1 ) {

	first_entry "$doing $fn...";

	while ( read_a_line( NORMAL_READ ) ) {

	    my ( $type, $net1, $interfacelist, $net2, $net3, $proto, $dport, $sport ) =
		split_line( 'netmap file',
			    { type => 0, net1 => 1, interface => 2, net2 => 3, net3 => 4, proto => 5, dport => 6, sport => 7 } );

	    $net3 = ALLIP if $net3 eq '-';

	    for my $interface ( split_list $interfacelist, 'interface' ) {

		my $iface = $interface;

		fatal_error "Unknown interface ($interface)" unless my $interfaceref = known_interface( $interface );

		my @rule = do_iproto( $proto, $dport, $sport );

		my @rulein;
		my @ruleout;

		$net1 = validate_net $net1, 0;
		$net2 = validate_net $net2, 0;

		if ( $interfaceref->{root} ) {
		    $interface = $interfaceref->{name} if $interface eq $interfaceref->{physical};
		} else {
		    @rulein  = imatch_source_dev( $interface );
		    @ruleout = imatch_dest_dev( $interface );
		    $interface = $interfaceref->{name};
		}

		require_capability 'NETMAP_TARGET', 'Stateful Netmap Entries', '';

		if ( $type eq 'DNAT' ) {
		    dest_iexclusion(  ensure_chain( 'nat' , input_chain $interface ) ,
				      j => 'NETMAP' ,
				      "--to $net2",
				      $net1 ,
				      @rulein  ,
				      imatch_source_net( $net3 ) );
		} elsif ( $type eq 'SNAT' ) {
		    source_iexclusion( ensure_chain( 'nat' , output_chain $interface ) ,
				       j => 'NETMAP' ,
				       "--to $net2" ,
				       $net1 ,
				       @ruleout ,
				       imatch_dest_net( $net3 ) );
		} else {
		    fatal_error 'TYPE must be specified' if $type eq '-';
		    fatal_error "Invalid type ($type)";
		}

		progress_message "   Network $net1 on $iface mapped to $net2 ($type)";
	    }
	}
    }

}

#
# Called from process_rule to add a rule to the NAT table
#
sub handle_nat_rule( $$$$$$$$$$$$$ ) {
    my ( $dest,           # <server>[:port]
	 $proto,          # Protocol
	 $ports,          # Destination port list
	 $origdest,       # Original Destination
	 $action_target,  # If the target is an action, the name of the log action chain to jump to
	 $action,         # The Action
	 $sourceref,      # Reference to the Source Zone's table entry in the Zones module
	 $action_chain,   # Name of the action chain if the rule is in an action
	 $rule,           # Matches 
	 $source,         # Source Address
	 $loglevel,       # [<level>[:<tag>]]
	 $log_action,     # Action name to include in the log message
	 $wildcard        # Part of a wildcard rule
       ) = @_;

    my ( $server, $serverport , $origdstports ) = ( '', '', '' );
    my $randomize = $dest =~ s/:random$// ? ' --random' : '';

    #
    # Isolate server port
    #
    if ( ( $family == F_IPV4 && $dest =~ /^(.*)(?::(.+))$/ ) || ( $family == F_IPV6 && $dest =~ /^\[(.*)]:(.+)$/ ) ) {
	#
	# Server IP and Port
	#
	$server = $1;      # May be empty
	$serverport = $2;  # Not Empty due to RE

	my ( $p ) = split( ':', $proto ); # Might be "tcp:syn"

	require_capability( 'UDPLITEREDIRECT', 'UDPLITE Port Redirection', 's' ) if resolve_proto( $p ) == UDPLITE; 

	$origdstports = validate_port( $proto, $ports )	if $ports && $ports ne '-' && port_count( $ports ) == 1;

	if ( $serverport =~ /^(\d+)-(\d+)$/ ) {
	    #
	    # Server Port Range
	    #
	    fatal_error "Invalid port range ($serverport)" unless $1 < $2;
	    my @ports = ( $1, $2 );
	    $_ = validate_port( proto_name( $proto ), $_) for ( @ports );
	    ( $ports = $serverport ) =~ tr/-/:/;
	} else {
	    $serverport = $ports = validate_port( proto_name( $proto ), $serverport );
	}
    } elsif ( $dest ne ':' ) {
	#
	# Simple server IP address (may be empty or "-")
	#
	$server = $dest;
    }

    #
    # Check for list in $server
    #
    fatal_error "An address list ($server) is not allowed in the DEST column of a $action RULE" if $server =~ /,/;
    #
    # Generate the target
    #
    my $target = '';

    if ( $action eq 'REDIRECT' ) {
	fatal_error "A server IP address ($server) may not be specified in a REDIRECT rule" if $server;
	$target  = 'REDIRECT';
	$target .= " --to-port $serverport" if $serverport;
	if ( $origdest eq '' || $origdest eq '-' ) {
	    $origdest = ALLIP;
	} elsif ( $origdest eq 'detect' ) {
	    fatal_error 'ORIGINAL DEST "detect" is invalid in an action' if $action_chain;

	    if ( $config{DETECT_DNAT_IPADDRS} ) {
		my $interfacesref = $sourceref->{interfaces};
		my @interfaces = keys %$interfacesref;
		$origdest = @interfaces ? "detect:@interfaces" : ALLIP;
	    } else {
		$origdest = ALLIP;
	    }
	}
    } elsif ( $action_target ) {
	fatal_error "A server port ($serverport) is not allowed in $action rule" if $serverport;
	$target = $action_target;
    } else {
	if ( $server eq '' ) {
	    fatal_error "A server and/or port must be specified in the DEST column in $action rules" unless $serverport;
	} elsif ( $server =~ /^(.+)-(.+)$/ ) {
	    if ( $family == F_IPV4 ) {
		validate_range( $1, $2 );
	    } else {
		my ( $addr1, $addr2 ) = ( $1, $2 );

		if ( $server =~ /^\[(.+)\]$/ ) {
		    $server = $1;
		    fatal_error "Correct address range syntax is '[<addr1>-<addr2>]'" if $server =~ /]-\[/;
		    assert( $server =~ /^(.+)-(.+)$/ );
		    ( $addr1, $addr2 ) = ( $1, $2 );
		}

		validate_range( $addr1, $addr2 );
		$server = join( '-', $addr1, $addr2 );
	    }
	} elsif ( $server eq ALLIP || $server eq NILIP ) {
	    fatal_error "Invalid or missing server IP address";
	} else {
	    $server = $1 if $family == F_IPV6 && $server =~ /^\[(.+)\]$/;
	    fatal_error "Invalid server IP address ($server)" if $server eq ALLIP || $server eq NILIP;

	    my @servers;

	    if ( ( $server =~ /^([&%])(.+)/ ) ) {
		@servers = ( record_runtime_address( $1, $2 ) );
	    } else {
		@servers = validate_address $server, 1;
	    }

	    $server = join ',', @servers;
	}

	if ( $action eq 'DNAT' ) {
	    $target = $action;
	    if ( $server ) {
		$serverport = ":$serverport" if $serverport;
		if ( $family == F_IPV4 ) {
		    for my $serv ( split /,/, $server ) {
			$target .= " --to-destination ${serv}${serverport}";
		    }
		} else {
		    for my $serv ( split /,/, $server ) {
			$target .= " --to-destination [${serv}]${serverport}";
		    }
		}
	    } else {
		$target .= " --to-destination :$serverport";
	    }
	}

	unless ( $origdest && $origdest ne '-' && $origdest ne 'detect' ) {
	    if ( ! $action_chain && $config{DETECT_DNAT_IPADDRS} ) {
		my $interfacesref = $sourceref->{interfaces};
		my @interfaces = keys %$interfacesref;
		$origdest = @interfaces ? "detect:@interfaces" : ALLIP;
	    } else {
		$origdest = ALLIP;
	    }
	}
    }

    $target .= $randomize;
    #
    # And generate the nat table rule(s)
    #
    my $firewallsource = $sourceref && ( $sourceref->{type} & ( FIREWALL | VSERVER ) );

    my $chainref = ensure_chain ('nat' ,
				( $action_chain   ? $action_chain :
				  $firewallsource ? 'OUTPUT' :
				  dnat_chain $sourceref->{name} ) );
    expand_rule ( $chainref,
		  $firewallsource ? OUTPUT_RESTRICT : PREROUTE_RESTRICT ,
		  '' ,
		  $rule ,
		  $source ,
		  $origdest ,
		  '' ,
		  $target ,
		  $loglevel ,
		  $log_action ,
		  $serverport ? do_proto( $proto, '', '' ) : '' ,
		  '' ,
		)
	unless unreachable_warning( $wildcard, $chainref );

    ( $ports, $origdstports, $server );
}

#
# Called from process_rule1() to handle the nat table part of the NONAT and ACCEPT+ actions
#
sub handle_nonat_rule( $$$$$$$$$$$ ) {
    my ( $action, $source, $dest, $origdest, $sourceref, $inaction, $chain, $loglevel, $log_action, $rule, $wildcard ) = @_;

    my $sourcezone = $sourceref->{name};
    #
    # NONAT or ACCEPT+ may not specify a destination interface
    #
    fatal_error "Invalid DEST ($dest) in $action rule" if $dest =~ /:/;

    $origdest = '' unless $origdest and $origdest ne '-';

    if ( $origdest eq 'detect' ) {
	my $interfacesref = $sourceref->{interfaces};
	my $interfaces = [ ( keys %$interfacesref ) ];
	$origdest = $interfaces ? "detect:@$interfaces" : ALLIP;
    }

    my $tgt = 'RETURN';

    my $nonat_chain;

    my $chn;

    if ( $inaction ) {
	$nonat_chain = ensure_chain( 'nat', $chain );
    } elsif ( $sourceref->{type} == FIREWALL ) {
	$nonat_chain = $nat_table->{OUTPUT};
    } else {
	$nonat_chain = ensure_chain( 'nat', dnat_chain( $sourcezone ) );

	my @interfaces = keys %{zone_interfaces $sourcezone};

	for ( @interfaces ) {
	    my $ichain = input_chain $_;

	    if ( $nat_table->{$ichain} ) {
		#
		# Static NAT is defined on this interface
		#
		$chn = new_chain( 'nat', newnonatchain ) unless $chn;
		add_ijump $chn, j => $nat_table->{$ichain}, @interfaces > 1 ? imatch_source_dev( $_ )  : ();
	    }
	}

	if ( $chn ) {
	    #
	    # Call expand_rule() to correctly handle logging. Because
	    # the 'logname' argument is passed, expand_rule() will
	    # not create a separate logging chain but will rather emit
	    # any logging rule in-line.
	    #
	    expand_rule( $chn,
			 PREROUTE_RESTRICT,
			 '', # Prerule
			 '', # Rule
			 '', # Source
			 '', # Dest
			 '', # Original dest
			 'ACCEPT',
			 $loglevel,
			 $log_action,
			 '',
			 '',
			 dnat_chain( $sourcezone  ) )
		unless unreachable_warning( $wildcard, $chn );

	    $loglevel = '';
	    $tgt = $chn->{name};
	} else {
	    $tgt = 'ACCEPT';
	}
    }

    expand_rule( $nonat_chain ,
		 PREROUTE_RESTRICT ,
		 '' ,
		 $rule ,
		 $source ,
		 $dest ,
		 $origdest ,
		 $tgt,
		 $loglevel ,
		 $log_action ,
		 '',
		 '',
	       )
	unless unreachable_warning( $wildcard, $nonat_chain );
}

sub add_addresses () {
    if ( @addresses_to_add ) {
	my @addrs = @addresses_to_add;
	my $arg = '';
	my $addresses = 0;

	while ( @addrs ) {
	    my $addr      = shift @addrs;
	    my $interface = shift @addrs;
	    $arg = "$arg $addr $interface";
	    unless ( $config{RETAIN_ALIASES} ) {
		emit '' unless $addresses++;
		$interface =~ s/:.*//;
		emit "del_ip_addr $addr $interface";
	    }
	}

	emit "\nadd_ip_aliases $arg";
    }
}

1;
