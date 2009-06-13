#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Providers.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009 - Tom Eastep (teastep@shorewall.net)
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
#   This module deals with the /etc/shorewall/providers and
#   /etc/shorewall/route_rules files.
#
package Shorewall::Providers;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_providers @routemarked_interfaces handle_stickiness );
our @EXPORT_OK = qw( initialize lookup_provider );
our $VERSION = '4.3_7';

use constant { LOCAL_TABLE   => 255,
	       MAIN_TABLE    => 254,
	       DEFAULT_TABLE => 253,
	       UNSPEC_TABLE  => 0
	       };

our @routemarked_providers;
our %routemarked_interfaces;
our @routemarked_interfaces;

our $balancing;
our $fallback;
our $first_default_route;
our $first_fallback_route;

our %providers;

our @providers;

our $family;

#
# Initialize globals -- we take this novel approach to globals initialization to allow
#                       the compiler to run multiple times in the same process. The
#                       initialize() function does globals initialization for this
#                       module and is called from an INIT block below. The function is
#                       also called by Shorewall::Compiler::compiler at the beginning of
#                       the second and subsequent calls to that function.
#

sub initialize( $ ) {
    $family = shift;

    @routemarked_providers = ();
    %routemarked_interfaces = ();
    @routemarked_interfaces = ();
    $balancing           = 0;
    $fallback            = 0;
    $first_default_route  = 1;
    $first_fallback_route = 1;

    %providers  = ( local   => { number => LOCAL_TABLE   , mark => 0 , optional => 0 } ,
		    main    => { number => MAIN_TABLE    , mark => 0 , optional => 0 } ,
		    default => { number => DEFAULT_TABLE , mark => 0 , optional => 0 } ,
		    unspec  => { number => UNSPEC_TABLE  , mark => 0 , optional => 0 } );
    @providers = ();
}

INIT {
    initialize( F_IPV4 );
}

#
# Set up marking for 'tracked' interfaces.
#
sub setup_route_marking() {
    my $mask = $config{HIGH_ROUTE_MARKS} ? $config{WIDE_TC_MARKS} ? '0xFF0000' : '0xFF00' : '0xFF';

    require_capability( 'CONNMARK_MATCH' , 'the provider \'track\' option' , 's' );
    require_capability( 'CONNMARK' ,       'the provider \'track\' option' , 's' );

    add_rule $mangle_table->{PREROUTING} , "-m connmark ! --mark 0/$mask -j CONNMARK --restore-mark --mask $mask";
    add_rule $mangle_table->{OUTPUT} ,     "-m connmark ! --mark 0/$mask -j CONNMARK --restore-mark --mask $mask";

    my $chainref  = new_chain 'mangle', 'routemark';
    my $chainref1 = new_chain 'mangle', 'setsticky';
    my $chainref2 = new_chain 'mangle', 'setsticko';

    my %marked_interfaces;

    for my $providerref ( @routemarked_providers ) {
	my $interface = $providerref->{interface};
	my $mark      = $providerref->{mark};
	my $base      = uc chain_base $interface;

	add_command( $chainref, qq(if [ -n "\$${base}_IS_UP" ]; then) ), incr_cmd_level( $chainref ) if $providerref->{optional};

	unless ( $marked_interfaces{$interface} ) {
	    add_rule $mangle_table->{PREROUTING} , "-i $interface -m mark --mark 0/$mask -j routemark";
	    add_jump $mangle_table->{PREROUTING} , $chainref1, 0, "! -i $interface -m mark --mark  $mark/$mask ";
	    add_jump $mangle_table->{OUTPUT}     , $chainref2, 0, "-m mark --mark  $mark/$mask ";
	    $marked_interfaces{$interface} = 1;
	}

	if ( $providerref->{shared} ) {
	    add_rule $chainref, " -i $interface -m mac --mac-source $providerref->{mac} -j MARK --set-mark $providerref->{mark}";
	} else {
	    add_rule $chainref, " -i $interface -j MARK --set-mark $providerref->{mark}";
	}

	decr_cmd_level( $chainref), add_command( $chainref, "fi" ) if $providerref->{optional};
    }

    add_rule $chainref, "-m mark ! --mark 0/$mask -j CONNMARK --save-mark --mask $mask";
}

sub copy_table( $$$ ) {
    my ( $duplicate, $number, $realm ) = @_;

    if ( $realm ) {
	emit  ( "\$IP -$family route show table $duplicate | sed -r 's/ realm [[:alnum:]_]+//' | while read net route; do" )
    } else {
	emit  ( "\$IP -$family route show table $duplicate | while read net route; do" )
    }

    emit ( '    case $net in',
	   '        default|nexthop)',
	   '            ;;',
	   '        *)',
	   "            run_ip route add table $number \$net \$route $realm",
	   '            ;;',
	   '    esac',
	   "done\n"
	 );
}

sub copy_and_edit_table( $$$$ ) {
    my ( $duplicate, $number, $copy, $realm) = @_;

    if ( $realm ) {
	emit  ( "\$IP -$family route show table $duplicate | sed -r 's/ realm [[:alnum:]_]+//' | while read net route; do" )
    } else {
	emit  ( "\$IP -$family route show table $duplicate | while read net route; do" )
    }

    emit (  '    case $net in',
	    '        default|nexthop)',
	    '            ;;',
	    '        *)',
	    '            case $(find_device $route) in',
	    "                $copy)",
	    "                    run_ip route add table $number \$net \$route $realm",
	    '                    ;;',
	    '            esac',
	    '            ;;',
	    '    esac',
	    "done\n" );
}

sub balance_default_route( $$$$ ) {
    my ( $weight, $gateway, $interface, $realm ) = @_;

    $balancing = 1;

    emit '';

    if ( $first_default_route ) {
	if ( $gateway ) {
	    emit "DEFAULT_ROUTE=\"nexthop via $gateway dev $interface weight $weight $realm\"";
	} else {
	    emit "DEFAULT_ROUTE=\"nexthop dev $interface weight $weight $realm\"";
	}

	$first_default_route = 0;
    } else {
	if ( $gateway ) {
	    emit "DEFAULT_ROUTE=\"\$DEFAULT_ROUTE nexthop via $gateway dev $interface weight $weight $realm\"";
	} else {
	    emit "DEFAULT_ROUTE=\"\$DEFAULT_ROUTE nexthop dev $interface weight $weight $realm\"";
	}
    }
}

sub balance_fallback_route( $$$$ ) {
    my ( $weight, $gateway, $interface, $realm ) = @_;

    $fallback = 1;

    emit '';

    if ( $first_fallback_route ) {
	if ( $gateway ) {
	    emit "FALLBACK_ROUTE=\"nexthop via $gateway dev $interface weight $weight $realm\"";
	} else {
	    emit "FALLBACK_ROUTE=\"nexthop dev $interface weight $weight $realm\"";
	}

	$first_fallback_route = 0;
    } else {
	if ( $gateway ) {
	    emit "FALLBACK_ROUTE=\"\$FALLBACK_ROUTE nexthop via $gateway dev $interface weight $weight $realm\"";
	} else {
	    emit "FALLBACK_ROUTE=\"\$FALLBACK_ROUTE nexthop dev $interface weight $weight $realm\"";
	}
    }
}

sub start_provider( $$$ ) {
    my ($table, $number, $test ) = @_;

    emit $test;
    push_indent;

    emit "#\n# Add Provider $table ($number)\n#";

    emit "qt ip -$family route flush table $number";
    emit "echo \"qt \$IP -$family route flush table $number\" >> \${VARDIR}/undo_routing";
}

sub add_a_provider( ) {

    my ($table, $number, $mark, $duplicate, $interface, $gateway,  $options, $copy ) = split_line 6, 8, 'providers file';

    fatal_error "Duplicate provider ($table)" if $providers{$table};

    my $num = numeric_value $number;

    fatal_error "Invalid Provider number ($number)" unless defined $num;

    $number = $num;

    for my $providerref ( values %providers  ) {
	fatal_error "Duplicate provider number ($number)" if $providerref->{number} == $number;
    }

    ( $interface, my $address ) = split /:/, $interface;

    my $shared = 0;

    if ( defined $address ) {
	validate_address $address, 0;
	$shared = 1;
	require_capability 'REALM_MATCH', "Configuring multiple providers through one interface", "s";
    }

    fatal_error "Unknown Interface ($interface)" unless known_interface $interface;

    my $provider    = chain_base $table;
    my $base        = uc chain_base $interface;
    my $gatewaycase = '';

    if ( $gateway eq 'detect' ) {
	fatal_error "Configuring multiple providers through one interface requires an explicit gateway" if $shared;
	$gateway = get_interface_gateway $interface;
	$gatewaycase = 'detect';
    } elsif ( $gateway && $gateway ne '-' ) {
	validate_address $gateway, 0;
	$gatewaycase = 'specified';
    } else {
	$gatewaycase = 'none';
	fatal_error "Configuring multiple providers through one interface requires a gateway" if $shared;
	$gateway = '';
    }

    my $val = 0;
    my $pref;

    if ( $mark ne '-' ) {

	$val = numeric_value $mark;

	fatal_error "Invalid Mark Value ($mark)" unless defined $val;

	verify_mark $mark;

	if ( $val < 65535 ) {
	    if ( $config{HIGH_ROUTE_MARKS} ) {
		fatal_error "Invalid Mark Value ($mark) with HIGH_ROUTE_MARKS=Yes and WIDE_TC_MARKS=Yes" if $config{WIDE_TC_MARKS};
		fatal_error "Invalid Mark Value ($mark) with HIGH_ROUTE_MARKS=Yes" if $val < 256;
	    }
	} else {
	    fatal_error "Invalid Mark Value ($mark)" unless $config{HIGH_ROUTE_MARKS} && $config{WIDE_TC_MARKS};
	}

	for my $providerref ( values %providers  ) {
	    fatal_error "Duplicate mark value ($mark)" if numeric_value( $providerref->{mark} ) == $val;
	}

	$pref = 10000 + $number - 1;

    }

    my ( $loose, $track, $balance , $default, $default_balance, $optional, $mtu ) = (0,0,0,0,$config{USE_DEFAULT_RT} ? 1 : 0,interface_is_optional( $interface ), '' );

    unless ( $options eq '-' ) {
	for my $option ( split_list $options, 'option' ) {
	    if ( $option eq 'track' ) {
		$track = 1;
	    } elsif ( $option =~ /^balance=(\d+)$/ ) {
		fatal_error q('balance' is not available in IPv6) if $family == F_IPV6;
		$balance = $1;
	    } elsif ( $option eq 'balance' ) {
		fatal_error q('balance' is not available in IPv6) if $family == F_IPV6;
		$balance = 1;
	    } elsif ( $option eq 'loose' ) {
		$loose   = 1;
		$default_balance = 0;
	    } elsif ( $option eq 'optional' ) {
		set_interface_option $interface, 'optional', 1;
		$optional = 1;
	    } elsif ( $option =~ /^src=(.*)$/ ) {
		fatal_error "OPTION 'src' not allowed on shared interface" if $shared;
		$address = validate_address( $1 , 1 );
	    } elsif ( $option =~ /^mtu=(\d+)$/ ) {
		$mtu = "mtu $1 ";
	    } elsif ( $option =~ /^fallback=(\d+)$/ ) {
		fatal_error q('fallback' is not available in IPv6) if $family == F_IPV6;
		if ( $config{USE_DEFAULT_RT} ) {
		    warning_message "'fallback' is ignored when USE_DEFAULT_RT=Yes";
		} else {
		    $default = $1;
		    fatal_error 'fallback must be non-zero' unless $default;
		}
	    } elsif ( $option eq 'fallback' ) {
		fatal_error q('fallback' is not available in IPv6) if $family == F_IPV6;
		if ( $config{USE_DEFAULT_RT} ) {
		    warning_message "'fallback' is ignored when USE_DEFAULT_RT=Yes";
		} else {
		    $default = -1;
		}
	    } else {
		fatal_error "Invalid option ($option)";
	    }
	}
    }

    unless ( $loose ) {
	warning_message q(The 'proxyarp' option is dangerous when specified on a Provider interface) if get_interface_option( $interface, 'proxyarp' );
	warning_message q(The 'proxyndp' option is dangerous when specified on a Provider interface) if get_interface_option( $interface, 'proxyndp' );
    }

    $balance = $default_balance unless $balance;

    $providers{$table} = { provider  => $table,
			   number    => $number ,
			   mark      => $val ? in_hex($val) : $val ,
			   interface => $interface ,
			   optional  => $optional ,
			   gateway   => $gateway ,
			   shared    => $shared ,
			   default   => $default };

    if ( $track ) {
	fatal_error "The 'track' option requires a numeric value in the MARK column" if $mark eq '-';

	if ( $routemarked_interfaces{$interface} ) {
	    fatal_error "Interface $interface is tracked through an earlier provider" if $routemarked_interfaces{$interface} > 1;
	    fatal_error "Multiple providers through the same interface must their IP address specified in the INTERFACES" unless $shared;
	} else {
	    $routemarked_interfaces{$interface} = $shared ? 1 : 2;
	    push @routemarked_interfaces, $interface;
	}

	push @routemarked_providers, $providers{$table};
    }

    my $realm = '';

    if ( $shared ) {
	my $variable = $providers{$table}{mac} = get_interface_mac( $gateway, $interface , $table );
	$realm = "realm $number";
	start_provider( $table, $number, qq(if interface_is_usable $interface && [ -n "$variable" ]; then) );
    } elsif ( $gatewaycase eq 'detect' ) {
	start_provider( $table, $number, qq(if interface_is_usable $interface && [ -n "$gateway" ]; then) );
    } else {
	start_provider( $table, $number, "if interface_is_usable $interface; then" );
	emit "run_ip route add default dev $interface table $number" if $gatewaycase eq 'none';
    }	

    if ( $mark ne '-' ) {
	emit ( "qt \$IP -$family rule del fwmark $mark" ) if $config{DELETE_THEN_ADD};

	emit ( "run_ip rule add fwmark $mark pref $pref table $number",
	       "echo \"qt \$IP -$family rule del fwmark $mark\" >> \${VARDIR}/undo_routing"
	     );
    }

    if ( $duplicate ne '-' ) {
	fatal_error "The DUPLICATE column must be empty when USE_DEFAULT_RT=Yes" if $config{USE_DEFAULT_RT};
	if ( $copy eq '-' ) {
	    copy_table ( $duplicate, $number, $realm );
	} else {
	    if ( $copy eq 'none' ) {
		$copy = $interface;
	    } else {
		$copy =~ tr/,/|/;
		$copy = "$interface|$copy";
	    }

	    copy_and_edit_table( $duplicate, $number ,$copy , $realm);
	}
    } elsif ( $copy ne '-' ) {
	fatal_error "The COPY column must be empty when USE_DEFAULT_RT=Yes" if $config{USE_DEFAULT_RT};
	fatal_error 'A non-empty COPY column requires that a routing table be specified in the DUPLICATE column';
    }

    if ( $gateway ) {
	$address = get_interface_address $interface unless $address;
	emit "run_ip route replace $gateway src $address dev $interface ${mtu}table $number $realm";
	emit "run_ip route add default via $gateway src $address dev $interface ${mtu}table $number $realm";
    }

    balance_default_route $balance , $gateway, $interface, $realm if $balance;

    if ( $default > 0 ) {
	balance_fallback_route $default , $gateway, $interface, $realm;
    } elsif ( $default ) {
	emit '';
	if ( $gateway ) {
	    emit qq(run_ip route replace default via $gateway src $address dev $interface table ) . DEFAULT_TABLE . qq( dev $interface metric $number);
	    emit qq(echo "qt \$IP route del default via $gateway table ) . DEFAULT_TABLE . qq(" >> \${VARDIR}/undo_routing);
	} else {
	    emit qq(run_ip route add default table ) . DEFAULT_TABLE . qq( dev $interface metric $number);
	    emit qq(echo "qt \$IP route del default dev $interface table ) . DEFAULT_TABLE . qq(" >> \${VARDIR}/undo_routing);
	}
    }

    if ( $loose ) {
	if ( $config{DELETE_THEN_ADD} ) {
	    emit ( "\nfind_interface_addresses $interface | while read address; do",
		   "    qt \$IP -$family rule del from \$address",
		   'done'
		 );
	}
    } elsif ( $shared ) {
	emit  "qt \$IP -$family rule del from $address" if $config{DELETE_THEN_ADD};
	emit( "run_ip rule add from $address pref 20000 table $number" ,
	      "echo \"qt \$IP -$family rule del from $address\" >> \${VARDIR}/undo_routing" );
    } else {
	my $rulebase = 20000 + ( 256 * ( $number - 1 ) );

	emit "\nrulenum=0\n";

	emit  ( "find_interface_addresses $interface | while read address; do" );
	emit  (	"    qt \$IP -$family rule del from \$address" ) if $config{DELETE_THEN_ADD};
	emit  (	"    run_ip rule add from \$address pref \$(( $rulebase + \$rulenum )) table $number",
		"    echo \"qt \$IP -$family rule del from \$address\" >> \${VARDIR}/undo_routing",
		'    rulenum=$(($rulenum + 1))',
		'done'
	      );
    }

    emit qq(\nprogress_message "   Provider $table ($number) Added"\n);

    emit ( "${base}_IS_UP=Yes" ) if $optional;

    pop_indent;
    emit 'else';

    if ( $optional ) {
	if ( $shared ) {
	    emit ( "    error_message \"WARNING: Interface $interface is not usable -- Provider $table ($number) not Added\"" );
	} else {
	    emit ( "    error_message \"WARNING: Gateway $gateway is not reachable -- Provider $table ($number) not Added\"" );
	}

	emit( "    ${base}_IS_UP=" );
    } else {
	if ( $shared ) {
	    emit( "    fatal_error \"Gateway $gateway is not reachable -- Provider $table ($number) Cannot be Added\"" );
	} else {
	    emit( "    fatal_error \"Interface $interface is not usable -- Provider $table ($number) Cannot be Added\"" );
	}
    }

    emit "fi\n";

    push @providers, $table;

    progress_message "   Provider \"$currentline\" $done";
}

sub add_an_rtrule( ) {
    my ( $source, $dest, $provider, $priority ) = split_line 4, 4, 'route_rules file';

    unless ( $providers{$provider} ) {
	my $found = 0;

	if ( "\L$provider" =~ /^(0x[a-f0-9]+|0[0-7]*|[0-9]*)$/ ) {
	    my $provider_number = numeric_value $provider;

	    for ( keys %providers ) {
		if ( $providers{$_}{number} == $provider_number ) {
		    $provider = $_;
		    $found = 1;
		    last;
		}
	    }
	}

	fatal_error "Unknown provider ($provider)" unless $found;
    }

    fatal_error "You must specify either the source or destination in a route_rules entry" if $source eq '-' && $dest eq '-';

    if ( $dest eq '-' ) {
	$dest = 'to ' . ALLIP; 
    } else {
	validate_net( $dest, 0 );
	$dest = "to $dest";
    }

    if ( $source eq '-' ) {
	$source = 'from ' . ALLIP;
    } elsif ( $family == F_IPV4 ) {
	if ( $source =~ /:/ ) {
	    ( my $interface, $source , my $remainder ) = split( /:/, $source, 3 );
	    fatal_error "Invalid SOURCE" if defined $remainder;
	    validate_net ( $source, 0 );
	    $source = "iif $interface from $source";
	} elsif ( $source =~ /\..*\..*/ ) {
	    validate_net ( $source, 0 );
	    $source = "from $source";
	} else {
	    $source = "iif $source";
	}
    } elsif ( $source =~  /^(.+?):<(.+)>\s*$/ ) {
	my ($interface, $source ) = ($1, $2);
	validate_net ($source, 0);
	$source = "iif $interface from $source";
    } elsif (  $source =~ /:.*:/ || $source =~ /\..*\..*/ ) {
	validate_net ( $source, 0 );
	$source = "from $source";
    } else {
	$source = "iif $source";
    }

    fatal_error "Invalid priority ($priority)" unless $priority && $priority =~ /^\d{1,5}$/;

    $priority = "priority $priority";

    emit ( "qt \$IP -$family rule del $source $dest $priority" ) if $config{DELETE_THEN_ADD};

    my ( $optional, $number ) = ( $providers{$provider}{optional} , $providers{$provider}{number} );

    if ( $optional ) {
	my $base = uc chain_base( $providers{$provider}{interface} );
	emit ( '', "if [ -n \$${base}_IS_UP ]; then" );
	push_indent;
    }

    emit ( "run_ip rule add $source $dest $priority table $number",
	   "echo \"qt \$IP -$family rule del $source $dest $priority\" >> \${VARDIR}/undo_routing" );

    pop_indent, emit ( "fi\n" ) if $optional;

    progress_message "   Routing rule \"$currentline\" $done";
}

#
# This probably doesn't belong here but looking forward to the day when we get Shorewall out of the routing business,
# it makes sense to keep all of the routing code together
#
sub setup_null_routing() {
    save_progress_message "Null Routing the RFC 1918 subnets";
    for ( rfc1918_networks ) {
	emit( "run_ip route replace unreachable $_" );
	emit( "echo \"qt \$IP -$family route del unreachable $_\" >> \${VARDIR}/undo_routing" );
    } 
}

sub start_providers() {
    require_capability( 'MANGLE_ENABLED' , 'a non-empty providers file' , 's' );
    
    fatal_error "A non-empty providers file is not permitted with MANGLE_ENABLED=No" unless $config{MANGLE_ENABLED};

    emit "\nif [ -z \"\$NOROUTES\" ]; then";

    push_indent;

    emit  ( '#',
	    '# Undo any changes made since the last time that we [re]started -- this will not restore the default route',
	    '#',
	    'undo_routing' );

    unless ( $config{KEEP_RT_TABLES} ) {
	emit  (
	       '#',
	       '# Save current routing table database so that it can be restored later',
	       '#',
	       'cp /etc/iproute2/rt_tables ${VARDIR}/' );
	
    }

    emit  ( '#',
	    '# Capture the default route(s) if we don\'t have it (them) already.',
	    '#',
	    '[ -f ${VARDIR}/default_route ] || $IP -' . $family . ' route list | grep -E \'^\s*(default |nexthop )\' > ${VARDIR}/default_route',
	    '#',
	    '# Initialize the file that holds \'undo\' commands',
	    '#',
	    '> ${VARDIR}/undo_routing' );
    
    save_progress_message 'Adding Providers...';
    
    emit 'DEFAULT_ROUTE=';
    emit 'FALLBACK_ROUTE=';
    emit '';
}

sub finish_providers() {
    if ( $balancing ) {
	my $table = MAIN_TABLE;

	if ( $config{USE_DEFAULT_RT} ) {
	    emit ( 'run_ip rule add from ' . ALLIP . ' table ' . MAIN_TABLE . ' pref 999',
		   "\$IP -$family rule del from " . ALLIP . ' table ' . MAIN_TABLE . ' pref 32766',
		   qq(echo "qt \$IP -$family rule add from ) . ALLIP . ' table ' . MAIN_TABLE . ' pref 32766" >> ${VARDIR}/undo_routing',
		   qq(echo "qt \$IP -$family rule del from ) . ALLIP . ' table ' . MAIN_TABLE . ' pref 999" >> ${VARDIR}/undo_routing',
		   '' );
	    $table = DEFAULT_TABLE;
	}

	emit  ( 'if [ -n "$DEFAULT_ROUTE" ]; then' );
	emit  ( "    run_ip route replace default scope global table $table \$DEFAULT_ROUTE" );
	emit  ( "    qt \$IP -$family route del default table " . MAIN_TABLE ) if $config{USE_DEFAULT_RT};
	emit  ( "    progress_message \"Default route '\$(echo \$DEFAULT_ROUTE | sed 's/\$\\s*//')' Added\"",
		'else',
		'    error_message "WARNING: No Default route added (all \'balance\' providers are down)"' );

	if ( $config{RESTORE_DEFAULT_ROUTE} ) {
	    emit '    restore_default_route && error_message "NOTICE: Default route restored"'
	} else {
	    emit qq(    qt \$IP -$family route del default table $table && error_message "WARNING: Default route deleted from table $table");
	}
	
	emit(   'fi',
		'' );
    } else {
	emit ( '#',
	       '# We don\'t have any \'balance\' providers so we restore any default route that we\'ve saved',
	       '#',
	       'restore_default_route' ,
	       '' );
    }

    if ( $fallback ) {
	emit  ( 'if [ -n "$FALLBACK_ROUTE" ]; then' ,
		"    run_ip route replace default scope global table " . DEFAULT_TABLE . " \$FALLBACK_ROUTE" ,
		"    progress_message \"Fallback route '\$(echo \$FALLBACK_ROUTE | sed 's/\$\\s*//')' Added\"",
		'fi',
		'' );
    }

    unless ( $config{KEEP_RT_TABLES} ) {
	emit( 'if [ -w /etc/iproute2/rt_tables ]; then',
	      '    cat > /etc/iproute2/rt_tables <<EOF' );

	push_indent;

	emit_unindented join( "\n",
			      '#',
			      '# reserved values',
			      '#',
			      LOCAL_TABLE   . "\tlocal",
			      MAIN_TABLE    . "\tmain",
			      DEFAULT_TABLE . "\tdefault",
			      "0\tunspec",
			      '#',
			      '# local',
			      '#',
			      "EOF\n" );

	emit "echocommand=\$(find_echo)\n";

	for my $table ( @providers ) {
	    emit "\$echocommand \"$providers{$table}{number}\\t$table\" >>  /etc/iproute2/rt_tables";
	}

	pop_indent;

	emit "fi\n";
    }
}

sub setup_providers() {
    my $providers = 0;

    my $fn = open_file 'providers';

    first_entry sub() { progress_message2 "$doing $fn..."; start_providers; };

    add_a_provider, $providers++ while read_a_line;

    if ( $providers ) {
	finish_providers;

	my $fn = open_file 'route_rules';

	if ( $fn ) {

	    first_entry "$doing $fn...";

	    emit '';
	    
	    add_an_rtrule while read_a_line;
	}

	setup_null_routing if $config{NULL_ROUTE_RFC1918};
	emit "\nrun_ip route flush cache";
	pop_indent;
	emit "fi\n";

	setup_route_marking if @routemarked_interfaces;
    } else {
	emit "\nundo_routing";
	emit 'restore_default_route';
	if ( $config{NULL_ROUTE_RFC1918} ) {
	    emit "\nif [ -z \"\$NOROUTES\" ]; then";

	    push_indent;

	    emit  ( '#',
		    '# Initialize the file that holds \'undo\' commands',
		    '#',
		    '> ${VARDIR}/undo_routing' );
	    setup_null_routing;
	    emit "\nrun_ip route flush cache";

	    pop_indent;

	    emit "fi\n";
	}
    }

}

sub lookup_provider( $ ) {
    my $provider    = $_[0];
    my $providerref = $providers{ $provider };

    unless ( $providerref ) {
	fatal_error "Unknown provider ($provider)" unless $provider =~ /^(0x[a-f0-9]+|0[0-7]*|[0-9]*)$/;

	my $provider_number = numeric_value $provider;

	for ( keys %providers ) {
	    if ( $providers{$_}{number} == $provider_number ) {
		$providerref = $providers{$_};
		last;
	    }
	}

	fatal_error "Unknown provider ($provider)" unless $providerref;
    }


    $providerref->{shared} ? $providerref->{number} : 0;
}

#
# The Tc module has collected the 'sticky' rules in the 'tcpre' and 'tcout' chains. In this function, we apply them
# to the 'tracked' providers
#
sub handle_stickiness( $ ) {
    my $havesticky   = shift;
    my $mask         = $config{HIGH_ROUTE_MARKS} ? $config{WIDE_TC_MARKS} ? '0xFF0000' : '0xFF00' : '0xFF';
    my $setstickyref = $mangle_table->{setsticky};
    my $setstickoref = $mangle_table->{setsticko};
    my $tcpreref     = $mangle_table->{tcpre};
    my $tcoutref     = $mangle_table->{tcout};
    my %marked_interfaces;
    my $sticky = 1;

    if ( $havesticky ) {
	fatal_error "There are SAME tcrules but no 'track' providers" unless @routemarked_providers;
	

	for my $providerref ( @routemarked_providers ) {
	    my $interface = $providerref->{interface};
	    my $base      = uc chain_base $interface;
	    my $mark      = $providerref->{mark};
	
	    for ( grep /-j sticky/, @{$tcpreref->{rules}} ) {
		my $stickyref = ensure_mangle_chain 'sticky';
		my ( $rule1, $rule2 );
		my $list = sprintf "sticky%03d" , $sticky++;
		
		for my $chainref ( $stickyref, $setstickyref ) {

		    add_command( $chainref, qq(if [ -n "\$${base}_IS_UP" ]; then) ), incr_cmd_level( $chainref ) if $providerref->{optional};

		    if ( $chainref->{name} eq 'sticky' ) {
			$rule1 = $_;
			$rule1 =~ s/-j sticky/-m recent --name $list --update --seconds 300 -j MARK --set-mark $mark/;
			$rule2 = $_;
			$rule2 =~ s/-j sticky/-m mark --mark 0\/$mask -m recent --name $list --remove/;
		    } else {
			$rule1 = $_;
			$rule1 =~ s/-j sticky/-m mark --mark $mark\/$mask -m recent --name $list --set/;
		    }
		
		    $rule1 =~ s/-A //;

		    add_rule $chainref, $rule1;

		    if ( $rule2 ) {
			$rule2 =~ s/-A //;
			add_rule $chainref, $rule2;
		    }

		    decr_cmd_level( $chainref), add_command( $chainref, "fi" ) if $providerref->{optional};
		    
		}
	    }

	    for ( grep /-j sticko/, @{$tcoutref->{rules}} ) {
		my ( $rule1, $rule2 );
		my $list = sprintf "sticky%03d" , $sticky++;
		my $stickoref = ensure_mangle_chain 'sticko';

		for my $chainref ( $stickoref, $setstickoref ) {
		    add_command( $chainref, qq(if [ -n "\$${base}_IS_UP" ]; then) ), incr_cmd_level( $chainref ) if $providerref->{optional};

		    if ( $chainref->{name} eq 'sticko' ) {
			$rule1 = $_;
			$rule1 =~ s/-j sticko/-m recent --name $list --rdest --update --seconds 300 -j MARK --set-mark $mark/;
			$rule2 = $_;
			$rule2 =~ s/-j sticko/-m mark --mark 0\/$mask -m recent --name $list --rdest --remove/;
		    } else {
			$rule1 = $_;
			$rule1 =~ s/-j sticko/-m mark --mark $mark -m recent --name $list --rdest --set/;
		    }
		
		    $rule1 =~ s/-A //;

		    add_rule $chainref, $rule1;

		    if ( $rule2 ) {
			$rule2 =~ s/-A //;
			add_rule $chainref, $rule2;
		    }

		    decr_cmd_level( $chainref), add_command( $chainref, "fi" ) if $providerref->{optional};
		}
	    }
	}
    }

    if ( @routemarked_providers ) {
	purge_jump $mangle_table->{PREROUTING}, $setstickyref unless @{$setstickyref->{rules}};
	purge_jump $mangle_table->{OUTPUT},     $setstickoref unless @{$setstickoref->{rules}};	
    }
}
1;
