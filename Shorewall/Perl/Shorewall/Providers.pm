#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Providers.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010.2011,2012 - Tom Eastep (teastep@shorewall.net)
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
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MAS 02110-1301 USA.
#
#   This module deals with the /etc/shorewall/providers,
#   /etc/shorewall/rtrules and /etc/shorewall/routes files.
#
package Shorewall::Providers;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::Proc qw( setup_interface_proc );

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( process_providers
		  setup_providers
		  @routemarked_interfaces
		  handle_stickiness
		  handle_optional_interfaces
		  setup_load_distribution
	       );
our @EXPORT_OK = qw( initialize lookup_provider );
our $VERSION = '4.4_24';

use constant { LOCAL_TABLE   => 255,
	       MAIN_TABLE    => 254,
	       DEFAULT_TABLE => 253,
	       BALANCE_TABLE => 250,
	       UNSPEC_TABLE  => 0
	       };

my  @routemarked_providers;
my  %routemarked_interfaces;
our @routemarked_interfaces;
my  %provider_interfaces;
my  @load_providers;
my  @load_interfaces;

my $balancing;
my $fallback;
my $first_default_route;
my $first_fallback_route;
my $maxload;

my %providers;

my @providers;

my $family;

my $lastmark;

use constant { ROUTEMARKED_SHARED => 1, ROUTEMARKED_UNSHARED => 2 };

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

    @routemarked_providers  = ();
    %routemarked_interfaces = ();
    @routemarked_interfaces = ();
    %provider_interfaces    = ();
    @load_providers         = ();
    @load_interfaces        = ();
    $balancing              = 0;
    $fallback               = 0;
    $first_default_route    = 1;
    $first_fallback_route   = 1;
    $maxload                = 0;

    %providers  = ( local   => { number => LOCAL_TABLE   , mark => 0 , optional => 0 ,routes => [], rules => [] } ,
		    main    => { number => MAIN_TABLE    , mark => 0 , optional => 0 ,routes => [], rules => [] } ,
		    default => { number => DEFAULT_TABLE , mark => 0 , optional => 0 ,routes => [], rules => [] } ,
		    balance => { number => BALANCE_TABLE , mark => 0 , optional => 0 ,routes => [], rules => [] } ,
		    unspec  => { number => UNSPEC_TABLE  , mark => 0 , optional => 0 ,routes => [], rules => [] } );
    @providers = ();
}

#
# Set up marking for 'tracked' interfaces.
#
sub setup_route_marking() {
    my $mask = in_hex( $globals{PROVIDER_MASK} );

    require_capability( $_ , q(The provider 'track' option) , 's' ) for qw/CONNMARK_MATCH CONNMARK/;

    add_ijump $mangle_table->{$_} , j => 'CONNMARK', targetopts => "--restore-mark --mask $mask", connmark => "! --mark 0/$mask" for qw/PREROUTING OUTPUT/;

    my $chainref  = new_chain 'mangle', 'routemark';

    if ( @routemarked_providers ) {
	my $chainref1 = new_chain 'mangle', 'setsticky';
	my $chainref2 = new_chain 'mangle', 'setsticko';

	my %marked_interfaces;

	for my $providerref ( @routemarked_providers ) {
	    my $interface = $providerref->{interface};
	    my $physical  = $providerref->{physical};
	    my $mark      = $providerref->{mark};

	    unless ( $marked_interfaces{$interface} ) {
		add_ijump $mangle_table->{PREROUTING} , j => $chainref,  i => $physical,     mark => "--mark 0/$mask";
		add_ijump $mangle_table->{PREROUTING} , j => $chainref1, i => "! $physical", mark => "--mark  $mark/$mask";
		add_ijump $mangle_table->{OUTPUT}     , j => $chainref2,                     mark => "--mark  $mark/$mask";
		$marked_interfaces{$interface} = 1;
	    }

	    if ( $providerref->{shared} ) {
		add_commands( $chainref, qq(if [ -n "$providerref->{mac}" ]; then) ), incr_cmd_level( $chainref ) if $providerref->{optional};
		add_ijump $chainref, j => 'MARK', targetopts => "--set-mark $providerref->{mark}", imatch_source_dev( $interface ), mac => "--mac-source $providerref->{mac}";
		decr_cmd_level( $chainref ), add_commands( $chainref, "fi\n" ) if $providerref->{optional};
	    } else {
		add_ijump $chainref, j => 'MARK', targetopts => "--set-mark $providerref->{mark}", imatch_source_dev( $interface );
	    }
	}

	add_ijump $chainref, j => 'CONNMARK', targetopts => "--save-mark --mask $mask", mark => "! --mark 0/$mask";
    }

    if ( @load_interfaces ) {
	my $chainref1 = new_chain 'mangle', 'balance';
	my @match;

	add_ijump $chainref,               g => $chainref1, mark => "--mark 0/$mask";
	add_ijump $mangle_table->{OUTPUT}, j => $chainref1, state_imatch( 'NEW,RELATED' ), mark => "--mark 0/$mask";

	for my $physical ( @load_interfaces ) {

	    my $chainref2 = new_chain( 'mangle', load_chain( $physical ) );

	    set_optflags( $chainref2, DONT_OPTIMIZE | DONT_MOVE | DONT_DELETE );
	
  	    add_ijump ( $chainref1,
			j => $chainref2 ,
		        mark => "--mark 0/$mask" );
	}
    }
}

sub copy_table( $$$ ) {
    my ( $duplicate, $number, $realm ) = @_;
    
    my $filter = $family == F_IPV6 ? q(fgrep -v ' cache ' | sed 's/ via :: / /' | ) : '';

    emit '';

    if ( $realm ) {
	emit  ( "\$IP -$family -o route show table $duplicate | sed -r 's/ realm [[:alnum:]_]+//' | ${filter}while read net route; do" )
    } else {
	emit  ( "\$IP -$family -o route show table $duplicate | ${filter}while read net route; do" )
    }

    emit ( '    case $net in',
	   '        default)',
	   '            ;;',
	   '        *)' );
	   
    if ( $family == F_IPV4 ) {
	emit ( '            case $net in',
	       '                255.255.255.255*)',
	       '                    ;;',
	       '                *)',
	       "                    run_ip route add table $number \$net \$route $realm",
	       '                    ;;',
	       '            esac',
	     );
    } else {
	emit ( "            run_ip route add table $number \$net \$route $realm" );
    }

    emit ( '            ;;',
	   '    esac',
	   "done\n"
	 );
}

sub copy_and_edit_table( $$$$ ) {
    my ( $duplicate, $number, $copy, $realm) = @_;

    my $filter = $family == F_IPV6 ? q(fgrep -v ' cache ' | sed 's/ via :: / /' | ) : '';
    #
    # Map physical names in $copy to logical names
    #
    $copy = join( '|' , map( physical_name($_) , split( ',' , $copy ) ) );
    #
    # Shell and iptables use a different wildcard character
    #
    $copy =~ s/\+/*/g;
    
    emit '';

    if ( $realm ) {
	emit  ( "\$IP -$family -o route show table $duplicate | sed -r 's/ realm [[:alnum:]]+//' | ${filter}while read net route; do" )
    } else {
	emit  ( "\$IP -$family -o route show table $duplicate | ${filter}while read net route; do" )
    }

    emit (  '    case $net in',
	    '        default)',
	    '            ;;',
	    '        *)',
	    '            case $(find_device $route) in',
	    "                $copy)" );
    if ( $family == F_IPV4 ) {
	emit (  '                    case $net in',
		'                        255.255.255.255*)',
		'                            ;;',
		'                        *)',
		"                            run_ip route add table $number \$net \$route $realm",
		'                            ;;',
		'                    esac',
	     );
    } else {
	emit (  "                    run_ip route add table $number \$net \$route $realm" );
    } 

    emit (  '                    ;;',
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
	if ( $family == F_IPV4 ) {
	    if ( $gateway ) {
		emit "DEFAULT_ROUTE=\"nexthop via $gateway dev $interface weight $weight $realm\"";
	    } else {
		emit "DEFAULT_ROUTE=\"nexthop dev $interface weight $weight $realm\"";
	    }
	} else {
	    #
	    # IPv6 doesn't support multi-hop routes
	    #
	    if ( $gateway ) {
		emit "DEFAULT_ROUTE=\"via $gateway dev $interface $realm\"";
	    } else {
		emit "DEFAULT_ROUTE=\"dev $interface $realm\"";
	    }
	}

	$first_default_route = 0;
    } else {
	fatal_error "Only one 'balance' provider is allowed with IPv6" if $family == F_IPV6;

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
	if ( $family == F_IPV4 ) {
	    if ( $gateway ) {
		emit "FALLBACK_ROUTE=\"nexthop via $gateway dev $interface weight $weight $realm\"";
	    } else {
		emit "FALLBACK_ROUTE=\"nexthop dev $interface weight $weight $realm\"";
	    }
	} else {
	    #
	    # IPv6 doesn't support multi-hop routes
	    #
	    if ( $gateway ) {
		emit "FALLBACK_ROUTE=\"via $gateway dev $interface $realm\"";
	    } else {
		emit "FALLBACK_ROUTE=\"dev $interface $realm\"";
	    }
	}

	$first_fallback_route = 0;
    } else {
	fatal_error "Only one 'fallback' provider is allowed with IPv6" if $family == F_IPV6;

	if ( $gateway ) {
	    emit "FALLBACK_ROUTE=\"\$FALLBACK_ROUTE nexthop via $gateway dev $interface weight $weight $realm\"";
	} else {
	    emit "FALLBACK_ROUTE=\"\$FALLBACK_ROUTE nexthop dev $interface weight $weight $realm\"";
	}
    }
}

sub start_provider( $$$ ) {
    my ($table, $number, $test ) = @_;

    emit "\n#\n# Add Provider $table ($number)\n#";

    emit "start_provider_$table() {";
    push_indent;
    emit $test;
    push_indent;

    emit "qt ip -$family route flush table $number";
    emit "echo \"qt \$IP -$family route flush table $number\" > \${VARDIR}/undo_${table}_routing";
}

#
# Process a record in the providers file
#
sub process_a_provider() {

    my ($table, $number, $mark, $duplicate, $interface, $gateway,  $options, $copy ) =
	split_line 'providers file', { table => 0, number => 1, mark => 2, duplicate => 3, interface => 4, gateway => 5, options => 6, copy => 7 };

    fatal_error "Duplicate provider ($table)" if $providers{$table};

    fatal_error 'NAME must be specified' if $table eq '-';
    fatal_error "Invalid Provider Name ($table)" unless $table =~ /^[\w]+$/;

    my $num = numeric_value $number;

    fatal_error 'NUMBER must be specified' if $number eq '-';
    fatal_error "Invalid Provider number ($number)" unless defined $num;

    $number = $num;

    for my $providerref ( values %providers  ) {
	fatal_error "Duplicate provider number ($number)" if $providerref->{number} == $number;
    }

    fatal_error 'INTERFACE must be specified' if $interface eq '-';

    ( $interface, my $address ) = split /:/, $interface;

    my $shared = 0;

    if ( defined $address ) {
	validate_address $address, 0;
	$shared = 1;
	require_capability 'REALM_MATCH', "Configuring multiple providers through one interface", "s";
    }

    fatal_error "Unknown Interface ($interface)" unless known_interface( $interface );
    fatal_error "A bridge port ($interface) may not be configured as a provider interface" if port_to_bridge $interface;

    my $physical    = get_physical $interface;
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

    my ( $loose, $track,                   $balance , $default, $default_balance,                $optional,                           $mtu, $local , $load ) =
	(0,      $config{TRACK_PROVIDERS}, 0 ,        0,        $config{USE_DEFAULT_RT} ? 1 : 0, interface_is_optional( $interface ), ''  , 0      , 0 );

    unless ( $options eq '-' ) {
	for my $option ( split_list $options, 'option' ) {
	    if ( $option eq 'track' ) {
		require_capability( 'MANGLE_ENABLED' , q(The 'track' option) , 's' );
		$track = 1;
	    } elsif ( $option eq 'notrack' ) {
		$track = 0;
	    } elsif ( $option =~ /^balance=(\d+)$/ ) {
		fatal_error q('balance=<weight>' is not available in IPv6) if $family == F_IPV6;
		$balance = $1;
	    } elsif ( $option eq 'balance' ) {
		$balance = 1;
	    } elsif ( $option eq 'loose' ) {
		$loose   = 1;
		$default_balance = 0;
	    } elsif ( $option eq 'optional' ) {
		unless ( $shared ) {
		    warning_message q(The 'optional' provider option is deprecated - use the 'optional' interface option instead);
		    set_interface_option $interface, 'optional', 1;
		}

		$optional = 1;
	    } elsif ( $option =~ /^src=(.*)$/ ) {
		fatal_error "OPTION 'src' not allowed on shared interface" if $shared;
		$address = validate_address( $1 , 1 );
	    } elsif ( $option =~ /^mtu=(\d+)$/ ) {
		$mtu = "mtu $1 ";
	    } elsif ( $option =~ /^fallback=(\d+)$/ ) {
		fatal_error q('fallback=<weight>' is not available in IPv6) if $family == F_IPV6;
		$default = $1;
		$default_balance = 0;
		fatal_error 'fallback must be non-zero' unless $default;
	    } elsif ( $option eq 'fallback' ) {
		$default = -1;
		$default_balance = 0;
	    } elsif ( $option eq 'local' ) {
		$local = 1;
		$track = 0           if $config{TRACK_PROVIDERS};
		$default_balance = 0 if $config{USE_DEFAULT_RT};
	    } elsif ( $option =~ /^load=(0?\.\d{1,8})/ ) {
		$load = $1;
		require_capability 'STATISTIC_MATCH', "load=$load", 's';
	    } else {
		fatal_error "Invalid option ($option)";
	    }
	}
    }

    fatal_error q(The 'balance' and 'fallback' options are mutually exclusive) if $balance && $default;

    if ( $load ) {
	fatal_error q(The 'balance=<weight>' and 'load=<load-factor>' options are mutually exclusive) if $balance > 1;
	fatal_error q(The 'fallback=<weight>' and 'load=<load-factor>' options are mutually exclusive) if $default > 1;
	$maxload += $load;
    }

    if ( $local ) {
	fatal_error "GATEWAY not valid with 'local' provider" unless $gatewaycase eq 'none';
	fatal_error "'track' not valid with 'local'"          if $track;
	fatal_error "DUPLICATE not valid with 'local'"        if $duplicate ne '-';
	fatal_error "MARK required with 'local'"              unless $mark;
    }

    my $val = 0;
    my $pref;

    $mark = ( $lastmark += ( 1 << $config{PROVIDER_OFFSET} ) ) if $mark eq '-' && $track;

    if ( $mark ne '-' ) {

	require_capability( 'MANGLE_ENABLED' , 'Provider marks' , '' );

	$val = numeric_value $mark;

	fatal_error "Invalid Mark Value ($mark)" unless defined $val && $val;

	verify_mark $mark;

	fatal_error "Invalid Mark Value ($mark)" unless ( $val & $globals{PROVIDER_MASK} ) == $val;

	fatal_error "Provider MARK may not be specified when PROVIDER_BITS=0" unless $config{PROVIDER_BITS};

	for my $providerref ( values %providers  ) {
	    fatal_error "Duplicate mark value ($mark)" if numeric_value( $providerref->{mark} ) == $val;
	}

	$pref = 10000 + $number - 1;

	$lastmark = $val;

    }

    unless ( $loose ) {
	warning_message q(The 'proxyarp' option is dangerous when specified on a Provider interface) if get_interface_option( $interface, 'proxyarp' );
	warning_message q(The 'proxyndp' option is dangerous when specified on a Provider interface) if get_interface_option( $interface, 'proxyndp' );
    }

    $balance = $default_balance unless $balance;

    fatal_error "Interface $interface is already associated with non-shared provider $provider_interfaces{$interface}" if $provider_interfaces{$table};

    if ( $duplicate ne '-' ) {
	fatal_error "The DUPLICATE column must be empty when USE_DEFAULT_RT=Yes" if $config{USE_DEFAULT_RT};
    } elsif ( $copy ne '-' ) {
	fatal_error "The COPY column must be empty when USE_DEFAULT_RT=Yes" if $config{USE_DEFAULT_RT};
	fatal_error 'A non-empty COPY column requires that a routing table be specified in the DUPLICATE column';
    }

    $providers{$table} = { provider    => $table,
			   number      => $number ,
			   rawmark     => $mark ,
			   mark        => $val ? in_hex($val) : $val ,
			   interface   => $interface ,
			   physical    => $physical ,
			   optional    => $optional ,
			   gateway     => $gateway ,
			   gatewaycase => $gatewaycase ,
			   shared      => $shared ,
			   default     => $default ,
			   copy        => $copy ,
			   balance     => $balance ,
			   pref        => $pref ,
			   mtu         => $mtu ,
			   track       => $track ,
			   loose       => $loose ,
			   duplicate   => $duplicate ,
			   address     => $address ,
			   local       => $local ,
			   load        => $load ,
			   rules       => [] ,
			   routes      => [] ,
			 };

    if ( $track ) {
	fatal_error "The 'track' option requires a numeric value in the MARK column" if $mark eq '-';

	if ( $routemarked_interfaces{$interface} ) {
	    fatal_error "Interface $interface is tracked through an earlier provider" if $routemarked_interfaces{$interface} == ROUTEMARKED_UNSHARED;
	    fatal_error "Multiple providers through the same interface must their IP address specified in the INTERFACES" unless $shared;
	} else {
	    $routemarked_interfaces{$interface} = $shared ? ROUTEMARKED_SHARED : ROUTEMARKED_UNSHARED;
	    push @routemarked_interfaces, $interface;
	}

	push @routemarked_providers, $providers{$table};
    }

    push @load_interfaces, $physical if $load;

    push @providers, $table;

    progress_message "   Provider \"$currentline\" $done";
}

#
# Generate the start_provider_...() function for the passed provider
#
sub add_a_provider( $$ ) {
  
    my ( $providerref, $tcdevices ) = @_;
    
    my $table       = $providerref->{provider};
    my $number      = $providerref->{number};
    my $mark        = $providerref->{rawmark};
    my $interface   = $providerref->{interface};
    my $physical    = $providerref->{physical};
    my $optional    = $providerref->{optional};
    my $gateway     = $providerref->{gateway};
    my $gatewaycase = $providerref->{gatewaycase};
    my $shared      = $providerref->{shared};
    my $default     = $providerref->{default};
    my $copy        = $providerref->{copy};
    my $balance     = $providerref->{balance};
    my $pref        = $providerref->{pref};
    my $mtu         = $providerref->{mtu};
    my $track       = $providerref->{track};
    my $loose       = $providerref->{loose};
    my $duplicate   = $providerref->{duplicate};
    my $address     = $providerref->{address};
    my $local       = $providerref->{local};
    my $load        = $providerref->{load};

    my $dev         = chain_base $physical;
    my $base        = uc $dev;
    my $realm = '';

    if ( $shared ) {
	my $variable = $providers{$table}{mac} = get_interface_mac( $gateway, $interface , $table );
	$realm = "realm $number";
	start_provider( $table, $number, qq(if interface_is_usable $physical && [ -n "$variable" ]; then) );
    } else {
	if ( $optional ) {
	    start_provider( $table, $number, qq(if [ -n "\$SW_${base}_IS_USABLE" ]; then) );
	} elsif ( $gatewaycase eq 'detect' ) {
	    start_provider( $table, $number, qq(if interface_is_usable $physical && [ -n "$gateway" ]; then) );
	} else {
	    start_provider( $table, $number, "if interface_is_usable $physical; then" );
	}
	$provider_interfaces{$interface} = $table;

	if ( $gatewaycase eq 'none' ) {
	    if ( $local ) {
		emit 'run_ip route add local ' . ALLIP . " dev $physical table $number";
	    } else {
		emit "run_ip route add default dev $physical table $number";
	    }
	}
    }

    emit( qq(echo $load > \${VARDIR}/${physical}_load) ) if $load;

    emit( '', 
	  "cat <<EOF >> \${VARDIR}/undo_${table}_routing" );
    
    emit_unindented 'case \$COMMAND in';
    emit_unindented '    enable|disable)';
    emit_unindented '        ;;';
    emit_unindented '    *)';
    emit_unindented "        rm -f \${VARDIR}/${physical}_load" if $load;
    emit_unindented <<"CEOF", 1;
        rm -f \${VARDIR}/${physical}.status
        ;;
esac
EOF
CEOF
    #
    # /proc for this interface
    #
    setup_interface_proc( $interface );

    if ( $mark ne '-' ) {
	my $mask = have_capability 'FWMARK_RT_MASK' ? '/' . in_hex $globals{PROVIDER_MASK} : '';

	emit ( "qt \$IP -$family rule del fwmark ${mark}${mask}" ) if $config{DELETE_THEN_ADD};

	emit ( "run_ip rule add fwmark ${mark}${mask} pref $pref table $number",
	       "echo \"qt \$IP -$family rule del fwmark ${mark}${mask}\" >> \${VARDIR}/undo_${table}_routing"
	     );
    }

    if ( $duplicate ne '-' ) {
	if ( $copy eq '-' ) {
	    copy_table ( $duplicate, $number, $realm );
	} else {
	    if ( $copy eq 'none' ) {
		$copy = $interface;
	    } else {
		$copy = "$interface,$copy";
	    }

	    copy_and_edit_table( $duplicate, $number ,$copy , $realm);
	}
    }

    if ( $gateway ) {
	$address = get_interface_address $interface unless $address;
	if ( $family == F_IPV4 ) {
	    emit "run_ip route replace $gateway src $address dev $physical ${mtu}";
	    emit "run_ip route replace $gateway src $address dev $physical ${mtu}table $number $realm";
	} else {
	    emit "qt \$IP -6 route add $gateway src $address dev $physical ${mtu}";
	    emit "qt \$IP -6 route del $gateway src $address dev $physical ${mtu}table $number $realm";
	    emit "run_ip route add $gateway src $address dev $physical ${mtu}table $number $realm";
	}

	emit "run_ip route add default via $gateway src $address dev $physical ${mtu}table $number $realm";
    }

    if ( $balance ) {
	balance_default_route( $balance , $gateway, $physical, $realm );
    } elsif ( $default > 0 ) {
	balance_fallback_route( $default , $gateway, $physical, $realm );
    } elsif ( $default ) {
	emit '';
	if ( $gateway ) {
	    if ( $family == F_IPV4 ) {
		emit qq(run_ip route replace $gateway dev $physical table ) . DEFAULT_TABLE;
		emit qq(run_ip route replace default via $gateway src $address dev $physical table ) . DEFAULT_TABLE . qq( metric $number);
	    } else {
		emit qq(qt \$IP -6 route del default via $gateway src $address dev $physical table ) . DEFAULT_TABLE . qq( metric $number);
		emit qq(run_ip route add default via $gateway src $address dev $physical table ) . DEFAULT_TABLE . qq( metric $number);
	    }
	    emit qq(echo "qt \$IP -$family route del default via $gateway table ) . DEFAULT_TABLE . qq(" >> \${VARDIR}/undo_${table}_routing);
	} else {
	    emit qq(run_ip route add default table ) . DEFAULT_TABLE . qq( dev $physical metric $number);
	    emit qq(echo "qt \$IP -$family route del default dev $physical table ) . DEFAULT_TABLE . qq(" >> \${VARDIR}/undo_${table}_routing);
	}
	
	$fallback = 1;
    }

    emit( qq(\n) ,
	  qq(if ! \$IP -6 rule ls | egrep -q "32767:[[:space:]]+from all lookup (default|253)"; then) ,
	  qq(    qt \$IP -6 rule add from all table ) . DEFAULT_TABLE . qq( prio 32767\n) ,
	  qq(fi) ) if $family == F_IPV6;

    unless ( $local ) {
	emit '';

	if ( $loose ) {
	    if ( $config{DELETE_THEN_ADD} ) {
		emit ( "find_interface_addresses $physical | while read address; do",
		       "    qt \$IP -$family rule del from \$address",
		       'done'
		     );
	    }
	} elsif ( $shared ) {
	    emit  "qt \$IP -$family rule del from $address" if $config{DELETE_THEN_ADD};
	    emit( "run_ip rule add from $address pref 20000 table $number" ,
		  "echo \"qt \$IP -$family rule del from $address\" >> \${VARDIR}/undo_${table}_routing" );
	} else {
	    emit  ( "find_interface_addresses $physical | while read address; do" );
	    emit  ( "    qt \$IP -$family rule del from \$address" ) if $config{DELETE_THEN_ADD};
	    emit  ( "    run_ip rule add from \$address pref 20000 table $number",
		    "    echo \"qt \$IP -$family rule del from \$address\" >> \${VARDIR}/undo_${table}_routing",
		    '    rulenum=$(($rulenum + 1))',
		    'done'
		  );
	}
    }

    if ( @{$providerref->{rules}} ) {
	emit '';
	emit $_ for @{$providers{$table}->{rules}};
    }
    
    if ( @{$providerref->{routes}} ) {
	emit '';
	emit $_ for @{$providers{$table}->{routes}};
    }

    emit( '' );
    
    my ( $tbl, $weight );

    emit( qq(echo 0 > \${VARDIR}/${physical}.status) );

    if ( $optional ) {	
	emit( '',
	      'if [ $COMMAND = enable ]; then' );

	push_indent;

	if ( $balance || $default > 0 ) {
	    $tbl    = $default ? DEFAULT_TABLE : $config{USE_DEFAULT_RT} ? BALANCE_TABLE : MAIN_TABLE;
	    $weight = $balance ? $balance : $default;

	    if ( $family == F_IPV4 ) {
		if ( $gateway ) {
		    emit qq(add_gateway "nexthop via $gateway dev $physical weight $weight $realm" ) . $tbl;
		} else {
		    emit qq(add_gateway "nexthop dev $physical weight $weight $realm" ) . $tbl;
		}
	    } else {
		#
		# IPv6 doesn't support multi-hop routes
		#
		if ( $gateway ) {
		    emit qq(add_gateway "via $gateway dev $physical $realm" ) . $tbl;
		} else {
		    emit qq(add_gateway "nexthop dev $physical $realm" ) . $tbl;
		}
	    }
	    	} else {
	    $weight = 1;
	}

	emit ( "distribute_load $maxload @load_interfaces" ) if $load;

	unless ( $shared ) {
	    emit( "setup_${dev}_tc" ) if $tcdevices->{$interface};
	}

	emit ( qq(progress_message2 "   Provider $table ($number) Started") );

	pop_indent;
 
	emit( 'else' );
	emit( qq(    echo $weight > \${VARDIR}/${physical}_weight) ,
	      qq(    progress_message "   Provider $table ($number) Started"),
	      qq(fi\n)
	    );
    } else {
	emit( qq(echo 0 > \${VARDIR}/${physical}.status) );
	emit( qq(progress_message "Provider $table ($number) Started") );
    }
    
    pop_indent;

    emit 'else';

    push_indent;
    
    emit( qq(echo 1 > \${VARDIR}/${physical}.status) );

    if ( $optional ) {
	if ( $shared ) {
	    emit ( "error_message \"WARNING: Gateway $gateway is not reachable -- Provider $table ($number) not Started\"" );	    
	} else {
	    emit ( "error_message \"WARNING: Interface $physical is not usable -- Provider $table ($number) not Started\"" );
	}
    } else {
	if ( $shared ) {
	    emit( "fatal_error \"Gateway $gateway is not reachable -- Provider $table ($number) Cannot be Started\"" );
	} else {
	    emit( "fatal_error \"Interface $physical is not usable -- Provider $table ($number) Cannot be Started\"" );
	}
    }

    pop_indent;

    emit 'fi';

    pop_indent;

    emit '}'; # End of start_provider_$table();

    if ( $optional ) {
	emit( '',
	      '#',
	      "# Stop provider $table",
	      '#',
	      "stop_provider_$table() {" );

	push_indent;

	my $undo = "\${VARDIR}/undo_${table}_routing";

	emit( "if [ -f $undo ]; then" );

	push_indent;

	if ( $balance || $default > 0 ) {
	    $tbl    = $default ? DEFAULT_TABLE : $config{USE_DEFAULT_RT} ? BALANCE_TABLE : MAIN_TABLE;
	    $weight = $balance ? $balance : $default;

	    my $via;

	    if ( $gateway ) {
		$via = "via $gateway dev $physical";
	    } else {    
		$via = "dev $physical";
	    }

	    $via .= " weight $weight" unless $weight < 0 or $family == F_IPV6; # IPv6 doesn't support route weights
	    $via .= " $realm"         if $realm;

	    emit( qq(delete_gateway "$via" $tbl $physical) );
	}

	emit (". $undo",
	      "> $undo" );

	emit ( '',
	       "distribute_load $maxload @load_interfaces" ) if $load;

	unless ( $shared ) {
	    emit( '', 
		  "qt \$TC qdisc del dev $physical root",
		  "qt \$TC qdisc del dev $physical ingress\n" ) if $tcdevices->{$interface};
	}

	emit( "progress_message2 \"   Provider $table ($number) stopped\"" );

	pop_indent;

	emit( 'else',
	      "    startup_error \"$undo does not exist\"",
	      'fi'
	    );

	pop_indent;

	emit '}';
    }
}

sub add_an_rtrule( ) {
    my ( $source, $dest, $provider, $priority, $originalmark ) = split_line 'rtrules file', { source => 0, dest => 1, provider => 2, priority => 3 , mark => 4 };

    our $current_if;

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

    my $providerref = $providers{$provider};

    my $number = $providerref->{number};

    fatal_error "You may not add rules for the $provider provider" if $number == LOCAL_TABLE || $number == UNSPEC_TABLE;
    fatal_error "You must specify either the source or destination in a rtrules entry" if $source eq '-' && $dest eq '-';

    if ( $dest eq '-' ) {
	$dest = 'to ' . ALLIP;
    } else {
	validate_net( $dest, 0 );
	$dest = "to $dest";
    }

    if ( $source eq '-' ) {
	$source = 'from ' . ALLIP;
    } elsif ( $source =~ s/^&// ) {
	$source = 'from ' . record_runtime_address '&', $source;
    } elsif ( $family == F_IPV4 ) {
	if ( $source =~ /:/ ) {
	    ( my $interface, $source , my $remainder ) = split( /:/, $source, 3 );
	    fatal_error "Invalid SOURCE" if defined $remainder;
	    validate_net ( $source, 0 );
	    $interface = physical_name $interface;
	    $source = "iif $interface from $source";
	} elsif ( $source =~ /\..*\..*/ ) {
	    validate_net ( $source, 0 );
	    $source = "from $source";
	} else {
	    $source = "iif $source";
	}
    } elsif ( $source =~  /^(.+?):<(.+)>\s*$/ ||  $source =~  /^(.+?):\[(.+)\]\s*$/ ) {
	my ($interface, $source ) = ($1, $2);
	validate_net ($source, 0);
	$interface = physical_name $interface;
	$source = "iif $interface from $source";
    } elsif (  $source =~ /:.*:/ || $source =~ /\..*\..*/ ) {
	validate_net ( $source, 0 );
	$source = "from $source";
    } else {
	$source = "iif $source";
    }

    my $mark = '';
    my $mask;

    if ( $originalmark ne '-' ) {
	validate_mark( $originalmark );

	( $mark, $mask ) = split '/' , $originalmark;
	$mask = $globals{PROVIDER_MASK} unless supplied $mask;

	$mark = ' fwmark ' . in_hex( $mark ) . '/' . in_hex( $mask );
    }

    fatal_error "Invalid priority ($priority)" unless $priority && $priority =~ /^\d{1,5}$/;

    $priority = "priority $priority";

    push @{$providerref->{rules}}, "qt \$IP -$family rule del $source ${dest}${mark} $priority" if $config{DELETE_THEN_ADD};
    push @{$providerref->{rules}}, "run_ip rule add $source ${dest}${mark} $priority table $number";
    push @{$providerref->{rules}}, "echo \"qt \$IP -$family rule del $source ${dest}${mark} $priority\" >> \${VARDIR}/undo_${provider}_routing";

    progress_message "   Routing rule \"$currentline\" $done";
}

sub add_a_route( ) {
    my ( $provider, $dest, $gateway, $device ) = split_line 'routes file', { provider => 0, dest => 1, gateway => 2, device => 3 };

    our $current_if;

    fatal_error 'PROVIDER must be specified' if $provider eq '-';

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

    fatal_error 'DEST must be specified' if $dest eq '-';
    validate_net ( $dest, 1 );

    validate_address ( $gateway, 1 ) if $gateway ne '-';

    my $providerref = $providers{$provider};
    my $number = $providerref->{number};
    my $physical = $device eq '-' ? $providers{$provider}{physical} : physical_name( $device );
    my $routes = $providerref->{routes};

    fatal_error "You may not add routes to the $provider table" if $number == LOCAL_TABLE || $number == UNSPEC_TABLE;
    
    if ( $gateway ne '-' ) {
	if ( $device ne '-' ) {
	    push @$routes, qq(run_ip route add $dest via $gateway dev $physical table $number);
	    emit qq(echo "qt \$IP -$family route del $dest via $gateway dev $physical table $number" >> \${VARDIR}/undo_${provider}_routing) if $number >= DEFAULT_TABLE;
	} else {
	    push @$routes, qq(run_ip route add $dest via $gateway table $number);
	    emit qq(echo "\$IP -$family route del $dest via $gateway table $number" >> \${VARDIR}/undo_${provider}_routing) if $number >= DEFAULT_TABLE; 
	}
    } else {
	fatal_error "You must specify a device for this route" unless $physical;
	push @$routes, qq(run_ip route add $dest dev $physical table $number);
	emit qq(echo "\$IP -$family route del $dest dev $physical table $number" >> \${VARDIR}/undo_${provider}_routing) if $number >= DEFAULT_TABLE;
    }

    progress_message "   Route \"$currentline\" $done";
}

sub setup_null_routing() {
    save_progress_message "Null Routing the RFC 1918 subnets";
    emit "> \${VARDIR}/undo_rfc1918_routing\n";
    for ( rfc1918_networks ) {
	emit( qq(if ! \$IP -4 route ls | grep -q '^$_.* dev '; then),
	      qq(    run_ip route replace unreachable $_),
	      qq(    echo "qt \$IP -4 route del unreachable $_" >> \${VARDIR}/undo_rfc1918_routing),
	      qq(fi\n) );
    }
}

sub start_providers() {
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
	    "[ -f \${VARDIR}/default_route ] || \$IP -$family route list | save_default_route > \${VARDIR}/default_route" );

    save_progress_message 'Adding Providers...';

    emit 'DEFAULT_ROUTE=';
    emit 'FALLBACK_ROUTE=';
    emit '';
    
    for my $provider ( qw/main default/ ) {
	emit '';
	emit qq(> \${VARDIR}/undo_${provider}_routing );
	emit '';
	emit $_ for @{$providers{$provider}{routes}};
	emit '';
	emit $_ for @{$providers{$provider}{rules}};
    }
}

sub finish_providers() {
    my $table = MAIN_TABLE;
    
    if ( $config{USE_DEFAULT_RT} ) {
	emit ( 'run_ip rule add from ' . ALLIP . ' table ' . MAIN_TABLE .    ' pref 999',
	       'run_ip rule add from ' . ALLIP . ' table ' . BALANCE_TABLE . ' pref 32765',
	       "\$IP -$family rule del from " . ALLIP . ' table ' . MAIN_TABLE . ' pref 32766',
	       qq(echo "qt \$IP -$family rule add from ) . ALLIP . ' table ' . MAIN_TABLE .    ' pref 32766" >> ${VARDIR}/undo_main_routing',
	       qq(echo "qt \$IP -$family rule del from ) . ALLIP . ' table ' . MAIN_TABLE .    ' pref 999" >> ${VARDIR}/undo_main_routing',
	       qq(echo "qt \$IP -$family rule del from ) . ALLIP . ' table ' . BALANCE_TABLE . ' pref 32765" >> ${VARDIR}/undo_balance_routing',
	       '' );
	$table = BALANCE_TABLE;
    }

    if ( $balancing ) {
	emit  ( 'if [ -n "$DEFAULT_ROUTE" ]; then' );
	if ( $family == F_IPV4 ) {
	    emit  ( "    run_ip route replace default scope global table $table \$DEFAULT_ROUTE" );
	} else {
	    emit  ( "    qt \$IP -6 route del default scope global table $table \$DEFAULT_ROUTE" );
	    emit  ( "    run_ip route add default scope global table $table \$DEFAULT_ROUTE" );
	}

	if ( $config{USE_DEFAULT_RT} ) {
	    emit  ( "    while qt \$IP -$family route del default table " . MAIN_TABLE . '; do',
		    '        true',
		    '    done',
		    ''
		  );
	}
 
	emit  ( "    progress_message \"Default route '\$(echo \$DEFAULT_ROUTE | sed 's/\$\\s*//')' Added\"",
		'else',
		'    error_message "WARNING: No Default route added (all \'balance\' providers are down)"' );

	if ( $config{RESTORE_DEFAULT_ROUTE} ) {
	    emit qq(    restore_default_route $config{USE_DEFAULT_RT} && error_message "NOTICE: Default route restored")
	} else {
	    emit qq(    qt \$IP -$family route del default table $table && error_message "WARNING: Default route deleted from table $table");
	}

	emit(   'fi',
		'' );
    } else {
	emit ( '#',
	       '# We don\'t have any \'balance\' providers so we restore any default route that we\'ve saved',
	       '#',
	       "restore_default_route $config{USE_DEFAULT_RT}" ,
	       '' );
    }

    if ( $fallback ) {
	emit  ( 'if [ -n "$FALLBACK_ROUTE" ]; then' );
	if ( $family == F_IPV4 ) {
	    emit( "    run_ip route replace default scope global table " . DEFAULT_TABLE . " \$FALLBACK_ROUTE" );
	} else {
	    emit( "    qt \$IP -6 route del default scope global table " . DEFAULT_TABLE . " \$FALLBACK_ROUTE" );
	    emit( "    run_ip route add default scope global table " . DEFAULT_TABLE . " \$FALLBACK_ROUTE" );
	}

	emit( "    progress_message \"Fallback route '\$(echo \$FALLBACK_ROUTE | sed 's/\$\\s*//')' Added\"",
	      'fi',
	      '' );
    } elsif ( $config{USE_DEFAULT_RT} ) {
	emit "qt \$IP -$family route del default table " . DEFAULT_TABLE;
    }

    unless ( $config{KEEP_RT_TABLES} ) {
	emit( 'if [ -w /etc/iproute2/rt_tables ]; then',
	      '    cat > /etc/iproute2/rt_tables <<EOF' );

	emit_unindented join( "\n",
			      '#',
			      '# reserved values',
			      '#',
			      LOCAL_TABLE   . "\tlocal",
			      MAIN_TABLE    . "\tmain",
			      $config{USE_DEFAULT_RT} ? ( DEFAULT_TABLE . "\tdefault\n" . BALANCE_TABLE . "\tbalance" ) : DEFAULT_TABLE . "\tdefault",
			      "0\tunspec",
			      '#',
			      '# local',
			      '#' );
	emit_unindented "$providers{$_}{number}\t$_" for @providers;
	emit_unindented "EOF\n";

	emit "fi\n";
    }
}

sub process_providers( $ ) {
    my $tcdevices = shift;

    our $providers = 0;

    $lastmark = 0;

    if ( my $fn = open_file 'providers' ) {
	first_entry "$doing $fn..."; 
	process_a_provider, $providers++ while read_a_line( NORMAL_READ );
    }

    if ( $providers ) {
	my $fn = open_file( 'route_rules' );

	if ( $fn ){
	    if ( -f ( my $fn1 = find_file 'rtrules' ) ) {
		warning_message "Both $fn and $fn1 exists: $fn1 will be ignored";
	    }
	} else {
	    $fn = open_file( 'rtrules' );
	}

	if ( $fn ) {
	    first_entry "$doing $fn...";
	    
	    emit '';

	    add_an_rtrule while read_a_line( NORMAL_READ );
	}

	$fn = open_file 'routes';

	if ( $fn ) {
	    first_entry "$doing $fn...";
	    emit '';
	    add_a_route while read_a_line( NORMAL_READ );
	}
    }

    add_a_provider( $providers{$_}, $tcdevices ) for @providers;
    
    emit << 'EOF';;

#
# Enable an optional provider
#
enable_provider() {
    g_interface=$1;

    case $g_interface in
EOF

    push_indent;
    push_indent;

    for my $provider (@providers ) {
	my $providerref = $providers{$provider};

	if ( $providerref->{optional} ) {
	    if ( $providerref->{shared} || $providerref->{physical} eq $provider) {
		emit "$provider})";
	    } else {
		emit( "$providerref->{physical}|$provider)" );
	    }

	    emit ( "    if [ -z \"`\$IP -$family route ls table $providerref->{number}`\" ]; then", 
		   "        start_provider_$provider",
		   '    else',
		   "        startup_error \"Interface $providerref->{physical} is already enabled\"",
		   '    fi',
		   '    ;;'
		 );
	}
    }

    pop_indent;
    pop_indent;

    emit << 'EOF';;
        *)
            startup_error "$g_interface is not an optional provider or provider interface"
            ;;
    esac
}

#
# Disable an optional provider
#
disable_provider() {
    g_interface=$1;

    case $g_interface in
EOF

    push_indent;
    push_indent;

    for my $provider (@providers ) {
	my $providerref = $providers{$provider};

	emit( "$providerref->{physical}|$provider)",
	      "    if [ -n \"`\$IP -$family route ls table $providerref->{number}`\" ]; then", 
	      "        stop_provider_$provider",
	      '    else',
	      "        startup_error \"Interface $providerref->{physical} is already disabled\"",
	      '    fi',
	      '    ;;'
	    ) if $providerref->{optional};
    }

    pop_indent;
    pop_indent;

    emit << 'EOF';;
        *)
            startup_error "$g_interface is not an optional provider interface"
            ;;
    esac
}
EOF

}

sub setup_providers() {
    our $providers;

    if ( $providers ) {
	emit "\nif [ -z \"\$g_noroutes\" ]; then";
	
	push_indent;

	start_providers;
	
	emit '';

	emit "start_provider_$_" for @providers;

	emit '';

	finish_providers;

	setup_null_routing if $config{NULL_ROUTE_RFC1918};
	emit "\nrun_ip route flush cache";

	pop_indent;
	emit "fi\n";

	setup_route_marking if @routemarked_interfaces || @load_interfaces;
    } else {
	emit "\nif [ -z \"\$g_noroutes\" ]; then";

	push_indent;

	emit "\nundo_routing";
	emit "restore_default_route $config{USE_DEFAULT_RT}";

	if ( $config{NULL_ROUTE_RFC1918} ) {
	    setup_null_routing;
	    emit "\nrun_ip route flush cache";
	}

	pop_indent;

	emit "fi\n";
    }

}

sub lookup_provider( $ ) {
    my $provider    = $_[0];
    my $providerref = $providers{ $provider };

    unless ( $providerref ) {
	fatal_error "Unknown provider ($provider)" unless $provider =~ /^(0x[a-f0-9]+|0[0-7]*|[0-9]*)$/;

	my $provider_number = numeric_value $provider;

	for ( values %providers ) {
	    $providerref = $_, last if $_->{number} == $provider_number;
	}

	fatal_error "Unknown provider ($provider)" unless $providerref;
    }

    $providerref->{shared} ? $providerref->{number} : 0;
}

#
# This function is called by the compiler when it is generating the detect_configuration() function.
# The function calls Shorewall::Zones::verify_required_interfaces then emits code to set the
# ..._IS_USABLE interface variables appropriately for the  optional interfaces
#
# Returns true if there were required or optional interfaces
#
sub handle_optional_interfaces( $ ) {

    my ( $interfaces, $wildcards )  = find_interfaces_by_option1 'optional';

    if ( @$interfaces ) {
	my $require     = $config{REQUIRE_INTERFACE};

	verify_required_interfaces( shift );

	emit( 'HAVE_INTERFACE=', '' ) if $require;
	#
	# Clear the '_IS_USABLE' variables
	#
	emit( join( '_', 'SW', uc chain_base( get_physical( $_ ) ) , 'IS_USABLE=' ) ) for @$interfaces;

	if ( $wildcards ) {
	    #
	    # We must consider all interfaces with an address in $family -- generate a list of such addresses.
	    #
	    emit( '',
		  'for interface in $(find_all_interfaces1); do',
		);

	    push_indent;
	    emit ( 'case "$interface" in' );
	    push_indent;
	} else {
	    emit '';
	}

	for my $interface ( grep $provider_interfaces{$_}, @$interfaces ) {
	    my $provider    = $provider_interfaces{$interface};
	    my $physical    = get_physical $interface;
	    my $base        = uc chain_base( $physical );
	    my $providerref = $providers{$provider};

	    emit( "$physical)" ), push_indent if $wildcards;

	    if ( $providerref->{gatewaycase} eq 'detect' ) {
		emit qq(if interface_is_usable $physical && [ -n "$providerref->{gateway}" ]; then);
	    } else {
		emit qq(if interface_is_usable $physical; then);
	    }

	    emit( '    HAVE_INTERFACE=Yes' ) if $require;

	    emit( "    SW_${base}_IS_USABLE=Yes" ,
		  'fi' );

	    emit( ';;' ), pop_indent if $wildcards;
	}

	for my $interface ( grep ! $provider_interfaces{$_}, @$interfaces ) {
	    my $physical    = get_physical $interface;
	    my $base        = uc chain_base( $physical );
	    my $case        = $physical;
	    my $wild        = $case =~ s/\+$/*/;

	    if ( $wildcards ) {
		emit( "$case)" );
		push_indent;

		if ( $wild ) {
		    emit( qq(if [ -z "\$SW_${base}_IS_USABLE" ]; then) );
		    push_indent;
		    emit ( 'if interface_is_usable $interface; then' );
		} else {
		    emit ( "if interface_is_usable $physical; then" );
		}
	    } else {
		emit ( "if interface_is_usable $physical; then" );
	    }

	    emit ( '    HAVE_INTERFACE=Yes' ) if $require;
	    emit ( "    SW_${base}_IS_USABLE=Yes" ,
		   'fi' );

	    if ( $wildcards ) {
		pop_indent, emit( 'fi' ) if $wild;
		emit( ';;' );
		pop_indent;
	    }
	}

	if ( $wildcards ) {
	    emit( '*)' ,
		  '    ;;'
		);
	    pop_indent;
	    emit( 'esac' );
	    pop_indent;
	    emit('done' );
	}

	if ( $require ) {
	    emit( '',
		  'if [ -z "$HAVE_INTERFACE" ]; then' ,
		  '    case "$COMMAND" in',
		  '        start|restart|restore|refresh)'
		);

	    if ( $family == F_IPV4 ) {
		emit( '            if shorewall_is_started; then' );
	    } else {
		emit( '            if shorewall6_is_started; then' );
	    }

	    emit( '                fatal_error "No network interface available"',
		  '            else',
		  '                startup_error "No network interface available"',
		  '            fi',
		  '            ;;',
		  '    esac',
		  'fi'
		);
	}

	return 1;
    }

    verify_required_interfaces( shift );
}

#
# The Tc module has collected the 'sticky' rules in the 'tcpre' and 'tcout' chains. In this function, we apply them
# to the 'tracked' providers
#
sub handle_stickiness( $ ) {
    my $havesticky   = shift;
    my $mask         = in_hex( $globals{PROVIDER_MASK} );
    my $setstickyref = $mangle_table->{setsticky};
    my $setstickoref = $mangle_table->{setsticko};
    my $tcpreref     = $mangle_table->{tcpre};
    my $tcoutref     = $mangle_table->{tcout};
    my %marked_interfaces;
    my $sticky = 1;

    if ( $havesticky ) {
	fatal_error "There are SAME tcrules but no 'track' providers" unless @routemarked_providers;

	for my $providerref ( @routemarked_providers ) {
	    my $interface = $providerref->{physical};
	    my $base      = uc chain_base $interface;
	    my $mark      = $providerref->{mark};

	    for ( grep rule_target($_) eq 'sticky', @{$tcpreref->{rules}} ) {
		my $stickyref = ensure_mangle_chain 'sticky';
		my ( $rule1, $rule2 );
		my $list = sprintf "sticky%03d" , $sticky++;

		for my $chainref ( $stickyref, $setstickyref ) {
		    if ( $chainref->{name} eq 'sticky' ) {
			$rule1 = clone_rule( $_ );

			set_rule_target( $rule1, 'MARK',   "--set-mark $mark" );
			set_rule_option( $rule1, 'recent', "--name $list --update --seconds 300" );

			$rule2 = clone_rule( $_ );

			clear_rule_target( $rule2 );
			set_rule_option( $rule2, 'mark', "--mark 0/$mask -m recent --name $list --remove" );
		    } else {
			$rule1 = clone_rule( $_ );

			clear_rule_target( $rule1 );
			set_rule_option( $rule1, 'mark', "--mark $mark\/$mask -m recent --name $list --set" ); 

			$rule2 = '';
		    }

		    add_trule $chainref, $rule1;

		    if ( $rule2 ) {
			add_trule $chainref, $rule2;
		    }
		}
	    }

	    for ( grep rule_target( $_ ) eq 'sticko', , @{$tcoutref->{rules}} ) {
		my ( $rule1, $rule2 );
		my $list = sprintf "sticky%03d" , $sticky++;
		my $stickoref = ensure_mangle_chain 'sticko';

		for my $chainref ( $stickoref, $setstickoref ) {
		    if ( $chainref->{name} eq 'sticko' ) {
			$rule1 = {};

			while ( my ( $key, $value ) = each %$_ ) {
			    $rule1->{$key} = $value;
			}

			set_rule_target( $rule1, 'MARK',   "--set-mark $mark" );
			set_rule_option( $rule1, 'recent', " --name $list --rdest --update --seconds 300" );

			$rule2 = {};

			while ( my ( $key, $value ) = each %$_ ) {
			    $rule2->{$key} = $value;
			}
			
			clear_rule_target( $rule2 );
			set_rule_option  ( $rule2, 'mark', "--mark 0\/$mask -m recent --name $list --rdest --remove" );
		    } else {
			$rule1 = {};

			while ( my ( $key, $value ) = each %$_ ) {
			    $rule1->{$key} = $value;
			}

			clear_rule_target( $rule1 );
			set_rule_option  ( $rule1, 'mark', "--mark $mark -m recent --name $list --rdest --set" );

			$rule2 = '';
		    }

		    add_trule $chainref, $rule1;

		    if ( $rule2 ) {
			add_trule $chainref, $rule2;
		    }
		}
	    }
	}
    }

    if ( @routemarked_providers || @load_interfaces ) {
	delete_jumps $mangle_table->{PREROUTING}, $setstickyref unless @{$setstickyref->{rules}};
	delete_jumps $mangle_table->{OUTPUT},     $setstickoref unless @{$setstickoref->{rules}};
    }
}

sub setup_load_distribution() {
    emit ( '',
	   "        distribute_load $maxload @load_interfaces" ,
	   '' 
	 ) if @load_interfaces;
}

1;
