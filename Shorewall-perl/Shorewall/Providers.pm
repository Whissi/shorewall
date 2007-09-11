#
# Shorewall-perl 4.0 -- /usr/share/shorewall-perl/Shorewall/Providers.pm
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
#   This module deals with the /etc/shorewall/providers and
#   /etc/shorewall/route_rules files.
#
package Shorewall::Providers;
require Exporter;
use Shorewall::Config;
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_providers @routemarked_interfaces);
our @EXPORT_OK = qw( initialize );
our $VERSION = '4.03';

use constant { LOCAL_NUMBER   => 255,
	       MAIN_NUMBER    => 254,
	       DEFAULT_NUMBER => 253,
	       UNSPEC_NUMBER  => 0
	       };

our %routemarked_interfaces;
our @routemarked_interfaces;

our $balance;
our $first_default_route;

our %providers;

our @providers;

#
# Initialize globals -- we take this novel approach to globals initialization to allow
#                       the compiler to run multiple times in the same process. The
#                       initialize() function does globals initialization for this
#                       module and is called from an INIT block below. The function is
#                       also called by Shorewall::Compiler::compiler at the beginning of
#                       the second and subsequent calls to that function.
#

sub initialize() {
    %routemarked_interfaces = ();
    @routemarked_interfaces = ();
    $balance             = 0;
    $first_default_route = 1;

    %providers  = ( 'local' => { number => LOCAL_NUMBER   , mark => 0 , optional => 0 } ,
		    main    => { number => MAIN_NUMBER    , mark => 0 , optional => 0 } ,
		    default => { number => DEFAULT_NUMBER , mark => 0 , optional => 0 } ,
		    unspec  => { number => UNSPEC_NUMBER  , mark => 0 , optional => 0 } );
    @providers = ();
}

INIT {
    initialize;
}

#
# Set up marking for 'tracked' interfaces. Unlike in Shorewall 3.x, we add these rules unconditionally, even if the associated interface isn't up.
#
sub setup_route_marking() {
    my $mask    = $config{HIGH_ROUTE_MARKS} ? '0xFF00' : '0xFF';
    my $mark_op = $config{HIGH_ROUTE_MARKS} ? '--or-mark' : '--set-mark';

    require_capability( 'CONNMARK_MATCH' , 'the provider \'track\' option' , 's' );
    require_capability( 'CONNMARK' ,       'the provider \'track\' option' , 's' );

    add_rule $mangle_table->{4}{PREROUTING} , "-m connmark ! --mark 0/$mask -j CONNMARK --restore-mark --mask $mask";
    add_rule $mangle_table->{4}{OUTPUT} ,     "-m connmark ! --mark 0/$mask -j CONNMARK --restore-mark --mask $mask";

    my $chainref = new_chain 'mangle', 'routemark';

    while ( my ( $interface, $mark ) = ( each %routemarked_interfaces ) ) {
	add_rule $mangle_table->{4}{PREROUTING} , "-i $interface -m mark --mark 0/$mask -j routemark";
	add_rule $chainref, " -i $interface -j MARK $mark_op $mark";
    }

    add_rule $chainref, "-m mark ! --mark 0/$mask -j CONNMARK --save-mark --mask $mask";
}

sub copy_table( $$ ) {
    my ( $duplicate, $number ) = @_;

    emit ( "ip route show table $duplicate | while read net route; do",
	   '    case $net in',
	   '        default|nexthop)',
	   '            ;;',
	   '        *)',
	   "            run_ip route add table $number \$net \$route",
	   '            ;;',
	   '    esac',
	   "done\n"
	 );
}

sub copy_and_edit_table( $$$ ) {
    my ( $duplicate, $number, $copy ) = @_;

    emit  ( "ip route show table $duplicate | while read net route; do",
	    '    case $net in',
	    '        default|nexthop)',
	    '            ;;',
	    '        *)',
	    '            case $(find_device $route) in',
	    "                $copy)",
	    "                    run_ip route add table $number \$net \$route",
	    '                    ;;',
	    '            esac',
	    '            ;;',
	    '    esac',
	    "done\n" );
}

sub balance_default_route( $$$ ) {
    my ( $weight, $gateway, $interface ) = @_;

    $balance = 1;

    emit '';

    if ( $first_default_route ) {
	if ( $gateway ) {
	    emit "DEFAULT_ROUTE=\"nexthop via $gateway dev $interface weight $weight\"";
	} else {
	    emit "DEFAULT_ROUTE=\"nexthop dev $interface weight $weight\"";
	}

	$first_default_route = 0;
    } else {
	if ( $gateway ) {
	    emit "DEFAULT_ROUTE=\"\$DEFAULT_ROUTE nexthop via $gateway dev $interface weight $weight\"";
	} else {
	    emit "DEFAULT_ROUTE=\"\$DEFAULT_ROUTE nexthop dev $interface weight $weight\"";
	}
    }
}

sub add_a_provider( $$$$$$$$ ) {

    my ($table, $number, $mark, $duplicate, $interface, $gateway,  $options, $copy) = @_;

    fatal_error "Duplicate provider ($table)" if $providers{$table};

    for my $providerref ( values %providers  ) {
	fatal_error "Duplicate provider number ($number)" if $providerref->{number} == $number;
    }

    my $provider = chain_base $table;
    
    emit "#\n# Add Provider $table ($number)\n#";

    emit "if interface_is_usable $interface; then";
    push_indent;
    my $iface = chain_base $interface;

    emit "qt ip route flush table $number";
    emit "echo \"qt ip route flush table $number\" >> \${VARDIR}/undo_routing";

    if ( $duplicate ne '-' ) {
	if ( $copy eq '-' ) {
	    copy_table ( $duplicate, $number );
	} else {
	    if ( $copy eq 'none' ) {
		$copy = $interface;
	    } else {
		$copy =~ tr/,/|/;
	    }

	    copy_and_edit_table( $duplicate, $number ,$copy );
	}
    } else {
	fatal_error 'A non-empty COPY column requires that a routing table be specified in the DUPLICATE column' if $copy ne '-';
    }

    if ( $gateway eq 'detect' ) {
	my $variable = get_interface_address $interface;
	emit  ( "gateway=\$(detect_gateway $interface)\n",
		'if [ -n "$gateway" ]; then',
		"    run_ip route replace $variable dev $interface table $number",
		"    run_ip route add default via \$gateway dev $interface table $number",
		'else',
		"    fatal_error \"Unable to detect the gateway through interface $interface\"",
		"fi\n" );
	$gateway = '$gateway';
    } elsif ( $gateway && $gateway ne '-' ) {
	validate_address $gateway;
	my $variable = get_interface_address $interface;
	emit "run_ip route replace $gateway src $variable dev $interface table $number";
	emit "run_ip route add default via $gateway dev $interface table $number";
    } else {
	$gateway = '';
	emit "run_ip route add default dev $interface table $number";
    }

    my $val = 0;

    if ( $mark ne '-' ) {

	$val = numeric_value $mark;

	verify_mark $mark;

	if ( $val < 256) {
	    fatal_error "Invalid Mark Value ($mark) with HIGH_ROUTE_MARKS=Yes" if $config{HIGH_ROUTE_MARKS};
	} else {
	    fatal_error "Invalid Mark Value ($mark) with HIGH_ROUTE_MARKS=No" if ! $config{HIGH_ROUTE_MARKS};
	}

	for my $providerref ( values %providers  ) {
	    fatal_error "Duplicate mark value ($mark)" if $providerref->{mark} == $val;
	}

	my $pref = 10000 + $val;

	emit ( "qt ip rule del fwmark $mark",
	       "run_ip rule add fwmark $mark pref $pref table $number",
	       "echo \"qt ip rule del fwmark $mark\" >> \${VARDIR}/undo_routing"
	     );
    }

    $providers{$table}         = {};
    $providers{$table}{number} = $number;
    $providers{$table}{mark}   = $val;

    my ( $loose, $optional ) = (0,0);

    unless ( $options eq '-' ) {
	for my $option ( split /,/, $options ) {
	    if ( $option eq 'track' ) {
		fatal_error "Interface $interface is tracked through an earlier provider" if $routemarked_interfaces{$interface};
		fatal_error "The 'track' option requires a numeric value in the MARK column" if $mark eq '-';
		$routemarked_interfaces{$interface} = $mark;
		push @routemarked_interfaces, $interface;
	    } elsif ( $option =~ /^balance=(\d+)$/ ) {
		balance_default_route $1 , $gateway, $interface;
	    } elsif ( $option eq 'balance' ) {
		balance_default_route 1 , $gateway, $interface;
	    } elsif ( $option eq 'loose' ) {
		$loose = 1;
	    } elsif ( $option eq 'optional' ) {
		$optional = 1;
	    } else {
		fatal_error "Invalid option ($option)";
	    }
	}
    }

    $providers{$table}{optional} = $optional;

    if ( $loose ) {
	my $rulebase = 20000 + ( 256 * ( $number - 1 ) );

	emit "\nrulenum=0\n";

	emit  ( "find_interface_addresses $interface | while read address; do",
		'    qt ip rule del from $address',
		"    run_ip rule add from \$address pref \$(( $rulebase + \$rulenum )) table $number",
		"    echo \"qt ip rule del from \$address\" >> \${VARDIR}/undo_routing",
		'    rulenum=$(($rulenum + 1))',
		'done'
	      );
    } else {
	emit ( "\nfind_interface_addresses $interface | while read address; do",
	       '    qt ip rule del from $address',
	       'done'
	     );
    }

    emit "\nprogress_message \"   Provider $table ($number) Added\"\n";

    emit ( "${provider}_is_up=Yes" ) if $optional;

    pop_indent;
    emit 'else';

    if ( $optional ) {
	emit ( "    error_message \"WARNING: Interface $interface is not configured -- Provider $table ($number) not Added\"",
	       "    ${provider}_is_up=" );
    } else {
	emit( "    fatal_error \"Interface $interface is not configured -- Provider $table ($number) Cannot be Added\"" );
    }

    emit "fi\n";
}

sub add_an_rtrule( $$$$ ) {
    my ( $source, $dest, $provider, $priority ) = @_;

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

    $dest = $dest eq '-' ? '' : "to $dest";

    if ( $source eq '-' ) {
	$source = '';
    } elsif ( $source =~ /:/ ) {
	( my $interface, $source , my $remainder ) = split( /:/, $source, 3 );
	fatal_error "Invalid SOURCE" if defined $remainder;
	$source = "iif $interface from $source";
    } elsif ( $source =~ /\..*\..*/ ) {
	$source = "from $source";
    } else {
	$source = "iif $source";
    }

    fatal_error "Invalid priority ($priority)" unless $priority && $priority =~ /^\d{1,5}$/;

    $priority = "priority $priority";

    emit ( "qt ip rule del $source $dest $priority" );

    my ( $base, $optional, $number ) = ( chain_base( $provider ), $providers{$provider}{optional} , $providers{$provider}{number} );

    emit ( '', "if [ -n \$${base}_is_up ]; then" ), push_indent if $optional;

    emit ( "run_ip rule add $source $dest $priority table $number",
	   "echo \"qt ip rule del $source $dest $priority\" >> \${VARDIR}/undo_routing" );

    pop_indent, emit ( "fi\n" ) if $optional;

    progress_message "   Routing rule \"$currentline\" $done";
}

sub setup_providers() {
    my $providers = 0;

    my $fn = open_file 'providers';

    while ( read_a_line ) {
	unless ( $providers ) {
	    progress_message2 "$doing $fn ...";
	    require_capability( 'MANGLE_ENABLED' , 'a non-empty providers file' , 's' );

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
		    '[ -f ${VARDIR}/default_route ] || ip route list | grep -E \'^\s*(default |nexthop )\' > ${VARDIR}/default_route',
		    '#',
		    '# Initialize the file that holds \'undo\' commands',
		    '#',
		    '> ${VARDIR}/undo_routing' );

	    save_progress_message 'Adding Providers...';

	    emit 'DEFAULT_ROUTE=';
	}

	my ( $table, $number, $mark, $duplicate, $interface, $gateway,  $options, $copy ) = split_line 6, 8, 'providers file';

	add_a_provider(  $table, $number, $mark, $duplicate, $interface, $gateway,  $options, $copy );

	push @providers, $table;

	$providers++;

	progress_message "   Provider \"$currentline\" $done";

    }

    if ( $providers ) {
	if ( $balance ) {
	    emit  ( 'if [ -n "$DEFAULT_ROUTE" ]; then',
		    '    run_ip route replace default scope global $DEFAULT_ROUTE',
		    "    progress_message \"Default route '\$(echo \$DEFAULT_ROUTE | sed 's/\$\\s*//')' Added\"",
		    'else',
		    '    error_message "WARNING: No Default route added (all \'balance\' providers are down)"',
		    '    restore_default_route',
		    'fi',
		    '' );
	} else {
	    emit ( '#',
		   '# We don\'t have any \'balance\' providers so we restore any default route that we\'ve saved',
		   '#',
		   'restore_default_route' );
	}

	unless ( $config{KEEP_RT_TABLES} ) {
	    emit( 'if [ -w /etc/iproute2/rt_tables ]; then',
		  '    cat > /etc/iproute2/rt_tables <<EOF' );

	    push_indent;

	    emit_unindented join( "\n",
				  '#',
				  '# reserved values',
				  '#',
				  "255\tlocal",
				  "254\tmain",
				  "253\tdefault",
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

	my $fn = open_file 'route_rules';

	if ( $fn ) {

	    my $first_entry = 0;

	    emit '';

	    while ( read_a_line ) {

		if ( $first_entry ) {
		    progress_message2 "$doing $fn...";
		    $first_entry = 0;
		}

		my ( $source, $dest, $provider, $priority ) = split_line 4, 4, 'route_rules file';

		add_an_rtrule( $source, $dest, $provider , $priority );
	    }
	}

	emit "\nrun_ip route flush cache";
	pop_indent;
	emit "fi\n";

	setup_route_marking if @routemarked_interfaces;
    } else {
	emit "\nundo_routing";
	emit 'restore_default_route';
    }
}

1;
