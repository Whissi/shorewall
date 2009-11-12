#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Rules.pm
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
#   This module contains the high-level code for dealing with rules.
#
package Shorewall::Rules;
require Exporter;

use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::Actions;
use Shorewall::Policy;
use Shorewall::Proc;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( process_tos
		  setup_ecn
		  add_common_rules
		  setup_mac_lists
		  process_rules
		  process_routestopped
		  generate_matrix
		  compile_stop_firewall
		  );
our @EXPORT_OK = qw( process_rule process_rule1 initialize );
our $VERSION = '4.4_4';

#
# Set to one if we find a SECTION
#
our $sectioned;
our $macro_nest_level;
our $current_param;
our @param_stack;
our $family;

#
# When splitting a line in the rules file, don't pad out the columns with '-' if the first column contains one of these
#

my %rules_commands = ( COMMENT => 0,
		       SECTION => 2 );

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
    $sectioned = 0;
    $macro_nest_level = 0;
    $current_param = '';
    @param_stack = ();
}

use constant { MAX_MACRO_NEST_LEVEL => 5 };

sub process_tos() {
    my $chain    = $capabilities{MANGLE_FORWARD} ? 'fortos'  : 'pretos';
    my $stdchain = $capabilities{MANGLE_FORWARD} ? 'FORWARD' : 'PREROUTING';

    my %tosoptions = ( 'minimize-delay'       => 0x10 ,
		       'maximize-throughput'  => 0x08 ,
		       'maximize-reliability' => 0x04 ,
		       'minimize-cost'        => 0x02 ,
		       'normal-service'       => 0x00 );

    if ( my $fn = open_file 'tos' ) {
	my $first_entry = 1;

	my ( $pretosref, $outtosref );

	first_entry( sub { progress_message2 "$doing $fn..."; $pretosref = ensure_chain 'mangle' , $chain; $outtosref = ensure_chain 'mangle' , 'outtos'; } );

	while ( read_a_line ) {

	    my ($src, $dst, $proto, $sports, $ports , $tos, $mark ) = split_line 6, 7, 'tos file entry';

	    $first_entry = 0;

	    fatal_error 'A value must be supplied in the TOS column' if $tos eq '-';

	    if ( defined ( my $tosval = $tosoptions{"\L$tos"} ) ) {
		$tos = $tosval;
	    } else {
		my $val = numeric_value( $tos );
		fatal_error "Invalid TOS value ($tos)" unless defined( $val ) && $val < 0x1f;
	    }

	    my $chainref;

	    my $restriction = NO_RESTRICT;

	    my ( $srczone , $source , $remainder );

	    if ( $family == F_IPV4 ) {
		( $srczone , $source , $remainder ) = split( /:/, $src, 3 );
		fatal_error 'Invalid SOURCE' if defined $remainder;
	    } elsif ( $src =~ /^(.+?):<(.*)>\s*$/ ) {
		$srczone = $1;
		$source  = $2;
	    } else {
		$srczone = $src;
	    }

	    if ( $srczone eq firewall_zone ) {
		$chainref    = $outtosref;
		$src         = $source || '-';
		$restriction = OUTPUT_RESTRICT;
	    } else {
		$chainref = $pretosref;
		$src =~ s/^all:?//;
	    }

	    $dst =~ s/^all:?//;

	    expand_rule
		$chainref ,
		$restriction ,
		do_proto( $proto, $ports, $sports ) . do_test( $mark , 0xFF ) ,
		$src ,
		$dst ,
		'' ,
		"-j TOS --set-tos $tos" ,
		'' ,
		'' ,
		'';
	}

	unless ( $first_entry ) {
	    add_rule $mangle_table->{$stdchain}, "-j $chain" if $pretosref->{referenced};
	    add_rule $mangle_table->{OUTPUT},    "-j outtos" if $outtosref->{referenced};
	}
    }
}

#
# Setup ECN disabling rules
#
sub setup_ecn()
{
    my %interfaces;
    my @hosts;

    if ( my $fn = open_file 'ecn' ) {

	first_entry "$doing $fn...";

	while ( read_a_line ) {

	    my ($interface, $hosts ) = split_line 1, 2, 'ecn file entry';

	    fatal_error "Unknown interface ($interface)" unless known_interface $interface;

	    $interfaces{$interface} = 1;

	    $hosts = ALLIP if $hosts eq '-';

	    for my $host( split_list $hosts, 'address' ) {
		validate_host( $host , 1 );
		push @hosts, [ $interface, $host ];
	    }
	}

	if ( @hosts ) {
	    my @interfaces = ( keys %interfaces );

	    progress_message "$doing ECN control on @interfaces...";

	    for my $interface ( @interfaces ) {
		my $chainref = ensure_chain 'mangle', ecn_chain( $interface );

		add_jump $mangle_table->{POSTROUTING} , $chainref, 0, "-p tcp " . match_dest_dev( $interface );
		add_jump $mangle_table->{OUTPUT},       $chainref, 0, "-p tcp " . match_dest_dev( $interface );
	    }

	    for my $host ( @hosts ) {
		add_rule $mangle_table->{ecn_chain $host->[0]}, join ('', '-p tcp ', match_dest_net( $host->[1] ) , ' -j ECN --ecn-tcp-remove' );
	    }
	}
    }
}

sub add_rule_pair( $$$$ ) {
    my ($chainref , $predicate , $target , $level ) = @_;

    log_rule( $level, $chainref, "\U$target", $predicate )  if defined $level && $level ne '';
    add_rule $chainref , "${predicate}-j $target";
}

sub setup_blacklist() {

    my $hosts = find_hosts_by_option 'blacklist';
    my $chainref;
    my ( $level, $disposition ) = @config{'BLACKLIST_LOGLEVEL', 'BLACKLIST_DISPOSITION' };
    my $target = $disposition eq 'REJECT' ? 'reject' : $disposition;

    if ( @$hosts ) {
	$chainref = new_standard_chain 'blacklst';

	if ( defined $level && $level ne '' ) {
	    my $logchainref = new_standard_chain 'blacklog';

	    log_rule_limit( $level , $logchainref , 'blacklst' , $disposition , "$globals{LOGLIMIT}" , '', 'add',	'' );

	    add_rule $logchainref, "-j $target" ;

	    $target = 'blacklog';
	}
    }

  BLACKLIST:
    {
	if ( my $fn = open_file 'blacklist' ) {

	    my $first_entry = 1;

	    first_entry "$doing $fn...";

	    while ( read_a_line ) {

		if ( $first_entry ) {
		    unless  ( @$hosts ) {
			warning_message qq(The entries in $fn have been ignored because there are no 'blacklist' interfaces);
			close_file;
			last BLACKLIST;
		    }

		    $first_entry = 0;
		}

		my ( $networks, $protocol, $ports ) = split_line 1, 3, 'blacklist file';

		expand_rule(
			    $chainref ,
			    NO_RESTRICT ,
			    do_proto( $protocol , $ports, '' ) ,
			    $networks ,
			    '' ,
			    '' ,
			    "-j $target" ,
			    '' ,
			    $disposition ,
			    '' );

		progress_message "  \"$currentline\" added to blacklist";
	    }
	}

	my $state = $config{BLACKLISTNEWONLY} ? $globals{UNTRACKED} ? '-m state --state NEW,INVALID,UNTRACKED ' : '-m state --state NEW,INVALID ' : '';

	for my $hostref ( @$hosts ) {
	    my $interface  = $hostref->[0];
	    my $ipsec      = $hostref->[1];
	    my $policy     = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    my $network    = $hostref->[2];
	    my $source     = match_source_net $network;
	    my $target     = source_exclusion( $hostref->[3], $chainref );

	    for my $chain ( first_chains $interface ) {
		add_jump $filter_table->{$chain} , $chainref, 0, "${source}${state}${policy}";
	    }

	    set_interface_option $interface, 'use_input_chain', 1;
	    set_interface_option $interface, 'use_forward_chain', 1;

	    progress_message "  Blacklisting enabled on ${interface}:${network}";
	}
    }
}

sub process_routestopped() {

    my ( @allhosts, %source, %dest , %notrack, @rule );

    my $fn = open_file 'routestopped';

    my $seq = 0;

    first_entry "$doing $fn...";

    while ( read_a_line ) {

	my $routeback = 0;

	my ($interface, $hosts, $options , $proto, $ports, $sports ) = split_line 1, 6, 'routestopped file';

	fatal_error "Unknown interface ($interface)" unless known_interface $interface;

	$hosts = ALLIP unless $hosts && $hosts ne '-';

	my @hosts;

	$seq++;

	my $rule = do_proto( $proto, $ports, $sports, 1 );

	for my $host ( split /,/, $hosts ) {
	    validate_host $host, 1;
	    push @hosts, "$interface|$host|$seq";
	    push @rule, $rule;
	}

	unless ( $options eq '-' ) {

	    for my $option (split /,/, $options ) {
		if ( $option eq 'routeback' ) {
		    if ( $routeback ) {
			warning_message "Duplicate 'routeback' option ignored";
		    } else {
			my $chainref = $filter_table->{FORWARD};

			$routeback = 1;

			for my $host ( split /,/, $hosts ) {
			    add_rule( $chainref , 
				      match_source_dev( $interface ) . 
				      match_dest_dev( $interface ) .
				      match_source_net( $host ) .
				      match_dest_net( $host ) );
			    clearrule;
			}
		    }
		} elsif ( $option eq 'source' ) {
		    for my $host ( split /,/, $hosts ) {
			$source{"$interface|$host|$seq"} = 1;
		    }
		} elsif ( $option eq 'dest' ) {
		    for my $host ( split /,/, $hosts ) {
			$dest{"$interface|$host|$seq"} = 1;
		    }
		} elsif ( $option eq 'notrack' ) {
		    for my $host ( split /,/, $hosts ) {
			$notrack{"$interface|$host|$seq"} = 1;
		    }
		} else {
		    warning_message "Unknown routestopped option ( $option ) ignored" unless $option eq 'critical';
		    warning_message "The 'critical' option is no longer supported (or needed)";
		}
	    }
	}

	push @allhosts, @hosts;
    }

    for my $host ( @allhosts ) {
	my ( $interface, $h, $seq ) = split /\|/, $host;
	my $source  = match_source_net $h;
	my $dest    = match_dest_net $h;
	my $sourcei = match_source_dev $interface;
	my $desti   = match_dest_dev $interface;
	my $rule    = shift @rule;

	add_rule $filter_table->{INPUT},  "$sourcei $source $rule -j ACCEPT", 1;
	add_rule $filter_table->{OUTPUT}, "$desti $dest $rule -j ACCEPT", 1 unless $config{ADMINISABSENTMINDED};

	my $matched = 0;

	if ( $source{$host} ) {
	    add_rule $filter_table->{FORWARD}, "$sourcei $source $rule -j ACCEPT", 1;
	    $matched = 1;
	}

	if ( $dest{$host} ) {
	    add_rule $filter_table->{FORWARD}, "$desti $dest $rule -j ACCEPT", 1;
	    $matched = 1;
	}

	if ( $notrack{$host} ) {
	    add_rule $raw_table->{PREROUTING}, "$sourcei $source $rule -j NOTRACK", 1;
	    add_rule $raw_table->{OUTPUT},     "$desti $dest $rule -j NOTRACK", 1;
	}

	unless ( $matched ) {
	    for my $host1 ( @allhosts ) {
		unless ( $host eq $host1 ) {
		    my ( $interface1, $h1 , $seq1 ) = split /\|/, $host1;
		    my $dest1 = match_dest_net $h1;
		    my $desti1 = match_dest_dev $interface1;
		    add_rule $filter_table->{FORWARD}, "$sourcei $desti1 $source $dest1 $rule -j ACCEPT", 1;
		    clearrule;
		}
	    }
	}
    }
}

sub setup_mss();

sub add_common_rules() {
    my $interface;
    my $chainref;
    my $level;
    my $target;
    my $rule;
    my $list;
    my $chain;

    new_standard_chain 'dynamic';

    my $state = $config{BLACKLISTNEWONLY} ? $globals{UNTRACKED} ? '-m state --state NEW,INVALID,UNTRACKED ' : '-m state --state NEW,INVALID ' : '';

    add_rule $filter_table->{$_}, "$state -j dynamic" for qw( INPUT FORWARD );

    setup_mss;

    if ( $config{FASTACCEPT} ) {
	add_rule( $filter_table->{$_} , "-m state --state ESTABLISHED,RELATED -j ACCEPT" ) for qw( INPUT FORWARD OUTPUT );
    }

    my $rejectref = new_standard_chain 'reject';

    $level = $config{BLACKLIST_LOGLEVEL};

    add_rule_pair new_standard_chain( 'logdrop' ),   ' ' , 'DROP'   , $level ;
    add_rule_pair new_standard_chain( 'logreject' ), ' ' , 'reject' , $level ;

    for $interface ( all_interfaces ) {
	ensure_chain( 'filter', $_ ) for first_chains( $interface ), output_chain( $interface );
    }

    run_user_exit1 'initdone';

    setup_blacklist;

    $list = find_hosts_by_option 'nosmurfs';

    $chainref = new_standard_chain 'smurfs';

    if ( $capabilities{ADDRTYPE} ) {
	add_rule $chainref , '-s 0.0.0.0 -j RETURN';
	add_rule_pair $chainref, '-m addrtype --src-type BROADCAST ', 'DROP', $config{SMURF_LOG_LEVEL} ;
    } else {
	if ( $family == F_IPV4 ) {
	    add_commands $chainref, 'for address in $ALL_BCASTS; do';
	} else {
	    add_commands $chainref, 'for address in $ALL_ACASTS; do';
	}

	incr_cmd_level $chainref;
	log_rule( $config{SMURF_LOG_LEVEL} , $chainref, 'DROP', '-s $address ' );
	add_rule $chainref, '-s $address -j DROP';
	decr_cmd_level $chainref;
	add_commands $chainref, 'done';
    }

    if ( $family == F_IPV4 ) {
	add_rule_pair $chainref, '-s 224.0.0.0/4 ', 'DROP', $config{SMURF_LOG_LEVEL};
    } else {
	add_rule_pair $chainref, '-s ff00::/10 ', 'DROP', $config{SMURF_LOG_LEVEL} if $family == F_IPV4;
    }

    if ( $capabilities{ADDRTYPE} ) {
	add_rule $rejectref , '-m addrtype --src-type BROADCAST -j DROP';
    } else {
	if ( $family == F_IPV4 ) {
	    add_commands $rejectref, 'for address in $ALL_BCASTS; do';
	} else {
	    add_commands $rejectref, 'for address in $ALL_ACASTS; do';
	}

	incr_cmd_level $rejectref;
	add_rule $rejectref, '-d $address -j DROP';
	decr_cmd_level $rejectref;
	add_commands $rejectref, 'done';
    }

    if ( $family == F_IPV4 ) {
	add_rule $rejectref , '-s 224.0.0.0/4 -j DROP';
    } else {
	add_rule $rejectref , '-s ff00::/10 -j DROP';
    }

    if ( @$list ) {
	progress_message2 'Adding Anti-smurf Rules';

	my $state = $globals{UNTRACKED} ? 'NEW,INVALID,UNTRACKED' : 'NEW,INVALID';

	for my $hostref  ( @$list ) {
	    $interface     = $hostref->[0];
	    my $ipsec      = $hostref->[1];
	    my $policy     = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    my $target     = source_exclusion( $hostref->[3], $chainref );

	    for $chain ( first_chains $interface ) {
		add_jump $filter_table->{$chain} , $target, 0, join( '', "-m state --state $state ", match_source_net( $hostref->[2] ),  $policy );
	    }

	    set_interface_option $interface, 'use_input_chain', 1;
	    set_interface_option $interface, 'use_forward_chain', 1;
	}
    }

    add_rule $rejectref , '-p 2 -j DROP';
    add_rule $rejectref , '-p 6 -j REJECT --reject-with tcp-reset';

    if ( $capabilities{ENHANCED_REJECT} ) {
	add_rule $rejectref , '-p 17 -j REJECT';

	if ( $family == F_IPV4 ) {
	    add_rule $rejectref, '-p 1 -j REJECT --reject-with icmp-host-unreachable';
	    add_rule $rejectref, '-j REJECT --reject-with icmp-host-prohibited';
	} else {
	    add_rule $rejectref, '-p 58 -j REJECT --reject-with icmp6-addr-unreachable';
	    add_rule $rejectref, '-j REJECT --reject-with icmp6-adm-prohibited';
	}
    } else {
	add_rule $rejectref , '-j REJECT';
    }

    $list = find_interfaces_by_option 'dhcp';

    if ( @$list ) {
	progress_message2 'Adding rules for DHCP';

	my $ports = $family == F_IPV4 ? '67:68' : '546:547';

	for $interface ( @$list ) {
	    set_interface_option $interface, 'use_input_chain', 1;
	    set_interface_option $interface, 'use_forward_chain', 1;

	    for $chain ( input_chain $interface, output_chain $interface ) {
		add_rule $filter_table->{$chain} , "-p udp --dport $ports -j ACCEPT";
	    }

	    add_rule( $filter_table->{forward_chain $interface} , 
		      "-p udp " .
		      match_dest_dev( $interface ) .
		      "--dport $ports -j ACCEPT" )
		if get_interface_option( $interface, 'bridge' );
	}
    }

    $list = find_hosts_by_option 'tcpflags';

    if ( @$list ) {
	my $disposition;

	progress_message2 "$doing TCP Flags filtering...";

	$chainref = new_standard_chain 'tcpflags';

	if ( $config{TCP_FLAGS_LOG_LEVEL} ne ''  ) {
	    my $logflagsref = new_standard_chain 'logflags';

	    my $savelogparms = $globals{LOGPARMS};

	    $globals{LOGPARMS} = "$globals{LOGPARMS}--log-ip-options ";

	    log_rule $config{TCP_FLAGS_LOG_LEVEL} , $logflagsref , $config{TCP_FLAGS_DISPOSITION}, '';

	    $globals{LOGPARMS} = $savelogparms;

	    if ( $config{TCP_FLAGS_DISPOSITION} eq 'REJECT' ) {
		add_rule $logflagsref , '-p 6 -j REJECT --reject-with tcp-reset';
	    } else {
		add_rule $logflagsref , "-j $config{TCP_FLAGS_DISPOSITION}";
	    }

	    $disposition = 'logflags';
	} else {
	    $disposition = $config{TCP_FLAGS_DISPOSITION};
	}

	add_rule $chainref , "-p tcp --tcp-flags ALL FIN,URG,PSH -j $disposition";
	add_rule $chainref , "-p tcp --tcp-flags ALL NONE        -j $disposition";
	add_rule $chainref , "-p tcp --tcp-flags SYN,RST SYN,RST -j $disposition";
	add_rule $chainref , "-p tcp --tcp-flags SYN,FIN SYN,FIN -j $disposition";
	add_rule $chainref , "-p tcp --syn --sport 0 -j $disposition";

	for my $hostref  ( @$list ) {
	    my $interface  = $hostref->[0];
	    my $target     = source_exclusion( $hostref->[3], $chainref );
	    my $policy     = $capabilities{POLICY_MATCH} ? "-m policy --pol $hostref->[1] --dir in " : '';

	    for $chain ( first_chains $interface ) {
		add_jump $filter_table->{$chain} , $target, 0, join( '', '-p tcp ', match_source_net( $hostref->[2] ), $policy );
	    }
	    set_interface_option $interface, 'use_input_chain', 1;
	    set_interface_option $interface, 'use_forward_chain', 1;
	}
    }

    if ( $family == F_IPV4 ) {
	my $announced = 0;

	$list = find_interfaces_by_option 'upnp';

	if ( @$list ) {
	    progress_message2 "$doing UPnP";

	    new_nat_chain( 'UPnP' );

	    $announced = 1;

	    for $interface ( @$list ) {
		add_rule $nat_table->{PREROUTING} , match_source_dev ( $interface ) . '-j UPnP';
	    }
	}

	$list = find_interfaces_by_option 'upnpclient';

	if ( @$list ) {
	    progress_message2 "$doing UPnP" unless $announced;

	    for $interface ( @$list ) {
		my $chainref = $filter_table->{input_chain $interface};
		my $base     = uc chain_base $interface;
		my $variable = get_interface_gateway $interface;

		if ( interface_is_optional $interface ) {
		    add_commands( $chainref,
				  qq(if [ -n "\$${base}_IS_USABLE" -a -n "$variable" ]; then) ,
				  qq(    echo -A $chainref->{name} ) . match_source_dev( $interface ) . qq(-s $variable -p udp -j ACCEPT >&3) ,
				  qq(fi) );
		} else {
		    add_commands( $chainref, qq(echo -A $chainref->{name} ) . match_source_dev( $interface ) . qq(-s $variable -p udp -j ACCEPT >&3) );
		}
	    }
	}
    }

    setup_syn_flood_chains;

}

my %maclist_targets = ( ACCEPT => { target => 'RETURN' , mangle => 1 } ,
			REJECT => { target => 'reject' , mangle => 0 } ,
			DROP   => { target => 'DROP' ,   mangle => 1 } );

sub setup_mac_lists( $ ) {

    my $phase = $_[0];

    my %maclist_interfaces;

    my $table = $config{MACLIST_TABLE};

    my $maclist_hosts = find_hosts_by_option 'maclist';

    my $target      = $globals{MACLIST_TARGET};
    my $level       = $config{MACLIST_LOG_LEVEL};
    my $disposition = $config{MACLIST_DISPOSITION};
    my $ttl         = $config{MACLIST_TTL};

    progress_message2 "$doing MAC Filtration -- Phase $phase...";

    for my $hostref ( @$maclist_hosts ) {
	$maclist_interfaces{ $hostref->[0] } = 1;
    }

    my @maclist_interfaces = ( sort keys %maclist_interfaces );

    if ( $phase == 1 ) {

	for my $interface ( @maclist_interfaces ) {
	    my $chainref = new_chain $table , mac_chain $interface;

	    if ( $family == F_IPV4 ) {
		add_rule $chainref , '-s 0.0.0.0 -d 255.255.255.255 -p udp --dport 67:68 -j RETURN'
		    if $table eq 'mangle'  && get_interface_option( $interface, 'dhcp');
	    } else {
		#
		# Accept any packet with a link-level source or destination address
		#
		add_rule $chainref , '-s ff80::/10 -j RETURN';
		add_rule $chainref , '-d ff80::/10 -j RETURN';
		#
		# Accept Multicast
		#
		add_rule $chainref , '-d ff00::/10 -j RETURN';
	    }

	    if ( $ttl ) {
		my $chain1ref = new_chain $table, macrecent_target $interface;

		my $chain = $chainref->{name};

		add_rule $chainref, "-m recent --rcheck --seconds $ttl --name $chain -j RETURN";
		add_rule $chainref, "-j $chain1ref->{name}";
		add_rule $chainref, "-m recent --update --name $chain -j RETURN";
		add_rule $chainref, "-m recent --set --name $chain";
	    }
	}

	my $fn = open_file 'maclist';

	first_entry "$doing $fn...";

	while ( read_a_line ) {

	    my ( $original_disposition, $interface, $mac, $addresses  ) = split_line1 3, 4, 'maclist file';

	    if ( $original_disposition eq 'COMMENT' ) {
		process_comment;
	    } else {
		my ( $disposition, $level, $remainder) = split( /:/, $original_disposition, 3 );

		fatal_error "Invalid DISPOSITION ($original_disposition)" if defined $remainder || ! $disposition;

		my $targetref = $maclist_targets{$disposition};

		fatal_error "Invalid DISPOSITION ($original_disposition)"              if ! $targetref || ( ( $table eq 'mangle' ) && ! $targetref->{mangle} );
		fatal_error "Unknown Interface ($interface)"                           unless known_interface( $interface );
		fatal_error "No hosts on $interface have the maclist option specified" unless $maclist_interfaces{$interface};

		my $chainref = $chain_table{$table}{( $ttl ? macrecent_target $interface : mac_chain $interface )};

		$mac       = '' unless $mac && ( $mac ne '-' );
		$addresses = '' unless defined $addresses && ( $addresses ne '-' );

		fatal_error "You must specify a MAC address or an IP address" unless $mac || $addresses;

		$mac = mac_match $mac if $mac;

		if ( $addresses ) {
		    for my $address ( split ',', $addresses ) {
			my $source = match_source_net $address;
			log_rule_limit $level, $chainref , mac_chain( $interface) , $disposition, '', '', 'add' , "${mac}${source}"
			    if defined $level && $level ne '';
			add_rule $chainref , "${mac}${source}-j $targetref->{target}";
		    }
		} else {
		    log_rule_limit $level, $chainref , mac_chain( $interface) , $disposition, '', '', 'add' , $mac
			if defined $level && $level ne '';
		    add_rule $chainref , "$mac-j $targetref->{target}";
		}

		progress_message "      Maclist entry \"$currentline\" $done";
	    }
	}

	clear_comment;
	#
	# Generate jumps from the input and forward chains
	#
	for my $hostref ( @$maclist_hosts ) {
	    my $interface  = $hostref->[0];
	    my $ipsec      = $hostref->[1];
	    my $policy     = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    my $source     = match_source_net $hostref->[2];

	    my $state = $globals{UNTRACKED} ? 'NEW,UNTRACKED' : 'NEW';

	    if ( $table eq 'filter' ) {
		my $chainref = source_exclusion( $hostref->[3], $filter_table->{mac_chain $interface} );

		for my $chain ( first_chains $interface ) {
		    add_jump $filter_table->{$chain} , $chainref, 0, "${source}-m state --state ${state} ${policy}";
		}

		set_interface_option $interface, 'use_input_chain', 1;
		set_interface_option $interface, 'use_forward_chain', 1;
	    } else {
		my $chainref = source_exclusion( $hostref->[3], $mangle_table->{mac_chain $interface} );
		add_jump $mangle_table->{PREROUTING}, $chainref, 0, match_source_dev( $interface ) . "${source}-m state --state ${state} ${policy}";
	    }
	}
    } else {
	#
	# Phase II
	#
	for my $interface ( @maclist_interfaces ) {
	    my $chainref = $chain_table{$table}{( $ttl ? macrecent_target $interface : mac_chain $interface )};
	    my $chain    = $chainref->{name};

	    if ( $family == F_IPV4 ) {
		if ( $level ne '' || $disposition ne 'ACCEPT' ) {
		    my $variable = get_interface_addresses source_port_to_bridge( $interface );

		    if ( $capabilities{ADDRTYPE} ) {
			add_commands( $chainref,
				      "for address in $variable; do",
				      "    echo \"-A $chainref->{name} -s \$address -m addrtype --dst-type BROADCAST -j RETURN\" >&3",
				      "    echo \"-A $chainref->{name} -s \$address -d 224.0.0.0/4 -j RETURN\" >&3",
				      'done' );
		    } else {
			my $bridge    = source_port_to_bridge( $interface );
			my $bridgeref = find_interface( $bridge );

			add_commands( $chainref,
				      "for address in $variable; do" );

			if ( $bridgeref->{broadcasts} ) {
			    for my $address ( @{$bridgeref->{broadcasts}}, '255.255.255.255' ) {
				add_commands( $chainref ,
					      "    echo \"-A $chainref->{name} -s \$address -d $address -j RETURN\" >&3" );
			    }
			} else {
			    my $variable1 = get_interface_bcasts $bridge;

			    add_commands( $chainref,
					  "    for address1 in $variable1; do" ,
					  "        echo \"-A $chainref->{name} -s \$address -d \$address1 -j RETURN\" >&3",
					  "    done" );
			}

			add_commands( $chainref
				      , "    echo \"-A $chainref->{name} -s \$address -d 224.0.0.0/4 -j RETURN\" >&3" ,
				      , 'done' );
		    }
		}
	    }

	    run_user_exit2( 'maclog', $chainref );

	    log_rule_limit $level, $chainref , $chain , $disposition, '', '', 'add', '' if $level ne '';
	    add_rule $chainref, "-j $target";
	}
    }
}

sub process_rule1 ( $$$$$$$$$$$$$ );

#
# Expand a macro rule from the rules file
#
sub process_macro ( $$$$$$$$$$$$$$$ ) {
    my ($macro, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $wildcard ) = @_;

    my $nocomment = no_comment;

    my $format = 1;

    macro_comment $macro;

    my $macrofile = $macros{$macro};

    progress_message "..Expanding Macro $macrofile...";

    push_open $macrofile;

    while ( read_a_line ) {

	my ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $morigdest, $mrate, $muser, $mmark, $mconnlimit, $mtime);

	if ( $format == 1 ) {
	    ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split_line1 1, 8, 'macro file', $macro_commands;
	    ( $morigdest, $mmark, $mconnlimit, $mtime ) = qw/- - - -/;
	} else {
	    ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $morigdest, $mrate, $muser, $mmark, $mconnlimit, $mtime ) = split_line1 1, 12, 'macro file', $macro_commands;
	}

	if ( $mtarget eq 'COMMENT' ) {
	    process_comment unless $nocomment;
	    next;
	}

	if ( $mtarget eq 'FORMAT' ) {
	    fatal_error "Invalid FORMAT ($msource)" unless $msource =~ /^[12]$/;
	    $format = $msource;
	    next;
	}

	$mtarget = merge_levels $target, $mtarget;

	if ( $mtarget =~ /^PARAM(:.*)?$/ ) {
	    fatal_error 'PARAM requires a parameter to be supplied in macro invocation' unless $param ne '';
	    $mtarget = substitute_param $param,  $mtarget;
	}

	my $action = isolate_basic_target $mtarget;

	fatal_error "Invalid or missing ACTION ($mtarget)" unless defined $action;

	my $actiontype = $targets{$action} || find_macro( $action );

	fatal_error "Invalid Action ($mtarget) in macro" unless $actiontype & ( ACTION +  STANDARD + NATRULE + MACRO );

	if ( $msource ) {
	    if ( $msource eq '-' ) {
		$msource = $source || '';
	    } elsif ( $msource =~ s/^DEST:?// ) {
		$msource = merge_macro_source_dest $msource, $dest;
	    } else {
		$msource =~ s/^SOURCE:?//;
		$msource = merge_macro_source_dest $msource, $source;
	    }
	} else {
	    $msource = '';
	}

	if ( $mdest ) {
	    if ( $mdest eq '-' ) {
		$mdest = $dest || '';
	    } elsif ( $mdest =~ s/^SOURCE:?// ) {
		$mdest = merge_macro_source_dest $mdest , $source;
	    } else {
		$mdest =~ s/DEST:?//;
		$mdest = merge_macro_source_dest $mdest, $dest;
	    }
	} else {
	    $mdest = '';
	}

	process_rule1(
		      $mtarget,
		      $msource,
		      $mdest,
		      merge_macro_column( $mproto,     $proto ) ,
		      merge_macro_column( $mports,     $ports ) ,
		      merge_macro_column( $msports,    $sports ) ,
		      merge_macro_column( $morigdest,  $origdest ) ,
		      merge_macro_column( $mrate,      $rate ) ,
		      merge_macro_column( $muser,      $user ) ,
		      merge_macro_column( $mmark,      $mark ) ,
		      merge_macro_column( $mconnlimit, $connlimit) ,
		      merge_macro_column( $mtime,      $time ),
		      $wildcard
		     );

	progress_message "   Rule \"$currentline\" $done";
    }

    pop_open;

    progress_message "..End Macro $macrofile";

    clear_comment unless $nocomment;

}
#
# Once a rule has been expanded via wildcards (source and/or dest zone == 'all'), it is processed by this function. If
# the target is a macro, the macro is expanded and this function is called recursively for each rule in the expansion.
#
sub process_rule1 ( $$$$$$$$$$$$$ ) {
    my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time, $wildcard ) = @_;
    my ( $action, $loglevel) = split_action $target;
    my ( $basictarget, $param ) = get_target_param $action;
    my $rule = '';
    my $actionchainref;
    my $optimize = $wildcard ? ( $basictarget =~ /!$/ ? 0 : $config{OPTIMIZE} ) : 0;

    unless ( defined $param ) {
	( $basictarget, $param ) = ( $1, $2 ) if $action =~ /^(\w+)[(](.*)[)]$/;
    }

    $param = '' unless defined $param;

    #
    # Determine the validity of the action
    #
    my $actiontype = $targets{$basictarget} || find_macro( $basictarget );

    if ( $config{ MAPOLDACTIONS } ) {
	( $basictarget, $actiontype , $param ) = map_old_actions( $basictarget ) unless ( $actiontype || $param );
    }

    fatal_error "Unknown action ($action)" unless $actiontype;

    if ( $actiontype == MACRO ) {
	#
	# process_macro() will call process_rule1() recursively for each rule in the macro body
	#
	fatal_error "Macro invocations nested too deeply" if ++$macro_nest_level > MAX_MACRO_NEST_LEVEL;

	if ( $param ne '' ) {
	    push @param_stack, $current_param;
	    $current_param = $param;
	}

	process_macro( $basictarget,
		       $target ,
		       $current_param,
		       $source,
		       $dest,
		       $proto,
		       $ports,
		       $sports,
		       $origdest,
		       $ratelimit,
		       $user,
		       $mark,
		       $connlimit,
		       $time,
		       $wildcard );

	$macro_nest_level--;

	$current_param = pop @param_stack if $param ne '';

	return;

    } elsif ( $actiontype & NFQ ) {
	require_capability( 'NFQUEUE_TARGET', 'NFQUEUE Rules', '' );
	my $paramval = $param eq '' ? 0 : numeric_value( $param );
	fatal_error "Invalid value ($param) for NFQUEUE queue number" unless defined($paramval) && $paramval <= 65535;
	$action = "NFQUEUE --queue-num $paramval";
    } else {
	fatal_error "The $basictarget TARGET does not accept a parameter" unless $param eq '';
    }
    #
    # We can now dispense with the postfix character
    #
    $action =~ s/[\+\-!]$//;
    #
    # Mark target as used
    #
    if ( $actiontype & ACTION ) {
	unless ( $usedactions{$target} ) {
	    $usedactions{$target} = 1;
	    createactionchain $target;
	}
    }
    #
    # Take care of irregular syntax and targets
    #
    my $log_action = $action;

    if ( $actiontype & REDIRECT ) {
	my $z = $actiontype & NATONLY ? '' : firewall_zone;
	if ( $dest eq '-' ) {
	    $dest = join( '', $z, '::' , $ports =~ /[:,]/ ? '' : $ports );
	} else {
	    $dest = join( '', $z, '::', $dest ) unless $dest =~ /:/;
	}
    } elsif ( $action eq 'REJECT' ) {
	$action = 'reject';
    } elsif ( $action eq 'CONTINUE' ) {
	$action = 'RETURN';
    } elsif ( $action eq 'COUNT' ) {
	$action = '';
    } elsif ( $actiontype & LOGRULE ) {
	fatal_error 'LOG requires a log level' unless defined $loglevel and $loglevel ne '';
    }
    #
    # Isolate and validate source and destination zones
    #
    my $sourcezone;
    my $destzone;
    my $sourceref;
    my $destref;
    my $origdstports;

    if ( $source =~ /^(.+?):(.*)/ ) {
	fatal_error "Missing SOURCE Qualifier ($source)" if $2 eq '';
	$sourcezone = $1;
	$source = $2;
    } else {
	$sourcezone = $source;
	$source = ALLIP;
    }

    if ( $dest =~ /^(.*?):(.*)/ ) {
	fatal_error "Missing DEST Qualifier ($dest)" if $2 eq '';
	$destzone = $1;
	$dest = $2;
    } elsif ( $dest =~ /.*\..*\./ ) {
	#
	# Appears to be an address
	#
	$destzone = '-';
    } else {
	$destzone = $dest;
	$dest = ALLIP;
    }

    fatal_error "Missing source zone" if $sourcezone eq '-' || $sourcezone =~ /^:/;
    fatal_error "Unknown source zone ($sourcezone)" unless $sourceref = defined_zone( $sourcezone );

    if ( $actiontype & NATONLY ) {
	unless ( $destzone eq '-' || $destzone eq '' ) {
	    $destref = defined_zone( $destzone );

	    if ( $destref ) {
		warning_message "Destination zone ($destzone) ignored";
	    } else {
		$dest = join ':', $destzone, $dest;
		$destzone = '';
	    }
	}
    } else {
	fatal_error "Missing destination zone" if $destzone eq '-' || $destzone eq '';
	fatal_error "Unknown destination zone ($destzone)" unless $destref = defined_zone( $destzone );
    }

    my $restriction = NO_RESTRICT;

    if ( $sourcezone eq firewall_zone ) {
	$restriction = $destzone eq firewall_zone ? ALL_RESTRICT : OUTPUT_RESTRICT;
    } else {
	$restriction = INPUT_RESTRICT if $destzone eq firewall_zone;
    }

    my ( $chain, $chainref, $policy );
    #
    # For compatibility with older Shorewall versions
    #
    $origdest = ALLIP if $origdest eq 'all';

    #
    # Take care of chain
    #

    unless ( $actiontype & NATONLY ) {
	#
	# Check for illegal bridge port rule
	#
	if ( $destref->{type} == BPORT ) {
	    unless ( $sourceref->{bridge} eq $destref->{bridge} || single_interface( $sourcezone ) eq $destref->{bridge} ) {
		return 1 if $wildcard;
		fatal_error "Rules with a DESTINATION Bridge Port zone must have a SOURCE zone on the same bridge";
	    }
	}

	$chain    = canonical_chain( ${sourcezone}, ${destzone} );
	$chainref = ensure_chain 'filter', $chain;
	$policy   = $chainref->{policy};

	if ( $policy eq 'NONE' ) {
	    return 1 if $wildcard;
	    fatal_error "Rules may not override a NONE policy";
	}
	#
	# Handle Optimization
	#
	if ( $optimize > 0 ) {
	    my $loglevel = $filter_table->{$chainref->{policychain}}{loglevel};
	    if ( $loglevel ne '' ) {
		return 1 if $target eq "${policy}:$loglevel}";
	    } else {
		return 1 if $basictarget eq $policy;
	    }
	}
	#
	# Mark the chain as referenced and add appropriate rules from earlier sections.
	#
	$chainref = ensure_filter_chain $chain, 1;
    }

    #
    # Generate Fixed part of the rule
    #
    $rule = join( '', do_proto($proto, $ports, $sports), do_ratelimit( $ratelimit, $basictarget ) , do_user( $user ) , do_test( $mark , 0xFF ) , do_connlimit( $connlimit ), do_time( $time ) );

    unless ( $section eq 'NEW' ) {
	fatal_error "Entries in the $section SECTION of the rules file not permitted with FASTACCEPT=Yes" if $config{FASTACCEPT};
	fatal_error "$basictarget rules are not allowed in the $section SECTION" if $actiontype & ( NATRULE | NONAT );
	$rule .= "-m state --state $section "
    }

    #
    # Generate NAT rule(s), if any
    #
    if ( $actiontype & NATRULE ) {
	my ( $server, $serverport );
	my $randomize = $dest =~ s/:random$// ? '--random ' : '';

	require_capability( 'NAT_ENABLED' , "$basictarget rules", '' );
	#
	# Isolate server port
	#
	if ( $dest =~ /^(.*)(:(.+))$/ ) {
	    #
	    # Server IP and Port
	    #
	    $server = $1;      # May be empty
	    $serverport = $3;  # Not Empty due to RE
	    $origdstports = $ports;

	    if ( $origdstports && $origdstports ne '-' && port_count( $origdstports ) == 1 ) {
		$origdstports = validate_port( $proto, $origdstports );
	    } else {
		$origdstports = '';
	    }

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
	} elsif ( $dest eq ':' ) {
	    #
	    # Rule with no server IP or port ( zone:: )
	    #
	    $server = $serverport = '';
	} else {
	    #
	    # Simple server IP address (may be empty or "-")
	    #
	    $server = $dest;
	    $serverport = '';
	}

	#
	# Generate the target
	#
	my $target = '';

	if ( $actiontype  & REDIRECT ) {
	    fatal_error "A server IP address may not be specified in a REDIRECT rule" if $server;
	    $target  = '-j REDIRECT ';
	    $target .= "--to-port $serverport " if $serverport;
	    if ( $origdest eq '' || $origdest eq '-' ) {
		$origdest = ALLIP;
	    } elsif ( $origdest eq 'detect' ) {
		if ( $config{DETECT_DNAT_IPADDRS} && $sourcezone ne firewall_zone ) {
		    my $interfacesref = $sourceref->{interfaces};
		    my @interfaces = keys %$interfacesref;
		    $origdest = @interfaces ? "detect:@interfaces" : ALLIP;
 		} else {
		    $origdest = ALLIP;
		}
	    }
	} else {
	    fatal_error "A server must be specified in the DEST column in $action rules" if $server eq '';

	    if ( $server =~ /^(.+)-(.+)$/ ) {
		validate_range( $1, $2 );
	    } else {
		my @servers = validate_address $server, 1;
		$server = join ',', @servers;
	    }

	    if ( $action eq 'DNAT' ) {
		$target = '-j DNAT ';
		$serverport = ":$serverport" if $serverport;
		for my $serv ( split /,/, $server ) {
		    $target .= "--to-destination ${serv}${serverport} ";
		}
	    }

	    unless ( $origdest && $origdest ne '-' && $origdest ne 'detect' ) {
		if ( $config{DETECT_DNAT_IPADDRS} && $sourcezone ne firewall_zone ) {
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
	expand_rule ( ensure_chain ('nat' , $sourceref->{type} == FIREWALL ? 'OUTPUT' : dnat_chain $sourcezone ),
		      PREROUTE_RESTRICT ,
		      $rule ,
		      $source ,
		      $origdest ,
		      '' ,
		      $target ,
		      $loglevel ,
		      $log_action ,
		      $serverport ? do_proto( $proto, '', '' ) : '' );
	#
	# After NAT:
	#   - the destination port will be the server port ($ports) -- we did that above
	#   - the destination IP   will be the server IP   ($dest)
	#   - there will be no log level (we log NAT rules in the nat table rather than in the filter table).
	#   - the target will be ACCEPT.
	#
	unless ( $actiontype & NATONLY ) {
	    $rule = join( '', do_proto( $proto, $ports, $sports ), do_ratelimit( $ratelimit, 'ACCEPT' ), do_user $user , do_test( $mark , 0xFF ) );
	    $loglevel = '';
	    $dest     = $server;
	    $action   = 'ACCEPT';
	}
    } elsif ( $actiontype & NONAT ) {
	#
	# NONAT or ACCEPT+ -- May not specify a destination interface
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

	if ( $sourceref->{type} == FIREWALL ) {
	    $nonat_chain = $nat_table->{OUTPUT};
	} else {
	    $nonat_chain = ensure_chain 'nat', dnat_chain $sourcezone;

	    my @interfaces = keys %{zone_interfaces $sourcezone};

	    for ( @interfaces ) {
		my $ichain = input_chain $_;

		if ( $nat_table->{$ichain} ) {
		    #
		    # Static NAT is defined on this interface
		    #
		    $chn = new_chain( 'nat', newnonatchain ) unless $chn;
		    add_jump $chn, $nat_table->{$ichain}, 0, @interfaces > 1 ? match_source_dev( $_ )  : '';
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
			     '', # Rule
			     '', # Source
			     '', # Dest
			     '', # Original dest
			     '-j ACCEPT',
			     $loglevel,
			     $log_action,
			     '',
			     dnat_chain( $sourcezone  ) );
		$loglevel = '';
		$tgt = $chn->{name};
	    } else {
		$tgt = 'ACCEPT';
	    }
	}

	expand_rule( $nonat_chain ,
		     PREROUTE_RESTRICT ,
		     $rule ,
		     $source ,
		     $dest ,
		     $origdest ,
		     "-j $tgt",
		     $loglevel ,
		     $log_action ,
		     ''
		   );
	#
	# Possible optimization if the rule just generated was a simple jump to the nonat chain
	#
	if ( $chn && ${$nonat_chain->{rules}}[-1] eq "-A -j $tgt" ) {
	    #
	    # It was -- delete that rule
	    #
	    pop @{$nonat_chain->{rules}};
	    #
	    # And move the rules from the nonat chain to the zone dnat chain
	    #
	    move_rules ( $chn, $nonat_chain );
	}
    }

    #
    # Add filter table rule, unless this is a NATONLY rule type
    #
    unless ( $actiontype & NATONLY ) {

	if ( $actiontype & ACTION ) {
	    $action = (find_logactionchain $target)->{name};
	    $loglevel = '';
	}

	if ( $origdest ) {
	    unless ( $origdest eq '-' ) {
		require_capability( 'CONNTRACK_MATCH', 'ORIGINAL DEST in a non-NAT rule', 's' ) unless $actiontype & NATRULE;
	    } else {
		$origdest = '';
	    }
	}

	$rule .= "-m conntrack --ctorigdstport $origdstports " if $capabilities{NEW_CONNTRACK_MATCH} && $origdstports;

	expand_rule( ensure_chain( 'filter', $chain ) ,
		     $restriction ,
		     $rule ,
		     $source ,
		     $dest ,
		     $origdest ,
		     $action ? "-j $action " : '' ,
		     $loglevel ,
		     $log_action ,
		     '' );
    }
}

#
# Process a Record in the rules file
#
#     Deals with the ugliness of wildcard zones ('all' in SOURCE and/or DEST column).
#
sub process_rule ( ) {
    my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time ) = split_line1 1, 12, 'rules file', \%rules_commands;

    if ( $target eq 'COMMENT' ) {
	process_comment;
	return 1;
    }

    if ( $target eq 'SECTION' ) {
	#
	# read_a_line has already verified that there are exactly two tokens on the line
	#
	fatal_error "Invalid SECTION ($source)" unless defined $sections{$source};
	fatal_error "Duplicate or out of order SECTION $source" if $sections{$source};
	$sectioned = 1;
	$sections{$source} = 1;

	if ( $source eq 'RELATED' ) {
	    $sections{ESTABLISHED} = 1;
	    finish_section 'ESTABLISHED';
	} elsif ( $source eq 'NEW' ) {
	    @sections{'ESTABLISHED','RELATED'} = ( 1, 1 );
	    finish_section ( ( $section eq 'RELATED' ) ? 'RELATED' : 'ESTABLISHED,RELATED' );
	}

	$section = $source;
	return 1;
    }

    if ( $source =~ /^none(:.*)?$/i || $dest =~ /^none(:.*)?$/i ) {
	progress_message "Rule \"$currentline\" ignored.";
	return 1;
    }

    my $intrazone = 0;
    my $includesrcfw = 1;
    my $includedstfw = 1;
    my $thisline = $currentline;
    my $anysource = ( $source =~ s/^any/all/ );
    my $anydest   = ( $dest   =~ s/^any/all/ );
    #
    # Section Names are optional so once we get to an actual rule, we need to be sure that
    # we close off any missing sections.
    #
    unless ( $sectioned ) {
	finish_section 'ESTABLISHED,RELATED';
	$sections{$section = 'NEW'} = 1;
	$sectioned = 1;
    }

    #
    # Handle Wildcards
    #

    if ( $source =~ /^all[-+]/ ) {
	if ( $source eq 'all+' ) {
	    $source = 'all';
	    $intrazone = 1;
	} elsif ( ( $source eq 'all+-' ) || ( $source eq 'all-+' ) ) {
	    $source = 'all';
	    $intrazone = 1;
	    $includesrcfw = 0;
	} elsif ( $source eq 'all-' ) {
	    $source = 'all';
	    $includesrcfw = 0;
	} else {
	    fatal_error "Invalid SOURCE ($source)";
	}
    }

    if ( $dest =~ /^all[-+]/ ) {
	if ( $dest eq 'all+' ) {
	    $dest = 'all';
	    $intrazone = 1;
	} elsif ( ( $dest eq 'all+-' ) || ( $dest eq 'all-+' ) ) {
	    $dest = 'all';
	    $intrazone = 1;
	    $includedstfw = 0;
	} elsif ( $dest eq 'all-' ) {
	    $dest = 'all';
	    $includedstfw = 0;
	} else {
	    fatal_error "Invalid DEST ($dest)";
	}

    }

    my $action = isolate_basic_target $target;

    my @source;
    my @dest;

    if ( $source eq 'all' ) {
	if ( $anysource ) {
	    @source = ( all_parent_zones );
	} else {
	    @source = ( non_firewall_zones )
	}

	unshift @source, firewall_zone if $includesrcfw;
    }

    if ( $dest eq 'all' ) {
	if ( $anydest ) {
	    @dest = ( all_parent_zones );
	} else {
	    @dest = ( non_firewall_zones )
	}

	unshift @dest, firewall_zone if $includedstfw;
    }

    fatal_error "Invalid or missing ACTION ($target)" unless defined $action;

    if ( $source eq 'all' ) {
	for my $zone ( @source ) {
	    if ( $dest eq 'all' ) {
		for my $zone1 ( @dest ) {
		    if ( $intrazone || ( $zone ne $zone1 ) ) {
			process_rule1 $target, $zone, $zone1 , $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time, 1;
		    }
		}
	    } else {
		my $destzone = (split( /:/, $dest, 2 ) )[0];
		$destzone = $action =~ /^REDIRECT/ ? firewall_zone : '' unless defined_zone $destzone;
		if ( $intrazone || ( $zone ne $destzone ) ) {
		    process_rule1 $target, $zone, $dest , $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time, 1;
		}
	    }
	}
    } elsif ( $dest eq 'all' ) {
	for my $zone ( @dest ) {
	    my $sourcezone = ( split( /:/, $source, 2 ) )[0];
	    if ( ( $sourcezone ne $zone ) || $intrazone ) {
		process_rule1 $target, $source, $zone , $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time, 1;
	    }
	}
    } else {
	process_rule1  $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time, 0;
    }

    progress_message "   Rule \"$thisline\" $done";
}

#
# Process the Rules File
#
sub process_rules() {

    my $fn = open_file 'rules';

    first_entry "$doing $fn...";

    process_rule while read_a_line;

    clear_comment;
    $section = 'DONE';
}

#
# Add jumps from the builtin chains to the interface-chains that are used by this configuration
#
sub add_interface_jumps {
    our %input_jump_added;
    our %output_jump_added;
    our %forward_jump_added;
    #
    # Add Nat jumps
    #
    for my $interface ( @_ ) {
	addnatjump 'POSTROUTING' , snat_chain( $interface ), match_dest_dev( $interface );
    }

    addnatjump 'PREROUTING'  , 'nat_in'  , '';
    addnatjump 'POSTROUTING' , 'nat_out' , '';
    addnatjump 'PREROUTING', 'dnat', '';

    for my $interface ( @_ ) {
	addnatjump 'PREROUTING'  , input_chain( $interface )  , match_source_dev( $interface );
	addnatjump 'POSTROUTING' , output_chain( $interface ) , match_dest_dev( $interface );
	addnatjump 'POSTROUTING' , masq_chain( $interface ) , match_dest_dev( $interface );
    }
    #
    # Add the jumps to the interface chains from filter FORWARD, INPUT, OUTPUT
    #
    for my $interface ( @_ ) {
	add_jump( $filter_table->{FORWARD} , forward_chain $interface , 0, match_source_dev( $interface ) ) unless $forward_jump_added{$interface} || ! use_forward_chain $interface;
	add_jump( $filter_table->{INPUT}   , input_chain $interface ,   0, match_source_dev( $interface ) ) unless $input_jump_added{$interface}   || ! use_input_chain $interface;

	unless ( $output_jump_added{$interface} || ! use_output_chain $interface ) {
	    add_jump $filter_table->{OUTPUT} , output_chain $interface , 0, match_dest_dev( $interface ) unless get_interface_option( $interface, 'port' );
	}
    }
    #
    # Loopback
    #
    my $fw = firewall_zone;
    my $chainref = $filter_table->{canonical_chain( ${fw}, ${fw} )};

    add_rule $filter_table->{OUTPUT} , "-o lo -j " . ($chainref->{referenced} ? "$chainref->{name}" : 'ACCEPT' );
    add_rule $filter_table->{INPUT} , '-i lo -j ACCEPT';
}

# Generate the rules matrix.
#
# Stealing a comment from the Burroughs B6700 MCP Operating System source, "generate_matrix makes a sow's ear out of a silk purse".
#
# The biggest disadvantage of the zone-policy-rule model used by Shorewall is that it doesn't scale well as the number of zones increases (Order N**2 where N = number of zones).
# A major goal of the rewrite of the compiler in Perl was to restrict those scaling effects to this function and the rules that it generates.
#
# The function traverses the full "source-zone by destination-zone" matrix and generates the rules necessary to direct traffic through the right set of filter-table rules.
#
sub generate_matrix() {
    #
    # Helper functions for generate_matrix()
    #-----------------------------------------
    #
    # Return the target for rules from $zone to $zone1.
    #
    sub rules_target( $$ ) {
	my ( $zone, $zone1 ) = @_;
	my $chain = canonical_chain( ${zone}, ${zone1} );
	my $chainref = $filter_table->{$chain};

	return $chain   if $chainref && $chainref->{referenced};
	return 'ACCEPT' if $zone eq $zone1;

	assert( $chainref );

	if ( $chainref->{policy} ne 'CONTINUE' ) {
	    my $policyref = $filter_table->{$chainref->{policychain}};
	    assert( $policyref );
	    return $policyref->{name};
	}

	''; # CONTINUE policy
    }

    #
    # Set a breakpoint in this function if you want to step through generate_matrix().
    #
    sub start_matrix() {
	progress_message2 'Generating Rule Matrix...';
    }

    #
    #                               G e n e r a t e _ M a t r i x ( )   S t a r t s  H e r e
    #
    start_matrix;

    my @interfaces = ( all_interfaces );
    my $preroutingref = ensure_chain 'nat', 'dnat';
    my $fw = firewall_zone;
    my $notrackref = $raw_table->{notrack_chain $fw};
    my @zones = non_firewall_zones;
    my $interface_jumps_added = 0;
    our %input_jump_added   = ();
    our %output_jump_added  = ();
    our %forward_jump_added = ();

    #
    # Special processing for complex configurations
    #
    for my $zone ( @zones ) {
	my $zoneref = find_zone( $zone );

	next if @zones <= 2 && ! $zoneref->{options}{complex};
	#
	# Complex zone and we have more than one non-firewall zone -- create a zone forwarding chain
	#
	my $frwd_ref = new_standard_chain zone_forward_chain( $zone );

	if ( $capabilities{POLICY_MATCH} ) {
	    #
	    # Because policy match only matches an 'in' or an 'out' policy (but not both), we have to place the
	    # '--pol ipsec --dir in' rules at the front of the (interface) forwarding chains. Otherwise, decrypted packets
	    # can match '--pol none --dir out' rules and send the packets down the wrong rules chain.
	    #
	    my $type       = $zoneref->{type};
	    my $source_ref = ( $zoneref->{hosts}{ipsec} ) || {};

	    for my $interface ( sort { interface_number( $a ) <=> interface_number( $b ) } keys %$source_ref ) {
		my $sourcechainref;
		my $interfacematch = '';

		if ( use_forward_chain( $interface ) ) {
		    $sourcechainref = $filter_table->{forward_chain $interface};
		    add_jump $filter_table->{FORWARD} , $sourcechainref, 0 , match_source_dev( $interface ) unless $forward_jump_added{$interface}++;
		} else {
		    $sourcechainref = $filter_table->{FORWARD};
		    $interfacematch = match_source_dev $interface;
		    move_rules( $filter_table->{forward_chain $interface} , $frwd_ref );
		}

		my $arrayref = $source_ref->{$interface};

		for my $hostref ( @{$arrayref} ) {
		    my $ipsec_match = match_ipsec_in $zone , $hostref;
		    for my $net ( @{$hostref->{hosts}} ) {
			add_jump(
				 $sourcechainref,
				 source_exclusion( $hostref->{exclusions}, $frwd_ref ),
				 ! @{$zoneref->{parents}},
				 join( '', $interfacematch , match_source_net( $net ), $ipsec_match )
				);
		    }
		}
	    }
	}
    }

    #
    # NOTRACK from firewall
    #
    add_rule $raw_table->{OUTPUT}, "-j $notrackref->{name}" if $notrackref->{referenced};
    #
    # Main source-zone matrix-generation loop
    #
    for my $zone ( @zones ) {
	my $zoneref          = find_zone( $zone );
	my $source_hosts_ref = $zoneref->{hosts};
	my $chain1           = rules_target firewall_zone , $zone;
	my $chain2           = rules_target $zone, firewall_zone;
	my $chain3           = rules_target $zone, $zone;
	my $complex          = $zoneref->{options}{complex} || 0;
	my $type             = $zoneref->{type};
	my $frwd_ref         = $filter_table->{zone_forward_chain $zone};
	my $chain            = 0;
	my $dnatref          = ensure_chain 'nat' , dnat_chain( $zone );
	my $notrackref       = ensure_chain 'raw' , notrack_chain( $zone );
	my $nested           = $zoneref->{options}{nested};
	my $parenthasnat     = 0;
	my $parenthasnotrack = 0;

	if ( $nested ) {
	    #
	    # This is a sub-zone. We need to determine if
	    #
	    #   a) A parent zone defines DNAT/REDIRECT or notrack rules; and
	    #   b) The current zone has a CONTINUE policy to some other zone.
	    #
	    # If a) but not b), then we must avoid sending packets from this
	    # zone through the DNAT/REDIRECT or notrack chain for the parent.
	    #
	    for my $parent ( @{$zoneref->{parents}} ) {
		my $ref1 = $nat_table->{dnat_chain $parent} || {};
		my $ref2 = $raw_table->{notrack_chain $parent} || {};
		$parenthasnat     = 1 if $ref1->{referenced};
		$parenthasnotrack = 1 if $ref2->{referenced};
		last if $parenthasnat && $parenthasnotrack;
	    }

	    if ( $parenthasnat || $parenthasnotrack ) {
		for my $zone1 ( all_zones ) {
		    if ( $filter_table->{canonical_chain( ${zone}, ${zone1} )}->{policy} eq 'CONTINUE' ) {
			#
			# This zone has a continue policy to another zone. We must
			# send packets from this zone through the parent's DNAT/REDIRECT/NOTRACK chain.
			#
			$nested = 0;
			last;
		    }
		}
	    } else {
		#
		# No parent has DNAT or notrack so there is nothing to worry about. Don't bother to generate needless RETURN rules in the 'dnat' or 'notrack' chain.
		#
		$nested = 0;
	    }
	}
	#
	# Take care of PREROUTING, INPUT and OUTPUT jumps
	#
	for my $typeref ( values %$source_hosts_ref ) {
	    for my $interface ( sort { interface_number( $a ) <=> interface_number( $b ) } keys %$typeref ) {
		my $arrayref = $typeref->{$interface};

		if ( $interface eq '+' ) {
		    #
		    # Insert the interface-specific jumps before this one which is not interface-specific
		    #
		    add_interface_jumps(@interfaces) unless $interface_jumps_added++;
		}

		for my $hostref ( @$arrayref ) {
		    my $ipsec_in_match  = match_ipsec_in  $zone , $hostref;
		    my $ipsec_out_match = match_ipsec_out $zone , $hostref;
		    my $exclusions = $hostref->{exclusions};

		    for my $net ( @{$hostref->{hosts}} ) {
			my $dest   = match_dest_net $net;

			if ( $chain1 ) {
			    my $nextchain = dest_exclusion( $exclusions, $chain1 );
			    my $outputref;
			    my $interfacematch = '';

			    if ( use_output_chain $interface ) {
				$outputref = $filter_table->{output_chain $interface};
				add_jump $filter_table->{OUTPUT}, $outputref, 0, match_dest_dev( $interface ) unless $output_jump_added{$interface}++;
			    } else {
				$outputref = $filter_table->{OUTPUT};
				$interfacematch = match_dest_dev $interface;
			    }

			    add_jump $outputref , $nextchain, 0, join( '', $interfacematch, $dest, $ipsec_out_match );

			    add_jump( $outputref , $nextchain, 0, join('', $interfacematch, '-d 255.255.255.255 ' , $ipsec_out_match ) )
				if $hostref->{options}{broadcast};

			    move_rules( $filter_table->{output_chain $interface} , $filter_table->{$chain1} ) unless use_output_chain $interface;
			}

			clearrule;

			next if $hostref->{options}{destonly};

			my $source = match_source_net $net;

			if ( $dnatref->{referenced} ) {
			    #
			    # There are DNAT/REDIRECT rules with this zone as the source.
			    # Add a jump from this source network to this zone's DNAT/REDIRECT chain
			    #
			    add_jump $preroutingref, source_exclusion( $exclusions, $dnatref), 0, join( '', match_source_dev( $interface), $source, $ipsec_in_match );
			}

			if ( $notrackref->{referenced} ) {
			    #
			    # There are notrack rules with this zone as the source.
			    # Add a jump from this source network to this zone's notrack chain
			    #
			    add_jump $raw_table->{PREROUTING}, source_exclusion( $exclusions, $notrackref), 0, join( '', match_source_dev( $interface), $source, $ipsec_in_match );
			}
			#
			# If this zone has parents with DNAT/REDIRECT or notrack rules and there are no CONTINUE polcies with this zone as the source
			# then add a RETURN jump for this source network.
			#
			if ( $nested ) {
			    add_rule $preroutingref, join( '', match_source_dev( $interface), $source, $ipsec_in_match, '-j RETURN' )           if $parenthasnat;
			    add_rule $raw_table->{PREROUTING}, join( '', match_source_dev( $interface), $source, $ipsec_in_match, '-j RETURN' ) if $parenthasnotrack;
			}

			my $inputchainref;
			my $interfacematch = '';

			if ( use_input_chain $interface ) {
			    $inputchainref = $filter_table->{input_chain $interface};
			    add_jump $filter_table->{INPUT}, $inputchainref, 0, match_source_dev($interface) unless $input_jump_added{$interface}++;
			} else {
			    $inputchainref = $filter_table->{INPUT};
			    $interfacematch = match_source_dev $interface;
			}

			if ( $chain2 ) {
			    add_jump $inputchainref, source_exclusion( $exclusions, $chain2 ), 0, join( '', $interfacematch, $source, $ipsec_in_match );
			    move_rules( $filter_table->{input_chain $interface} , $filter_table->{$chain2} ) unless use_input_chain $interface;
			}

			if ( $frwd_ref && $hostref->{ipsec} ne 'ipsec' ) {
			    my $ref = source_exclusion( $exclusions, $frwd_ref );
			    if ( use_forward_chain $interface ) {
				my $forwardref = $filter_table->{forward_chain $interface};
				add_jump $forwardref , $ref, 0, join( '', $source, $ipsec_in_match );
				add_jump $filter_table->{FORWARD} , $forwardref, 0 , match_source_dev( $interface ) unless $forward_jump_added{$interface}++;
			    } else {
				add_jump $filter_table->{FORWARD} , $ref, 0, join( '', match_source_dev( $interface ) , $source, $ipsec_in_match );
				move_rules ( $filter_table->{forward_chain $interface} , $frwd_ref );
			    }
			}
		    }
		}
	    }
	}

	#
	#                           F O R W A R D I N G
	#
	my @dest_zones;
	my $last_chain = '';

	if ( $config{OPTIMIZE} > 0 ) {
	    my @temp_zones;

	    for my $zone1 ( @zones )  {
		my $zone1ref = find_zone( $zone1 );
		my $policy = $filter_table->{canonical_chain( ${zone}, ${zone1} )}->{policy};

		next if $policy eq 'NONE';

		my $chain = rules_target $zone, $zone1;

		next unless $chain;

		if ( $zone eq $zone1 ) {
		    next if ( scalar ( keys( %{ $zoneref->{interfaces}} ) ) < 2 ) && ! $zoneref->{options}{in_out}{routeback};
		}

		if ( $zone1ref->{type} == BPORT ) {
		    next unless $zoneref->{bridge} eq $zone1ref->{bridge};
		}

		if ( $chain =~ /(2all|-all)$/ ) {
		    if ( $chain ne $last_chain ) {
			$last_chain = $chain;
			push @dest_zones, @temp_zones;
			@temp_zones = ( $zone1 );
		    } elsif ( $policy eq 'ACCEPT' ) {
			push @temp_zones , $zone1;
		    } else {
			$last_chain = $chain;
			@temp_zones = ( $zone1 );
		    }
		} else {
		    push @dest_zones, @temp_zones, $zone1;
		    @temp_zones = ();
		    $last_chain = '';
		}
	    }

	    if ( $last_chain && @temp_zones == 1 ) {
		push @dest_zones, @temp_zones;
		$last_chain = '';
	    }
	} else {
	    @dest_zones =  @zones ;
	}
	#
	# Here it is -- THE BIG UGLY!!!!!!!!!!!!
	#
	# We now loop through the destination zones creating jumps to the rules chain for each source/dest combination.
	# @dest_zones is the list of destination zones that we need to handle from this source zone
	#
	for my $zone1 ( @dest_zones ) {
	    my $zone1ref = find_zone( $zone1 );

	    next if $filter_table->{canonical_chain( ${zone}, ${zone1} )}->{policy}  eq 'NONE';

	    my $chain = rules_target $zone, $zone1;

	    next unless $chain; # CONTINUE policy with no rules

	    my $num_ifaces = 0;

	    if ( $zone eq $zone1 ) {
		next if ( $num_ifaces = scalar( keys ( %{$zoneref->{interfaces}} ) ) ) < 2 && ! $zoneref->{options}{in_out}{routeback};
	    }

	    if ( $zone1ref->{type} == BPORT ) {
		next unless $zoneref->{bridge} eq $zone1ref->{bridge};
	    }

	    my $chainref = $filter_table->{$chain}; #Will be null if $chain is a Netfilter Built-in target like ACCEPT

	    if ( $frwd_ref ) {
		#
		# Simple case -- the source zone has it's own forwarding chain
		#
		for my $typeref ( values %{$zone1ref->{hosts}} ) {
		    for my $interface ( sort { interface_number( $a ) <=> interface_number( $b ) } keys %$typeref ) {
			for my $hostref ( @{$typeref->{$interface}} ) {
			    next if $hostref->{options}{sourceonly};
			    if ( $zone ne $zone1 || $num_ifaces > 1 || $hostref->{options}{routeback} ) {
				my $ipsec_out_match = match_ipsec_out $zone1 , $hostref;
				for my $net ( @{$hostref->{hosts}} ) {
				    add_jump $frwd_ref, dest_exclusion( $hostref->{exclusions}, $chain), 0, join( '', match_dest_dev( $interface) , match_dest_net($net), $ipsec_out_match );
				}
			    }
			}
		    }
		}
	    } else {
		#
		# More compilcated case. If the interface is associated with a single simple zone, we try to combine the interface's forwarding chain with the rules chain
		#
		for my $typeref ( values %$source_hosts_ref ) {
		    for my $interface ( keys %$typeref ) {
			my $chain3ref;
			my $match_source_dev = '';
			my $forwardchainref = $filter_table->{forward_chain $interface};

			if ( use_forward_chain $interface || ( @{$forwardchainref->{rules} } && ! $chainref ) ) {
			    #
			    # Either we must use the interface's forwarding chain or that chain has rules and we have nowhere to move them
			    #
			    $chain3ref = $forwardchainref;
			    add_jump $filter_table->{FORWARD} , $chain3ref, 0 , match_source_dev( $interface ) unless $forward_jump_added{$interface}++;
			} else {
			    #
			    # Don't use the interface's forward chain -- move any rules in that chain to this rules chain
			    #
			    $chain3ref  = $filter_table->{FORWARD};
			    $match_source_dev = match_source_dev $interface;
			    move_rules $forwardchainref, $chainref;
			}

			for my $hostref ( @{$typeref->{$interface}} ) {
			    next if $hostref->{options}{destonly};
			    my $excl3ref = source_exclusion( $hostref->{exclusions}, $chain3ref );
			    for my $net ( @{$hostref->{hosts}} ) {
				for my $type1ref ( values %{$zone1ref->{hosts}} ) {
				    for my $interface1 ( keys %$type1ref ) {
					my $array1ref = $type1ref->{$interface1};
					for my $host1ref ( @$array1ref ) {
					    next if $host1ref->{options}{sourceonly};
					    my $ipsec_out_match = match_ipsec_out $zone1 , $host1ref;
					    for my $net1 ( @{$host1ref->{hosts}} ) {
						unless ( $interface eq $interface1 && $net eq $net1 && ! $host1ref->{options}{routeback} ) {
						    #
						    # We defer evaluation of the source net match to accomodate systems without $capabilities{KLUDEFREE};
						    #
						    add_jump(
							     $excl3ref ,
							     dest_exclusion( $host1ref->{exclusions}, $chain ),
							     0,
							     join( '',
								   $match_source_dev,
								   match_dest_dev($interface1),
								   match_source_net($net),
								   match_dest_net($net1),
								   $ipsec_out_match )
							    );
						}
					    }
					}
				    }
				}
			    }
			}
		    }
		}
	    }
	}
	#
	#                                      E N D   F O R W A R D I N G
	#
	# Now add an unconditional jump to the last unique policy-only chain determined above, if any
	#
	add_jump $frwd_ref , $last_chain, 1 if $frwd_ref && $last_chain;
    }

    add_interface_jumps @interfaces unless $interface_jumps_added;

    my %builtins = ( mangle => [ qw/PREROUTING INPUT FORWARD POSTROUTING/ ] ,
		     nat=>     [ qw/PREROUTING OUTPUT POSTROUTING/ ] ,
		     filter=>  [ qw/INPUT FORWARD OUTPUT/ ] );

    complete_standard_chain $filter_table->{INPUT}   , 'all' , firewall_zone , 'DROP';
    complete_standard_chain $filter_table->{OUTPUT}  , firewall_zone , 'all', 'REJECT';
    complete_standard_chain $filter_table->{FORWARD} , 'all' , 'all', 'REJECT';

    if ( $config{LOGALLNEW} ) {
	for my $table qw/mangle nat filter/ {
	    for my $chain ( @{$builtins{$table}} ) {
		log_rule_limit
		    $config{LOGALLNEW} ,
		    $chain_table{$table}{$chain} ,
		    $table ,
		    $chain ,
		    '' ,
		    '' ,
		    'insert' ,
		    '-m state --state NEW ';
	    }
	}
    }
}

sub setup_mss( ) {
    my $clampmss = $config{CLAMPMSS};
    my $option;
    my $match = '';
    my $chainref = $filter_table->{FORWARD};

    if ( $clampmss ) {
	if ( "\L$clampmss" eq 'yes' ) {
	    $option = '--clamp-mss-to-pmtu';
	} else {
	    $match  = "-m tcpmss --mss $clampmss: " if $capabilities{TCPMSS_MATCH};
	    $option = "--set-mss $clampmss";
	}

	$match .= '-m policy --pol none --dir out ' if $capabilities{POLICY_MATCH};
    }

    my $interfaces = find_interfaces_by_option( 'mss' );

    if ( @$interfaces ) {
	#
	# Since we will need multiple rules, we create a separate chain
	#
	$chainref = new_chain 'filter', 'settcpmss';
	#
	# Send all forwarded SYN packets to the 'settcpmss' chain
	#
	add_rule $filter_table->{FORWARD} ,  "-p tcp --tcp-flags SYN,RST SYN -j settcpmss";

	my $in_match  = '';
	my $out_match = '';

	if ( $capabilities{POLICY_MATCH} ) {
	    $in_match  = '-m policy --pol none --dir in ';
	    $out_match = '-m policy --pol none --dir out ';
	}

	for ( @$interfaces ) {
	    my $mss      = get_interface_option( $_, 'mss' );
	    my $mssmatch = $capabilities{TCPMSS_MATCH} ? "-m tcpmss --mss $mss: " : '';
	    my $source   = match_source_dev $_;
	    my $dest     = match_dest_dev $_;
	    add_rule $chainref, "${dest}-p tcp --tcp-flags SYN,RST SYN ${mssmatch}${out_match}-j TCPMSS --set-mss $mss";
	    add_rule $chainref, "${dest}-j RETURN" if $clampmss;
	    add_rule $chainref, "${source}-p tcp --tcp-flags SYN,RST SYN ${mssmatch}${in_match}-j TCPMSS --set-mss $mss";
	    add_rule $chainref, "${source}-j RETURN" if $clampmss;
	}
    }

    add_rule $chainref , "-p tcp --tcp-flags SYN,RST SYN ${match}-j TCPMSS $option" if $clampmss;
}

#
# Compile the stop_firewall() function
#
sub compile_stop_firewall( $ ) {
    my $test = shift;

    my $input   = $filter_table->{INPUT};
    my $output  = $filter_table->{OUTPUT};
    my $forward = $filter_table->{FORWARD};

    emit <<'EOF';
#
# Stop/restore the firewall after an error or because of a 'stop' or 'clear' command
#
stop_firewall() {
EOF

    $output->{policy} = 'ACCEPT' if $config{ADMINISABSENTMINDED};

    if ( $family == F_IPV4 ) {
	emit( '    deletechain() {',
	      '        qt $IPTABLES -L $1 -n && qt $IPTABLES -F $1 && qt $IPTABLES -X $1' );
    } else {
	emit( '    deletechain() {',
	      '         qt $IP6TABLES -L $1 -n && qt $IP6TABLES -F $1 && qt $IP6TABLES -X $1' );
    }

    emit <<'EOF';
    }

    case $COMMAND in
	stop|clear|restore)
	    ;;
	*)
	    set +x

            case $COMMAND in
	        start)
	            logger -p kern.err "ERROR:$PRODUCT start failed"
	            ;;
	        restart)
	            logger -p kern.err "ERROR:$PRODUCT restart failed"
	            ;;
	        restore)
	            logger -p kern.err "ERROR:$PRODUCT restore failed"
	            ;;
            esac

            if [ "$RESTOREFILE" = NONE ]; then
                COMMAND=clear
                clear_firewall
                echo "$PRODUCT Cleared"

	        kill $$
	        exit 2
            else
	        RESTOREPATH=${VARDIR}/$RESTOREFILE

	        if [ -x $RESTOREPATH ]; then
		    echo Restoring ${PRODUCT:=Shorewall}...

		    if $RESTOREPATH restore; then
		        echo "$PRODUCT restored from $RESTOREPATH"
		        set_state "Started"
		    else
		        set_state "Unknown"
		    fi

	            kill $$
	            exit 2
	        fi
            fi
	    ;;
    esac

    set_state "Stopping"

    STOPPING="Yes"

    TERMINATOR=

    deletechain shorewall

    run_stop_exit
EOF

    if ( $capabilities{NAT_ENABLED} ) {
	emit<<'EOF';
    if [ -f ${VARDIR}/nat ]; then
        while read external interface; do
      	    del_ip_addr $external $interface
	done < ${VARDIR}/nat

	rm -f ${VARDIR}/nat
    fi
EOF
    }

    if ( $family == F_IPV4 ) {
	emit <<'EOF';
    if [ -f ${VARDIR}/proxyarp ]; then
	while read address interface external haveroute; do
	    qt arp -i $external -d $address pub
	    [ -z "${haveroute}${NOROUTES}" ] && qt $IP -4 route del $address dev $interface
	    f=/proc/sys/net/ipv4/conf/$interface/proxy_arp
	    [ -f $f ] && echo 0 > $f
	done < ${VARDIR}/proxyarp

         rm -f ${VARDIR}/proxyarp
    fi

EOF
    }

    push_indent;

    emit 'delete_tc1' if $config{CLEAR_TC};

    emit( 'undo_routing',
	  'restore_default_route'
	  );

    my @chains = $config{ADMINISABSENTMINDED} ? qw/INPUT FORWARD/ : qw/INPUT OUTPUT FORWARD/;

    add_rule $filter_table->{$_}, '-m state --state ESTABLISHED,RELATED -j ACCEPT' for @chains;

    if ( $family == F_IPV6 ) {
	add_rule $input, '-s ff80::/10 -j ACCEPT';
	add_rule $input, '-d ff80::/10 -j ACCEPT';
	add_rule $input, '-d ff00::/10 -j ACCEPT';

	unless ( $config{ADMINISABSENTMINDED} ) {
	    add_rule $output, '-d ff80::/10 -j ACCEPT';
	    add_rule $output, '-d ff00::/10 -j ACCEPT';
	}
    }

    process_routestopped;

    add_rule $input, '-i lo -j ACCEPT';
    add_rule $input, '-i lo -j ACCEPT';

    add_rule $output, '-o lo -j ACCEPT' unless $config{ADMINISABSENTMINDED};

    my $interfaces = find_interfaces_by_option 'dhcp';

    if ( @$interfaces ) {
	my $ports = $family == F_IPV4 ? '67:68' : '546:547';

	for my $interface ( @$interfaces ) {
	    add_rule $input,  "-p udp " . match_source_dev( $interface ) . "--dport $ports -j ACCEPT";
	    add_rule $output, "-p udp " . match_dest_dev( $interface )   . "--dport $ports -j ACCEPT" unless $config{ADMINISABSENTMINDED};
	    #
	    # This might be a bridge
	    #
	    add_rule $forward, "-p udp " . match_source_dev( $interface ) . match_dest_dev( $interface ) . "--dport $ports -j ACCEPT";
	}
    }

    emit '';

    create_stop_load $test;

    if ( $family == F_IPV4 ) {
	if ( $config{IP_FORWARDING} eq 'on' ) {
	    emit( 'echo 1 > /proc/sys/net/ipv4/ip_forward',
		  'progress_message2 IPv4 Forwarding Enabled' );
	} elsif ( $config{IP_FORWARDING} eq 'off' ) {
	    emit( 'echo 0 > /proc/sys/net/ipv4/ip_forward',
		  'progress_message2 IPv4 Forwarding Disabled!'
		);
	}
    } else {
	for my $interface ( all_bridges ) {
	    emit "do_iptables -A FORWARD -p 58 " . match_source_interface( $interface ) . match_dest_interface( $interface ) . "-j ACCEPT";
	}

	if ( $config{IP_FORWARDING} eq 'on' ) {
	    emit( 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding',
		  'progress_message2 IPv6 Forwarding Enabled' );
	} elsif ( $config{IP_FORWARDING} eq 'off' ) {
	    emit( 'echo 0 > /proc/sys/net/ipv6/conf/all/forwarding',
		  'progress_message2 IPv6 Forwarding Disabled!'
		);
	}
    }

    pop_indent;

    emit '
    run_stopped_exit';

    my @ipsets = all_ipsets;

    if ( @ipsets ) {
	emit <<'EOF';

    if [ -n "$(mywhich ipset)" ]; then
        if $IPSET -S > ${VARDIR}/ipsets.tmp; then
            #
            # Don't save an 'empty' file
            #
            grep -q '^-N' ${VARDIR}/ipsets.tmp && mv -f ${VARDIR}/ipsets.tmp ${VARDIR}/ipsets.save
	fi
    fi
EOF
    }

    emit '
    set_state "Stopped"

    logger -p kern.info "$PRODUCT Stopped"

    case $COMMAND in
    stop|clear)
	;;
    *)
	#
	# The firewall is being stopped when we were trying to do something
	# else. Kill the shell in case we\'re running in a subshell
	#
	kill $$
	;;
    esac
}
';

}

1;
