#
# Shorewall-perl 3.9 -- /usr/share/shorewall-perl/Shorewall/Rules.pm
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
#   This module contains the high-level code for dealing with rules.
#
package Shorewall::Rules;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Interfaces;
use Shorewall::Chains;
use Shorewall::Hosts;
use Shorewall::Actions;
use Shorewall::Macros;
use Shorewall::Policy;
use Shorewall::Proc;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( process_tos
		  setup_ecn
		  add_common_rules
		  setup_mac_lists
		  process_criticalhosts
		  process_routestopped
		  process_rules
		  generate_matrix
		  setup_mss
		  dump_rule_chains
		  );
our @EXPORT_OK = qw( process_rule process_rule1 );
our @VERSION = 1.00;

#
# Keep track of chains for the /var/lib/shorewall[-lite]/chains file
#
my @rule_chains;
#
# Set to one if we find a SECTION
#
my $sectioned = 0;

sub process_tos() {
    my $chain    = $capabilities{MANGLE_FORWARD} ? 'fortos'  : 'pretos';
    my $stdchain = $capabilities{MANGLE_FORWARD} ? 'FORWARD' : 'PREROUTING';

    if ( my $fn = open_file 'tos' ) {
	my $first_entry = 1;

	my ( $pretosref, $outtosref );

	while ( read_a_line ) {

	    my ($src, $dst, $proto, $sports, $ports , $tos ) = split_line 6, 6, 'tos file';

	    if ( $first_entry ) {
		progress_message2 "$doing $fn...";
		$pretosref = ensure_chain 'mangle' , $chain;
		$outtosref = ensure_chain 'mangle' , 'outtos';
		$first_entry = 0;
	    }

	    fatal_error "TOS field required" unless $tos ne '-';

	    my $chainref;

	    my $restriction = NO_RESTRICT;

	    my ( $srczone , $source ) = split /:/, $src;

	    if ( $srczone eq $firewall_zone ) {
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
		do_proto( $proto, $ports, $sports ) ,
		$src ,
		$dst ,
		'' ,
		"-j TOS --set-tos $tos" ,
		'' ,
		'' ,
		'';
	}

	unless ( $first_entry ) {
	    add_rule $mangle_table->{$stdchain}, "-j $chain";
	    add_rule $mangle_table->{OUTPUT},    "-j outtos";
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

	my $first_entry = 1;

	while ( read_a_line ) {

	    my ($interface, $hosts ) = split_line 1, 2, 'ecn file';

	    if ( $first_entry ) {
		progress_message2 "$doing $fn...";
		$first_entry = 0;
	    }

	    fatal_error "Unknown interface ( $interface )" unless known_interface $interface;

	    $interfaces{$interface} = 1;

	    $hosts = ALLIPv4 if $hosts eq '-';

	    for my $host( split /,/, $hosts ) {
		push @hosts, [ $interface, $host ];
	    }
	}

	if ( @hosts ) {
	    my @interfaces = ( keys %interfaces );

	    progress_message "$doing ECN control on @interfaces...";

	    for my $interface ( @interfaces ) {
		my $chainref = ensure_chain 'mangle', ecn_chain( $interface );

		if ( $capabilities{MANGLE_FORWARD} ) {
		    add_rule $mangle_table->{POSTROUTING}, "-p tcp -o $interface -j $chainref->{name}";
		} else {
		    add_rule $mangle_table->{PREROUTING}, "-p tcp -o $interface -j $chainref->{name}";
		    add_rule $mangle_table->{OUTPUT},     "-p tcp -o $interface -j $chainref->{name}";
		}
	    }

	    for my $host ( @hosts ) {
		add_rule $mangle_table->{ecn_chain $host->[0]}, join ('', '-p tcp ', match_dest_net( $host->[1] ) , ' -j ECN --ecn-tcp-remove' );
	    }
	}
    }
}

sub add_rule_pair( $$$$ ) {
    my ($chainref , $predicate , $target , $level ) = @_;

    log_rule $level, $chainref, $target,  , $predicate,  if defined $level && $level ne '';
    add_rule $chainref , "${predicate}-j $target";
}

sub setup_rfc1918_filteration( $ ) {

    my $listref      = $_[0];
    my $norfc1918ref = new_standard_chain 'norfc1918';
    my $rfc1918ref   = new_standard_chain 'rfc1918';
    my $chainref     = $norfc1918ref;

    log_rule $config{RFC1918_LOG_LEVEL} , $rfc1918ref , 'DROP' , '';

    add_rule $rfc1918ref , '-j DROP';

    $chainref = new_standard_chain 'rfc1918d' if $config{RFC1918_STRICT};

    my $fn = open_file 'rfc1918';

    my $first_entry = 1;

    while ( read_a_line ) {

	my ( $networks, $target ) = split_line 2, 2, 'rfc1918 file';

	my $s_target;

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	if ( $target eq 'logdrop' ) {
	    $target   = 'rfc1918';
	    $s_target = 'rfc1918';
	} elsif ( $target eq 'DROP' ) {
	    $s_target = 'DROP';
	} elsif ( $target eq 'RETURN' ) {
	    $s_target = $config{RFC1918_STRICT} ? 'rfc1918d' : 'RETURN';
	} else {
	    fatal_error "Invalid target ($target) for $networks";
	}

	for my $network ( split /,/, $networks ) {
	    add_rule $norfc1918ref , match_source_net( $network ) . "-j $s_target";
	    add_rule $chainref , match_orig_dest( $network ) . "-j $target" ;
	}
    }

    add_rule $norfc1918ref , '-j rfc1918d' if $config{RFC1918_STRICT};

    for my $hostref  ( @$listref ) {
	my $interface = $hostref->[0];
	my $ipsec     = $hostref->[1];
	my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in "  : '';
	for my $chain ( @{first_chains $interface}) {
	    add_rule $filter_table->{$chain} , join( '', '-m state --state NEW ', match_source_net( $hostref->[2]) , "${policy}-j norfc1918" );
	}
    }
}

sub setup_syn_flood_chains() {
    for my $chainref ( @policy_chains ) {
	my $limit = $chainref->{synparams};
	if ( $limit ) {
	    my $level = $chainref->{loglevel};
	    ( $limit, my $burst ) = split ':', $limit;
	    $burst = $burst ? "--limit-burst $burst " : '';
	    my $synchainref = new_chain 'filter' , syn_chain $chainref->{name};
	    add_rule $synchainref , "-m limit --limit $limit ${burst}-j RETURN";
	    log_rule_limit $level , $synchainref , $chainref->{name} , 'DROP', '-m limit --limit 5/min --limit-burst 5' , '' , 'add' , ''
		if $level ne '';
	    add_rule $synchainref, '-j DROP';
	}
    }
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

	    while ( read_a_line ) {

		my ( $networks, $protocol, $ports ) = split_line 1, 3, 'blacklist file';

		if ( $first_entry ) {
		    unless  ( @$hosts ) {
			warning_message "The entries in $fn have been ignored because there are no 'blacklist' interfaces";
			close_file;
			last BLACKLIST;
		    }

		    progress_message2 "$doing $fn...";
		    $first_entry = 0;
		}

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

		progress_message "         \"$line\" added to blacklist";
	    }
	}

	my $state = $config{BLACKLISTNEWONLY} ? '-m state --state NEW,INVALID ' : '';

	for my $hostref ( @$hosts ) {
	    my $interface = $hostref->[0];
	    my $ipsec     = $hostref->[1];
	    my $policy    = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    my $network   = $hostref->[2];
	    my $source    = match_source_net $network;

	    for my $chain ( @{first_chains $interface}) {
		add_rule $filter_table->{$chain} , "${source}${state}${policy}-j blacklst";
	    }

	    progress_message "   Blacklisting enabled on ${interface}:${network}";
	}
    }
}

sub process_criticalhosts() {

    my  @critical = ();

    my $fn = open_file 'routestopped';

    my $first_entry = 1;

    while ( read_a_line ) {

	my $routeback = 0;

	my ($interface, $hosts, $options ) = split_line 1, 3, 'routestopped file';

	if ( $first_entry ) {
	    progress_message2 "$doing $fn for critical hosts...";
	    $first_entry = 0;
	}

	$hosts = ALLIPv4 unless $hosts ne '-';

	my @hosts;

	for my $host ( split /,/, $hosts ) {
	    push @hosts, "$interface:$hosts";
	}

	unless ( $options eq '-' ) {
	    for my $option (split /,/, $options ) {
		unless ( $option eq 'routeback' || $option eq 'source' || $option eq 'dest' ) {
		    if ( $option eq 'critical' ) {
			push @critical, @hosts;
		    } else {
			warning_message "Unknown routestopped option ( $option ) ignored";
		    }
		}
	    }
	}
    }

    \@critical;
}

sub process_routestopped() {

    my ( @allhosts, %source, %dest );

    my $fn = open_file 'routestopped';

    my $first_entry = 1;

    while ( read_a_line ) {

	my $routeback = 0;

	my ($interface, $hosts, $options ) = split_line 1, 3, 'routestopped file';

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	$hosts = ALLIPv4 unless $hosts && $hosts ne '-';

	my @hosts;

	for my $host ( split /,/, $hosts ) {
	    push @hosts, "$interface:$hosts";
	}

	unless ( $options eq '-' ) {
	    for my $option (split /,/, $options ) {
		if ( $option eq 'routeback' ) {
		    if ( $routeback ) {
			warning_message "Duplicate 'routeback' option ignored";
		    } else {
			$routeback = 1;

			for my $host ( split /,/, $hosts ) {
			    my $source = match_source_net $host;
			    my $dest   = match_dest_net   $host;

			    emit "run_iptables -A FORWARD -i $interface -o $interface $source $dest -j ACCEPT";
			    clearrule;
			}
		    }
		} elsif ( $option eq 'source' ) {
		    for my $host ( split /,/, $hosts ) {
			$source{"$interface:$host"} = 1;
		    }
		} elsif ( $option eq 'dest' ) {
		    for my $host ( split /,/, $hosts ) {
			$dest{"$interface:$host"} = 1;
		    }
		} else {
		    warning_message "Unknown routestopped option ( $option ) ignored" unless $option eq 'critical';
		}
	    }
	}

	push @allhosts, @hosts;
    }

    for my $host ( @allhosts ) {
	my ( $interface, $h ) = split /:/, $host;
	my $source  = match_source_net $h;
	my $dest    = match_dest_net $h;

	emit "\$IPTABLES -A INPUT -i $interface $source -j ACCEPT";
	emit "\$IPTABLES -A OUTPUT -o $interface $dest -j ACCEPT"    if $config{ADMINISABSENTMINDED};

	my $matched = 0;

	if ( $source{$host} ) {
	    emit "\$IPTABLES -A FORWARD -i $interface $source -j ACCEPT";
	    $matched = 1;
	}

	if ( $dest{$host} ) {
	    emit "\$IPTABLES -A FORWARD -o $interface $dest -j ACCEPT";
	    $matched = 1;
	}

	unless ( $matched ) {
	    for my $host1 ( @allhosts ) {
		unless ( $host eq $host1 ) {
		    my ( $interface1, $h1 ) = split /:/, $host1;
		    my $dest1 = match_dest_net $h1;
		    emit "\$IPTABLES -A FORWARD -i $interface -o $interface1 $source $dest1 -j ACCEPT";
		    clearrule;
		}
	    }
	}
    }
}

sub add_common_rules() {
    my $interface;
    my $chainref;
    my $level;
    my $target;
    my $rule;
    my $list;
    my $chain;

    my $rejectref = new_standard_chain 'reject';

    $level = $config{BLACKLIST_LOGLEVEL};

    add_rule_pair new_standard_chain( 'logdrop' ),   ' ' , 'DROP'   , $level ;
    add_rule_pair new_standard_chain( 'logreject' ), ' ' , 'REJECT' , $level ;

    new_standard_chain 'dynamic';

    my $state = $config{BLACKLISTNEWONLY} ? '-m state --state NEW,INVALID ' : '';

    for $interface ( @interfaces ) {
	for $chain ( input_chain $interface , forward_chain $interface ) {
	    add_rule new_standard_chain( $chain ) , "$state -j dynamic";
	}

	new_standard_chain output_chain( $interface );
    }
    
    setup_blacklist;

    $list = find_hosts_by_option 'nosmurfs';

    $chainref = new_standard_chain 'smurfs';

    add_rule $chainref , '-s 0.0.0.0 -j RETURN';

    add_rule_pair $chainref, '-m addrtype --src-type BROADCAST ', 'DROP', $config{SMURF_LOG_LEVEL} ;
    add_rule_pair $chainref, '-m addrtype --src-type MULTICAST ', 'DROP', $config{SMURF_LOG_LEVEL} ;
    
    add_rule $rejectref , '-m addrtype --src-type BROADCAST -j DROP';
    add_rule $rejectref , '-m addrtype --src-type MULTICAST -j DROP';

    if ( @$list ) {
	progress_message2 'Adding Anti-smurf Rules';
	for my $hostref  ( @$list ) {
	    $interface = $hostref->[0];
	    my $ipsec  = $hostref->[1];
	    my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    for $chain ( @{first_chains $interface}) {
		add_rule $filter_table->{$chain} , join( '', '-m state --state NEW,INVALID ', match_source_net( $hostref->[2] ),  "${policy}-j smurfs" );
	    }
	}
    }

    add_rule $rejectref , '-p tcp -j REJECT --reject-with tcp-reset';

    if ( $capabilities{ENHANCED_REJECT} ) {
	add_rule $rejectref , '-p udp -j REJECT';
	add_rule $rejectref, '-p icmp -j REJECT --reject-with icmp-host-unreachable';
	add_rule $rejectref, '-j REJECT --reject-with icmp-host-prohibited';
    } else {
	add_rule $rejectref , '-j REJECT';
    }

    $list = find_interfaces_by_option 'dhcp';

    if ( @$list ) {
	progress_message2 'Adding rules for DHCP';

	for $interface ( @$list ) {
	    for $chain ( @{first_chains $interface}) {
		add_rule $filter_table->{$chain} , '-p udp --dport 67:68 -j ACCEPT';
	    }

	    add_rule $filter_table->{forward_chain $interface} , "-p udp -o $interface --dport 67:68 -j ACCEPT" if $interfaces{$interface}{options}{routeback};
	}
    }

    $list = find_hosts_by_option 'norfc1918';

    setup_rfc1918_filteration $list if @$list;

    $list = find_hosts_by_option 'tcpflags';

    if ( @$list ) {
	my $disposition;

	progress_message2 "$doing TCP Flags filtering...";

	$chainref = new_standard_chain 'tcpflags';

	if ( $config{TCP_FLAGS_LOG_LEVEL} ne ''  ) {
	    my $logflagsref = new_standard_chain 'logflags';

	    my $savelogparms = $globals{LOGPARMS};

	    $globals{LOGPARMS} = "$globals{LOGPARMS} --log-ip-options" unless $config{TCP_FLAGS_LOG_LEVEL} eq 'ULOG';

	    log_rule $config{TCP_FLAGS_LOG_LEVEL} , $logflagsref , $config{TCP_FLAGS_DISPOSITION}, '';

	    $globals{LOGPARMS} = $savelogparms;

	    if ( $config{TCP_FLAGS_DISPOSITION} eq 'REJECT' ) {
		add_rule $logflagsref , '-j REJECT --reject-with tcp-reset';
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
	    $interface = $hostref->[0];
	    my $ipsec  = $hostref->[1];
	    my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    for $chain ( @{first_chains $interface}) {
		add_rule $filter_table->{$chain} , join( '', '-p tcp ', match_source_net( $hostref->[2]), "${policy}-j tcpflags" );
	    }
	}
    }

    if ( $config{DYNAMIC_ZONES} ) {
	for $interface ( @interfaces) {
	    for $chain ( @{dynamic_chains $interface} ) {
		new_standard_chain $chain;
	    }

	    (new_chain 'nat' , $chain = dynamic_in($interface) )->{referenced} = 1;

	    add_rule $filter_table->{input_chain $interface},  "-j $chain";
	    add_rule $filter_table->{forward_chain $interface}, '-j ' . dynamic_fwd $interface;
	    add_rule $filter_table->{output_chain $interface},  '-j ' . dynamic_out $interface;
	}	
    }

    $list = find_interfaces_by_option 'upnp';

    if ( @$list ) {
	progress_message2 '$doing UPnP';

	(new_chain 'nat', 'UPnP')->{referenced} = 1;

	for $interface ( @$list ) {
	    add_rule $nat_table->{PREROUTING} , "-i $interface -j UPnP";
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
    
    for my $hostref ( @$maclist_hosts ) {
	$maclist_interfaces{ $hostref->[0] } = 1;
    }

    my @maclist_interfaces = ( sort keys %maclist_interfaces );

    progress_message "   $doing MAC Verification for @maclist_interfaces -- Phase $phase...";

    if ( $phase == 1 ) {

	for my $interface ( @maclist_interfaces ) {
	    my $chainref = new_chain $table , mac_chain $interface;

	    add_rule $chainref , '-s 0.0.0.0 -d 255.255.255.255 -p udp --dport 67:68 -j RETURN'
		if ( $table eq 'mangle' ) && $interfaces{$interface}{options}{dhcp};

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

	my $first_entry = 1;

	while ( read_a_line ) {

	    my ( $disposition, $interface, $mac, $addresses  ) = split_line 3, 4, 'maclist file';

	    if ( $first_entry ) {
		progress_message2 "$doing $fn...";
		$first_entry = 0;
	    }

	    if ( $disposition eq 'COMMENT' ) {
		if ( $capabilities{COMMENTS} ) {
		    ( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		    $comment =~ s/\s*$//;
		} else {
		    warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
		}
	    } else {
		( $disposition, my $level ) = split /:/, $disposition;

		my $targetref = $maclist_targets{$disposition};

		fatal_error "Invalid DISPOSITION ( $disposition)" if ( $table eq 'mangle' ) && ! $targetref->{mangle};

		fatal_error "No hosts on $interface have the maclist option specified" unless $maclist_interfaces{$interface};

		my $chainref = $chain_table{$table}{( $ttl ? macrecent_target $interface : mac_chain $interface )};

		$mac       = '' unless $mac && ( $mac ne '-' );
		$addresses = '' unless $addresses && ( $addresses ne '-' );

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

		progress_message "      Maclist entry \"$line\" $done";
	    }
	}

	$comment = '';
	#
	# Generate jumps from the input and forward chains
	#
	for my $hostref ( @$maclist_hosts ) {
	    my $interface = $hostref->[0];
	    my $ipsec  = $hostref->[1];
	    my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    my $source = match_source_net $hostref->[2];
	    my $target = mac_chain $interface;
	    if ( $table eq 'filter' ) {
		for my $chain ( @{first_chains $interface}) {
		    add_rule $filter_table->{$chain} , "${source}-m state --state NEW ${policy}-j $target";
		}
	    } else {
		add_rule $mangle_table->{PREROUTING}, "-i $interface ${source}-m state --state NEW ${policy}-j $target";
	    }
	}
    } else {
	for my $interface ( @maclist_interfaces ) {
	    my $chainref = $chain_table{$table}{( $ttl ? macrecent_target $interface : mac_chain $interface )};
	    my $chain    = $chainref->{name};

	    if ( $level ne '' || $disposition ne 'ACCEPT' ) {
		my $variable = get_interface_addresses $interface;
		add_command $chainref, "for address in $variable; do";
		add_command $chainref, "    echo \"-A $chainref->{name} -s \$address -m addrtype --dst-type BROADCAST -j RETURN\" >&3";
		add_command $chainref, "    echo \"-A $chainref->{name} -s \$address -m addrtype --dst-type MULTICAST -j RETURN\" >&3";
		add_command $chainref, 'done';
	    }

	    add_file $chainref, 'maclog';

	    log_rule_limit $level, $chainref , $chain , $disposition, '', '', 'add', '' if $level ne '';
	    add_rule $chainref, "-j $target";
	}
    }
}

sub process_rule1 ( $$$$$$$$$ );

#
# Expand a macro rule from the rules file
#
sub process_macro ( $$$$$$$$$$$ ) {
    my ($macrofile, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user) = @_;

    my $standard = ( $macrofile =~ /^($globals{SHAREDIR})/ );

    progress_message "..Expanding Macro $macrofile...";

    push_open $macrofile;

    while ( read_a_line ) {

	my ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split_line 1, 8, 'macro file';

	$mtarget = merge_levels $target, $mtarget;

	if ( $mtarget =~ /^PARAM:?/ ) {
	    fatal_error 'PARAM requires that a parameter be supplied in macro invocation' unless $param;
	    $mtarget = substitute_action $param,  $mtarget;
	}

	my $action     = isolate_basic_target $mtarget;
	my $actiontype = $targets{$action} || 0;

	if ( $actiontype & ACTION ) {
	    unless ( $usedactions{$action} ) {
		createactionchain $mtarget;
		$usedactions{$mtarget} = 1;
	    }

	    $mtarget = find_logactionchain $mtarget;
	} else {
	    fatal_error "Invalid Action ($mtarget)"  unless $actiontype & STANDARD;
	}

	if ( $msource ) {
	    if ( ( $msource eq '-' ) || ( $msource eq 'SOURCE' ) ) {
		$msource = $source || '';
	    } elsif ( $msource eq 'DEST' ) {
		$msource = $dest || '';
	    } else {
		$msource = merge_macro_source_dest $msource, $source;
	    }
	} else {
	    $msource = '';
	}

	$msource = '' if $msource eq '-';

	if ( $mdest ) {
	    if ( ( $mdest eq '-' ) || ( $mdest eq 'DEST' ) ) {
		$mdest = $dest || '';
	    } elsif ( $mdest eq 'SOURCE' ) {
		$mdest = $source || '';
	    } else {
		$mdest = merge_macro_source_dest $mdest, $dest;
	    }
	} else {
	    $mdest = '';
	}

	$mdest   = '' if $mdest   eq '-';

	$mproto  = merge_macro_column $mproto,  $proto;
	$mports  = merge_macro_column $mports,  $ports;
	$msports = merge_macro_column $msports, $sports;
	$mrate   = merge_macro_column $mrate,   $rate;
	$muser   = merge_macro_column $muser,   $user;

	process_rule1 $mtarget, $msource, $mdest, $mproto, $mports, $msports, $origdest, $rate, $user;

	progress_message "   Rule \"$line\" $done";
    }

    pop_open;

    progress_message '..End Macro'
}

#
# Once a rule has been completely resolved by macro expansion and wildcard (source and/or dest zone == 'all'), it is processed by this function.
#
sub process_rule1 ( $$$$$$$$$ ) {
    my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user ) = @_;
    my ( $action, $loglevel) = split_action $target;
    my ( $basictarget, $param ) = split '/', $action;
    my $rule = '';
    my $actionchainref;

    #
    # Determine the validity of the action
    #
    my $actiontype = $targets{$basictarget} || find_macro( $basictarget );

    fatal_error "Unknown action ($action)" unless $actiontype;

    if ( $actiontype == MACRO ) {
	#
	# We will be called recursively for each rule in the macro body
	#
	process_macro
	    $macros{$basictarget},
	    $target ,
	    $param ,
	    $source,
	    $dest,
	    $proto,
	    $ports,
	    $sports,
	    $origdest,
	    $ratelimit,
	    $user;
	return;
    }
    #
    # We can now dispense with the postfix characters
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
    if ( $actiontype & REDIRECT ) {
	if ( $dest eq '-' ) {
	    $dest = "$firewall_zone";
	} else {
	    $dest = join( '', $firewall_zone, '::', $dest );
	}
    } elsif ( $action eq 'REJECT' ) {
	$action = 'reject';
    } elsif ( $action eq 'CONTINUE' ) {
	$action = 'RETURN';
    }
    #
    # Isolate and validate source and destination zones
    #
    my $sourcezone;
    my $destzone;

    if ( $source =~ /^(.+?):(.*)/ ) {
	$sourcezone = $1;
	$source = $2;
    } else {
	$sourcezone = $source;
	$source = ALLIPv4;
    }

    if ( $dest =~ /^(.+?):(.*)/ ) {
	$destzone = $1;
	$dest = $2;
    } else {
	$destzone = $dest;
	$dest = ALLIPv4;
    }

    fatal_error "Unknown source zone ($sourcezone)"    unless $zones{$sourcezone};
    fatal_error "Unknown destination zone ($destzone)" unless $zones{$destzone};

    my $restriction = NO_RESTRICT;

    if ( $sourcezone eq $firewall_zone ) {
	$restriction = $destzone eq $firewall_zone ? ALL_RESTRICT : OUTPUT_RESTRICT;
    } else {
	$restriction = INPUT_RESTRICT if $destzone eq $firewall_zone;
    }
    #
    # Take care of chain
    #
    my $chain    = "${sourcezone}2${destzone}";
    my $chainref = ensure_filter_chain $chain, 1;
    #
    # Validate Policy
    #
    my $policy   = $chainref->{policy};
    fatal_error "No policy defined from zone $sourcezone to zone $destzone" unless $policy;
    fatal_error "Rules may not override a NONE policy"                      if $policy eq 'NONE';
    #
    # Generate Fixed part of the rule
    #
    $rule = join( '', do_proto($proto, $ports, $sports), do_ratelimit( $ratelimit ) , do_user( $user ) );

    #
    # Generate NAT rule(s), if any
    #
    if ( $actiontype & NATRULE ) {
	my ( $server, $serverport , $natchain );
	fatal_error "$target rules not allowed in the $section SECTION"  if $section ne 'NEW';
	require_capability( 'NAT_ENABLED' , "$basictarget rules" );
	#
	# Isolate server port
	#
	if ( $dest =~ /^(.*)(:(\d+))$/ ) {
	    $server = $1;
	    $serverport = $3;
	} else {
	    $server = $dest;
	    $serverport = '';
	}
	#
	# After DNAT, dest port will be the server port
	#
	$ports = $serverport if $serverport;

	fatal_error "A server must be specified in the DEST column in $action rules" unless ( $actiontype & REDIRECT ) || $server;
	fatal_error "Invalid server ($server)" if $server =~ /:/;
	#
	# Generate the target
	#
	my $target = '';

	if ( $actiontype  & REDIRECT ) {
	    $target = '-j REDIRECT --to-port ' . ( $serverport ? $serverport : $ports );
	} else {
	    if ( $action eq 'SAME' ) {
		fatal_error 'Port mapping not allowed in SAME rules' if $serverport;
		fatal_error 'SAME not allowed with SOURCE=$FW'       if $sourcezone eq $firewall_zone;
		$target = '-j SAME ';
		for my $serv ( split /,/, $server ) {
		    $target .= "--to $serv ";
		}

		$serverport = $ports;
	    } elsif ( $action eq 'DNAT' ) {
		$target = '-j DNAT ';
		$serverport = ":$serverport" if $serverport;
		for my $serv ( split /,/, $server ) {
		    $target .= "--to-destination ${serv}${serverport} ";
		}
	    }

	    unless ( $origdest && $origdest ne '-' && $origdest ne 'detect' ) {
		if ( $config{DETECT_DNAT_IPADDRS} ) {
		    my $interfacesref = $zones{$sourcezone}{interfaces};
		    my @interfaces = keys %$interfacesref;
		    $origdest = @interfaces ? "detect:@interfaces" : ALLIPv4;
		} else {
		    $origdest = ALLIPv4;
		}
	    }
	}
	#
	# And generate the nat table rule(s)
	#
	expand_rule
	    ensure_chain ('nat' , $zones{$sourcezone}{type} eq 'firewall' ? 'OUTPUT' : dnat_chain $sourcezone ),
	    PREROUTE_RESTRICT ,
	    $rule ,
	    $source ,
	    $origdest ,
	    '' ,
	    $target ,
	    $loglevel ,
	    $action ,
	    $serverport ? do_proto( $proto, '', '' ) : '';
	#
	# After NAT:
	#   - the destination port will be the server port
	#   - the destination IP   will be the server IP
	#   - there will be no log level (we log NAT rules in the nat table rather than in the filter table).
	#
	unless ( $actiontype & NATONLY ) {
	    $rule = join( '', do_proto( $proto, $ports, $sports ), do_ratelimit( $ratelimit ), do_user $user );
	    $loglevel = '';
	    $dest     = $server;
	    $action   = 'ACCEPT';
	}
    } else {
	if ( $actiontype & NONAT ) {
	    #
	    # NONAT or ACCEPT+ -- May not specify a destination interface
	    #
	    fatal_error "Invalid DEST ($dest) in $action rule" if $dest =~ /:/;

	    $origdest = '' unless $origdest and $origdest ne '-';

	    if ( $origdest eq 'detect' ) {
		my $interfacesref = $zones{$sourcezone}{interfaces};
		my $interfaces = "@$interfacesref";
		$origdest = $interfaces ? "detect:$interfaces" : ALLIPv4;
	    }

	    expand_rule
		ensure_chain ('nat' , $zones{$sourcezone}{type} eq 'firewall' ? 'OUTPUT' : dnat_chain $sourcezone) ,
		PREROUTE_RESTRICT ,
		$rule ,
		$source ,
		$dest ,
		$origdest ,
		'-j RETURN ' ,
		$loglevel ,
		$action ,
		'';
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

	unless ( $origdest eq '-' ) {
	    require_capability( 'CONNTRACK_MATCH', 'ORIGINAL DEST in non-NAT rule' ) unless $actiontype & NATRULE;
	} else {
	    $origdest = '';
	}

	expand_rule
	    ensure_chain ('filter', $chain ) ,
	    $restriction ,
	    $rule ,
	    $source ,
	    $dest ,
	    $origdest ,
	    "-j $action " ,
	    $loglevel ,
	    $action ,
	    '';
    }
}

#
# Process a Record in the rules file 
#
#     Deals with the ugliness of wildcard zones ('all' in rules).
#
sub process_rule ( $$$$$$$$$ ) {
    my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user ) = @_;
    my $intrazone = 0;
    my $includesrcfw = 1;
    my $includedstfw = 1;
    my $optimize = $config{OPTIMIZE};
    my $thisline = $line;
    #
    # Section Names are optional so once we get to an actual rule, we need to be sure that
    # we close off any missing sections.
    #
    unless ( $sectioned ) {
	finish_section 'ESTABLISHED,RELATED';
	$section = 'NEW';
	$sectioned = 1;
    }

    fatal_error "Invalid rules file entry" if $source eq '-' || $dest eq '-';
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
	} elsif ( $source eq 'all-' ) {
	    $dest = 'all';
	    $includedstfw = 0;
	}
    }

    my $action = isolate_basic_target $target;

    $optimize = 0 if $action =~ /!^/;

    if ( $source eq 'all' ) {
	for my $zone ( @zones ) {
	    if ( $includesrcfw || ( $zones{$zone}{type} ne 'firewall' ) ) {
		if ( $dest eq 'all' ) {
		    for my $zone1 ( @zones ) {
			if ( $includedstfw || ( $zones{$zone1}{type} ne 'firewall' ) ) {
			    if ( $intrazone || ( $zone ne $zone1 ) ) {
				my $policychainref = $filter_table->{"${zone}2${zone1}"}{policychain};
				fatal_error "No policy from zone $zone to zone $zone1" unless $policychainref;
				if ( ( ( my $policy ) = $policychainref->{policy} ) ne 'NONE' ) {
				    if ( $optimize > 0 ) {
					my $loglevel = $policychainref->{loglevel};
					if ( $loglevel ne '' ) {
					    next if $target eq "${policy}:$loglevel}";
					} else {
					    next if $action eq $policy;
					}
				    }
				    process_rule1 $target, $zone, $zone1 , $proto, $ports, $sports, $origdest, $ratelimit, $user;
				}
			    }
			}
		    }
		} else {
		    my $destzone = (split /:/, $dest)[0];
		    fatal_error "Unknown destination zone ($destzone)" unless $zones{$destzone};
		    my $policychainref = $filter_table->{"${zone}2${destzone}"}{policychain};
		    if ( $intrazone || ( $zone ne $destzone ) ) {
			fatal_error "No policy from zone $zone to zone $destzone" unless $policychainref;
			if ( ( ( my $policy ) = $policychainref->{policy} ) ne 'NONE' ) {
			    if ( $optimize > 0 ) {
				my $loglevel = $policychainref->{loglevel};
				if ( $loglevel ne '') {
				    next if $target eq "${policy}:$loglevel}";
				} else {
				    next if $action eq $policy;
				}
			    }
			    process_rule1 $target, $zone, $dest , $proto, $ports, $sports, $origdest, $ratelimit, $user;
			}
		    }
		}
	    }
	}
    } elsif ( $dest eq 'all' ) {
	for my $zone ( @zones ) {
	    my $sourcezone = ( split /:/, $source )[0];
	    if ( ( $includedstfw || ( $zones{$zone}{type} ne 'firewall') ) && ( ( $sourcezone ne $zone ) || $intrazone) ) {
		fatal_error "Unknown source zone ($sourcezone)" unless $zones{$sourcezone};
		my $policychainref = $filter_table->{"${sourcezone}2${zone}"}{policychain};
		if ( ( ( my $policy ) = $policychainref->{policy} ) ne 'NONE' ) {
		    if ( $optimize > 0 ) {
			my $loglevel = $policychainref->{loglevel};
			if ( $loglevel ne '' ) {
			    next if $target eq "${policy}:$loglevel}";
			} else {
			    next if $action eq $policy;
			}
		    }
		}
		process_rule1 $target, $source, $zone , $proto, $ports, $sports, $origdest, $ratelimit, $user;
	    }
	}
    } else {
	process_rule1  $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user;
    }

    progress_message "   Rule \"$thisline\" $done";
}

#
# Process the Rules File
#
sub process_rules() {

    my $fn = open_file 'rules';

    my $first_entry = 1;

    while ( read_a_line ) {

	my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user ) = split_line 3, 9, 'rules file';

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	if ( $target eq 'COMMENT' ) {
	    if ( $capabilities{COMMENTS} ) {
		( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		$comment =~ s/\s*$//;
	    } else {
		warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
	    }
	} elsif ( $target eq 'SECTION' ) {
	    fatal_error "Invalid SECTION $source" unless defined $sections{$source};
	    fatal_error "Duplicate or out of order SECTION $source" if $sections{$source};
	    fatal_error "Invalid Section $source $dest" if $dest;
	    $sectioned = 1;
	    $sections{$source} = 1;

	    if ( $section eq 'RELATED' ) {
		$sections{ESTABLISHED} = 1;
		finish_section 'ESTABLISHED';
	    } elsif ( $section eq 'NEW' ) {
		@sections{'ESTABLISHED','RELATED'} = ( 1, 1 );
		finish_section ( ( $section eq 'RELATED' ) ? 'RELATED' : 'ESTABLISHED,RELATED' );
	    }

	    $section = $source;
	} else {
	    if ( "\L$source" =~ /^none(:.*)?$/ || "\L$dest" =~ /^none(:.*)?$/ ) {
		progress_message "Rule \"$line\" ignored."
	    } else {
		process_rule $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user;
	    }
	}
    }

    $comment = '';
    $section = 'DONE';
}

#
# To quote an old comment, generate_matrix makes a sows ear out of a silk purse.
#
# The biggest disadvantage of the zone-policy-rule model used by Shorewall is that it doesn't scale well as the number of zones increases (Order N**2 where N = number of zones).
# A major goal of the rewrite of the compiler in Perl was to restrict those scaling effects to this functions and the rules that it generates.
#
# The function traverses the full "source-zone X destination-zone" matrix and generates the rules necessary to direct traffic through the right set of filter-table rules.
#
sub generate_matrix() {
    #
    # Helper functions for generate_matrix()
    #-----------------------------------------
    #
    # Return the target for rules from the $zone to $zone1.
    #
    sub rules_target( $$ ) {
	my ( $zone, $zone1 ) = @_;
	my $chain = "${zone}2${zone1}";
	my $chainref = $filter_table->{$chain};

	return $chain   if $chainref && $chainref->{referenced};
	return 'ACCEPT' if $zone eq $zone1;

	if ( $chainref->{policy} ne 'CONTINUE' ) {
	    my $policyref = $chainref->{policychain};
	    return $policyref->{name} if $policyref;
	    fatal_error "No policy defined for zone $zone to zone $zone1";
	}

	'';
    }

    #
    # Add a jump to the passed chain ($chainref) to the dynamic zone chain for the passed zone.
    #
    sub create_zone_dyn_chain( $$ ) {
	my ( $zone , $chainref ) = @_;
	my $name = "${zone}_dyn";
	new_standard_chain $name;
	add_rule $chainref, "-j $name";
    }

    #
    # Insert the passed exclusions at the front of the passed chain.
    #
    sub insert_exclusions( $$ ) {
	my ( $chainref, $exclusionsref ) = @_;

	my $num = 1;

	for my $host ( @{$exclusionsref} ) {
	    my ( $interface, $net ) = split /:/, $host;
	    insert_rule $chainref , $num++, join( '', "-i $interface ", match_source_net( $net ), '-j RETURN' );
	}
    }

    #
    # Add the passed exclusions at the end of the passed chain.
    #
    sub add_exclusions ( $$ ) {
	my ( $chainref, $exclusionsref ) = @_;

	for my $host ( @{$exclusionsref} ) {
	    my ( $interface, $net ) = split /:/, $host;
	    add_rule $chainref , join( '', "-i $interface ", match_source_net( $net ), '-j RETURN' );
	}
    }

    my $prerouting_rule  = 1;
    my $postrouting_rule = 1;
    my $exclusion_seq    = 1;
    my %chain_exclusions;
    my %policy_exclusions;

    #
    # Generate_Matrix() Starts Here
    #
    for my $interface ( @interfaces ) {
	addnatjump 'POSTROUTING' , snat_chain( $interface ), "-o $interface ";
    }

    if ( $config{DYNAMIC_ZONES} ) {
	for my $interface ( @interfaces ) {
	    addnatjump 'PREROUTING' , dynamic_in( $interface ), "-i $interface ";
	}
    }

    addnatjump 'PREROUTING'  , 'nat_in'  , '';
    addnatjump 'POSTROUTING' , 'nat_out' , '';

    for my $interface ( @interfaces ) {
	addnatjump 'PREROUTING'  , input_chain( $interface )  , "-i $interface ";
	addnatjump 'POSTROUTING' , output_chain( $interface ) , "-o $interface ";
    }

    for my $zone ( grep $zones{$_}{options}{complex} , @zones ) {
	my $frwd_ref   = new_standard_chain "${zone}_frwd";
	my $zoneref    = $zones{$zone};
	my $exclusions = $zoneref->{exclusions};

	if ( @$exclusions ) {
	    my $num = 1;
	    my $in_ref  = new_standard_chain "${zone}_input";
	    my $out_ref = new_standard_chain "${zone}_output";

	    add_rule ensure_filter_chain( "${zone}2${zone}", 1 ) , '-j ACCEPT' if rules_target( $zone, $zone ) eq 'ACCEPT';

	    for my $host ( @$exclusions ) {
		my ( $interface, $net ) = split /:/, $host;
		add_rule $frwd_ref , "-i $interface -s $net -j RETURN";
		add_rule $in_ref   , "-i $interface -s $net -j RETURN";
		add_rule $out_ref  , "-i $interface -s $net -j RETURN";
	    }

	    if ( $capabilities{POLICY_MATCH} ) {
		my $type       = $zoneref->{type};
		my $source_ref = $zoneref->{hosts}{ipsec} || [];

		create_zone_dyn_chain $zone, $frwd_ref && $config{DYNAMIC_ZONES} && (@$source_ref || $type ne 'ipsec4' );

		for my $interface ( keys %$source_ref ) {
		    my $arrayref = $source_ref->{$interface};
		    for my $hostref ( @{$arrayref} ) {
			my $ipsec_match = match_ipsec_in $zone , $hostref;
			for my $net ( @{$hostref->{hosts}} ) {
			    add_rule
				find_chainref( 'filter' , forward_chain $interface ) ,
				match_source_net join( '', $net, $ipsec_match, "-j $frwd_ref->n{name}" );
			}
		    }
		}
	    }
	}
    }
    #
    # Main source-zone matrix-generation loop
    #
    for my $zone ( grep ( $zones{$_}{type} ne 'firewall'  ,  @zones ) ) {
	my $zoneref          = $zones{$zone};
	my $source_hosts_ref = $zoneref->{hosts};
	my $chain1           = rules_target $firewall_zone , $zone;
	my $chain2           = rules_target $zone, $firewall_zone;
	my $complex          = $zoneref->{options}{complex} || 0;
	my $type             = $zoneref->{type};
	my $exclusions       = $zoneref->{exclusions};
	my $need_broadcast   = {}; ### Fixme ###
	my $frwd_ref         = 0;
	my $chain            = 0;
	my %needbroadcast;

	if ( $complex ) {
	    $frwd_ref = $filter_table->{"${zone}_frwd"};
	    my $dnat_ref = ensure_chain 'nat' , dnat_chain( $zone );
	    if ( @$exclusions ) {
		insert_exclusions $dnat_ref, $exclusions if $dnat_ref->{referenced};
	    }
	}

	if ( $config{DYNAMIC_ZONES} ) {
	    push @rule_chains , [ $firewall_zone , $zone , $chain1 ];
	    push @rule_chains , [ $zone , $firewall_zone , $chain2 ];
	}

	#
	# Take care of PREROUTING, INPUT and OUTPUT jumps
	#
	for my $typeref ( values %$source_hosts_ref ) {
	    for my $interface (keys %$typeref ) {
		my $arrayref = $typeref->{$interface};
		for my $hostref ( @$arrayref ) {
		    my $ipsec_in_match  = match_ipsec_in  $zone , $hostref;
		    my $ipsec_out_match = match_ipsec_out $zone , $hostref;
		    for my $net ( @{$hostref->{hosts}} ) {
			my $dest   = match_dest_net   $net;

			if ( $chain1 ) {
			    if ( @$exclusions ) {
				add_rule $filter_table->{output_chain $interface} , join( '', $dest, $ipsec_out_match, "-j ${zone}_output" );
				add_rule $filter_table->{"${zone}_output"} , "-j $chain1";
			    } else {
				add_rule $filter_table->{output_chain $interface} , join( '', $dest, $ipsec_out_match, "-j $chain1" );
			    }
			}

			my $source = match_source_net $net;

			insertnatjump 'PREROUTING' , dnat_chain $zone, \$prerouting_rule, join( '', "-i $interface ", $source, $ipsec_in_match );

			if ( $chain2 ) {
			    if ( @$exclusions ) {
				add_rule $filter_table->{input_chain $interface}, join( '', $source, $ipsec_in_match, "-j ${zone}_input" );
				add_rule $filter_table->{"${zone}_input"} , "-j $chain2";
			    } else {
				add_rule $filter_table->{input_chain $interface}, join( '', $source, $ipsec_in_match, "-j $chain2" );
			    }
			}

			add_rule $filter_table->{forward_chain $interface} , join( '', $source, $ipsec_in_match. "-j $frwd_ref->{name}" )
			    if $complex && $hostref->{ipsec} ne 'ipsec';

			$needbroadcast{$interface} = 1 if get_interface_option $interface, 'detectnets';
		    }
		}
	    }
	}

	if ( $chain1 ) {
	    for my $interface ( keys %needbroadcast ) {
		add_rule $filter_table->{output_chain $interface} , "-d 255.255.255.255 -j $chain1";
		add_rule $filter_table->{output_chain $interface} , "-d 224.0.0.0/4     -j $chain1";
	    }
	}

	#
	#                           F O R W A R D I N G
	#
	my @dest_zones;
	my $last_chain = '';

	if ( $config{OPTIMIZE} > 0 ) {
	    my @temp_zones;

	  ZONE1:
	    for my $zone1 ( grep $zones{$_}{type} ne 'firewall' , @zones )  {
		my $zone1ref = $zones{$zone1};
		my $policy = $filter_table->{"${zone}2${zone1}"}->{policy};

		next if $policy  eq 'NONE';

		my $chain = rules_target $zone, $zone1;

		next unless $chain;

		if ( $zone eq $zone1 ) {
		    #
		    # One thing that the Llama fails to mention is that evaluating a hash in a numeric context produces a warning.
		    #
		    no warnings;
		    next if (  %{ $zoneref->{interfaces}} < 2 ) && ! ( $zoneref->{options}{in_out}{routeback} || @$exclusions );
		}

		if ( $chain =~ /2all$/ ) {
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
	    @dest_zones =  grep $zones{$_}{type} ne 'firewall' , @zones ;
	}
	#
	# Here it is -- THE BIG UGLY!!!!!!!!!!!!
	#
	# We now loop through the destination zones creating jumps to the rules chain for each source/dest combination.
	# @dest_zones is the list of destination zones that we need to handle from this source zone
	#
      ZONE1:
	for my $zone1 ( @dest_zones ) {
	    my $zone1ref = $zones{$zone1};
	    my $policy   = $filter_table->{"${zone}2${zone1}"}->{policy};

	    next if $policy  eq 'NONE';

	    my $chain = rules_target $zone, $zone1;

	    next unless $chain;

	    push @rule_chains, [ $zone , $zone1 , $chain ] if $config{DYNAMIC_ZONES};

	    my $num_ifaces = 0;

	    if ( $zone eq $zone1 ) {
		#
		# One thing that the Llama fails to mention is that evaluating a hash in a numeric context produces a warning.
		#
		no warnings;
		next ZONE1 if ( $num_ifaces = %{$zoneref->{interfaces}} ) < 2 && ! ( $zoneref->{options}{in_out}{routeback} || @$exclusions );
	    }

	    my $chainref    = $filter_table->{$chain};
	    my $exclusions1 = $zone1ref->{exclusions};

	    my $dest_hosts_ref = $zone1ref->{hosts};

	    if ( @$exclusions1 ) {
		if ( $chain eq "all2$zone1" ) {
		    unless ( $chain_exclusions{$chain} ) {
			$chain_exclusions{$chain} = 1;
			insert_exclusions $chainref , $exclusions1;
		    }
		} elsif ( $chain =~ /2all$/ ) {
		    my $chain1 = $policy_exclusions{"${chain}_${zone1}"};

		    unless ( $chain ) {
			$chain1 = newexclusionchain;
			$policy_exclusions{"${chain}_${zone1}"} = $chain1;
			my $chain1ref = ensure_filter_chain $chain1, 0;
			add_exclusions $chain1ref, $exclusions1;
			add_rule $chain1ref, "-j $chain";
		    }

		    $chain = $chain1;
		} else {
		    insert_exclusions $chainref , $exclusions1;
		}
	    }

	    if ( $complex ) {
		for my $typeref ( values %$dest_hosts_ref ) {
		    for my $interface ( keys %$typeref ) {
			my $arrayref = $typeref->{$interface};
			for my $hostref ( @$arrayref ) {
			    if ( $zone ne $zone1 || $num_ifaces > 1 || $hostref->{options}{routeback} ) {
				my $ipsec_out_match = match_ipsec_out $zone1 , $hostref;
				for my $net ( @{$hostref->{hosts}} ) {
				    add_rule $frwd_ref, join( '', "-o $interface ", match_dest_net($net), $ipsec_out_match, "-j $chain" );
				}
			    }
			}
		    }
		}
	    } else {
		for my $typeref ( values %$source_hosts_ref ) {
		    for my $interface ( keys %$typeref ) {
			my $arrayref = $typeref->{$interface};
			my $chain3ref = $filter_table->{forward_chain $interface};
			for my $hostref ( @$arrayref ) {
			    for my $net ( @{$hostref->{hosts}} ) {
				my $source_match = match_source_net $net;
				for my $type1ref ( values %$dest_hosts_ref ) {
				    for my $interface1 ( keys %$type1ref ) {
					my $array1ref = $type1ref->{$interface1};
					for my $host1ref ( @$array1ref ) {
					    my $ipsec_out_match = match_ipsec_out $zone1 , $host1ref;
					    for my $net1 ( @{$host1ref->{hosts}} ) {
						unless ( $interface eq $interface1 && $net eq $net1 && ! $host1ref->{options}{routeback} ) {
						    add_rule
							$chain3ref ,
							join( '', "-o $interface1 ", $source_match, match_dest_net($net1), $ipsec_out_match, "-j $chain" );
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
	    # Now add (an) unconditional jump(s) to the last unique policy-only chain determined above, if any
	    #
	    if ( $last_chain ) {
		if ( $complex ) {
		    add_rule $frwd_ref , "-j $last_chain";
		} else {
		    for my $typeref ( values %$source_hosts_ref ) {
			for my $interface ( keys %$typeref ) {
			    my $arrayref = $typeref->{$interface};
			    my $chain2ref = $filter_table->{forward_chain $interface};
			    for my $hostref ( @$arrayref ) {
				for my $net ( @{$hostref->{hosts}} ) {
				    add_rule $chain2ref, match_source_net($net) .  "-j $last_chain";
				}
			    }
			}
		    }
		}
	    }
	}
    }
    #
    # Now add the jumps to the interface chains from FORWARD, INPUT, OUTPUT and POSTROUTING
    #
    for my $interface ( @interfaces ) {
	add_rule $filter_table->{FORWARD} , "-i $interface -j " . forward_chain $interface;
	add_rule $filter_table->{INPUT}   , "-i $interface -j " . input_chain $interface;
	add_rule $filter_table->{OUTPUT}  , "-o $interface -j " . output_chain $interface;
	addnatjump 'POSTROUTING' , masq_chain( $interface ) , "-o $interface ";
    }

    my $chainref = $filter_table->{"${firewall_zone}2${firewall_zone}"};

    add_rule $filter_table->{OUTPUT} , "-o lo -j " . ($chainref->{referenced} ? "$chainref->{name}" : 'ACCEPT' );
    add_rule $filter_table->{INPUT} , '-i lo -j ACCEPT';

    my %builtins = ( mangle => [ qw/PREROUTING INPUT FORWARD POSTROUTING/ ] ,
		     nat=>     [ qw/PREROUTING OUTPUT POSTROUTING/ ] ,
		     filter=>  [ qw/INPUT FORWARD OUTPUT/ ] );

    complete_standard_chain $filter_table->{INPUT}   , 'all' , $firewall_zone;
    complete_standard_chain $filter_table->{OUTPUT}  , $firewall_zone , 'all';
    complete_standard_chain $filter_table->{FORWARD} , 'all' , 'all';

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

sub setup_mss( $ ) {
    my $clampmss = $_[0];
    my $option = "\L$clampmss" eq 'yes' ? '--clamp-mss-to-pmtu' : '--set-mss $clampmss';

    add_rule $filter_table->{FORWARD} , "-p tcp --tcp-flags SYN,RST SYN -j TCPMSS $option";
}

sub dump_rule_chains() {
    for my $arrayref ( @rule_chains ) {
	emit_unindented "@$arrayref";
    }
}

1;
