#! /usr/bin/perl -w

use strict;
use lib "$ENV{HOME}/shorewall/trunk/New";
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Chains;
use Shorewall::Zones;
use Shorewall::Interfaces;
use Shorewall::Hosts;
use Shorewall::Nat;
use Shorewall::Tc;
use Shorewall::Tunnels;
use Shorewall::Providers;
use Shorewall::Policy;
use Shorewall::Macros;
use Shorewall::Actions;
use Shorewall::Accounting;
use Shorewall::Rules;

sub process_tos() {
    my $chain    = 'pretos';
    my $stdchain = 'PREROUTING';

    if ( -s "$ENV{TMP_DIR}/tos" ) {
	progress_message2 'Setting up TOS...';

	my $pretosref = new_chain 'mangle' , 'pretos';
	my $outtosref = new_chain 'mangle' , 'outtos';

	open TOS, "$ENV{TMP_DIR}/tos" or fatal_error "Unable to open stripped tos file: $!";

	while ( $line = <TOS> ) {
	    
	    chomp $line;
	    $line =~ s/\s+/ /g;
	    
	    my ($source, $dest, $proto, $sports, $ports, $extra) = split /\s+/, $line;
	    
	    fatal_error "Invalid tos file entry: \"$line\"" if $extra;
	}

	close TOS;

	$comment = '';
    }
}

sub add_rule_pair( $$$$ ) {
    my ($chainref , $predicate , $target , $level ) = @_;

    log_rule $level, $chainref, $target,  , $predicate,  if $level;
    add_rule $chainref , "${predicate}-j $target";
}

sub setup_rfc1918_filteration( $ ) {

    my $listref      = $_[0];
    my $norfc1918ref = new_standard_chain 'norfc1918';
    my $rfc1918ref   = new_standard_chain 'rfc1918';
    my $chainref     = $norfc1918ref;

    log_rule $config{RFC1918_LOG_LEVEL} , $rfc1918ref , 'DROP' , '';

    add_rule $rfc1918ref , '-j DROP';

    if ( $config{RFC1918_STRICT} ) {
	$chainref = new_standard_chain 'rfc1918d';
    } 

    open RFC, "$ENV{TMP_DIR}/rfc1918" or fatal_error "Unable to open stripped rfc1918 file: $!"; 
	    
    while ( $line = <RFC> ) {
	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $networks, $target, $extra ) = split /\s+/, $line;
	
	my $s_target;

	if ( $target eq 'logdrop' ) {
	    $target   = 'rfc1918';
	    $s_target = 'rfc1918';
	} elsif ( $target eq 'DROP' ) {
	    $s_target = 'DROP';
	} elsif ( $target eq 'RETURN' ) {
	    $s_target = $config{RFC1918_LOG_LEVEL} ? 'rfc1918d' : 'RETURN';
	} else {
	    fatal_error "Invalid target ($target) for $networks";
	}

	for my $network ( split /,/, $networks ) {
	    add_rule $norfc1918ref , match_source_net( $network ) . "-j $s_target";
	    add_rule $chainref , match_orig_dest( $network ) . "-j $target" ;
	}
    }

    close RFC;

    add_rule $norfc1918ref , '-j rfc1918d' if $config{RFC1918_STRICT};

    for my $hostref  ( @$listref ) {
	my $interface = $hostref->[0];
	my $ipsec     = $hostref->[1];
	my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in "  : '';
	for my $chain ( @{first_chains $interface}) {
	    add_rule $filter_table->{$chain} , '-m state --state NEW ' . match_source_net( $hostref->[2]) . "${policy}-j norfc1918";
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
	    log_rule_limit $level , $synchainref , $chainref->{name} , 'DROP', '-m limit --limit 5/min --limit-burst 5' , '' , 'add' , '' if $level;
	    add_rule $synchainref, '-j DROP';
	}
    }
}

sub setup_blacklist() {

    my ( $level, $disposition ) = @config{'BLACKLIST_LOGLEVEL', 'BLACKLIST_DISPOSITION' };

    progress_message2 "   Setting up Blacklist...";

    open BL, "$ENV{TMP_DIR}/blacklist" or fatal_error "Unable to open stripped blacklist file: $!";

    progress_message( "      Processing " . find_file 'blacklist' . '...' );

    while ( $line = <BL> ) {

	chomp $line;
	$line =~ s/\s+/ /g;
	
	my ( $networks, $protocol, $ports , $extra ) = split /\s+/, $line;
	
	fatal_error "Invalid blacklist entry: \"$line\"" if $extra;

	expand_rule 
	    ensure_filter_chain( 'blacklst' , 0 ) ,
	    do_proto( $protocol , $ports, '' ) ,
	    $networks ,
	    '' ,
	    '' ,
	    '-j ' . ($disposition eq 'REJECT' ? 'reject' : $disposition),
	    $level ,
	    $disposition ,
	    '';
	
	progress_message "         \"$line\" added to blacklist";
    }

    close BL;

    my $hosts = find_hosts_by_option 'blacklist';

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

sub setup_forwarding() {
    if ( "\L$config{IP_FORWARDING}" eq 'on' ) {
	emit 'echo 1 > /proc/sys/net/ipv4/ip_forward';
	emit 'progress_message2 IP Forwarding Enabled';
    } elsif ( "\L$config{IP_FORWARDING}" eq 'off' ) {
	emit 'echo 0 > /proc/sys/net/ipv4/ip_forward';
	emit 'progress_message2 IP Forwarding Disabled!';
    }

    emit '';
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

    new_standard_chain 'dynamic';

    my $state = $config{BLACKLISTNEWONLY} ? '-m state --state NEW,INVALID' : '';

    for $interface ( @interfaces ) {
	for $chain ( input_chain $interface , forward_chain $interface ) {
	    add_rule new_standard_chain( $chain ) , "$state -j dynamic";
	}

	new_standard_chain output_chain( $interface );
    }

    $level = $env{BLACKLIST_LOG_LEVEL} || 'info';

    add_rule_pair new_standard_chain( 'logdrop' ),   ' ' , 'DROP'   , $level ;
    add_rule_pair new_standard_chain( 'logreject' ), ' ' , 'REJECT' , $level ;

    setup_blacklist;

    $list = find_hosts_by_option 'nosmurfs';

    if ( $capabilities{ADDRTYPE} ) {
	$chainref = new_standard_chain 'smurfs';

	add_rule_pair $chainref, '-m addrtype --src-type BROADCAST ', 'DROP', $config{SMURF_LOG_LEVEL} ;
	add_rule_pair $chainref, '-m addrtype --src-type MULTICAST ', 'DROP', $config{SMURF_LOG_LEVEL} ;

	add_rule $rejectref , '-m addrtype --src-type BROADCAST -j DROP';
	add_rule $rejectref , '-m addrtype --src-type MULTICAST -j DROP';
    } elsif ( @$list ) {
	fatal_error "The nosmurfs option requires Address Type Match in your kernel and iptables";
    }
    
    if ( @$list ) {
	progress_message2 '   Adding Anti-smurf Rules';
	for my $hostref  ( @$list ) {
	    $interface = $hostref->[0];
	    my $ipsec  = $hostref->[1];
	    my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    for $chain ( @{first_chains $interface}) {
		add_rule $filter_table->{$chain} , '-m state --state NEW,INVALID ' . match_source_net( $hostref->[2]) . "${policy}-j smurfs";
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
	progress_message2 '   Adding rules for DHCP';

	for $interface ( @$list ) {
	    for $chain ( @{first_chains $interface}) {
		add_rule $filter_table->{$chain} , '-p udp --dport 67:68 -j ACCEPT';
	    }

	    add_rule $filter_table->{forward_chain $interface} , "-p udp -o $interface --dport 67:68 -j ACCEPT" if $interfaces{$interface}{options}{routeback};
	}
    }

    $list = find_hosts_by_option 'norfc1918';

    if ( @$list ) {
	progress_message2 '   Enabling RFC1918 Filtering';

	setup_rfc1918_filteration $list;
    }

    $list = find_hosts_by_option 'tcpflags';

    if ( @$list ) {
	my $disposition;

	progress_message2 "   $doing TCP Flags checking...";
	
	$chainref = new_standard_chain 'tcpflags';

	if ( $config{TCP_FLAGS_LOG_LEVEL} ) {
	    my $logflagsref = new_standard_chain 'logflags';
	    
	    my $savelogparms = $env{LOGPARMS};

	    $env{LOGPARMS} = "$env{LOGPARMS} --log-ip-options" unless $config{TCP_FLAGS_LOG_LEVEL} eq 'ULOG';
	    
	    log_rule $config{TCP_FLAGS_LOG_LEVEL} , $logflagsref , $config{TCP_FLAGS_DISPOSITION}, '';
	    
	    $env{LOGPARMS} = $savelogparms;
									
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
		add_rule $filter_table->{$chain} , '-p tcp ' . match_source_net( $hostref->[2]) . "${policy}-j tcpflags";
	    }
	}
    }

    if ( $config{DYNAMIC_ZONES} ) {
	for $interface ( @interfaces) {
	    for $chain ( @{dynamic_chains $interface} ) {
		new_standard_chain $chain;
	    }
	}
	
	(new_chain 'nat' , $chain = dynamic_in($interface) )->{referenced} = 1; 
	    
	add_rule $filter_table->{input_chain $interface},  "-j $chain";
	add_rule $filter_table->{forward_chain $interface}, '-j ' . dynamic_fwd $interface;
	add_rule $filter_table->{output_chain $interface},  '-j ' . dynamic_out $interface;
    }	

    $list = find_interfaces_by_option 'upnp';

    if ( @$list ) {
	progress_message2 '   $doing UPnP';

	(new_chain 'nat', 'UPnP')->{referenced} = 1;

	for $interface ( @$list ) {
	    add_rule $nat_table->{PREROUTING} , "-i $interface -j UPnP";
	}
    }

    setup_syn_flood_chains;

    setup_forwarding;
}

my %maclist_targets = ( ACCEPT => { target => 'RETURN' , mangle => 1 } ,
			REJECT => { target => 'reject' , mangle => 0 } ,
			DROP   => { target => 'DROP' ,   mangle => 1 } );

sub setup_mac_lists( $ ) {

    my $phase = $_[0];

    my %maclist_interfaces;

    my $table = $config{MACLIST_TABLE};

    my $maclist_hosts = find_hosts_by_option 'maclist';

    for my $hostref ( $maclist_hosts ) {
	$maclist_interfaces{ $hostref->[0][0] } = 1;
    }

    my @maclist_interfaces = ( sort keys %maclist_interfaces );
    
    progress_message "   $doing MAC Verification for @maclist_interfaces -- Phase $phase...";

    if ( $phase == 1 ) {
	for my $interface ( @maclist_interfaces ) {
	    my $chainref = new_chain $table , mac_chain $interface;
	    
	    add_rule $chainref , '-s 0.0.0.0 -d 255.255.255.255 -p udp --dport 67:68 -j RETURN'
		if ( $table eq 'mangle' ) && $interfaces{$interface}{options}{dhcp};
	    
	    if ( $config{MACLIST_TTL} ) {
		my $chain1ref = new_chain $table, macrecent_target $interface;

		my $chain = $chainref->{name};

		add_rule $chainref, "-m recent --rcheck --seconds $config{MACLIST_TTL} --name $chain -j RETURN";
		add_rule $chainref, "-j $chain1ref->{name}";
		add_rule $chainref, "-m recent --update --name $chain -j RETURN";
		add_rule $chainref, "-m recent --set --name $chain";
	    }
	}

	open MAC, "$ENV{TMP_DIR}/maclist" or fatal_error "Unable to open stripped maclist file: $!";

	while ( $line = <MAC> ) {

	    chomp $line;
	    $line =~ s/\s+/ /g;

	    my ( $disposition, $interface, $mac, $addresses , $extra ) = split /\s+/, $line;

	    if ( $disposition eq 'COMMENT' ) {
		if ( $capabilities{COMMENTS} ) {
		    ( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		    $comment =~ s/\s*$//;
		} else {
		    warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
		}
	    } else {
		fatal_error "Invalid maclist entry: \"$line\"" if $extra;
	       
		( $disposition, my $level ) = split /:/, $disposition;

		my $targetref = $maclist_targets{$disposition};

		fatal_error "Invalid DISPOSITION ( $disposition) in rule \"$line\"" if ( $table eq 'mangle' ) && ! $targetref->{mangle};

		fatal_error "No hosts on $interface have the maclist option specified: \"$line\"" unless $maclist_interfaces{$interface};

		my $chainref = $chain_table{$table}{( $config{MACLIST_TTL} ? macrecent_target $interface : mac_chain $interface )};

		$mac       = '' unless $mac && ( $mac ne '-' );
		$addresses = '' unless $addresses && ( $addresses ne '-' );

		fatal_error "You must specify a MAC address or an IP address" unless $mac || $addresses;

		$mac = mac_match $mac if $mac;

		if ( $addresses ) {
		    for my $address ( split ',', $addresses ) {
			my $source = match_source_net $address;
			log_rule_limit $level, $chainref , mac_chain( $interface) , $disposition, '', '', 'add' , "${mac}${source}" if $level;
			add_rule $chainref , "${mac}${source}-j $targetref->{target}";
		    }
		} else {
		    log_rule_limit $level, $chainref , mac_chain( $interface) , $disposition, '', '', 'add' , $mac if $level;
		    add_rule $chainref , "$mac-j $targetref->{target}";
		}

		progress_message "      Maclist entry \"$line\" $done";
	    }
	}

	close MAC;

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
		    add_rule $filter_table->{$chain} , "${source}-m state --statue NEW ${policy}-j $target";
		}
	    } else {
		add_rule $mangle_table->{PREROUTING}, "-i $interface ${source}-m state --state NEW ${policy}-j $target";
	    }
	}
    } else {
	my $target      = $env{MACLIST_TARGET};
	my $level       = $config{MACLIST_LOG_LEVEL};
	my $disposition = $config{MACLIST_DISPOSITION};

	for my $interface ( @maclist_interfaces ) {
	    my $chainref = $chain_table{$table}{( $config{MACLIST_TTL} ? macrecent_target $interface : mac_chain $interface )};
	    my $chain    = mac_chain $interface;
	    log_rule_limit $level, $chainref , $chain , $disposition, '', '', 'add', '';
	    add_rule $chainref, "-j $target";
	}
    }
}

#
# To quote an old comment, generate_matrix makes a sows ear out of a silk purse.
#
# The biggest disadvantage of the zone-policy-rule model used by Shorewall is that it doesn't scale well as the number of zones increases (Order N**2 where N = number of zones).
# A major goal of the rewrite of the compiler in Perl was to restrict those scaling effects to this functions and the rules that it generates.
#
# The function traverses the full "source-zone X destination-zone" matrix and generates the rules necessary to direct traffic through the right set of rules.
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
	    insert_rule $chainref , $num++, "-i $interface " . match_source_net( $host ) . '-j RETURN';
	}
    }

    #
    # Add the passed exclusions at the end of the passed chain.
    #
    sub add_exclusions ( $$ ) {
	my ( $chainref, $exclusionsref ) = @_;
	
	for my $host ( @{$exclusionsref} ) {
	    my ( $interface, $net ) = split /:/, $host;
	    add_rule $chainref , "-i $interface " . match_source_net( $host ) . '-j RETURN';
	}
    }    
    #
    # Generate_Matrix() Starts Here
    #
    my $prerouting_rule  = 1;
    my $postrouting_rule = 1;
    my $exclusion_seq    = 1;
    my %chain_exclusions;
    my %policy_exclusions;

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
	    
	    add_rule ensure_filter_chain( "${zone}2${zone}", 1 ) , '-j ACCEPT' if rules_target $zone, $zone eq 'ACCEPT';

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
		
		while ( my ( $interface, $arrayref ) = each %$source_ref ) {
		    for my $hostref ( @{$arrayref} ) {
			my $ipsec_match = match_ipsec_in $zone , $hostref;
			for my $net ( @{$hostref->{hosts}} ) {
			    add_rule
				find_chainref( 'filter' , forward_chain $interface ) , 
				match_source_net $net . $ipsec_match . "-j $frwd_ref->n{name}";
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

	if ( $complex ) {
	    $frwd_ref = $filter_table->{"${zone}_frwd"};
	    my $dnat_ref = ensure_chain 'nat' , dnat_chain( $zone );
	    if ( @$exclusions ) {
		insert_exclusions $dnat_ref, $exclusions if $dnat_ref->{referenced};
	    }
	}
	#
	# Take care of PREROUTING, INPUT and OUTPUT jumps
	#
	for my $typeref ( values %$source_hosts_ref ) {
	    while ( my ( $interface, $arrayref ) = each %$typeref ) {
		for my $hostref ( @$arrayref ) {
		    my $ipsec_in_match  = match_ipsec_in  $zone , $hostref;
		    my $ipsec_out_match = match_ipsec_out $zone , $hostref; 
		    for my $net ( @{$hostref->{hosts}} ) {
			my $source = match_source_net $net;
			my $dest   = match_dest_net   $net;

			if ( $chain1 ) {
			    if ( @$exclusions ) {
				add_rule $filter_table->{output_chain $interface} , $dest . $ipsec_out_match . "-j ${zone}_output";
				add_rule $filter_table->{"${zone}_output"} , "-j $chain1";
			    } else {
				add_rule $filter_table->{output_chain $interface} , $dest . $ipsec_out_match . "-j $chain1";
			    }
			}
			
			insertnatjump 'PREROUTING' , dnat_chain $zone, \$prerouting_rule, ( "-i $interface " . $source . $ipsec_in_match );

			if ( $chain2 ) {
			    if ( @$exclusions ) {
				add_rule $filter_table->{input_chain $interface}, $source . $ipsec_in_match . "-j ${zone}_input";
				add_rule $filter_table->{"${zone}_input"} , "-j $chain2";
			    } else {
				add_rule $filter_table->{input_chain $interface}, $source . $ipsec_in_match . "-j $chain2";
			    }
			}

			add_rule $filter_table->{forward_chain $interface} , $source . $ipsec_in_match . "-j $frwd_ref->{name}"
			    if $complex && $hostref->{ipsec} ne 'ipsec';
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
		    next if (  %{ $zoneref->{interfaces}} < 2 ) && ! ( $zoneref->{options}{routeback} || @$exclusions );
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
	    
	    my $num_ifaces = 0;
	    
	    if ( $zone eq $zone1 ) {
		#
		# One thing that the Llama fails to mention is that evaluating a hash in a numeric context produces a warning.
		#
		no warnings;
		next ZONE1 if ( $num_ifaces = %{$zoneref->{interfaces}} ) < 2 && ! ( $zoneref->{options}{routeback} || @$exclusions );
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
		    while ( my ( $interface , $arrayref ) = each %$typeref ) {
			for my $hostref ( @$arrayref ) {
			    if ( $zone ne $zone1 || $num_ifaces > 1 || $hostref->{options}{routeback} ) {
				my $ipsec_out_match = match_ipsec_out $zone1 , $hostref; 
				for my $net ( @{$hostref->{hosts}} ) {
				    add_rule $frwd_ref, "-o $interface " . match_dest_net($net) . $ipsec_out_match . "-j $chain";
				}
			    }
			}
		    }
		}
	    } else {
		for my $typeref ( values %$source_hosts_ref ) {
		    while ( my ( $interface , $arrayref ) = each %$typeref ) {
			my $chain3ref = $filter_table->{forward_chain $interface};
			for my $hostref ( @$arrayref ) {
			    for my $net ( @{$hostref->{hosts}} ) {
				my $source_match = match_source_net $net;
				for my $type1ref ( values %$dest_hosts_ref ) {
				    while ( my ( $interface1, $array1ref ) = each %$type1ref ) {
					for my $host1ref ( @$array1ref ) {
					    my $ipsec_out_match = match_ipsec_out $zone1 , $host1ref; 
					    for my $net1 ( @{$host1ref->{hosts}} ) {
						unless ( $interface eq $interface1 && $net eq $net1 && ! $host1ref->{options}{routeback} ) {
						    add_rule $chain3ref, "-o $interface1 " . $source_match . match_dest_net($net1) . $ipsec_out_match . "-j $chain";
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
			while ( my ( $interface , $arrayref ) = each %$typeref ) {
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

    complete_standard_chain $filter_table->{INPUT}   , 'all' , $firewall_zone;
    complete_standard_chain $filter_table->{OUTPUT}  , $firewall_zone , 'all';
    complete_standard_chain $filter_table->{FORWARD} , 'all' , 'all';

    my %builtins = ( mangle => [ qw/PREROUTING INPUT FORWARD POSTROUTING/ ] ,
		     nat=>     [ qw/PREROUTING OUTPUT POSTROUTING/ ] ,
		     filter=>  [ qw/INPUT FORWARD OUTPUT/ ] );

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
		    '-m state --state NEW';
	    }
	}
    }
}

sub generate_script_1 {
    copy find_file 'prog.header';

    my $date = localtime;

    emit "#\n# Compiled firewall script generated by Shorewall $ENV{VERSION} - $date\n#";

    if ( $ENV{EXPORT} ) {
	emit 'SHAREDIR=/usr/share/shorewall-lite';
	emit 'CONFDIR=/etc/shorewall-lite';
	emit 'VARDIR=/var/lib/shorewall-lite';
	emit 'PRODUCT="Shorewall Lite"';
	
	copy "$env{SHAREDIR}/lib.base";
	
	emit '################################################################################';
	emit '# End of /usr/share/shorewall/lib.base';
	emit '################################################################################';
    } else {
	emit 'SHAREDIR=/usr/share/shorewall';
	emit 'CONFDIR=/etc/shorewall';
	emit 'VARDIR=/var/lib/shorewall\n';
	emit 'PRODUCT=\'Shorewall\'';
	emit '. /usr/share/shoreall-lite/lib.base';
    }
	
    emit '';
    
    for my $exit qw/init start tcclear started stop stopped/ {
	emit "run_${exit}_exit() {";
	push_indent;
	append_file $exit;
	pop_indent;
	emit "}\n";
    }
    
    emit 'initialize()';
    emit '{';

    push_indent;
    
    if ( $ENV{EXPORT} ) {
	emit '#';
	emit '# These variables are required by the library functions called in this script';
	emit '#';
	emit 'CONFIG_PATH="/etc/shorewall-lite:/usr/share/shorewall-lite"';
    } else {
	emit 'if [ ! -f ${SHAREDIR}/version ]; then';
	emit '    fatal_error "This script requires Shorewall which do not appear to be installed on this system (did you forget \"-e\" when you compiled?)"';
	emit 'fi';
	emit '';
	emit 'local version=\$(cat \${SHAREDIR}/version)';
	emit '';
	emit 'if [ ${SHOREWALL_LIBVERSION:-0} -lt 30203 ]; then';
	emit '    fatal_error "This script requires Shorewall version 3.3.3 or later; current version is $version"';
	emit 'fi';
	emit '#';
	emit '# These variables are required by the library functions called in this script';
	emit '#';
	emit "CONFIG_PATH=\"$config{CONFIG_PATH}\"";
    }

    propagateconfig;
	
    emit '[ -n "${COMMAND:=restart}" ]';
    emit '[ -n "${VERBOSE:=0}" ]';
    emit '[ -n "${RESTOREFILE:=$RESTOREFILE}" ]';
    emit '[ -n "$LOGFORMAT" ] || LOGFORMAT="Shorewall:%s:%s:"';
    emit "VERSION=\"$ENV{VERSION}\"";
    emit "PATH=\"$config{PATH}\"";
    emit 'TERMINATOR=fatal_error';
    
    if ( $config{IPTABLES} ) {
	emit "IPTABLES=\"$config{IPTABLES}\"\n";
	emit "[ -x \"$config{IPTABLES}\" ] || startup_error \"IPTABLES=$config{IPTABLES} does not exist or is not executable\"";
    } else {
	emit '[ -z "$IPTABLES" ] && IPTABLES=$(mywhich iptables 2> /dev/null)';
	emit '';
	emit '[ -n "$IPTABLES" -a -x "$IPTABLES" ] || startup_error "Can\'t find iptables executable"';
    }

    emit '';
    emit "STOPPING=";
    emit "COMMENT=\n";        # Fixme -- eventually this goes but it's ok now to maintain compability with lib.base
    emit '#';
    emit '# The library requires that ${VARDIR} exist';
    emit '#';
    emit '[ -d ${VARDIR} ] || mkdir -p ${VARDIR}';
    
    pop_indent;
    
    emit "}\n";
    
    copy find_file 'prog.functions';
    
}

sub generate_script_2 () {
    emit '#';
    emit '# Setup Routing and Traffic Shaping';
    emit '#';
    emit 'setup_routing_and_traffic_shaping() {';

    push_indent;
    
    emit 'local restore_file=$1';

    save_progress_message 'Initializing...';
    
    if ( $ENV{EXPORT} ) {
	my $mf = find_file 'modules';

	if ( $mf ne "$env{SHAREDIR}/module" && -f $mf ) {

	    emit 'echo MODULESDIR="$MODULESDIR" > ${VARDIR}/.modulesdir';
	    emit 'cat > ${VARDIR}/.modules << EOF';

	    open MF, $mf or fatal_error "Unable to open $mf: $!";

	    while ( $line = <MF> ) { emit_unindented $line if $line =~ /^\s*loadmodule\b/; }

	    close MF;

	    emit_unindented "EOF\n";

	    emit 'reload_kernel_modules < ${VARDIR}/.modules';
	} else {
	    emit 'load_kernel_modules Yes';
	}
    } else {
	emit 'load_kernel_modules Yes';
    }

    emit '';

    for my $interface ( @{find_interfaces_by_option 'norfc1918'} ) {
	emit "addr=\$(ip -f inet addr show $interface 2> /dev/null | grep 'inet\ ' | head -n1)";
	emit 'if [ -n "$addr" ]; then';
	emit "    addr=\$(echo \$addr | sed 's/inet //;s/\/.*//;s/ peer.*//')";
	emit '    for network in 10.0.0.0/8 176.16.0.0/12 192.168.0.0/16; do';
        emit '        if in_network $addr $network; then';
        emit "            startup_error \"The 'norfc1918' option has been specified on an interface with an RFC 1918 address. Interface:$interface\"";
        emit '        fi';
	emit '    done';
	emit "fi\n";
    }

    emit "run_init_exit\n";
    emit 'qt $IPTABLES -L shorewall -n && qt $IPTABLES -F shorewall && qt $IPTABLES -X shorewall';
    emit '';
    emit "delete_proxyarp\n";
    emit "delete_tc1\n"   if $config{CLEAR_TC};

    emit "disable_ipv6\n" if $config{DISABLE_IPV6};

}

sub generate_script_3() {
    pop_indent;

    emit "}\n";
    
    progress_message2 "Creating iptables-restore input...";
    create_netfilter_load;	
    emit "#\n# Start/Restart the Firewall\n#";
    emit 'define_firewall() {';
    emit '   setup_routing_and_traffic_shaping;';
    emit '   setup_netfilter';
    emit '   [ $COMMAND = restore ] || restore_dynamic_rules';
    emit "}\n";
    
    copy find_file 'prog.footer';	
}

sub compile_firewall( $ ) {
    
    my $objectfile = $_[0];

    ( $command, $doing, $done ) = qw/ check Checking Checked / unless $objectfile;

    initialize_chain_table;

    if ( $command eq 'compile' ) {
	create_temp_object( $objectfile );
	generate_script_1;
    }

    report_capabilities if $ENV{VERBOSE} > 1;

    fatal_error "Shorewall $ENV{VERSION} requires Conntrack Match Support" 
	unless $capabilities{CONNTRACK_MATCH};
    fatal_error "Shorewall $ENV{VERSION} requires Extended Multi-port Match Support"
	unless $capabilities{XMULTIPORT};
    fatal_error "Shorewall $ENV{VERSION} requires Address Type Match Support"
	unless $capabilities{ADDRTYPE};
    fatal_error 'BRIDGING=Yes requires Physdev Match support in your Kernel and iptables'
	if $config{BRIDGING} && ! $capabilities{PHYSDEV_MATCH};
    fatal_error 'MACLIST_TTL requires the Recent Match capability which is not present in your Kernel and/or iptables'
	if $config{MACLIST_TTL} && ! $capabilities{RECENT_MATCH};
    fatal_error 'RFC1918_STRICT=Yes requires Connection Tracking match'
	if $config{RFC1918_STRICT} && ! $capabilities{CONNTRACK_MATCH};
    #
    # Process the zones file.
    #
    progress_message2 "Determining Zones...";                    
    determine_zones;
    #
    # Process the interfaces file.
    #
    progress_message2 "Validating interfaces file...";           
    validate_interfaces_file;             
    dump_interface_info                if $ENV{DEBUG};
    #
    # Process the hosts file.
    #
    progress_message2 "Validating hosts file...";                
    validate_hosts_file;

    if ( $ENV{DEBUG} ) {
	dump_zone_info;
    } elsif ( $ENV{VERBOSE} > 1 ) {
	progress_message "Determining Hosts in Zones...";        
	zone_report;
    }
    #
    # Do action pre-processing.
    #
    progress_message2 "Preprocessing Action Files...";           
    process_actions1;
    #
    # Process the Policy File.
    #
    progress_message2 "Validating Policy file...";               
    validate_policy;
    #
    # Start Second Part of script
    #
    generate_script_2;
    #
    # Do all of the zone-independent stuff
    #
    progress_message2 "Setting up Common Rules...";              
    add_common_rules;
    #
    # [Re-]establish Routing
    # 
    if ( -s "$ENV{TMP_DIR}/providers" ) {
	setup_providers;
    } else {
	emit "\nundo_routing";
	emit 'restore_default_route';
    }
    #
    # Traffic Shaping
    #
    setup_traffic_shaping if -s "$ENV{TMP_DIR}/tcdevices";
    #
    # Setup Masquerading/SNAT
    #
    progress_message2 "$doing Masq file...";                     
    setup_masq;
    #
    # MACLIST Filtration
    #
    progress_message2 "Setting up MAC Filtration -- Phase 1..."; 
    setup_mac_lists 1;
    #
    # Process the rules file.
    #
    progress_message2 "$doing Rules...";                         
    process_rules;
    #
    # Add Tunnel rules.
    #
    progress_message2 "Adding Tunnels...";                       
    setup_tunnels;
    #
    # Post-rules action processing.
    #
    process_actions2;
    process_actions3;
    #
    # MACLIST Filtration again
    #
    progress_message2 "Setting up MAC Filtration -- Phase 2..."; 
    setup_mac_lists 2;
    #
    # Apply Policies
    #
    progress_message2 'Applying Policies...';                    
    apply_policy_rules;                    
    dump_action_table         if $ENV{DEBUG};
    #
    # Setup Nat
    #
    progress_message2 "$doing one-to-one NAT...";                
    setup_nat;
    #
    # TCRules
    #
    progress_message2 "Processing TC Rules...";                  
    process_tcrules;
    #
    # Accounting.
    #
    progress_message2 "Setting UP Accounting...";                
    setup_accounting;
    #
    # Do the BIG UGLY...
    #
    unless ( $command eq 'check' ) {
	#
	# Finish the script.
	#
	progress_message2 'Generating Rule Matrix...';           
	generate_matrix;                       
	dump_chain_table               if $ENV{DEBUG};
	generate_script_3;
	finalize_object;
    }
}

#
#                        E x e c u t i o n   S t a r t s   H e r e
#

$ENV{VERBOSE} = 2 if $ENV{DEBUG};
#
# Get shorewall.conf and capabilities.
#
get_configuration;
#
# Compile/Check the configuration.
#
compile_firewall $ARGV[0];
