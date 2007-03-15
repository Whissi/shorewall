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
use Shorewall::Actions;

#
# Set to one if we find a SECTION
#
my $sectioned = 0;

#  Action Table
#
#     %actions{ <action1> =>  { requires => { <requisite1> = 1,
#                                             <requisite2> = 1,
#                                             ...
#                                           } ,
#                               actchain => <action chain number> # Used for generating unique chain names for each <level>:<tag> pair.
#
my %actions;
#
# Contains an entry for each used <action>:<level>[:<tag>] that maps to the associated chain.
#
my %logactionchains;
#
# Maps each used macro to it's 'macro. ...' file.
#
my %macros;

#
# This function determines the logging for a subordinate action or a rule within a subordinate action
#
sub merge_levels ($$) {
    my ( $superior, $subordinate ) = @_;

    my @supparts = split /:/, $superior;
    my @subparts = split /:/, $subordinate;

    my $subparts = @subparts;

    my $target   = $subparts[0];

    push @subparts, '' while @subparts < 3;   #Avoid undefined values

    my $level = $supparts[1];
    my $tag   = $supparts[2];

    if ( @supparts == 3 ) {
	return "$target:none!:$tag"   if $level eq 'none!';
	return "$target:$level:$tag"  if $level =~ /!$/;
	return $subordinate           if $subparts >= 2;
	return "$target:$level";
    } 

    if ( @supparts == 2 ) {
	return "$target:none!"        if $level eq 'none!';
	return "$target:$level"       if ($level =~ /!$/) || ($subparts < 2);
    }

    $subordinate;
}

#
# Return ( action, level[:tag] ) from passed full action 
#
sub split_action ( $ ) {
    my $action = $_[0];
    my @a = split /:/ , $action;
    fatal_error "Invalid ACTION $action in rule \"$line\"" if ( $action =~ /::/ ) || ( @a > 3 );
    ( shift @a, join ":", @a );
}

#
# Get Macro Name
#
sub isolate_basic_target( $ ) {
    ( split '/' , $_[0] )[0];
}

# This function substitutes the second argument for the first part of the first argument up to the first colon (":")
#
# Example:
#
#         substitute_action DNAT PARAM:info:FTP
#
#         produces "DNAT:info:FTP"
#
sub substitute_action( $$ ) {
    my ( $param, $action ) = @_;

    if ( $action =~ /:/ ) {
	my $logpart = (split_action $action)[1];
	$logpart =~ s!/$!!;
	return "$param:$logpart";
    }

    $param;
}

#
# Define an Action
#
sub new_action( $ ) {

    my $action = $_[0];

    my %h;

    $h{actchain}   = '';
    $h{requires} = {};
    $actions{$action} = \%h;
}

#
# Add an entry to the requiredby hash
#
sub add_requiredby ( $$ ) {
    my ($requires , $requiredby ) = @_;
    $actions{$requiredby}{requires}{$requires} = 1;
}

#
# Create and record a log action chain -- Log action chains have names
# that are formed from the action name by prepending a "%" and appending
# a 1- or 2-digit sequence number. In the functions that follow,
# the CHAIN, LEVEL and TAG variable serves as arguments to the user's
# exit. We call the exit corresponding to the name of the action but we
# set CHAIN to the name of the iptables chain where rules are to be added.
# Similarly, LEVEL and TAG contain the log level and log tag respectively.
#
# For each <action>, we maintain two variables:
#
#    <action>_actchain - The action chain number.
#    <action>_chains   - List of ( level[:tag] , chainname ) pairs
#
# The maximum length of a chain name is 30 characters -- since the log
# action chain name is 2-3 characters longer than the base chain name,
# this function truncates the original chain name where necessary before
# it adds the leading "%" and trailing sequence number.#
# 
sub createlogactionchain( $$ ) {
    my ( $action, $level ) = @_;
    my $chain = $action;
    my $actionref = $actions{$action};
    my $chainref;

    $chain = substr $chain, 0, 28 if ( length $chain ) > 28;
	
    while ( $chain_table{'%' . $chain . $actionref->{actchain}} ) {
	$chain = substr $chain, 0, 27 if $actionref->{actchain} == 10 and length $chain == 28;
    }

    $actionref = new_action $action unless $actionref;

    $level = 'none' unless $level;

    $logactionchains{"$action:$level"} = new_chain 'filter', '%' . $chain . $actionref->{actchain}++;

    #
    # Fixme -- action file
    #
}

#
# Create an action chain and run it's associated user exit
#
sub createactionchain( $ ) {
    my ( $action , $level ) = split_action $_[0];

    if ( $level ) {
	if ( $level eq 'none' ) {
	    $logactionchains{"$action:none"} = new_chain 'filter', $action;
	} else {
	    createlogactionchain $action , $level;
	}
    } else {
	$logactionchains{"$action:none"} = new_chain 'filter', $action;
    }
}

#
# Find the chain that handles the passed action. If the chain cannot be found,
# a fatal error is generated and the function does not return.
#
sub find_logactionchain( $ ) {
    my $fullaction = $_[0];
    my ( $action, $level ) = split_action $fullaction;

    $level = 'none' unless $level;

    fatal_error "Fatal error in find_logactionchain" unless $logactionchains{"$action:$level"};
}

#
# Combine fields from a macro body with one from the macro invocation
#
sub merge_macro_source_dest( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( $invocation ) {
	if ( $body ) {
	    return $body if $invocation eq '-';
	    return "$body:$invocation" if $invocation =~ /.*?\.*?\.|^\+|^~|^!~/;
	    return "$invocation:$body";
	}
    }
    
    $body || '';
}

sub merge_macro_column( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( $invocation ) {
	return ( $body || '') if $invocation eq '-';
	$invocation || '';
    } else {
	$body || '';
    }
}

#
# Try to find a macro file -- RETURNS false if the file doesn't exist or MACRO if it does.
# If the file exists, the macro is entered into the 'targets' table and the fully-qualified
# name of the file is stored in the 'macro' table.
#
sub find_macro( $ )
{
    my $macro = $_[0];
    my $macrofile = find_file "macro.$macro";

    if ( -f $macrofile ) {
	$macros{$macro} = $macrofile;
	$targets{$macro} = MACRO;
    }
}    

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
# Macro and action files can have shell variables embedded. This function expands them from %ENV.
#
sub expand_shell_variables( $ ) {
    my $line = $_[0]; $line = $1 . ( $ENV{$2} || '' ) . $3 while $line =~ /^(.*?)\$([a-zA-Z]\w*)(.*)$/; $line;
}
    
sub process_rule1 ( $$$$$$$$$ );

#
# Expand a macro rule from the rules file
#
sub process_macro ( $$$$$$$$$$$ ) {
    my ($macrofile, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user) = @_;

    my $standard = ( $macrofile =~ /^($env{SHAREDIR})/ );

    progress_message "..Expanding Macro $macrofile...";

    open M, $macrofile or fatal_error "Unable to open $macrofile: $!";

    while ( $line = <M> ) {
	chomp $line;
	next if $line =~ /^\s*#/;
	next if $line =~ /^\s*$/;
	$line =~ s/\s+/ /g;
	$line =~ s/#.*$//;
	$line = expand_shell_variables $line unless $standard;
		
	my ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split /\s+/, $line;
	
	$mtarget = merge_levels $target, $mtarget;
	
	if ( $mtarget =~ /^PARAM:?/ ) {
	    fatal_error 'PARAM requires that a parameter be supplied in macro invocation' unless $param;
	    $mtarget = substitute_action $param,  $mtarget;
	}

	my $action     = isolate_basic_target $mtarget;
	my $actiontype = $targets{$action};

	if ( $actiontype & ACTION ) {
	    unless ( $usedactions{$action} ) {
		createactionchain $mtarget;
		$usedactions{$mtarget} = 1;
	    }
	    
	    $mtarget = find_logactionchain $mtarget;
	} else {
	    fatal_error "Invalid Action ($mtarget) in rule \"$line\""  unless $actiontype & STANDARD;
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

	progress_message "   Rule \"$line\" $done";    }

    close M;

    progress_message '..End Macro'
}

#
# Once a rule has been completely resolved by macro expansion, it is processed by this function.
#
sub process_rule1 ( $$$$$$$$$ ) {
    my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user ) = @_;
    my ( $action, $loglevel) = split_action $target;
    my $rule = '';
    my $actionchainref;

    $ports     = '' unless defined $ports;
    $sports    = '' unless defined $sports;
    $origdest  = '' unless defined $origdest;
    $ratelimit = '' unless defined $ratelimit;
    $user      = '' unless defined $user;
    
    #
    # Determine the validity of the action
    #
    my $actiontype = $targets{$action} || find_macro( isolate_basic_target $action );

    fatal_error "Unknown action ($action) in rule \"$line\"" unless $actiontype;

    if ( $actiontype == MACRO ) {
	process_macro 
	    $macros{isolate_basic_target $action}, $
	    target , 
	    (split '/', $action)[1] , 
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
	    $dest = "$firewall_zone" . '::' . "$dest";
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

    fatal_error "Unknown source zone ($sourcezone) in rule \"$line\"" unless $zones{$sourcezone}; 
    fatal_error "Unknown destination zone ($destzone) in rule \"$line\"" unless $zones{$destzone};
    #
    # Take care of chain
    #
    my $chain    = "${sourcezone}2${destzone}";
    my $chainref = ensure_filter_chain $chain, 1;
    #
    # Validate Policy
    #
    my $policy   = $chainref->{policy};
    fatal_error "No policy defined from $sourcezone to zone $destzone" unless $policy;
    fatal_error "Rules may not override a NONE policy: rule \"$line\"" if $policy eq 'NONE';
    #
    # Generate Fixed part of the rule
    #
    $rule = do_proto $proto, $ports, $sports . do_ratelimit( $ratelimit ) . ( do_user $user );

    $origdest = ALLIPv4 unless $origdest and $origdest ne '-';
    #
    # Generate NAT rule(s), if any
    #
    if ( $actiontype & NATRULE ) {
	my ( $server, $serverport , $natchain );
	fatal_error "$target rules not allowed in the $section SECTION"  if $section ne 'NEW';
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

	fatal_error "A server must be specified in the DEST column in $action rules: \"$line\"" unless ( $actiontype & REDIRECT ) || $server;
	fatal_error "Invalid server ($server), rule: \"$line\"" if $server =~ /:/;
	#
	# Generate the target
	#
	my $target = '';

	if ( $action eq 'SAME' ) {
	    fatal_error 'Port mapping not allowed in SAME rules' if $serverport;
	    $target = '-j SAME ';
	    for my $serv ( split /,/, $server ) {
		$target .= "--to $serv ";
	    }

	    $serverport = $ports;
	} elsif ( $action eq ' -j DNAT' ) {
	    $serverport = ":$serverport" if $serverport;
	    for my $serv ( split /,/, $server ) {
		$target .= "--to ${serv}${serverport} ";
	    }
	} else {
	    $target = '-j REDIRECT --to-port ' . ( $serverport ? $serverport : $ports );
	}

	#
	# And generate the nat table rule(s)
	#
	expand_rule
	    ensure_chain ('nat' , $zones{$sourcezone}{type} eq 'firewall' ? 'OUTPUT' : dnat_chain $sourcezone ) ,
	    $rule ,
	    $source ,
	    $origdest ,
	    '' ,
	    $target ,
	    $loglevel ,
	    $action , 
	    $serverport ? do_proto( $proto, '', '' ) : '';
	#
	# After NAT, the destination port will be the server port; Also, we log NAT rules in the nat table rather than in the filter table.
	#
	unless ( $actiontype & NATONLY ) {
	    $rule = do_proto $proto, $ports, $sports . do_ratelimit( $ratelimit ) . do_user $user;
	    $loglevel = '';
	}
    } elsif ( $actiontype & NONAT ) {
	#
	# NONAT or ACCEPT+ -- May not specify a destination interface
	#
	fatal_error "Invalid DEST ($dest) in $action rule \"$line\"" if $dest =~ /:/;
 
	expand_rule
	    ensure_chain ('nat' , $zones{$sourcezone}{type} eq 'firewall' ? 'OUTPUT' : dnat_chain $sourcezone) ,
	    $rule ,
	    $source ,
	    $dest ,
	    '' ,
	    '-j RETURN ' ,
	    $loglevel ,
	    $action ,
	    '';
    }
    #
    # Add filter table rule, unless this is a NATONLY rule type
    #
    unless ( $actiontype & NATONLY ) {

	if ( $actiontype & ACTION ) {
	    $action = (find_logactionchain $target)->{name};
	    $loglevel = '';
	}

	expand_rule
	    ensure_chain ('filter', $chain ) ,
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
					if ( $loglevel ) {
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
		    process_rule1 $target, $zone, $dest , $proto, $ports, $sports, $origdest, $ratelimit, $user;
		}
	    } 
	}
    } elsif ( $dest eq 'all' ) {
	for my $zone1 ( @zones ) {
	    my $zone = ( split /:/, $source )[0];
	    if ( ( $includedstfw || ( $zones{$zone1}{type} ne 'firewall') ) &&( ( $zone ne $zone1 ) || $intrazone) ) {
		process_rule1 $target, $source, $zone1 , $proto, $ports, $sports, $origdest, $ratelimit, $user;
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

    open RULES, "$ENV{TMP_DIR}/rules" or fatal_error "Unable to open stripped rules file: $!";

    while ( $line = <RULES> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user, $extra ) = split /\s+/, $line;

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
	    fatal_error "Invalid rules file entry: \"$line\"" if $extra;
	    process_rule $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user;
	}
    }
	
    close RULES;

    $comment = '';
    $section = 'DONE';
}

#
# Generate chain for non-builtin action invocation
#	
sub process_action3( $$$$$ ) {
    #
    # This function is called to process each rule generated from an action file.
    #
    sub process_action( $$$$$$$$$$ ) {
	my ($chainref, $actionname, $target, $source, $dest, $proto, $ports, $sports, $rate, $user ) = @_;
	
	my ( $action , $level ) = split_action $target;
	
	expand_rule ( $chainref ,
		      do_proto( $proto, $ports, $sports ) . do_ratelimit( $rate ) . do_user $user , 
		      $source ,
		      $dest ,
		      '', #Original Dest
		      '-j ' . ($action eq 'REJECT' ? 'reject' : $action eq 'CONTINUE' ? 'RETURN' : $action),
		      $level ,
		      $action ,
		      '' );
    }

    my ( $chainref, $wholeaction, $action, $level, $tag ) = @_;
    my $actionfile = find_file "action.$action";
    my $standard = ( $actionfile =~ /^($env{SHAREDIR})/ );

    fatal_error "Missing Action File: $actionfile" unless -f $actionfile;

    progress_message2 "Processing $actionfile for chain $chainref->{name}...";

    open A, $actionfile or fatal_error "Unable to open $actionfile: $!";

    while ( $line = <A> ) {
	chomp $line;
	next if $line =~ /^\s*#/;
	next if $line =~ /^\s*$/;
	$line =~ s/\s+/ /g;
	$line =~ s/#.*$//;	
	$line = expand_shell_variables $line unless $standard;
		
	my ($target, $source, $dest, $proto, $ports, $sports, $rate, $user , $extra ) = split /\s+/, $line;

	my $target2 = merge_levels $wholeaction, $target;

	my ( $action2 , $level2 ) = split_action $target2;

	my $action2type = $targets{isolate_basic_target $action2};

	unless ( $action2type == STANDARD ) {
	    if ( $target eq 'COMMENT' ) {
		if ( $capabilities{COMMENTS} ) {
		    ( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		    $comment =~ s/\s*$//;
		} else {
		    warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
		}
	    } elsif ( $action2type & ACTION ) {
		$target2 = (find_logactionchain ( $target = $target2 ))->{name};
	    } else {
		die "Internal Error" unless $action2type == MACRO;
	    }
	}

	if ( $action2type == MACRO ) {
	    ( $action2, my $param ) = split '/', $action2;

	    fatal_error "Null Macro" unless my $fn = $macros{$action2};

	    progress_message "..Expanding Macro $fn...";

	    open M, $fn or fatal_error "Can't open $fn: $!";
	    
	    my $standard = ( $fn =~ /^($env{SHAREDIR})/ );
	    
	    while ( $line = <M> ) {
		next if $line =~ /^\s*#/;
		next if $line =~ /^\s*$/;
		$line =~ s/\s+/ /g;
		$line =~ s/#.*$//;
		$line = expand_shell_variables $line unless $standard;

		my ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split /\s+/, $line;
		
		if ( $mtarget =~ /^PARAM:?/ ) {
		    fatal_error 'PARAM requires that a parameter be supplied in macro invocation' unless $param;
		    $mtarget = substitute_action $param,  $mtarget;
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

		process_action $chainref, $action, $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser;
	    }

	    close M;
	    
	    progress_message '..End Macro'

	} else {
	    process_action $chainref, $action, $target2, $source, $dest, $proto, $ports, $sports, $rate, $user;
	} 
    }

    $comment = '';
}	

#
# The next three functions implement the three phases of action processing.
#
# The first phase (process_actions1) occurs before the rules file is processed. ${SHAREDIR}/actions.std
# and ${CONFDIR}/actions are scanned (in that order) and for each action:
#
#      a) The related action definition file is located and scanned.
#      b) Forward and unresolved action references are trapped as errors.
#      c) A dependency graph is created using the 'requires' field in the 'actions' table.
#
# As the rules file is scanned, each action[:level[:tag]] is merged onto the 'usedactions' hash. When an <action>
# is merged into the hash, its action chain is created. Where logging is specified, a chain with the name
# %<action>n is used where the <action> name is truncated on the right where necessary to ensure that the total
# length of the chain name does not exceed 30 characters.
#
# The second phase (process_actions2) occurs after the rules file is scanned. The transitive closure of
# %usedactions is generated; again, as new actions are merged into the hash, their action chains are created.
#
# The final phase (process_actions3) is to traverse the keys of %usedactions populating each chain appropriately
# by reading the action definition files and creating rules. Note that a given action definition file is
# processed once for each unique [:level[:tag]] applied to an invocation of the action.
#    
sub process_actions1() {

    for my $act ( grep $targets{$_} & ACTION , keys %targets ) {
	new_action $act;
    }

    for my $file qw/actions.std actions/ {
	open F, "$ENV{TMP_DIR}/$file" or fatal_error "Unable to open stripped $file file: $!";
	
	while ( $line = <F> ) {
	    chomp $line;
	    my ( $action , $extra ) = split /\s+/, $line;
	    fatal_error "Invalid Action: $line" if $extra;
	    
	    if ( $action =~ /:/ ) {
		warning_message 'Default Actions are now specified in /etc/shorewall/shorewall.conf';
		$action =~ s/:.*$//;
	    }

	    next unless $action;

	    if ( $targets{$action} ) {
		next if $targets{$action} & ACTION;
		fatal_error "Invalid Action Name: $action";
	    }

	    $targets{$action} = ACTION;

	    fatal_error "Invalid Action Name: $action" unless "\L$action" =~ /^[a-z]\w*$/;

	    new_action $action;

	    my $actionfile = find_file "action.$action";

	    fatal_error "Missing Action File: $actionfile" unless -f $actionfile;

	    progress_message2 "   Pre-processing $actionfile...";

	    open A, $actionfile or fatal_error "Unable to open $actionfile: $!";

	    while ( $line = <A> ) {
		chomp $line;
		next if $line =~ /^\s*#/;
		next if $line =~ /^\s*$/;
		$line =~ s/\s+/ /g;
		$line =~ s/#.*$//;
		
		( my ($wholetarget, $source, $dest, $proto, $ports, $sports, $rate, $users ) , $extra ) = split /\s+/, $line;
		
		fatal_error "Invalid action rule \"$line\"\n" if $extra;

		my ( $target, $level ) = split_action $wholetarget;
		
		$level = 'none' unless $level;

		my $targettype = $targets{$target};

		if ( defined $targettype ) {
		    next if ( $targettype == STANDARD ) || ( $targettype == MACRO ) || ( $target eq 'LOG' );
		  
		    fatal_error "Invalid TARGET ($target) in action rule \"$line\"" if $targettype & STANDARD;

		    add_requiredby $wholetarget, $action if $targettype & ACTION;
		} else {
		    $target =~ s!/.*$!!;

		    if ( find_macro $target ) {
			my $macrofile = $macros{$target};

			progress_message "   ..Expanding Macro $macrofile...";
			
			open M, $macrofile or fatal_error "Unable to open $macrofile: $!";

			while ( $line = <M> ) {
			    next if $line =~ /^\s*#/;
			    $line =~ s/\s+/ /g;
			    $line =~ s/#.*$//;
			    next if $line =~ /^\s*$/;
			    
			    my ( $mtarget, $msource,  $mdest,  $mproto,  $mports,  $msports, $ mrate, $muser, $mextra ) = split /\s+/, $line;

			    fatal_error "Invalid macro rule \"$line\"" if $mextra;

			    $mtarget =~ s/:.*$//;

			    $targettype = $targets{$mtarget};

			    $targettype = 0 unless defined $targettype;

			    fatal_error "Invalid target ($mtarget) in rule \"$line\"" 
				unless ( $targettype == STANDARD ) || ( $mtarget eq 'PARAM' ) || ( $mtarget eq 'LOG' );
			}

			progress_message "   ..End Macro";
			
			close M;
		    } else {
			fatal_error "Invalid TARGET ($target) in rule \"$line\"";
		    }
		}
	    }
	    close A;
	}
	close F;
    }
}

sub process_actions2 () {  
    progress_message2 'Generating Transitive Closure of Used-action List...'; 

    my $changed = 1;

    while ( $changed ) {
	$changed = 0;
	for my $target (keys %usedactions) {
	    my ($action, $level) = split_action $target;
	    my $actionref = $actions{$action};
	    die "Null Action Reference in process_actions2" unless $actionref;
	    for my $action1 ( keys %{$actionref->{requires}} ) {
		my $action2 = merge_levels $target, $action1;
		unless ( $usedactions{ $action2 } ) {
		    $usedactions{ $action2 } = 1;
		    createactionchain $action2;
		    $changed = 1;
		}
	    }
	}
    }
}
		
sub process_actions3 () {
    #
    # The following small functions generate rules for the builtin actions of the same name
    #
    sub dropBcast( $$$ ) {
	my ($chainref, $level, $tag) = @_;
	
	if ( $level ) {
	    log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -m pkttype --pkt-type broadcast';
	    log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -m pkttype --pkt-type multicast';
	}
	
	add_rule $chainref, '-m pkttype --pkt-type broadcast -j DROP';
	add_rule $chainref, '-m pkttype --pkt-type multicast -j DROP';
    }
    
    sub allowBcast( $$$ ) {
	my ($chainref, $level, $tag) = @_;
	
	if ( $level ) {
	    log_rule_limit $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add', ' -m pkttype --pkt-type broadcast';
	    log_rule_limit $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add', ' -m pkttype --pkt-type multicast';
	}
	
	add_rule $chainref, '-m pkttype --pkt-type broadcast -j ACCEPT';
	add_rule $chainref, '-m pkttype --pkt-type multicast -j ACCEPT';
    }
    
    sub dropNotSyn ( $$$ ) {
	my ($chainref, $level, $tag) = @_;
	
	log_rule_limit $level, $chainref, 'dropNotSyn' , 'DROP', '', $tag, 'add', '-p tcp ! --syn ' if $level;    
	add_rule $chainref , '-p tcp ! --syn -j DROP';
    }
    
    sub rejNotSyn ( $$$ ) {
	my ($chainref, $level, $tag) = @_;

	log_rule_limit $level, $chainref, 'rejNotSyn' , 'REJECT', '', $tag, 'add', '-p tcp ! --syn ' if $level;    
	add_rule $chainref , '-p tcp ! --syn -j REJECT';
    }
    
    sub dropInvalid ( $$$ ) {
	my ($chainref, $level, $tag) = @_;
	
	log_rule_limit $level, $chainref, 'dropInvalid' , 'DROP', '', $tag, 'add', '-m state --state INVALID ' if $level;    
	add_rule $chainref , '-m state --state INVALID -j REJECT';
    }

    sub allowInvalid ( $$$ ) {
	my ($chainref, $level, $tag) = @_;
	
	log_rule_limit $level, $chainref, 'allowInvalid' , 'ACCEPT', '', $tag, 'add', '-m state --state INVALID ' if $level;    
	add_rule $chainref , '-m state --state INVALID -j ACCEPT';
    }
    
    sub forwardUPnP ( $$$ ) {
    }

    sub allowinUPnP ( $$$ ) {
	my ($chainref, $level, $tag) = @_;
	
	if ( $level ) {
	    log_rule_limit $level, $chainref, 'allowinUPnP' , 'ACCEPT', '', $tag, 'add', '-p udp --dport 1900 ';
	    log_rule_limit $level, $chainref, 'allowinUPnP' , 'ACCEPT', '', $tag, 'add', '-p tcp --dport 49152 ';
	}
	
	add_rule $chainref, '-p udp --dport 1900 -j ACCEPT';
	add_rule $chainref, '-p tcp --dport 49152 -j ACCEPT';
    }
    
    sub Limit( $$$ ) {
	my ($chainref, $level, $tag) = @_;
	
	my @tag = split /,/, $tag;
	
	fatal_error 'Limit rules must include <set name>,<max connections>,<interval> as the log tag' unless @tag == 3;
	
	add_rule $chainref, '-m recent --name $tag[0] --set';
	
	if ( $level ) {
	    my $xchainref = new_chain 'filter' , "$chainref->{name}%";
	    log_rule_limit $level, $xchainref, $tag[0], 'DROP', '', '', 'add', '';
	    add_rule $xchainref, '-j DROP';
	    add_rule $chainref,  "-m recent --name $tag[0] --update --seconds $tag[2] --hitcount $(( $tag[1] + 1 )) -j $chainref->{name}%";
	} else {
	    add_rule $chainref, "-m recent --update --name $tag[0] --seconds $tag[2] --hitcount $(( $tag[1] + 1 )) -j DROP";
	}
	
	add_rule $chainref, '-j ACCEPT';
    }

    my %builtinops = ( 'dropBcast'    => \&dropBcast,
		       'allowBcast'   => \&allowBcast,
		       'dropNotSyn'   => \&dropNotSyn,
		       'rejNotSyn'    => \&rejNotSyn,
		       'dropInvalid'  => \&dropInvalid,
		       'allowInvalid' => \&allowInvalid,
		       'allowinUPnP'  => \&allowinUPnP,
		       'forwardUPnP'  => \&forwardUPnP,
		       'Limit'        => \&Limit,
		       );

    for my $wholeaction ( keys %usedactions ) {
	my $chainref = find_logactionchain $wholeaction;
	my ( $action, $level, $tag ) = split /:/, $wholeaction;

	$level = '' unless defined $level;
	$tag   = '' unless defined $tag;
	
	if ( $targets{$action} & BUILTIN ) {
	    $level = '' if $level =~ /none!?/;
	    $builtinops{$action}->($chainref, $level, $tag);
	} else {
	    process_action3 $chainref, $wholeaction, $action, $level, $tag;
	}
    }   
}

sub dump_action_table() {
    my $action;

    print "\n";

    for $action ( sort keys %actions ) {
	print "Action $action\n";
	my $already = 0;
	for my $requires ( keys %{$actions{$action}{requires}} ) {
	    print "   Requires:\n" unless $already;
	    print "      $requires\n";
	    $already = 1;
	}
    }

    print "\nAction Chains:\n";

    for $action ( sort keys %usedactions ) {
	$action .= ':none' unless $action =~ /:/;
	print "   $action = $logactionchains{$action}{name}\n";
    }
}

#
# Accounting
#
my $jumpchainref;

sub process_accounting_rule( $$$$$$$$ ) {
    my ($action, $chain, $source, $dest, $proto, $ports, $sports, $user ) = @_;

    sub accounting_error() {
	warning_message "Invalid Accounting rule \"$line\"";
    }

    sub jump_to_chain( $ ) {
	my $jumpchain = $_[0];
	$jumpchainref = ensure_chain( 'filter', $jumpchain );
	"-j $jumpchain";
    }

    $chain = 'accounting' unless $chain and $chain ne '-';
    
    my $chainref = ensure_filter_chain $chain , 0;

    my $target = '';

    my $rule = do_proto( $proto, $ports, $sports ) . do_user ( $user );
    my $rule2 = 0;

    unless ( $action eq 'COUNT' ) {
	if ( $action eq 'DONE' ) {
	    $target = '-j RETURN';
	} else {
	    ( $action, my $cmd ) = split /:/, $action;
	    if ( $cmd ) {
		if ( $cmd eq 'COUNT' ) {
		    $rule2=1;
		    $target = jump_to_chain $action;
		} elsif ( $cmd ne 'JUMP' ) {
		    accounting_error;
		}
	    } else {
		$target = jump_to_chain $action;
	    }
	}
    }

    expand_rule
	$chainref ,
	$rule ,
	$source ,
	$dest ,
	'' ,
	$target ,
	'' ,
	'' ,
	'' ;

    if ( $rule2 ) {
	expand_rule 
	    $jumpchainref ,
	    $rule ,
	    $source ,
	    $dest ,
	    '' ,
	    '' ,
	    '' ,
	    '' ,
	    '' ;
    }
}

sub setup_accounting() {

    open ACC, "$ENV{TMP_DIR}/accounting" or fatal_error "Unable to open stripped accounting file: $!";

    while ( $line = <ACC> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $action, $chain, $source, $dest, $proto, $ports, $sports, $user, $extra ) = split /\s+/, $line;

	accounting_error if $extra;
	process_accounting_rule $action, $chain, $source, $dest, $proto, $ports, $sports, $user;
    }
	
    close ACC;

    if ( $filter_table->{accounting} ) {
	for my $chain qw/INPUT FORWARD OUTPUT/ {
	    insert_rule $filter_table->{$chain}, 1, '-j accounting';
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
do_initialize;

compile_firewall $ARGV[0];
