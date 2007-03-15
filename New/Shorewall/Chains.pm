package Shorewall::Chains;
require Exporter;

use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Interfaces;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( STANDARD
		  NATRULE
		  BUILTIN
		  NONAT
		  NATONLY
		  REDIRECT
		  ACTION
		  MACRO
		  LOGRULE
		  
		  add_rule
		  insert_rule
		  chain_base
		  forward_chain
		  input_chain
		  output_chain
		  masq_chain
		  syn_chain
		  mac_chain
		  macrecent_target
		  dynamic_fwd
		  dynamic_in
		  dynamic_out
		  dynamic_chains
		  dnat_chain
		  snat_chain
		  ecn_chain
		  first_chains
		  new_chain
		  ensure_chain
		  ensure_filter_chain
		  new_standard_chain
		  new_builtin_chain
		  initialize_chain_table
		  dump_chain_table
		  finish_section
		  newexclusionchain
		  clearrule
		  do_proto
		  mac_match
		  numeric_value
		  verify_mark
		  verify_small_mark
		  validate_mark
		  do_test
		  do_ratelimit
		  do_user
		  iprange_match
		  match_source_net
		  match_dest_net
		  match_orig_dest
		  match_ipsec_in
		  match_ipsec_out
		  log_rule_limit
		  log_rule
		  expand_rule
		  addnatjump
		  insertnatjump
		  generate_matrix
		  create_netfilter_load
		  
		  @policy_chains 
		  %chain_table 
		  $nat_table 
		  $mangle_table 
		  $filter_table
		  $section
		  %sections
		  $comment 
		  %targets
		  );
our @EXPORT_OK = ();
our @VERSION = 1.00;

#
# Chain Table
#
#    @policy_chains is a list of references to policy chains in the filter table
#
#    %chain_table { <table> => { <chain1>  => { name         => <chain name>
#                                               is_policy    => 0|1
#                                               is_optionsl  => 0|1
#                                               referenced   => 0|1      
#                                               policy       => <policy>
#                                               loglevel     => <level>
#                                               synparams    => <burst/limit>
#                                               default      => <default action>
#                                               policy_chain => <ref to policy chain -- self-reference if this is a policy chain>
#                                               rules        => [ <rule1>
#                                                                 <rule2>
#                                                                 ...
#                                                               ]
#
#       'is_optional' only applies to policy chains; when true, indicates that this is a provisional policy chain which might be
#       replaced. Policy chains created under the IMPLICIT_CONTINUE=Yes option are optional.
#
#       Only 'referenced' chains get written to the iptables-restore output.
#
#       'loglevel', 'synparams' and 'default' only apply to policy chains. 
#
our @policy_chains;
our %chain_table = ( raw    => {} , 
		     mangle => {},
		     nat    => {},
		     filter => {} );

our $nat_table    = $chain_table{nat};
our $mangle_table = $chain_table{mangle};
our $filter_table = $chain_table{filter};

#
# These get set to 1 as sections are encountered.
#
our %sections = ( ESTABLISHED => 0,
		  RELATED     => 0,
		  NEW         => 0
		  );
#
# Current rules file section.
#
our $section  = 'ESTABLISHED';
#
# Contents of last COMMENT line.
#
our $comment = '';
#  Target Table. Each entry maps a target to a set of flags defined as follows.
#
use constant { STANDARD => 1,              #defined by Netfilter
	       NATRULE  => 2,              #Involved NAT
	       BUILTIN  => 4,              #A built-in action
	       NONAT    => 8,              #'NONAT' or 'ACCEPT+'
	       NATONLY  => 16,             #'DNAT-' or 'REDIRECT-'
	       REDIRECT => 32,             #'REDIRECT'
	       ACTION   => 64,             #An action
	       MACRO    => 128,            #A Macro
	       LOGRULE  => 256,            #'LOG'
	   };
#
#   As new targets (Actions and Macros) are discovered, they are added to the table
#
our %targets = ('ACCEPT'       => STANDARD,
		'ACCEPT+'      => STANDARD  + NONAT,
		'ACCEPT!'      => STANDARD,
		'NONAT'        => STANDARD  + NONAT,
		'DROP'         => STANDARD,
		'DROP!'        => STANDARD,
		'REJECT'       => STANDARD,
		'REJECT!'      => STANDARD,
		'DNAT'         => NATRULE,
		'DNAT-'        => NATRULE  + NATONLY,
		'REDIRECT'     => NATRULE  + REDIRECT,
		'REDIRECT-'    => NATRULE  + REDIRECT + NATONLY,
		'LOG'          => STANDARD + LOGRULE,
		'CONTINUE'     => STANDARD,
		'QUEUE'        => STANDARD,
		'SAME'         => NATRULE,
		'SAME-'        => NATRULE  + NATONLY,
		'dropBcast'    => BUILTIN  + ACTION,
		'allowBcast'   => BUILTIN  + ACTION,
		'dropNotSyn'   => BUILTIN  + ACTION,
		'rejNotSyn'    => BUILTIN  + ACTION,
		'dropInvalid'  => BUILTIN  + ACTION,
		'allowInvalid' => BUILTIN  + ACTION,
		'allowinUPnP'  => BUILTIN  + ACTION,
		'forwardUPnP'  => BUILTIN  + ACTION,
		'Limit'        => BUILTIN  + ACTION,
		);
#
# Used to sequence 'exclusion' chains with names 'excl0', 'excl1', ...
#
my $exclseq = 0;
#
# Used to suppress duplicate match specifications.
#
my $ipsetmatch   = 0;
my $iprangematch = 0;
#

#
# Add a rule to a chain. Arguments are:
#
#    Chain reference , Rule
#
sub add_rule($$)
{
    my ($chainref, $rule) = @_;
    
    $rule .= " -m comment --comment \"$comment\"" if $comment;

    push @{$chainref->{rules}}, $rule;

    $chainref->{referenced} = 1;

    $iprangematch = 0;
    $ipsetmatch   = 0;
}

#
# Insert a rule into a chain. Arguments are:
#
#    Table , Chain , Rule Number, Rule
#
sub insert_rule($$$)
{
    my ($chainref, $number, $rule) = @_;
    
    $rule .= "-m comment --comment \"$comment\"" if $comment;

    splice @{$chainref->{rules}}, $number - 1, 0,  $rule;

    $chainref->{referenced} = 1;
    
    $iprangematch = 0;
    $ipsetmatch   = 0;
}

#
# Form the name of a chain. 
#
sub chain_base($) {
    my $chain = $_[0];

    $chain =~ s/^@/at_/;
    $chain =~ s/[.\-%@]/_/g;
    $chain;
}

#
# Forward Chain for an interface
#
sub forward_chain($)
{
    chain_base $_[0] . '_fwd';
}

#
# Input Chain for an interface
#
sub input_chain($)
{
    chain_base $_[0] . '_in';
}

#
# Output Chain for an interface
#
sub output_chain($)
{
    chain_base $_[0] . '_out';
}

#
# Masquerade Chain for an interface
#
sub masq_chain($)
{
    chain_base $_[0] . '_masq';
}

#
# Syn_chain
#
sub syn_chain ( $ ) {
    '@' . $_[0];
}
#
# MAC Verification Chain for an interface
#
sub mac_chain( $ )
{
    chain_base $_[0] . '_mac';
}

sub macrecent_target($)
{
     $config{MACLIST_TTL} ? chain_base $_[0] . '_rec' : 'RETURN';
}

#
# Functions for creating dynamic zone rules
#
sub dynamic_fwd( $ )
{
    chain_base $_[0] . '_dynf';
}

sub dynamic_in( $ )
{
    chain_base $_[0] . '_dyni';
}

sub dynamic_out( $ ) # $1 = interface
{
    chain_base $_[0] . '_out';
}

sub dynamic_chains( $ ) #$1 = interface
{
    my $c = chain_base $_[0];

    [ $c . '_dyni' , $c . '_dynf' , $c . '_dyno' ];
}

#
# DNAT Chain from a zone
#
sub dnat_chain( $ )
{
    chain_base $_[0] . '_dnat';
}

#
# SNAT Chain to an interface
#
sub snat_chain( $ )
{
    chain_base $_[0] . '_snat';
}

#
# ECN Chain to an interface
#
sub ecn_chain( $ )
{
    chain_base $_[0] . '_ecn';
}

#
# First chains for an interface
#
sub first_chains( $ ) #$1 = interface
{
    my $c = chain_base $_[0];

    [ $c . '_fwd', $c . '_in' ];
}

#
# Create a new chain and return a reference to it.
#
sub new_chain($$)
{
    my ($table, $chain) = @_;
    my %ch;
    my @rules;
    
    $ch{name} = $chain;
    $ch{log} = 1 if $env{LOGRULENUMBERS};
    $ch{rules} = \@rules;
    $ch{table} = $table;
    $chain_table{$table}{$chain} = \%ch;
    \%ch;
}

#
# Create a chain if it doesn't exist already
#
sub ensure_chain($$)
{
    my ($table, $chain) = @_;

    my $ref =  $chain_table{$table}{$chain};
    
    return $ref if $ref;

    new_chain $table, $chain;
}

sub finish_chain_section( $$ );

#
# Create a filter chain if necessary. Optionally populate it with the appropriate ESTABLISHED,RELATED rule(s) and perform SYN rate limiting.
#
sub ensure_filter_chain( $$ )
{
    my ($chain, $populate) = @_;

    my $chainref = $filter_table->{$chain};

    $chainref = new_chain 'filter' , $chain unless $chainref;

    if ( $populate and ! $chainref->{referenced} ) {
	if ( $section eq 'NEW' or $section eq 'DONE' ) {
	    finish_chain_section $chainref , 'ESTABLISHED,RELATED';
	} elsif ( $section eq 'ESTABLISHED' ) {
	    finish_chain_section $chainref , 'ESTABLISHED';
	}
    }

    $chainref->{referenced} = 1;
	    
    $chainref;
}

#
# Add a builtin chain
#
sub new_builtin_chain($$$)
{
    my $chainref = new_chain $_[0],$_[1];
    $chainref->{referenced} = 1;
    $chainref->{policy}     = $_[2];
    $chainref->{builtin}    = 1;
}

sub new_standard_chain($) {
    my $chainref = new_chain 'filter' ,$_[0];
    $chainref->{referenced} = 1;
    $chainref;
}    

#
# Add all builtin chains to the chain table
#
#
sub initialize_chain_table()
{
    for my $chain qw/OUTPUT PREROUTING/ {
	new_builtin_chain 'raw', $chain, 'ACCEPT';
    }

    for my $chain qw/INPUT OUTPUT FORWARD/ {
	new_builtin_chain 'filter', $chain, 'DROP';
    }

    for my $chain qw/PREROUTING POSTROUTING OUTPUT/ {
	new_builtin_chain 'nat', $chain, 'ACCEPT';
    }

    for my $chain qw/PREROUTING INPUT FORWARD OUTPUT POSTROUTING/ {
	new_builtin_chain 'mangle', $chain, 'ACCEPT';
    }
	
    if ( $capabilities{MANGLE_FORWARD} ) {
	for my $chain qw/ FORWARD POSTROUTING / {
	    new_builtin_chain 'mangle', $chain, 'ACCEPT';
	}
    }
}

#
# Dump the contents of the Chain Table
#
sub dump_chain_table()
{
    print "\n";

    for my $table qw/filter nat mangle/ {
	print "Table: $table\n";

	for my $chain ( sort keys %{$chain_table{$table}} ) {
	    my $chainref = $chain_table{$table}{$chain};
	    print "   Chain $chain:\n";
	    
	    if ( $chainref->{is_policy} ) {
		print "      This is a policy chain\n";
		my $val = $chainref->{is_optional} ? 'Yes' : 'No';
		print "         Optional:  $val\n";
		print "         Log Level: $chainref->{loglevel}\n" if $chainref->{loglevel};
		print "         Syn Parms: $chainref->{synparams}\n" if $chainref->{synparams};
		print "         Default:   $chainref->{default}\n" if $chainref->{default};
	    }
		
	    print "      Policy chain: $chainref->{policychain}{name}\n" if $chainref->{policychain} ;
	    print "      Policy: $chainref->{policy}\n"                  if $chainref->{policy};
	    print "      Referenced\n" if $chainref->{referenced};

	    if ( @{$chainref->{rules}} ) {
		print "      Rules:\n";
		for my $rule (  @{$chainref->{rules}} ) {
		    print "         $rule\n";
		}
	    }   
	}
    }
}

#
# Add ESTABLISHED,RELATED rules and synparam jumps to the passed chain 
#
sub finish_chain_section ($$) {
    my ($chainref, $state ) = @_;
    my $chain = $chainref->{name};

    add_rule $chainref, "-m state --state $state -j ACCEPT" unless $config{FASTACCEPT};
    
    if ($sections{RELATED} ) {
	if ( $chainref->{is_policy} ) {
	    if ( $chainref->{synparams} ) {
		my $synchainref = ensure_chain 'filter', "\@$chain";
		if ( $section eq 'DONE' ) {
		    if ( $chainref->{policy} =~ /^(ACCEPT|CONTINUE|QUEUE)$/ ) {
			add_rule $chainref, "-p tcp --syn -j $synchainref->{name}";
		    } 
		} else {
		    add_rule $chainref, "-p tcp --syn -j $synchainref->{name}";
		}
	    }
	} else {
	    my $policychainref = $chainref->{policychain};
	    if ( $policychainref->{synparams} ) {
		my $synchainref = ensure_chain 'filter', "\@$policychainref->{name}";
		add_rule $synchainref, "-p tcp --syn -j $synchainref->{name}";
	    }
	}
    }
}		    

#
# Do section-end processing
# 
sub finish_section ( $ ) {
    my $sections = $_[0];

    for my $zone ( @zones ) {
	for my $zone1 ( @zones ) {
	    my $chainref = $chain_table{'filter'}{"$zone}2${zone1}"};
	    if ( $chainref->{referenced} ) {
		finish_chain_section $chainref, $sections;
	    }
	}
    }
}

sub newexclusionchain() {
    my $seq = $exclseq++;
    "excl${seq}";
}

sub clearrule() {
    $iprangematch = $ipsetmatch = 0;
}

#
# Handle parsing of PROTO, DEST PORT(S) , SOURCE PORTS(S). Returns the appropriate match string.
#
sub do_proto( $$$ )
{
    my ($proto, $ports, $sports ) = @_;

    my $output = '';
    
    $proto  = '' unless defined $proto;
    $ports  = '' unless defined $ports;
    $sports = '' unless defined $sports;

    $proto  = '' if $proto  eq '-';
    $ports  = '' if $ports  eq '-';
    $sports = '' if $sports eq '-';

    if ( $proto ) {
	if ( $proto =~ /^(tcp|udp|6|17)$/i ) {
	    $output = "-p $proto ";
	    if ( $ports ) {
		my @ports = split /,/, $ports;
		my $count = @ports; 

		if ( $count > 1 ) {
		    fatal_error "Port list requires Multiport support in your kernel/iptables: $ports" unless $capabilities{MULTIPORT};
		    fatal_error "Port range in a list requires Extended Multiport Support in your kernel/iptables: $ports" unless $capabilities{XMULTIPORT};
		    
		    for my $port ( @ports ) {
			$count++ if $port =~ /:/;
		    }
 
		    fatal_error "Too many entries in port list: $ports" if $count > 15;

		    $output .= "-m multiport --dports $ports ";
		}  else {
		    $output .= "--dport $ports ";
		}
	    }
			
	    if ( $sports ) {
		my @ports = split /,/, $sports;
		my $count = @ports; 

		if ( $count > 1 ) {
		    fatal_error "Port list requires Multiport support in your kernel/iptables: $sports" unless $capabilities{MULTIPORT};
		    fatal_error "Port range in a list requires Extended Multiport Support in your kernel/iptables: $sports" unless $capabilities{XMULTIPORT};
		    
		    for my $port ( @ports ) {
			$count++ if $port =~ /:/;
		    }
 
		    fatal_error "Too many entries in port list: $sports" if $count > 15;

		    $output .= "-m multiport --sports $sports ";
		}  else {
		    $output .= "--sport $sports ";
		}
	    }
	} elsif ( $proto =~ /^(icmp|1)$/i ) {
	    $output .= "-p icmp --icmp-type $ports " if $ports;
	    fatal_error 'SOURCE PORT(S) not permitted with ICMP' if $sports;
	} elsif ( $proto =~ /^(ipp2p(:(tcp|udp|all)))?$/i ) {
	    fatal_error 'PROTO = ipp2p requires IPP2P match support in your kernel/iptables' unless $capabilities{IPP2P};
	    $proto = $2 ? $3 : 'tcp';
	    $ports = 'ipp2p' unless $ports;
	    $output .= "-p $proto -m ipp2p --$ports ";
	}
    } elsif ( $ports || $sports ) {
	fatal_error "SOURCE/DEST PORT(S) not allowed without PROTO, rule \"$line\""
    }

    $output;
}

sub mac_match( $ ) {
    my $mac = $_[0];

    $mac =~ s/^(!?)~//;
    $mac =~ s/^!// if my $invert = $1 ? '! ' : ''; 
    $mac =~ s/-/:/g;

    "--match mac --mac-source ${invert}$mac ";
}

#
# Convert value to decimal number
#
sub numeric_value ( $ ) {
    my $mark = $_[0];
    $mark =~ /^0x/ ? hex $mark : $mark =~ /^0/ ? oct $mark : $mark;
}

#
# Mark validatation functions
#
sub verify_mark( $ ) {
    my $mark  = $_[0];
    my $limit = $config{HIGH_ROUTE_MARKS} ? 0xFFFF : 0xFF;

    fatal_error "Invalid Mark or Mask value: $mark" 
	unless "\L$mark" =~ /^(0x[a-f0-9]+|0[0-7]*|[0-9]*)$/ && numeric_value( $mark ) <= $limit;
}

sub verify_small_mark( $ ) {
    verify_mark ( (my $mark) = $_[0] );
    fatal_error "Mark value ($mark) too large" if numeric_value( $mark ) > 0xFF;
}

sub validate_mark( $ ) {
    for ( split '/', $_[0] ) {
	verify_mark $_;
    }
}

#
# Generate an appropriate -m [conn]mark match string for the contents of a MARK column
#

sub do_test ( $$ )
{
    my ($testval, $mask) = @_;
    
    return '' unless $testval and $testval ne '-';

    my $invert = $testval =~ s/^!// ? '! ' : '';
    my $match =  $testval =~ s/:C$// ? '-m connmark ' : '-m mark ';
    
    $testval .= '/0xFF' unless ( $testval =~ '/' );

    "${invert}$match $testval ";
}
    

#
# Create a "-m limit" match for the passed LIMIT/BURST
#
sub do_ratelimit( $ ) {
    my $rate = $_[0];

    return '' unless $rate and $rate ne '-';
    
    if ( $rate =~ /^([^:]+):([^:]+)$/ ) {
	"-m limit --limit $1 --limit-burst $2 ";
    } else {
	"-m limit --limit $rate ";
    }
}

#
# Create a "-m owner" match for the passed USER/GROUP
#
sub do_user( $ ) {
    my $user = $_[0];
    my $rule = ' -m owner';

    return '' unless $user and $user ne '-';

    if ( $user =~ /^(!)?(.*)\+(.*)$/ ) {
	$rule .= "! --cmd-owner $2 " if $2;
	$user = "!$1";
    } elsif ( $user =~ /^(.*)\+(.*)$/ ) {
	$rule .= "--cmd-owner $2 " if $2;
	$user = $1;
    }
	
    if ( $user =~ /^!(.*):(.*)$/ ) {
	$rule .= "! --uid-owner $1 " if $1;
	$rule .= "! --gid-owner $2 " if $2;
    } elsif ( $user =~ /^(.*):(.*)$/ ) {
	$rule .= "--uid-owner $1 " if $1;
	$rule .= "--gid-owner $2 " if $2;
    } elsif ( $user =~ /^!/ ) {
	$rule .= "! --uid-owner $user ";
    } else {
	$rule .= "--uid-owner $user ";
    }

    $rule;
}
	
#
# Avoid generating a second '-m iprange' in a single rule.
#
sub iprange_match() {
    my $match = '';
    unless ( $iprangematch ) {
	$match = '-m iprange ';
	$iprangematch = 1;
    }

    $match;
}

#
# Match a Source. Currently only handles IP addresses and ranges
#
sub match_source_net( $ ) {
    my $net = $_[0];
    
    if ( $net =~ /^(!?).*\..*\..*\..*-.*\..*\..*\..*/ ) {
	$net =~ s/!// if my $invert = $1 ? '! ' : '';

	iprange_match . "${invert}--src-range $net ";
    } elsif ( $net =~ /^(!?)~(.*)$/ ) {
	( $net = $2 ) =~ s/-/:/g;
	"-m mac --mac-source $1 $net "
    } elsif ( $net =~ /^!/ ) {
	$net =~ s/!//;
	"-s ! $net ";
    } else {
	$net eq ALLIPv4 ? '' : "-s $net ";
    }
}

#
# Match a Source. Currently only handles IP addresses and ranges
#
sub match_dest_net( $ ) {
    my $net = $_[0];
    
    if ( $net =~ /^(!?).*\..*\..*\..*-.*\..*\..*\..*/ ) {
	$net =~ s/!// if my $invert = $1 ? '! ' : '';

	iprange_match . "${invert}--src-range $net ";
    } elsif ( $net =~ /^!/ ) {
	$net =~ s/!//;
	"-d ! $net ";
    } else {
	$net eq ALLIPv4 ? '' : "-d $net ";
    }
}

#
# Match original destination
#
sub match_orig_dest ( $ ) {
    my $net = $_[0];

    return '' if $net eq ALLIPv4;
    
    if ( $net =~ /^!/ ) {
	$net =~ s/!//;
	"-m conntrack --ctorigdst ! $net ";
    } else {
	$net eq ALLIPv4 ? '' : "-m conntrack --ctorigdst $net ";
    }
}


#
# Match Source IPSEC
#
sub match_ipsec_in( $$ ) {
    my ( $zone , $hostref ) = @_;
    my $match = '-m policy --dir in --pol ';
    my $zoneref    = $zones{$zone};
    my $optionsref = $zoneref->{options};

    if ( $zoneref->{type} eq 'ipsec4' ) {
	$match .= "ipsec $optionsref->{in_out}{ipsec}$optionsref->{in}{ipsec}";
    } elsif ( $capabilities{POLICY_MATCH} ) { 
	$match .= "$hostref->{ipsec} $optionsref->{in_out}{ipsec}$optionsref->{in}{ipsec}";
    } else {
	'';
    }
}
    
#
# Match Dest IPSEC
#
sub match_ipsec_out( $$ ) {
    my ( $zone , $hostref ) = @_;
    my $match = '-m policy --dir out --pol ';
    my $zoneref    = $zones{$zone};
    my $optionsref = $zoneref->{options};

    if ( $zoneref->{type} eq 'ipsec4' ) {
	$match .= "ipsec $optionsref->{in_out}{ipsec}$optionsref->{out}{ipsec}";
    } elsif ( $capabilities{POLICY_MATCH} ) { 
	$match .= "$hostref->{ipsec} $optionsref->{in_out}{ipsec}$optionsref->{out}{ipsec}"
    } else {
	'';
    }
}
    
#
# Generate a log message
#
sub log_rule_limit( $$$$$$$$ ) {
    my ($level, $chainref, $chain, $disposition, $limit, $tag, $command, $predicates ) = @_;

    my $prefix;

    $limit = $env{LOGLIMIT} unless $limit;

    if ( $tag ) {
	if ( $config{LOGTAGONLY} ) {
	    $chain = $tag;
	    $tag   = '';
	} else {
	    $tag .= ' ';
	}
    } else {
	$tag = '' unless defined $tag;
    }

    if ( $env{LOGRULENUMBERS} ) {
	$prefix = (sprintf $config{LOGFORMAT} , $chain , $chainref->{log}++, $disposition ) . $tag;
    } else {
	$prefix = (sprintf $config{LOGFORMAT} , $chain , $disposition) . $tag;
    }

    if ( length $prefix > 29 ) {
	$prefix = substr $prefix, 0, 29;
	warning_message "Log Prefix shortened to \"$prefix\"";
    }

    if ( $level eq 'ULOG' ) {
	$prefix = "-j ULOG $env{LOGPARMS} --ulog-prefix \"$prefix\" ";
    } else {
	$prefix = "-j LOG $env{LOGPARMS} --log-level $level --log-prefix \"$prefix\" ";
    }

    if ( $command eq 'add' ) {
	add_rule ( $chainref, $predicates . $prefix );
    } else {
	insert_rule ( $chainref , 1 , $predicates . $prefix );
    }
}

sub log_rule( $$$$ ) {
    my ( $level, $chainref, $disposition, $predicates ) = @_;

    log_rule_limit $level, $chainref, $chainref->{name} , $disposition, $env{LOGLIMIT}, '', 'add', $predicates;
}
	
#
# This function provides a uniform way to generate rules (something the original Shorewall sorely needed).
# 
sub expand_rule( $$$$$$$$$ )
{
    my ($chainref , $rule, $source, $dest, $origdest, $target, $loglevel , $disposition, $exceptionrule ) = @_;
    my ($iiface, $diface, $inets, $dnets, $iexcl, $dexcl, $onets , $oexcl );

    #
    # Isolate Source Interface, if any
    #
    if ( $source ) {
	if ( $source eq '-' ) {
	    $source = '';
	} elsif ( $source =~ /^([^:]+):([^:]+)$/ ) {
	    $iiface = $1;
	    $inets  = $2;
	} elsif ( $source =~ /\+|~|\..*\./ ) {
	    $inets = $source;
	} else {
	    $iiface = $source;
	}
    } else {
	$source = '';
    }
    #
    # Verify Inteface, if any
    #
    if ( $iiface ) {
	fatal_error "Unknown Interface ($iiface): \"$line\"" unless known_interface $iiface;
	$rule .= "-i $iiface ";
    }

    #
    # Isolate Destination Interface, if any
    #
    if ( $dest ) {
	if ( $dest eq '-' ) {
	    $dest = '';
	} elsif ( $dest =~ /^([^:]+):([^:]+)$/ ) {
	    $diface = $1;
	    $dnets  = $2;
	} elsif ( $dest =~ /\+|~|\..*\./ ) {
	    $dnets = $dest;
	} else {
	    $diface = $dest;
	}
    } else {
	$dest = '';
    }
    #
    # Verify Destination Interface, if any
    #
    if ( $diface ) {
	fatal_error "Unknown Interface ($diface) in rule \"$line\"" unless known_interface $diface;
	$rule .= "-o $diface ";
    }
    
    #
    # Handle Log Level
    #
    my $logtag;

    if ( $loglevel ) {
	( $loglevel, $logtag ) = split /:/, $loglevel;
	
	if ( $loglevel =~ /^none!?$/i ) {
	    return 1 if $disposition eq 'LOG';
	    $loglevel = $logtag = '';
	}
    }

    #
    # Determine if there is Source Exclusion
    #

    if ( $inets ) {
	if ( $inets =~ /^([^!]+)?!([^!]+)$/ ) {
	    $inets = $1;
	    $iexcl = $2;
	} else {
	    $iexcl = '';
	}

	if ( ! $inets ) {
	    my @iexcl = split /,/, $iexcl;
	    if ( @iexcl == 1 ) {
		$rule .= match_source_net "!$iexcl ";
		$iexcl = '';
	    }
	}
    } else {
	$iexcl = '';
    }

    #
    # Determine if there is Destination Exclusion
    #    $dexcl = '';


    if ( $dnets ) {
	if ( $dnets =~ /^([^!]+)?!([^!]+)$/ ) {
	    $dnets = $1;
	    $dexcl = $2;
	} else {
	    $dexcl = '';
	}

	if ( ! $dnets ) {
	    my @dexcl = split /,/, $dexcl;
	    if ( @dexcl == 1 ) {
		$rule .= match_dest_net "!$dexcl ";
		$dexcl = '';
	    }
	}
    } else {
	$dexcl = '';
    }

    if ( $origdest ) {
	if ( $origdest =~ /^([^!]+)?!([^!]+)$/ ) {
	    $onets = $1;
	    $oexcl = $2;
	} else {
	    $oexcl = '';
	}

	if ( ! $onets ) {
	    my @oexcl = split /,/, $oexcl;
	    if ( @oexcl == 1 ) {
		$rule .= "-m conntrack --ctorigdst ! $oexcl ";
		$oexcl = '';
	    }
	}
    } else {
	$oexcl = '';
    }

    $inets = ALLIPv4 unless $inets;
    $dnets = ALLIPv4 unless $dnets;
    $onets = ALLIPv4 unless $onets;

    if ( $iexcl || $dexcl || $oexcl ) {
	#
	# We have non-trivial exclusion -- need to create an exclusion chain
	#
	my $echain = newexclusionchain;
	
	#
	# Use the current rule and sent all possible matches to the exclusion chain
	#
	for my $onet ( split /,/, $onets ) {
	    $onet = match_orig_dest $onet;
	    for my $inet ( split /,/, $inets ) {
		$inet = match_source_net $inet;
		for my $dnet ( split /,/, $dnets ) {
		    add_rule $chainref, $rule . $inet . ( match_dest_net $dnet ) . $onet . "-j $echain";
		}
	    }
	}
	
	#
	# The final rule in the exclusion chain will not qualify the source or destination 
	#
	$inets = ALLIPv4;
	$dnets = ALLIPv4;
	
	#
	# Create the Exclusion Chain
	#
	my $echainref = new_chain $chainref->{table}, $echain;

	#
	# Generate RETURNs for each exclusion
	#
	for my $net ( split ',', $iexcl ) {
	    add_rule $echainref, ( match_source_net $net ) . '-j RETURN';
	}

	for my $net ( split ',', $dexcl ) {
	    add_rule $echainref, ( match_dest_net $net ) . '-j RETURN';
	}

	for my $net ( split ',', $oexcl ) {
	    add_rule $echainref, ( match_orig_dest $net ) . '-j RETURN';
	}

	#
	# Log rule
	#
	log_rule_limit $loglevel , $echainref , $chainref->{name}, $disposition , '',  $logtag , 'add' , '' if $loglevel;
	#
	# Generate Final Rule
	# 
	add_rule $echainref, $exceptionrule . $target unless $disposition eq 'LOG';

    } else {
	#
	# No exclusions
	#
	for my $onet ( split /,/, $onets ) {
	    $onet = match_orig_dest $onet;
	    for my $inet ( split /,/, $inets ) {
		$inet = match_source_net $inet;
		for my $dnet ( split /,/, $dnets ) {
		    log_rule_limit $loglevel , $chainref , $chainref->{name}, $disposition , '' , $logtag , 'add' , $rule . $inet . match_dest_net( $dnet ) . $onet if $loglevel;
		    add_rule $chainref, $rule . $inet . match_dest_net( $dnet ) . $onet . $target unless $disposition eq 'LOG';
		}
	    }
	}
    }	
}

#
# If the destination chain exists, then at the end of the source chain add a jump to the destination.
#
sub addnatjump( $$$ ) {
    my ( $source , $dest, $predicates ) = @_;

    my $destref   = $nat_table->{$dest} || {};
    
    if ( $destref->{referenced} ) {
	add_rule $nat_table->{$source} , $predicates . "-j $dest";
    } else {
	clearrule;
    }
}
#
# If the destination chain exists, then at the position in the source chain given by $$countref, add a jump to the destination.
#
sub insertnatjump( $$$$ ) {
    my ( $source, $dest, $countref, $predicates ) = @_;
    
    my $destref   = $nat_table->{$dest} || {};
    
    if ( $destref->{referenced} ) {
	insert_rule $nat_table->{$source} , ($$countref)++, $predicates . "-j $dest";
    } else {
	clearrule;
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

sub create_netfilter_load() {
    emit 'setup_netfilter()';
    emit '{';
    emit '    iptables-restore << __EOF__';

    for my $table qw/raw nat mangle filter/ {
	emit "*$table";
	my @chains;
	for my $chain ( grep $chain_table{$table}{$_}->{referenced} , ( sort keys %{$chain_table{$table}} ) ) {
	    my $chainref =  $chain_table{$table}{$chain};
	    if ( $chainref->{builtin} ) {
		emit ":$chainref->{name} $chainref->{policy} [0:0]";
	    } else {
		emit ":$chainref->{name} - [0:0]";
	    }

	    push @chains, $chainref;
	}

	for my $chainref ( @chains ) {
	    my $name = $chainref->{name};
	    for my $rule ( @{$chainref->{rules}} ) {
		emit "-A $name $rule";
	    }
	}

	emit 'COMMIT';
    }

    emit '__EOF__';
    emit "}\n";
}
       
1;
