#
# Shorewall 3.9 -- /usr/share/shorewall/Shorewall/Chains.pm
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
#
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
		  NO_RESTRICT
		  PREROUTE_RESTRICT
		  POSTROUTE_RESTRICT
		  
		  add_command
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
		  ensure_mangle_chain
		  new_standard_chain
		  new_builtin_chain
		  initialize_chain_table
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
		  do_tos
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
# expand_rule() restrictions
#
use constant { NO_RESTRICT        => 0,
	       PREROUTE_RESTRICT  => 1,
	       POSTROUTE_RESTRICT => 2 };
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
# Keep track of whether there are run-time commands in the chain rules
#
my $slowstart = 0;
#
# Sequence for naming temporary chains
#
my $chainseq;
#
# Add a run-time command to a chain. Arguments are:
#
#    Chain reference , Command
#
sub add_command($$)
{
    my ($chainref, $command) = @_;
    
    $command =~ s/^/~/mg;

    push @{$chainref->{rules}}, $command;

    $chainref->{referenced} = 1;

    $slowstart = 1;
}
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
# Create an anonymous chain
#
sub new_anon_chain( $ ) {
    my $chainref = $_[0];
    my $seq      = $chainseq++;
    new_chain( $chainref->{table}, 'chain' . "$seq" );
}

#
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

sub ensure_mangle_chain($) {
    my $chain = $_[0];

    my $chainref = ensure_chain 'mangle', $chain;
    
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
		    
		    for my $port ( @ports ) {
			if ( $port =~ /:/ ) {
			    fatal_error "Port range in a list requires Extended Multiport Support in your kernel/iptables: $ports" unless $capabilities{XMULTIPORT};
			    $count++;
			} 
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
		    
		    for my $port ( @ports ) {
			if ( $port =~ /:/ ) {
			    fatal_error "Port range in a list requires Extended Multiport Support in your kernel/iptables: $sports" unless $capabilities{XMULTIPORT};
			    $count++;
			}
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
	} else {
	    $output .= "-p $proto ";
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
# Create a "-m tos" match for the passed TOS
#
sub do_tos( $ ) {
    my $tos = $_[0];
    
    $tos = '-' unless $tos;

    $tos ne '-' ? "-m tos --tos $tos " : '';
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

	iprange_match . "${invert}--dst-range $net ";
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
sub expand_rule( $$$$$$$$$$ )
{
    my ($chainref , $restriction, $rule, $source, $dest, $origdest, $target, $loglevel , $disposition, $exceptionrule ) = @_;
    my ($iiface, $diface, $inets, $dnets, $iexcl, $dexcl, $onets , $oexcl );
    my $chain = $chainref->{name};
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
    # Count of the number of parameters to the current rule that are to be detected at run-time
    #
    my $detectcount = 0;
    #
    # Verify Inteface, if any
    #
    if ( $iiface ) {
	fatal_error "Unknown Interface ($iiface): \"$line\"" unless known_interface $iiface;

	if ( $restriction == POSTROUTE_RESTRICT ) {
	    add_command( $chainref , ('    ' x $detectcount) . "sources=\$(get_routed_networks $iiface);" );
	    add_command( $chainref , ('    ' x $detectcount) . qq([ -z "\$sourcess" ] && fatal_error "Unable to determine the routes through interface \"$iiface\"";) );
	    add_command( $chainref , ('    ' x $detectcount) . 'for source in $sources; do' );
	    $rule .= '-s $source';
	    $detectcount++;
	} else {
	    $rule .= "-i $iiface ";
	}
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

	if ( $restriction == PREROUTE_RESTRICT ) {
	    add_command( $chainref , ('    ' x $detectcount) . "dests=\$(find_interface_addresses $diface);" );
	    add_command( $chainref , ('    ' x $detectcount) . qq([ -z "\$dests" ] && fatal_error "Unable to determine the address(es) of interface \"$diface\";") );

	    add_command( $chainref , ('    ' x $detectcount) . 'for dest in $dests; do' );
	    $rule .= '-d $dest';
	    $detectcount++;
	} else {
	    $rule .= "-o $diface ";
	}
    }   
    #
    # If people are too lazy to specify their configuration fully, we don't go out of our way to reduce the number of rules.
    #
    if ( $detectcount ) {
	my $newchainref = new_anon_chain( $chainref );

	add_command $chainref, ('    ' x $detectcount) . qq(emit "-A $chain $rule -j $newchainref->{name}";);

	while ( $detectcount-- ) { 
	    add_command( $chainref, ('    ' x $detectcount) . 'done' ); 
	}

	$chainref = $newchainref;
	$rule     = '';
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
    #
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
	log_rule_limit $loglevel , $echainref , $chain, $disposition , '',  $logtag , 'add' , '' if $loglevel;
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
		    log_rule_limit $loglevel , $chainref , $chain, $disposition , '' , $logtag , 'add' , $rule . $inet . match_dest_net( $dnet ) . $onet if $loglevel;
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

my @builtins = qw(PREROUTING INPUT FORWARD OUTPUT POSTROUTING);

sub create_netfilter_load() {
    emit 'setup_netfilter()';
    emit '{';
    emit( $slowstart ? '    iptables_slow_restore << __EOF__' : '    iptables-restore << __EOF__' );

    for my $table qw/raw nat mangle filter/ {
	emit "*$table";
		
	my @chains;
	
	for my $chain ( @builtins ) {
	    my $chainref = $chain_table{$table}{$chain};
	    if ( $chainref ) {
		emit ":$chain $chainref->{policy} [0:0]";
		push @chains, $chainref;
	    }
	}

	for my $chain ( grep $chain_table{$table}{$_}->{referenced} , ( sort keys %{$chain_table{$table}} ) ) {
	    my $chainref =  $chain_table{$table}{$chain};
	    unless ( $chainref->{builtin} ) {
		emit ":$chainref->{name} - [0:0]";
		push @chains, $chainref;
	    }
	}

	for my $chainref ( @chains ) {
	    my $name = $chainref->{name};
	    for my $rule ( @{$chainref->{rules}} ) {
		$rule = "-A $name $rule" unless substr( $rule, 0, 1) eq '~';
		emit_unindented $rule;
	    }
	}

	emit 'COMMIT';
    }

    emit '__EOF__';
    emit "}\n";
}
       
1;
