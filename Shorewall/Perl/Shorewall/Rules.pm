#
# Shorewall 5.0 -- /usr/share/shorewall/Shorewall/Rules.pm
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
#   This module handles policies and rules. It contains:
#
#       process_() and it's associated helpers.
#       process_rules() and it's associated helpers for handling Actions and Macros.
#
#   This module combines the former Policy, Rules and Actions modules.
#
package Shorewall::Rules;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Nat qw(:rules);
use Shorewall::Raw qw( handle_helper_rule );
use Scalar::Util 'reftype';
use Shorewall::Providers qw( provider_realm );

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		  process_policies
		  complete_policy_chains
		  complete_standard_chain
		  setup_syn_flood_chains
		  save_policies
		  ensure_rules_chain
		  optimize_policy_chains
		  process_actions
		  process_rules
		  verify_audit
		  perl_action_helper
		  perl_action_tcp_helper
		  check_state
                  process_reject_action
                  setup_snat
	       );

our @EXPORT_OK = qw( initialize process_rule );

our %EXPORT_TAGS = ( Traffic => [ qw( process_tc_rule
			              process_mangle_rule

			              %classids
			              %tcdevices
			              %tcclasses
			              %tosoptions
			              %restrictions

			              $mangle
			              $sticky
			            ) , ]
    );

Exporter::export_ok_tags('Traffic');

our $VERSION = 'MODULEVERSION';
#
# Globals are documented in the initialize() function
#
our %sections;

our $section;
our $next_section;

use constant { NULL_SECTION          => 0x00,
               BLACKLIST_SECTION     => 0x01,
	       ALL_SECTION           => 0x02,
	       ESTABLISHED_SECTION   => 0x04,
	       RELATED_SECTION       => 0x08,
	       INVALID_SECTION       => 0x10,
	       UNTRACKED_SECTION     => 0x20,
	       NEW_SECTION           => 0x40,
	       DEFAULTACTION_SECTION => 0x80 };
#
# Number of elements in the action tuple
#
use constant { ACTION_TUPLE_ELEMENTS => 5 };
#
# Section => name function 
#
our %section_functions = ( ALL_SECTION ,        \&rules_chain,
			   BLACKLIST_SECTION ,  \&blacklist_chain,
			   ESTABLISHED_SECTION, \&established_chain,
			   RELATED_SECTION,     \&related_chain,
			   INVALID_SECTION,     \&invalid_chain,
			   UNTRACKED_SECTION,   \&untracked_chain,
			   NEW_SECTION,         \&rules_chain );

#
# Section => STATE map - initialized in process_rules().
#
our %section_states;
#
# These are the sections that may appear in a section header
#
our %section_map = ( ALL           => ALL_SECTION,
		     ESTABLISHED   => ESTABLISHED_SECTION,
		     RELATED       => RELATED_SECTION,
                     INVALID       => INVALID_SECTION,
                     UNTRACKED     => UNTRACKED_SECTION,
		     NEW           => NEW_SECTION );
#
# Reverse map
#
our %section_rmap = ( ALL_SECTION ,        'ALL',
		      BLACKLIST_SECTION ,  'BLACKLIST',
		      ESTABLISHED_SECTION, 'ESTABLISHED',
		      RELATED_SECTION,     'RELATED',
		      INVALID_SECTION,     'INVALID',
		      UNTRACKED_SECTION,   'UNTRACKED',
		      NEW_SECTION,         'NEW' );

our @policy_chains;

our %policy_actions;

our %macros;

our $family;

#
# Commands that can be embedded in a basic rule and how many total tokens on the line (0 => unlimited).
#
our $rule_commands   = {};
our $action_commands = { DEFAULTS => 2 };
our $macro_commands  = { DEFAULT => 2 };
#
# There is an implicit assumption that the last column of the @rulecolumns hash is always the last column of the @columns array.
# The @columns array doesn't include the ACTION but does include a 'wildcard' last element.
#
use constant { LAST_COLUMN => 14 };

our %rulecolumns = ( action    =>   0,
		     source    =>   1,
		     dest      =>   2,
		     proto     =>   3,
		     dport     =>   4,
		     sport     =>   5,
		     origdest  =>   6,
		     rate      =>   7,
		     user      =>   8,
		     mark      =>   9,
		     connlimit =>  10,
		     time      =>  11,
		     headers   =>  12,
		     switch    =>  13,
		     helper    =>  LAST_COLUMN,
		   );

use constant { MAX_MACRO_NEST_LEVEL => 10 };

our $macro_nest_level;

our @actionstack;
our %active;

#  Action Table
#
#     %actions{ actchain => used to eliminate collisions }
#
our %actions;
#
# Contains an entry for each used <action>:<level>:[<tag>]:[<calling chain>]:[<params>] that maps to the associated chain.
# See normalize_action().
#
our %usedactions;

#
# Policies for which AUDIT is allowed
#
our %auditpolicies = ( ACCEPT => 1,
		       DROP   => 1,
		       REJECT => 1
		     );
#
# Columns $source through $wildcard -- with the exception of the latter, these correspond to the rules file columns
# The columns array is a hidden argument to perl_action_helper() and perl_action_tcp_helper() that allows Perl
# code in inline actions to generate proper rules.
#
our @columns;
#
# Hidden return from perl_action_[tcp_]helper that indicates that a rule was generated
#
our $actionresult;
#
# See process_rules() and finish_chain_section().
#
our %statetable;
#
# Tracks which of the state match actions (action.Invalid, etc.) that is currently being expanded
#
our $statematch;
#
# Remembers NAT-oriented columns from top-level action invocations
#
our %nat_columns;

#
# Action/Inline options
#
use constant { INLINE_OPT           => 1 ,
	       NOINLINE_OPT         => 2 ,
	       NOLOG_OPT            => 4 ,
	       BUILTIN_OPT          => 8 ,
	       RAW_OPT              => 16 ,
	       MANGLE_OPT           => 32 ,
	       FILTER_OPT           => 64 ,
	       NAT_OPT              => 128 ,
	       TERMINATING_OPT      => 256 ,
	       AUDIT_OPT            => 512 ,
	       LOGJUMP_OPT          => 1024 ,
	       SECTION_OPT          => 2048 ,
};

our %options = ( inline      => INLINE_OPT ,
		 noinline    => NOINLINE_OPT ,
		 nolog       => NOLOG_OPT ,
		 builtin     => BUILTIN_OPT ,
		 raw         => RAW_OPT ,
		 mangle      => MANGLE_OPT ,
		 filter      => FILTER_OPT ,
		 nat         => NAT_OPT ,
		 terminating => TERMINATING_OPT ,
		 audit       => AUDIT_OPT ,
		 logjump     => LOGJUMP_OPT ,
		 section     => SECTION_OPT ,
    );

our %reject_options;
################################################################################
#   Declarations moved from the Tc module in 5.0.7                             #
################################################################################
use constant { NOMARK    => 0 ,
	       SMALLMARK => 1 ,
	       HIGHMARK  => 2
	       };

our %designator = ( F => 'tcfor' ,
		    T => 'tcpost' );

our %tosoptions = ( 'tos-minimize-delay'       => '0x10/0x10' ,
		    'tos-maximize-throughput'  => '0x08/0x08' ,
		    'tos-maximize-reliability' => '0x04/0x04' ,
		    'tos-minimize-cost'        => '0x02/0x02' ,
		    'tos-normal-service'       => '0x00/0x1e' );

our %restrictions = ( tcpre      => PREROUTE_RESTRICT ,
		      PREROUTING => PREROUTE_RESTRICT ,
		      tcpost     => POSTROUTE_RESTRICT ,
		      tcfor      => NO_RESTRICT ,
		      tcin       => INPUT_RESTRICT ,
		      tcout      => OUTPUT_RESTRICT ,
		    );
our %tcdevices;
our %tcclasses;
our %classids;

our $mangle;

our $sticky;

our $divertref; # DIVERT chain

our %validstates = ( NEW                => 0,
		     RELATED            => 0,
		     ESTABLISHED        => 0,
		     UNTRACKED          => 0,
		     INVALID            => 0,
		   );
#
# Rather than initializing globals in an INIT block or during declaration,
# we initialize them in a function. This is done for two reasons:
#
#   1. Proper initialization depends on the address family which isn't
#      known until the compiler has started.
#
#   2. The compiler can run multiple times in the same process so it has to be
#      able to re-initialize the state of its dependent modules.
#
sub initialize( $ ) {
    $family            = shift;
    #
    # Chains created as a result of entries in the policy file
    #
    @policy_chains  = ();
    #
    # This is updated from the *_DEFAULT settings in shorewall.conf. Those settings were stored
    # in the %config hash when shorewall[6].conf was processed.
    #
    %policy_actions  = ( DROP	    => [] ,
			 REJECT    => [] ,
			 BLACKLIST => [] ,
			 ACCEPT    => [] ,
			 QUEUE	   => [] ,
			 NFQUEUE   => [] ,
			 CONTINUE  => [] ,
			 NONE      => [] ,
			);
    #
    # These are set to 1 as sections are encountered.
    #
    %sections = ( ALL         => 0,
		  ESTABLISHED => 0,
		  RELATED     => 0,
		  INVALID     => 0,
                  UNTRACKED   => 0,
		  NEW         => 0
		  );
    #
    # Current rules file section.
    #
    $section      = NULL_SECTION;
    $next_section = NULL_SECTION;
    #
    # Macro=><macro file> mapping
    #
    %macros            = ();
    #
    # Stack of nested action calls while parsing action.* files.
    #
    @actionstack       = ();
    #
    # This hash provides keyed access to @actionstack
    #
    %active            = ();
    #
    # Self-explainatory
    #
    $macro_nest_level  = 0;
    #
    # All actions mentioned in /etc/shorewall[6]/actions and /usr/share/shorewall[6]/actions.std
    #
    %actions           = ();
    #
    # Action variants actually used. Key is <action>:<loglevel>:<tag>:<caller>:<params>; value is corresponding chain name
    #
    %usedactions       = ();

    @columns           = ( ( '-' ) x LAST_COLUMN, 0 );

    if ( $family == F_IPV4 ) {
	%reject_options = ( 'icmp-net-unreachable'   => 1,
			    'icmp-host-unreachable'  => 1,
			    'icmp-port-unreachable'  => 1,
			    'icmp-proto-unreachable' => 1,
			    'icmp-net-prohibited'    => 1,
			    'icmp-host-prohibited'   => 1,
			    'icmp-admin-prohibited'  => 1,
			    'icmp-tcp-reset'         => 2,
			    'tcp-reset'              => 2,
	                  );
			    
    } else {
	%reject_options = ( 'icmp6-no-route'         => 1,
			    'no-route'               => 1,
			    'icmp6-adm-prohibited'   => 1,
			    'adm-prohibited'         => 1,
			    'icmp6-addr-unreachable' => 1,
			    'addr-unreach'           => 1,
			    'icmp6-port-unreachable' => 1,
			    'tcp-reset'              => 2,
	                  );
    }

    %nat_columns = ( dest => '-', proto => '-', ports => '-' );

    ############################################################################
    # Initialize variables moved from the Tc module in Shorewall 5.0.7         #
    ############################################################################
    %classids  = ();
    %tcdevices = ();
    %tcclasses = ();
    $sticky    = 0;
    $divertref = 0;
}

#
# Create a rules chain
#
sub new_rules_chain( $ ) {
    my $chainref = new_chain( 'filter', $_[0] );

    if ( $config{FASTACCEPT} ) {
	if ( $globals{RELATED_TARGET} eq 'ACCEPT' && ! $config{RELATED_LOG_LEVEL} ) {
	    $chainref->{sections} = { ESTABLISHED => 1, RELATED => 1 };
	} else {
	    $chainref->{sections} = { ESTABLISHED => 1 };
	}
    } else {
	$chainref->{sections} = {};
    }

    $chainref;
}

###############################################################################
# Functions moved from the former Policy Module
###############################################################################
#
# Convert a chain into a policy chain.
#
sub convert_to_policy_chain($$$$$$)
{
    my ($chainref, $source, $dest, $policy, $provisional, $audit ) = @_;

    $chainref->{is_policy}   = 1;
    $chainref->{policy}      = $policy;
    $chainref->{provisional} = $provisional;
    $chainref->{audit}       = $audit;
    $chainref->{policychain} = $chainref->{name};
    $chainref->{policypair}  = [ $source, $dest ];
    $chainref->{pactions}    = [];
}

#
# Create a new policy chain and return a reference to it.
#
sub new_policy_chain($$$$$)
{
    my ($source, $dest, $policy, $provisional, $audit) = @_;

    my $chainref = new_rules_chain( rules_chain( ${source}, ${dest} ) );

    convert_to_policy_chain( $chainref, $source, $dest, $policy, $provisional, $audit );

    $chainref;
}

#
# Set the passed chain's policychain and policy to the passed values.
#
sub set_policy_chain($$$$$$)
{
    my ( $chain, $source, $dest, $polchainref, $policy, $intrazone ) = @_;

    my $chainref = $filter_table->{$chain};

    if ( $chainref ) {
	if ( $intrazone && $source eq $dest && $chainref->{provisional} ) {
	    $chainref->{policychain} = '';
	    $chainref->{provisional} = '';
	}
    } else {
	$chainref = new_rules_chain $chain;
    }

    unless ( $chainref->{policychain} ) {
	if ( $config{EXPAND_POLICIES} ) {
	    #
	    # We convert the canonical chain into a policy chain, using the settings of the
	    # passed policy chain.
	    #
	    $chainref->{policychain} = $chain;
	    $chainref->{loglevel}    = $polchainref->{loglevel} if defined $polchainref->{loglevel};
	    $chainref->{audit}       = $polchainref->{audit}    if defined $polchainref->{audit};

	    if ( defined $polchainref->{synparams} ) {
		$chainref->{synparams}   = $polchainref->{synparams};
		$chainref->{synchain}    = $polchainref->{synchain};
	    }

	    $chainref->{pactions}    = $polchainref->{pactions} || [];
	    $chainref->{is_policy}   = 1;
	    push @policy_chains, $chainref;
	} else {
	    $chainref->{policychain} = $polchainref->{name};
	}

	$chainref->{policy}     = $policy;
	$chainref->{policypair} = [ $source, $dest ];
	$chainref->{origin}     = $polchainref->{origin};
    }
}

#
# Process the policy file
#
use constant { PROVISIONAL => 1 };

sub add_or_modify_policy_chain( $$$ ) {
    my ( $zone, $zone1, $audit ) = @_;
    my $chain    = rules_chain( ${zone}, ${zone1} );
    my $chainref = $filter_table->{$chain};

    if ( $chainref ) {
	unless( $chainref->{is_policy} ) {
	    convert_to_policy_chain( $chainref, $zone, $zone1, 'CONTINUE', PROVISIONAL, $audit );
	    push @policy_chains, $chainref;
	}
    } else {
	push @policy_chains, ( new_policy_chain $zone, $zone1, 'CONTINUE', PROVISIONAL, $audit );
    }
}

sub print_policy($$$$) {
    my ( $source, $dest, $policy , $chain ) = @_;
    unless ( ( $source eq 'all' ) || ( $dest eq 'all' ) ) {
	if ( $policy eq 'CONTINUE' ) {
	    my ( $sourceref, $destref ) = ( find_zone($source) ,find_zone( $dest ) );
	    warning_message "CONTINUE policy between two un-nested zones ($source, $dest)" if ! ( @{$sourceref->{parents}} || @{$destref->{parents}} );
	}
	progress_message_nocompress "   Policy for $source to $dest is $policy using chain $chain" unless $source eq $dest;
    }
}

sub use_policy_action( $$ );
sub normalize_action( $$$ );
sub normalize_action_name( $ );
sub normalize_single_action( $ );

sub process_policy_action( $$$$ ) {
    my ( $originalpolicy, $policy, $paction, $level ) = @_;

    if ( supplied $paction ) {
	my $paction_option = ( $policy =~ /_DEFAULT$/ );
	my ( $act, $param ) = get_target_param( $paction );

	if ( supplied $level ) {
	    validate_level( $level );
	} else {
	    $level = 'none';
	}

	if ( ( $targets{$act} || 0 ) & ACTION ) {
	    $paction = supplied $param  ? normalize_action( $act, $level, $param  ) :
		       $level eq 'none' ? normalize_action_name $act :
		       normalize_action( $act, $level, '' );
	} elsif ( ( $targets{$act} || 0 ) == INLINE ) {
	    $paction = $act;
	    $paction = "$act($param)" if supplied $param;
	    $paction = join( ':', $paction, $level ) if $level ne 'none';
	} elsif ( $paction_option ) {
	    fatal_error "Unknown Action ($paction) in $policy setting";
	} else {
	    fatal_error "Unknown Policy Action ($paction)";
	}

    } else {
	$paction = $policy_actions{$policy};
    }

    $paction;
}

sub process_policy_actions( $$$ ) {
    my ( $originalpolicy, $policy, $pactions ) = @_;

    if ( supplied $pactions ) {
	my @pactions;

	if ( lc $pactions ne 'none' ) {
	    @pactions = @{$policy_actions{$policy}} if $pactions =~ s/^\+//;

	    for my $paction ( split_list3( $pactions, 'Policy Action' ) ) {
		my ( $action, $level, $remainder ) = split( /:/, $paction, 3 );

		fatal_error "Invalid policy action ($paction:$level:$remainder)" if defined $remainder;

		push @pactions, process_policy_action( $originalpolicy, $policy, $action, $level );
	    }
	}

	\@pactions;
    } else {
	$policy_actions{$policy};
    }
}

#
# Verify an NFQUEUE specification and return the appropriate ip[6]tables target
#
sub handle_nfqueue( $$ ) {
    my ($params, $allow_bypass ) = @_;
    my ( $action, $bypass, $fanout );
    my ( $queue1, $queue2, $queuenum1, $queuenum2 );

    require_capability( 'NFQUEUE_TARGET', 'NFQUEUE Rules and Policies', '' );

    if ( supplied( $params ) ) {
	( my $queue, $bypass, my $junk ) = split ',', $params, 3;

	fatal_error "Invalid NFQUEUE parameter list ($params)" if defined $junk;

	if ( supplied $queue ) {
	    if ( $queue eq 'bypass' ) {
		fatal_error "'bypass' is not allowed in this context" unless $allow_bypass;
		fatal_error "Invalid NFQUEUE options (bypass,$bypass)" if supplied $bypass;
		return 'NFQUEUE --queue-bypass';
	    }

	    ( $queue1, $queue2 ) = split ':', $queue, 2;

	    fatal_error "Invalid NFQUEUE parameter list ($params)" unless supplied $queue1;

	    $queuenum1 = numeric_value( $queue1 );

	    fatal_error "Invalid NFQUEUE queue number ($queue1)" unless defined( $queuenum1) && $queuenum1 >= 0 && $queuenum1 <= 65535;

	    if ( supplied $queue2 ) {
		$fanout    = $queue2 =~ s/c$// ? ' --queue-cpu-fanout' : '';
		$queuenum2 = numeric_value( $queue2 );

		fatal_error "Invalid NFQUEUE queue number ($queue2)" unless defined( $queuenum2) && $queuenum2 >= 0 && $queuenum2 <= 65535 && $queuenum1 < $queuenum2;
	    }
	} else {
	    $queuenum1 = 0;
	}
    } else {
	$queuenum1 = 0;
    }

    if ( supplied $bypass ) {
	fatal_error "Invalid NFQUEUE option ($bypass)" if $bypass ne 'bypass';
	fatal_error "'bypass' is not allowed in this context" unless $allow_bypass;

	$bypass =' --queue-bypass';
    } else {
	$bypass = '';
    }

    if ( supplied $queue2 ) {
	require_capability 'CPU_FANOUT', '"c"', 's' if $fanout;
	return "NFQUEUE --queue-balance ${queuenum1}:${queuenum2}${fanout}${bypass}";
    } else {
	return "NFQUEUE --queue-num ${queuenum1}${bypass}";
    }
}

#
# Process an entry in the policy file.
#
sub process_a_policy1($$$$$$$) {

    our %validpolicies;
    our @zonelist;

    my ( $client, $server, $originalpolicy, $loglevel, $synparams, $connlimit, $intrazone ) = @_;

    my $clientwild = ( "\L$client" =~ /^all(\+)?$/ );

    $intrazone  ||= $clientwild && $1;

    fatal_error "Undefined zone ($client)" unless $clientwild || defined_zone( $client );

    my $serverwild = ( "\L$server" =~ /^all(\+)?/ );
    $intrazone   ||= ( $serverwild && $1 );

    fatal_error "Undefined zone ($server)" unless $serverwild || defined_zone( $server );

    my $audit = ( $originalpolicy =~ s/:audit$// );

    require_capability 'AUDIT_TARGET', ":audit", "s" if $audit;

    my ( $policy, $pactions ) = split( /:/, $originalpolicy, 2 );

    fatal_error "Invalid or missing POLICY ($originalpolicy)" unless $policy;

    ( $policy , my $queue ) = get_target_param $policy;

    fatal_error "Invalid policy ($policy)" unless exists $validpolicies{$policy};

    if ( $audit ) {
	fatal_error "A $policy policy may not be audited" unless $auditpolicies{$policy};
    }

    my $pactionref = process_policy_actions( $originalpolicy, $policy, $pactions );

    if ( defined $queue ) {
	$policy = handle_nfqueue( $queue,
				  0 # Don't allow 'bypass'
	    );
    } elsif ( $policy eq 'NONE' ) {
	fatal_error "NONE policy not allowed with \"all\""
	    if $clientwild || $serverwild;
	fatal_error "NONE policy not allowed to/from firewall zone"
	    if ( zone_type( $client ) == FIREWALL ) || ( zone_type( $server ) == FIREWALL );
    } elsif ( $policy eq 'BLACKLIST' ) {
	fatal_error 'BLACKLIST policies require ipset-based dynamic blacklisting' unless $config{DYNAMIC_BLACKLIST} =~ /^ipset/;
    }

    unless ( $clientwild || $serverwild ) {
	if ( zone_type( $server ) & BPORT ) {
	    fatal_error "Invalid policy - DEST zone is a Bridge Port zone but the SOURCE zone is not associated with the same bridge"
		unless find_zone( $client )->{bridge} eq find_zone( $server)->{bridge} || single_interface( $client ) eq find_zone( $server )->{bridge};
	}
    }

    my $chain = rules_chain( ${client}, ${server} );
    my $chainref;

    if ( defined $filter_table->{$chain} ) {
	$chainref = $filter_table->{$chain};

	if ( $chainref->{is_policy} ) {
	    if ( $chainref->{provisional} ) {
		$chainref->{provisional} = 0;
		$chainref->{policy} = $policy;
	    } else {
		fatal_error qq(Policy "$client $server $originalpolicy" duplicates earlier policy "@{$chainref->{policypair}} $chainref->{policy}");
	    }
	} elsif ( $chainref->{policy} ) {
	    fatal_error qq(Policy "$client $server $originalpolicy" duplicates earlier policy "@{$chainref->{policypair}} $chainref->{policy}");
	} else {
	    convert_to_policy_chain( $chainref, $client, $server, $policy, 0 , $audit );
	    push @policy_chains, ( $chainref ) unless $config{EXPAND_POLICIES} && ( $clientwild || $serverwild );
	}
    } else {
	$chainref = new_policy_chain $client, $server, $policy, 0, $audit;
	push @policy_chains, ( $chainref ) unless $config{EXPAND_POLICIES} && ( $clientwild || $serverwild );
    }

    $chainref->{loglevel}  = validate_level( $loglevel ) if supplied $loglevel;

    if ( $synparams ne '' || $connlimit ne '' ) {
	my $value = '';
	fatal_error "Invalid CONNLIMIT ($connlimit)" if $connlimit =~ /^!/;
	$value  = do_ratelimit $synparams, 'ACCEPT'  if $synparams ne '';
	$value .= do_connlimit $connlimit            if $connlimit ne '';
	$chainref->{synparams} = $value;
	$chainref->{synchain}  = $chain
    }

    $chainref->{pactions} = $pactionref;
    $chainref->{origin}   = shortlineinfo('');

    if ( $clientwild ) {
	if ( $serverwild ) {
	    for my $zone ( @zonelist ) {
		for my $zone1 ( @zonelist ) {
		    set_policy_chain rules_chain( ${zone}, ${zone1} ), $zone, $zone1, $chainref, $policy, $intrazone;
		    print_policy $zone, $zone1, $originalpolicy, $chain;
		}
	    }
	} else {
	    for my $zone ( all_zones ) {
		set_policy_chain rules_chain( ${zone}, ${server} ), $zone, $server, $chainref, $policy, $intrazone;
		print_policy $zone, $server, $originalpolicy, $chain;
	    }
	}
    } elsif ( $serverwild ) {
	for my $zone ( @zonelist ) {
	    set_policy_chain rules_chain( ${client}, ${zone} ), $client, $zone, $chainref, $policy, $intrazone;
	    print_policy $client, $zone, $originalpolicy, $chain;
	}
    } else {
	print_policy $client, $server, $originalpolicy, $chain;
    }
}

sub process_a_policy() {

    our %validpolicies;
    our @zonelist;

    my ( $clients, $servers, $policy, $loglevel, $synparams, $connlimit ) =
	split_line2( 'policy file',
		     { source => 0, dest => 1, policy => 2, loglevel => 3, limit => 4, rate => 4, connlimit => 5 } ,
		     {} , # nopad
		     6  , # maxcolumns
		    );

    $loglevel  = '' if $loglevel  eq '-';
    $synparams = '' if $synparams eq '-';
    $connlimit = '' if $connlimit eq '-';

    my ( $intrazone, $clientlist, $serverlist );

    if ( $clientlist = ( $clients =~ /,/ ) ) {
	$intrazone = ( $clients =~ s/\+$// );
    }

    if ( $serverlist = ( $servers =~ /,/ ) ) {
	$intrazone ||= ( $servers =~ s/\+$// );
    }	

    fatal_error 'SOURCE must be specified' if $clients eq '-';
    fatal_error 'DEST must be specified'   if $servers eq '-';
    fatal_error 'POLICY must be specified' if $policy  eq '-';

    if ( $clientlist || $serverlist ) {
	for my $client ( split_list( $clients, 'zone' ) ) {
	    for my $server ( split_list( $servers, 'zone' ) ) {
		process_a_policy1( $client, $server, $policy, $loglevel, $synparams, $connlimit, $intrazone ) if $intrazone || $client ne $server;
	    }
	}
    } else {
	process_a_policy1( $clients, $servers, $policy, $loglevel, $synparams, $connlimit, 0 );
    }
}

#
# Generate contents of the /var/lib/shorewall[6]/.policies file as 'here documents' in the generated script
#
sub save_policies() {
    for my $zone1 ( all_zones ) {
	for my $zone2 ( all_zones ) {
	    my $chainref  = $filter_table->{ rules_chain( $zone1, $zone2 ) };
	    my $policyref = $filter_table->{ $chainref->{policychain} };

	    if ( $policyref->{referenced} ) {
		emit_unindented "$zone1 \t=>\t$zone2\t" . $policyref->{policy} . ' using chain ' . $policyref->{name};
	    } elsif ( $zone1 ne $zone2 ) {
		emit_unindented "$zone1 \t=>\t$zone2\t" . $policyref->{policy};
	    }
	}
    }
}

#
# Process the policy file
#
sub process_policies()
{
    our %validpolicies = (
			  ACCEPT => undef,
			  REJECT => undef,
			  DROP	 => undef,
			  CONTINUE => undef,
			  BLACKLIST => undef,
			  QUEUE => undef,
			  NFQUEUE => undef,
			  NONE => undef
			  );

    our %map = ( DROP_DEFAULT      => 'DROP' ,
		 REJECT_DEFAULT    => 'REJECT' ,
		 BLACKLIST_DEFAULT => 'BLACKLIST' ,
		 ACCEPT_DEFAULT    => 'ACCEPT' ,
		 QUEUE_DEFAULT     => 'QUEUE' ,
		 NFQUEUE_DEFAULT   => 'NFQUEUE' );

    my $zone;
    my $firewall = firewall_zone;
    our @zonelist = $config{EXPAND_POLICIES} ? all_zones : ( all_zones, 'all' );

    for my $option ( qw( DROP_DEFAULT REJECT_DEFAULT BLACKLIST_DEFAULT ACCEPT_DEFAULT QUEUE_DEFAULT NFQUEUE_DEFAULT) ) {
	my $actions = $config{$option};

	if ( $actions eq 'none' ) {
	    $actions = [];
	} else {
	    $actions = process_policy_actions( $actions, $option, $actions );
	}

	$policy_actions{$map{$option}} = $actions;
    }

    for $zone ( all_zones ) {
	push @policy_chains, ( new_policy_chain $zone,         $zone, 'ACCEPT', PROVISIONAL, 0 );
	push @policy_chains, ( new_policy_chain firewall_zone, $zone, 'NONE',   PROVISIONAL, 0 ) if zone_type( $zone ) & BPORT;

	my $zoneref = find_zone( $zone );
	my $type    = $zoneref->{type};

	if ( $type == LOCAL ) {
	    for my $zone1 ( off_firewall_zones ) {
		unless ( $zone eq $zone1 ) {
		    my $name  = rules_chain( $zone,  $zone1 );
		    my $name1 = rules_chain( $zone1, $zone  );
		    set_policy_chain( $name,  $zone,  $zone1, ensure_rules_chain( $name  ), 'NONE', 0 );
		    set_policy_chain( $name1, $zone1, $zone,  ensure_rules_chain( $name1 ), 'NONE', 0 );
		}
	    }
	} elsif ( $type == LOOPBACK ) {
	    for my $zone1 ( off_firewall_zones ) {
		unless ( $zone eq $zone1 || zone_type( $zone1 ) == LOOPBACK ) {
		    my $name  = rules_chain( $zone,  $zone1 );
		    my $name1 = rules_chain( $zone1, $zone  );
		    set_policy_chain( $name,  $zone,  $zone1, ensure_rules_chain( $name  ), 'NONE', 0 );
		    set_policy_chain( $name1, $zone1, $zone,  ensure_rules_chain( $name1 ), 'NONE', 0 );
		}
	    }
	}

	if ( $config{IMPLICIT_CONTINUE} && ( @{$zoneref->{parents}} || $zoneref->{type} & VSERVER ) ) {
	    for my $zone1 ( all_zones ) {
		unless( $zone eq $zone1 ) {
		    add_or_modify_policy_chain( $zone, $zone1, 0 );
		    add_or_modify_policy_chain( $zone1, $zone , 0 );
		}
	    }
	}
    }

    if ( my $fn = open_file 'policy' ) {
	first_entry "$doing $fn...";
	process_a_policy while read_a_line( NORMAL_READ );
    } else {
	fatal_error q(The 'policy' file does not exist or has zero size);
    }

    for $zone ( all_zones ) {
	for my $zone1 ( all_zones ) {
	    fatal_error "No policy defined from zone $zone to zone $zone1" unless $filter_table->{rules_chain( ${zone}, ${zone1} )}{policy};
	}
    }
}

#
# Policy Rule application
#
sub process_inline ($$$$$$$$$$$$$$$$$$$$$$);

#
# Determine the protocol to be used in the jump to the passed action
#
sub determine_action_protocol( $$ ) {
    my ( $action, $proto ) = @_;

    if ( my $actionproto = $actions{$action}{proto} ) {
	if ( $proto eq '-' ) {
	    $proto = $actionproto;
	} else {
	    if ( defined( my $protonum = resolve_proto( $proto ) ) ) {
		fatal_error( "The $action action is only usable with " . proto_name( $actionproto ) ) unless $actionproto == $protonum;
		$proto = $protonum;
	    } else {
		fatal_error( "Unknown protocol ($proto)" );
	    }
	}
    }

    $proto;
}

sub add_policy_rules( $$$$$ ) {
    my ( $chainref , $target, $loglevel, $pactions, $dropmulticast ) = @_;

    unless ( $target eq 'NONE' ) {
	my @pactions;

	@pactions = @$pactions;

	add_ijump $chainref, j => 'RETURN', d => '224.0.0.0/4' if $dropmulticast && $target ne 'CONTINUE' && $target ne 'ACCEPT';

	for my $paction ( @pactions ) {
	    my ( $action ) = split ':', $paction;

	    if ( ( $targets{$action} || 0 ) & ACTION ) {
		#
		# Default action is a regular action -- jump to the action chain
		#
		if ( ( my $proto = determine_action_protocol( $action, '-' ) ) ne '-' ) {
		    add_ijump( $chainref, j => use_policy_action( $paction, $chainref->{name} ), p => $proto );
		} else {
		    add_ijump $chainref, j => use_policy_action( $paction, $chainref->{name} );
		}
	    } else {
		#
		# Default action is an inline 
		#
		( undef, my $level )   = split /:/, $paction, 2;
		( $action, my $param ) = get_target_param( $action );

		process_inline( $action,      #Inline
				$chainref,    #Chain
				'',           #Matches
				'',           #Matches1
				$level || '', #Log Level and Tag
				$paction,     #Target
				$param || '', #Param
				'-',          #Source
				'-',          #Dest
				'-',          #Proto
				'-',          #Ports
				'-',          #Sports
				'-',          #Original Dest
				'-',          #Rate
				'-',          #User
				'-',          #Mark
				'-',          #ConnLimit
				'-',          #Time
				'-',          #Headers
				'-',          #Condition
				'-',          #Helper
				0,            #Wildcard
			      );
	    }
	}
 
	log_rule $loglevel , $chainref , $target , '' if $loglevel ne '';
	fatal_error "Null target in policy_rules()" unless $target;

	if ( $target eq 'BLACKLIST' ) {
	    my ( $dbl_type, $dbl_ipset, $dbl_level, $dbl_tag ) = split( ':', $config{DYNAMIC_BLACKLIST} );

	    if ( my $timeout = $globals{DBL_TIMEOUT} ) {
		add_ijump( $chainref, j => "SET --add-set $dbl_ipset src --exist --timeout $timeout" );
	    } else {
		add_ijump( $chainref, j => "SET --add-set $dbl_ipset src --exist" );
	    }

	    $target = 'DROP';
	} else {
	    add_ijump( $chainref , j => 'AUDIT', targetopts => '--type ' . lc $target ) if $chainref->{audit};
	}

	add_ijump( $chainref , g => $target eq 'REJECT' ? 'reject' : $target ) unless $target eq 'CONTINUE';
    }
}

sub report_syn_flood_protection() {
    progress_message_nocompress '      Enabled SYN flood Protection';
}

#
# Complete a policy chain - Add policy-enforcing rules and syn flood, if specified
#
sub complete_policy_chain( $$$ ) { #Chainref, Source Zone, Destination Zone
    my $chainref   = $_[0];
    my $policyref  = $filter_table->{$chainref->{policychain}};
    my $synparams  = $policyref->{synparams};
    my $defaults   = $policyref->{pactions};
    my $policy     = $policyref->{policy};
    my $loglevel   = $policyref->{loglevel};

    assert( $policyref );

    if ( $chainref eq $policyref ) {
	add_policy_rules $chainref , $policy, $loglevel , $defaults, $config{MULTICAST};
    } else {
	if ( $policy eq 'ACCEPT' || $policy eq 'QUEUE' || $policy =~ /^NFQUEUE/ ) {
	    if ( $synparams ) {
		report_syn_flood_protection;
		add_policy_rules $chainref , $policy , $loglevel , $defaults, $config{MULTICAST};
	    } else {
		add_ijump $chainref,  g => $policyref;
		$chainref = $policyref;
	    }
	} elsif ( $policy eq 'CONTINUE' ) {
	    report_syn_flood_protection if $synparams;
	    add_policy_rules $chainref , $policy , $loglevel , $defaults, $config{MULTICAST};
	} else {
	    report_syn_flood_protection if $synparams;
	    add_ijump $chainref , g => $policyref;
	    $chainref = $policyref;
	}
    }

    progress_message_nocompress "   Policy $policy from $_[1] to $_[2] using chain $chainref->{name}";
}

sub ensure_rules_chain( $ );

#
# Finish all policy Chains
#
sub complete_policy_chains() {
    progress_message2 'Applying Policies...';

    for my $chainref ( @policy_chains ) {
	unless ( ( my $policy = $chainref->{policy} ) eq 'NONE' ) {
	    my $loglevel    = $chainref->{loglevel};
	    my $provisional = $chainref->{provisional};
	    my $defaults    = $chainref->{pactions};
	    my $name        = $chainref->{name};
	    my $synparms    = $chainref->{synparms};

	    unless ( $chainref->{referenced} || $provisional || $policy eq 'CONTINUE' ) {
		if ( $config{OPTIMIZE} & 2 ) {
		    #
		    # This policy chain is empty and the only thing that we would put in it is
		    # the policy-related stuff. Don't create it if all we are going to put in it
		    # is a single jump. Generate_matrix() will just use the policy target when
		    # needed.
		    #
		    ensure_rules_chain $name if ( @$defaults         ||
						  $loglevel          ||
						  $synparms          ||
						  $config{MULTICAST} ||
						  ! ( $policy eq 'ACCEPT' || $config{FASTACCEPT} ) );
		} else {
		    ensure_rules_chain $name;
		}
	    }

	    if ( $name =~ /^all[-2]|[-2]all$/ ) {
		add_policy_rules $chainref , $policy, $loglevel , $defaults, $config{MULTICAST};
	    }
	}
    }

    for my $zone ( all_zones ) {
	for my $zone1 ( all_zones ) {
	    my $chainref = $filter_table->{rules_chain( ${zone}, ${zone1} )};

	    if ( $chainref->{referenced} ) {
		complete_policy_chain $chainref, $zone, $zone1;
	    }
	}
    }
}

#
# Complete a standard chain
#
#	- run any supplied user exit
#	- search the policy file for an applicable policy and add rules as
#	  appropriate
#	- If no applicable policy is found, add rules for an assummed
#	  policy of DROP INFO
#
sub complete_standard_chain ( $$$$ ) {
    my ( $stdchainref, $zone, $zone2, $default ) = @_;

    my $ruleschainref = $filter_table->{rules_chain( ${zone}, ${zone2} ) } || $filter_table->{rules_chain( 'all', 'all' ) };
    my ( $policy, $loglevel ) = ( $default , 6 );
    my $policy_actions = $policy_actions{$policy};
    my $policychainref;

    $policychainref = $filter_table->{$ruleschainref->{policychain}} if $ruleschainref;

    if ( $policychainref ) {
	( $policy, $loglevel, $policy_actions ) = @{$policychainref}{'policy', 'loglevel', 'pactions' };
	$stdchainref->{origin} = $policychainref->{origin};
    }

    add_policy_rules $stdchainref , $policy , $loglevel, $policy_actions, 0;
}

#
# Create and populate the synflood chains corresponding to entries in /etc/shorewall/policy
#
sub setup_syn_flood_chains() {
    my @zones = ( non_firewall_zones );
    for my $chainref ( @policy_chains ) {
	my $limit = $chainref->{synparams};
	if ( $limit && ! $filter_table->{syn_flood_chain $chainref} ) {
	    my $level = $chainref->{loglevel};
	    my $synchainref = @zones > 1 ?
		    new_chain 'filter' , syn_flood_chain $chainref :
		    new_chain( 'filter' , '@' . $chainref->{name} );
	    add_rule $synchainref , "${limit}-j RETURN";
	    log_irule_limit( $level ,
			     $synchainref ,
			     $chainref->{name} ,
			     'DROP',
			     @{$globals{LOGILIMIT}} ? $globals{LOGILIMIT} : [ limit => "--limit 5/min --limit-burst 5" ] ,
			    '' ,
			    'add',
			     ''  )
		if $level ne '';
	    add_ijump $synchainref, j => 'DROP';
	}
    }
}

#
# Optimize Policy chains with ACCEPT policy
#
sub optimize_policy_chains() {
    for my $chainref ( grep $_->{policy} eq 'ACCEPT', @policy_chains ) {
	optimize_chain ( $chainref );
    }
    #
    # Often, fw->all has an ACCEPT policy. This code allows optimization in that case
    #
    my $outputrules = $filter_table->{OUTPUT}{rules};

    if ( @{$outputrules} && $outputrules->[-1]->{target} eq 'ACCEPT' ) {
	optimize_chain( $filter_table->{OUTPUT} );
    }

    progress_message '  Policy chains optimized';
    progress_message '';
}

################################################################################
# Modules moved from the Chains module in 4.4.18
################################################################################

#
# Add ESTABLISHED,RELATED,INVALID,UNTRACKED rules and synparam jumps to the passed chain
#
sub finish_chain_section ($$$) {
    my ($chainref,
	$chain1ref,
	$state )            = @_;
    my $chain               = $chainref->{name};
    my $save_comment        = push_comment;
    my %state;

    $state{$_} = 1 for split ',', $state;

    for ( qw/ESTABLISHED RELATED INVALID UNTRACKED/ ) {
	delete $state{$_} if $chain1ref->{sections}{$_};
    }

    $chain1ref->{sections}{$_} = 1 for keys %state;

    for ( qw( ESTABLISHED RELATED INVALID UNTRACKED ) ) {
	if ( $state{$_} ) {
	    my ( $char, $level, $tag, $target , $origin, $level_origin ) = @{$statetable{$_}};
	    my $twochains = substr( $chainref->{name}, 0, 1 ) eq $char;

	    if ( $twochains || $level || $target ne 'ACCEPT' ) {
		if ( $level ) {
		    my $chain2ref;

		    if ( $twochains ) {
			$chain2ref = $chainref;
		    } else {
			$chain2ref = new_chain( 'filter', "${char}$chainref->{name}" );
		    }

		    log_rule_limit( $level,
				    $chain2ref,
				    $chain2ref->{name},
				    uc $target,
				    $globals{LOGLIMIT},
				    $tag ,
				    'add' ,
				    '',
				    $level_origin );

		    $target = ensure_audit_chain( $target ) if ( $targets{$target} || 0 ) & AUDIT;

		    add_ijump_extended( $chain2ref, g => $target , $origin ) if $target;

		    $target = $chain2ref->{name} unless $twochains;
		}

		if ( $twochains ) {
		    add_ijump_extended $chainref, g => $target , $origin if $target;
		    delete $state{$_};
		    last;
		}

		if ( $target ) {
		    $target = ensure_audit_chain( $target ) if ( $targets{$target} || 0 ) & AUDIT;
		    #
		    # Always handle ESTABLISHED first
		    #
		    if ( $state{ESTABLISHED} && $_ ne 'ESTABLISHED' ) {
			add_ijump( $chain1ref, j => 'ACCEPT', state_imatch 'ESTABLISHED' );
			delete $state{ESTABLISHED};
		    }

		    add_ijump_extended( $chainref, j => $target, $origin, state_imatch $_ );
		}

		delete $state{$_};
	    }
	}
    }

    if ( keys %state ) {
	my @state;

	unless ( $config{FASTACCEPT} ) {
	    for ( qw/ESTABLISHED RELATED/ ) {
		push @state, $_ if $state{$_};
	    }
	}

	push( @state, 'UNTRACKED' ),if $state{UNTRACKED} && $globals{UNTRACKED_TARGET} eq 'ACCEPT';

	add_ijump( $chain1ref, j => 'ACCEPT', state_imatch join(',', @state ) ) if @state;
    }

    if ($sections{NEW} ) {
	if ( $chain1ref->{is_policy} ) {
	    if ( $chain1ref->{synparams} ) {
		my $synchainref = ensure_chain 'filter', syn_flood_chain $chain1ref;
		if ( $section == DEFAULTACTION_SECTION ) {
		    if ( $chain1ref->{policy} =~ /^(ACCEPT|CONTINUE|QUEUE|NFQUEUE)/ ) {
			add_ijump $chain1ref, j => $synchainref, p => 'tcp --syn';
		    }
		} else {
		    add_ijump $chain1ref, j => $synchainref, p => 'tcp --syn';
		}
	    }
	} else {
	    my $policychainref = $filter_table->{$chain1ref->{policychain}};
	    if ( $policychainref->{synparams} ) {
		my $synchainref = ensure_chain 'filter', syn_flood_chain $policychainref;
		add_ijump $chain1ref, j => $synchainref, p => 'tcp --syn';
	    }
	}

	$chain1ref->{new} = @{$chain1ref->{rules}};
    }

    pop_comment( $save_comment );
}

#
# Create a rules chain if necessary and populate it with the appropriate ESTABLISHED,RELATED rule(s) and perform SYN rate limiting.
#
# Return a reference to the chain's table entry.
#
sub ensure_rules_chain( $ )
{
    my ($chain) = @_;

    my $chainref = $filter_table->{$chain};

    $chainref = new_rules_chain( $chain ) unless $chainref;

    unless ( $chainref->{referenced} ) {
	if ( $section & ( NEW_SECTION | DEFAULTACTION_SECTION ) ) {
	    finish_chain_section $chainref , $chainref, 'ESTABLISHED,RELATED,INVALID,UNTRACKED';
	} elsif ( $section == UNTRACKED_SECTION ) {
	    finish_chain_section $chainref , $chainref, 'ESTABLISHED,RELATED,INVALID';
	} elsif ( $section == INVALID_SECTION ) {
	    finish_chain_section $chainref , $chainref, 'ESTABLISHED,RELATED';
	} elsif ( $section == RELATED_SECTION ) {
	    finish_chain_section $chainref , $chainref, 'ESTABLISHED';
	}

	$chainref->{referenced} = 1;
    }

    $chainref;
}

#
# Do section-end processing
#
sub finish_section ( $ ) {
    my $sections = $_[0];

    $sections{$_} = 1 for split /,/, $sections;

    my $function = $section_functions{$section} || \&rules_chain;

    for my $zone ( all_zones ) {
	for my $zone1 ( all_zones ) {
	    my $chainref  = $filter_table->{$function->( $zone, $zone1 )};
	    my $chain1ref = $filter_table->{rules_chain( $zone, $zone1 )};
	    finish_chain_section $chainref || $chain1ref, $chain1ref, $sections if $chain1ref->{referenced};
	}
    }
}
################################################################################
# Functions moved from the Actions module in 4.4.16
################################################################################
#
# Create a normalized action name from the passed pieces.
#
# Internally, action invocations are uniquely identified by a 5-tuple that
# includes the action name, log level, log tag, calling chain and params.
# The pieces of the tuple are separated by ":". The calling chain is non-empty
# only when the action refers to @CALLER.
#
sub normalize_action( $$$ ) {
    my ( $action, $level, $param ) = @_;
    my $caller = '';     #We assume that the action doesn't use @CALLER

    ( $level, my $tag ) = split ':', $level;

    if ( $actions{$action}{options} & LOGJUMP_OPT ) {
	$level = 'none';
    } else {
	$level = 'none' unless supplied $level;
    }
    #
    # Note: SNAT actions store the current interface's name in the tag
    #
    $tag   = ''     unless defined $tag;

    if ( defined( $param ) ) {
	#
	# Normalize the parameters by removing trailing omitted
	# parameters
	#
	1 while $param =~ s/,-$//;

	$param = '' if $param eq '-';
    } else {
	$param = '';
    }

    join( ':', $action, $level, $tag, $caller, $param );
}

#
# Add the actual caller into an existing normalised name
#
sub insert_caller($$) {
    my ( $normalized, $caller ) = @_;

    my ( $action, $level, $tag, undef, $param ) = split /:/, $normalized;

    join( ':', $action, $level, $tag, $caller, $param );
}

#
# Accepts a rule target and returns a normalized tuple
#
sub normalize_action_name( $ ) {
    my $target = shift;
    my ( $action, $loglevel) = split_action $target;

    normalize_action( $action, $loglevel, '' );
}

#
# Create an action tuple from a single target name
#
sub normalize_single_action( $ ) {
    join(":", $_[0], 'none', '', '', '' );
}

#
# Produce a recognizable target from a normalized action
#
sub external_name( $ ) {
    my ( $target, $level, $tag, undef, $params ) = split /:/, shift, ACTION_TUPLE_ELEMENTS;

    $target  = join( '', $target, '(', $params , ')' ) if $params;
    $target .= ":$level" if $level && $level ne 'none';
    $target .= ":$tag"   if $tag;
    $target;
}

#
# Define an Action
#
sub new_action( $$$$$$ ) {

    my ( $action , $type, $options , $actionfile , $state, $proto ) = @_;

    fatal_error "Invalid action name($action)" if reserved_name( $action );

    $actions{$action} = { file => $actionfile, actchain => '' , type => $type, options => $options , state => $state, proto => $proto };

    $targets{$action} = $type;
}

#
# Create and record a log action chain -- Log action chains have names
# that are formed from the action name by prepending a "%" and appending
# a 1- or 2-digit sequence number. In the functions that follow,
# the $chain, $level and $tag variables serve as arguments to the user's
# exit. We call the exit corresponding to the name of the action but we
# set $chain to the name of the iptables chain where rules are to be added.
# Similarly, $level and $tag contain the log level and log tag respectively.
#
# The maximum length of a chain name is 30 characters -- since the log
# action chain name is 2-3 characters longer than the base chain name,
# this function truncates the original chain name where necessary before
# it adds the leading "%" and trailing sequence number.
#
sub createlogactionchain( $$$$$$ ) {
    my ( $table, $normalized, $action, $level, $tag, $param ) = @_;
    my $chain = $action;
    my $actionref = $actions{$action};
    my $chainref;
    my $tableref = $chain_table{$table};

    validate_level $level;

    assert( $actionref );

    $chain = substr $chain, 0, 28 if ( length $chain ) > 28;

    if ( $tableref->{$chain} ) {
      CHECKDUP:
	{
	    $actionref->{actchain}++ while $chain_table{filter}{'%' . $chain . $actionref->{actchain}};
	    $chain = substr( $chain, 0, 27 ), redo CHECKDUP if ( $actionref->{actchain} || 0 ) >= 10 and length $chain == 28;
	}

	$usedactions{$normalized} = $chainref = new_action_chain( $table,  '%' . $chain . $actionref->{actchain}++ );

	fatal_error "Too many invocations of Action $action" if $actionref->{actchain} > 99;
    } else {
	$usedactions{$normalized} = $chainref = new_action_chain( $table, $chain );
    }

    $chainref->{action} = $normalized;

    $chainref;
}

sub createsimpleactionchain( $$ ) {
    my ( $table, $action ) = @_;
    my $normalized = normalize_action_name( $action );

    return createlogactionchain( $table, $normalized, $action, 'none', '', '' ) if $filter_table->{$action} || $nat_table->{$action};

    my $chainref = new_action_chain( $table, $action );

    $usedactions{$normalized} = $chainref;

    $chainref->{action} = $normalized;

    $chainref;
}

#
# Create an action chain and run its associated user exit
#
sub createactionchain( $$ ) {
    my ( $table, $normalized ) = @_;

    my ( $target, $level, $tag, $caller, $param ) = split /:/, $normalized, ACTION_TUPLE_ELEMENTS;

    assert( defined $param );

    my $chainref;

    if ( $level eq 'none' && $tag eq '' && $param eq '' ) {
	createsimpleactionchain($table, $target );
    } else {
	createlogactionchain( $table, $normalized, $target , $level , $tag, $param );
    }
}

#
# Mark an action as used and create its chain. Returns a reference to the chain if the chain was
# created on this call or 0 otherwise.
#
sub use_action( $$ ) {
    my ( $table, $normalized ) = @_;

    if ( $usedactions{$normalized} ) {
	0;
    } else {
	createactionchain( $table, $normalized );
    }
}

#
# This function determines the logging and params for a subordinate action or a rule within a superior action
#
sub merge_levels ($$) {
    my ( $superior, $subordinate ) = @_;

    return $subordinate if $subordinate =~ /^(?:FORMAT|COMMENT|DEFAULTS?)$/;

    my @supparts = split /:/, $superior;
    my @subparts = split /:/, $subordinate;

    my $subparts = @subparts;

    my $target   = $subparts[0];

    fatal_error "Missing ACTION" unless supplied $target;

    push @subparts, '' while @subparts < 3;   #Avoid undefined values

    my $sublevel = $subparts[1];
    my $level    = $supparts[1];
    my $tag      = $supparts[2];

    if ( @supparts == 3 ) {
	return "$subordinate:$tag"    if $target =~ /^(?:NFLOG|ULOG)\b/;
	return "$target:none!:$tag"   if $level eq 'none!';
	return "$target:$level:$tag"  if $level =~ /!$/;
	return $subordinate           if $subparts >= 2;
	return "$target:$level:$tag";
    }

    if ( @supparts == 2 ) {
	return $subordinate           if $target =~ /^(?:NFLOG|ULOG)\b/;
	return "$target:none!"        if $level eq 'none!';
	return "$target:$level"       if ($level =~ /!$/) || ($subparts < 2);
    }

    $subordinate;
}

#
# Try to find a macro file -- RETURNS false if the file doesn't exist or MACRO if it does.
# If the file exists, the macro is entered into the 'targets' table and the fully-qualified
# name of the file is stored in the 'macro' table.
#
sub find_macro( $ )
{
    my $macro = $_[0];

    $macro =~ s/^macro\.//;

    my $macrofile = find_file "macro.$macro";

    if ( -f $macrofile ) {
	$macros{$macro} = $macrofile;
	$targets{$macro} = MACRO;
    } else {
	0;
    }
}

#
# This function substitutes the second argument for the first part of the first argument up to the first colon (":")
#
# Example:
#
#         substitute_param DNAT PARAM:info:FTP
#
#         produces "DNAT:info:FTP"
#
sub substitute_param( $$ ) {
    my ( $param, $action ) = @_;

    if ( $action =~ /:/ ) {
	my $logpart = (split_action $action)[1];
	$logpart =~ s!/$!!;
	return "$param:$logpart";
    }

    $param;
}

#
# Combine fields from a macro body with one from the macro invocation
#
sub merge_macro_source_dest( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( $invocation ) {
	if ( $body ) {
	    return $body if $invocation eq '-';
	    return "$body:$invocation" if $invocation =~ /.*?\.*?\.|^\+|^!+|^~|^!~|~<|~\[/;
	    return "$invocation:$body";
	}

	return $invocation;
    }

    $body || '';
}

#
# This one is used by snat inline
#
sub merge_inline_source_dest( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( $invocation ) {
	if ( supplied $body && $body ne '-' ) {
	    return $body if $invocation eq '-';

	    if ( $family == F_IPV4 ) {
		fatal_error 'Interface names cannot appear in the DEST column within an action body' if $body =~ /:/;

		if ( $invocation =~ /:/ ) {
		    $invocation =~ s/:.*//;
		    return join( ':', $invocation, $body );
		}
	    } else {
		fatal_error 'Interface names cannot appear in the DEST column within an action body' if $body =~ /:\[|:\+/;

		if ( $invocation =~ /:\[|:\+/ ) {
		    $invocation =~ s/:.*//;
		    return join( ':', $invocation, $body );
		}
	    }
	    
	    return "$invocation:$body";
	}

	return $invocation;
    }

    $body || '';
}

#
# This one is used by perl_action_helper()
#
sub merge_action_column( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( supplied( $body ) && $body ne '-' ) {
	$body;
    } else {
	$invocation;
    }
}

sub merge_macro_column( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( supplied( $invocation ) && $invocation ne '-' ) {
	$invocation;
    } else {
	$body;
    }
}

#
# Get Macro Name -- strips away trailing /*, :* and (*) from the first column in a rule, macro or action.
#
sub isolate_basic_target( $ ) {
    my $target = $_[0];

    if ( $target =~ /[\/]/ ) {
	( $target ) = split( '/', $target);
    } else {
	( $target ) = split_list2( $target, 'parameter' );
    } 

    $target =~ /^(\w+)[(].*[)]$/ ? $1 : $target;
}

#
# Map pre-3.0 actions to the corresponding Macro invocation
#

sub find_old_action ( $$$ ) {
    my ( $target, $macro, $param ) = @_;

    if ( my $actiontype = find_macro( $macro ) ) {
	( $macro, $actiontype , $param );
    } else {
	( $target, 0, '' );
    }
}

sub map_old_actions( $ ) {
    my $target = shift;

    if ( $target =~ /^Allow(.*)$/ ) {
	find_old_action( $target, $1, 'ACCEPT' );
    } elsif ( $target =~ /^Drop(.*)$/ ) {
	find_old_action( $target, $1, 'DROP' );
    } elsif ( $target = /^Reject(.*)$/ ) {
	find_old_action( $target, $1, 'REJECT' );
    } else {
	( $target, 0, '' );
    }
}

sub process_rule ( $$$$$$$$$$$$$$$$$$$$ );
sub process_mangle_rule1( $$$$$$$$$$$$$$$$$$$ );
sub process_snat1( $$$$$$$$$$$$ );
sub perl_action_helper( $$;$$ );

#
# Populate an action invocation chain. As new action tuples are encountered,
# the function will be called recursively by process_rule().
# 
# Note that the first two parameters are passed by reference and may be
# modified by this function.
#
sub process_action(\$\$$) {
    my ( $wholeactionref, $chainrefref, $caller ) = @_;
    my $wholeaction = ${$wholeactionref};
    my $chainref    = ${$chainrefref};
    my ( $action, $level, $tag, undef, $param ) = split /:/, $wholeaction, ACTION_TUPLE_ELEMENTS;
    my $type = $targets{$action};
    my $actionref = $actions{$action};
    my $matches   = fetch_inline_matches;

    if ( $type & MANGLE_TABLE ) {
	fatal_error "Action $action may only be used in the mangle file" unless $chainref->{table} eq 'mangle';
    } else {
	fatal_error "Action $action may not be used in the mangle file"  if $chainref->{table} eq 'mangle';
    }

    if ( $type & NAT_TABLE ) {
	fatal_error "Action $action may only be used in the snat file" unless $chainref->{table} eq 'nat';
    } else {
	fatal_error "Action $action may not be used in the snat file"  if $chainref->{table} eq 'nat';
    }

    $param = $1 if $param =~ /^.*\|(.*)$/; #Strip interface name off of the parameters

    my $actionfile = $actionref->{file};

    progress_message2 "$doing $actionfile for chain $chainref->{name}...";

    my $oldparms = push_action_params( $action, $chainref, $param, $level, $tag, $caller );
    my $options = $actionref->{options};
    my $nolog = $options & ( NOLOG_OPT | LOGJUMP_OPT );

    push_open $actionfile, 2, 1, undef, 2;

    setup_audit_action( $action ) if $options & AUDIT_OPT;

    $active{$action}++;
    push @actionstack, $wholeaction;

    my $save_comment = push_comment;

    while ( read_a_line( NORMAL_READ ) ) {
	unless ( $type & ( MANGLE_TABLE | NAT_TABLE | RAW_TABLE ) ) {
	    my ($target, $source, $dest, $protos, $ports, $sports, $origdest, $rate, $users, $mark, $connlimit, $time, $headers, $condition, $helper );

	    if ( $file_format == 1 ) {
		fatal_error( "FORMAT-1 actions are no longer supported" );
	    } else {
		($target, $source, $dest, $protos, $ports, $sports, $origdest, $rate, $users, $mark, $connlimit, $time, $headers, $condition, $helper )
		    = split_line2( 'action file',
				   \%rulecolumns,
				   $action_commands,
				   undef,
				   1 );
	    }

	    fatal_error 'TARGET must be specified' if $target eq '-';

	    if ( $target eq 'DEFAULTS' ) {
		default_action_params( $action, split_list $source, 'defaults' );

		if ( my $state = $actionref->{state} ) {
		    my ( $action ) = get_action_params( 1 );

		    if ( my $check = check_state( $state ) ) {
			perl_action_helper( $action, $check == 1 ? state_match( $state ) : '' , $state );
		    }
		}

		next;
	    }

	    for my $proto ( split_list( $protos, 'Protocol' ) ) {
		for my $user ( split_list( $users, 'User/Group' ) ) {
		    process_rule( $chainref,
				  '',
				  '',
				  $nolog ? $target : merge_levels( join(':', @actparams{'chain','loglevel','logtag'}), $target ),
				  '',
				  $source,
				  $dest,
				  $proto,
				  $ports,
				  $sports,
				  $origdest,
				  $rate,
				  $user,
				  $mark,
				  $connlimit,
				  $time,
				  $headers,
				  $condition,
				  $helper,
				  0 );

		    set_inline_matches( $matches );
		}
	    }
	} elsif ( $type & MANGLE_TABLE ) {
	    my ( $originalmark, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability , $dscp , $state, $time, $conditional );

	    if ( $family == F_IPV4 ) {
		( $originalmark, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $probability, $dscp, $state, $time, $conditional ) =
		    split_line2( 'mangle file',
				 { mark => 0,
				   action => 0,
				   source => 1,
				   dest => 2,
				   proto => 3,
				   dport => 4,
				   sport => 5,
				   user => 6,
				   test => 7,
				   length => 8,
				   tos => 9,
				   connbytes => 10,
				   helper => 11,
				   probability => 12 , 
				   scp => 13,
				   state => 14,
				   time => 15,
				   switch => 16,
				 },
				 {},
				 17,
				 1 );
		$headers = '-';
	    } else {
		( $originalmark, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability, $dscp, $state, $time, $conditional ) =
		    split_line2( 'action file',
				 { mark => 0,
				   action => 0,
				   source => 1,
				   dest => 2,
				   proto => 3,
				   dport => 4,
				   sport => 5,
				   user => 6,
				   test => 7,
				   length => 8,
				   tos => 9,
				   connbytes => 10,
				   helper => 11,
				   headers => 12,
				   probability => 13,
				   dscp => 14,
				   state => 15,
				   time => 16,
				   switch => 17,
				 },
				 {},
				 18,
				 1 );
	    }

	    fatal_error 'ACTION must be specified' if $originalmark eq '-';

	    if ( $originalmark eq 'DEFAULTS' ) {
		default_action_params( $action, split_list $source, 'defaults' );
		next;
	    }

	    for my $proto (split_list( $protos, 'Protocol' ) ) {
		process_mangle_rule1( $chainref,
				      $originalmark,
				      $source,
				      $dest,
				      $proto,
				      $ports,
				      $sports,
				      $user,
				      $testval,
				      $length,
				      $tos ,
				      $connbytes,
				      $helper,
				      $headers,
				      $probability ,
				      $dscp ,
				      $state,
				      $time,
				      $conditional );
		set_inline_matches( $matches );
	    }
	} else {
	    my ( $action, $source, $dest, $protos, $port, $ipsec, $mark, $user, $condition, $origdest, $probability) =
		split_line2( 'snat file',
			     { action =>0,
			       source => 1,
			       dest => 2,
			       proto => 3,
			       port => 4,
			       ipsec => 5,
			       mark => 6,
			       user => 7,
			       switch => 8,
			       origdest => 9,
			       probability => 10,
			     },
			     {},
			     11,
			     1 );

	    fatal_error 'ACTION must be specified' if $action eq '-';

	    if ( $action eq 'DEFAULTS' ) {
		default_action_params( $chainref, split_list( $source, 'defaults' ) );
		next;
	    }

	    for my $proto (split_list( $protos, 'Protocol' ) ) {
		process_snat1( $chainref,
			       $nolog ? $action : merge_levels( join(':', @actparams{'chain','loglevel','logtag'}), $action ),
			       $source,
			       $dest,
			       $proto,
			       $port,
			       $ipsec,
			       $mark,
			       $user,
			       $condition,
			       $origdest,
			       $probability,
		    );
	    }
	}
    }

    pop_comment( $save_comment );

    $active{$action}--;
    pop @actionstack;

    pop_open;

    unless ( @{$chainref->{rules}} ) {
	my $file = find_file( $action );

	fatal_error "File action.${action} is empty and file $action exists - the two must be combined as described in the Migration Considerations section of the Shorewall release notes" if -f $file;
    }

    #
    # Pop the action parameters
    #
    if ( ( my $result = pop_action_params( $oldparms ) ) & PARMSMODIFIED ) {
	#
	# The action modified its parameters -- delete it from %usedactions
	#
	delete $usedactions{$wholeaction};
    } elsif ( $result & USEDCALLER ) {
	#
	# The chain uses @CALLER but doesn't modify the action parameters.
	# We need to see if this caller has already invoked this action
	#
	my $renormalized_action = insert_caller( $wholeaction, $caller );
	my $chain1ref           = $usedactions{$renormalized_action};

	if ( $chain1ref ) {
	    #
	    # It has -- use the prior chain
	    #
	    ${$chainrefref} = $chain1ref;
	    #
	    # We leave the new chain in place but delete it from %usedactions below
	    # The optimizer will drop it from the final ruleset.
	    #
	} else {
	    #
	    # This is the first time that the current chain has invoked this action
	    #
	    $usedactions{$renormalized_action} = $chainref;
	    #
	    # Update the action member
	    #
	    $chainref->{action} = $renormalized_action;
	}
	#
	# Delete the usedactions entry with the original normalized key
	#
	delete $usedactions{$wholeaction};
	#
	# New normalized target
	#
	${$wholeactionref} = $renormalized_action;
    }
}

#
# This function is called prior to processing of the policy file. It:
#
# - Reads actions.std and actions (in that order) and for each entry:
#   o Adds the action to the target table
#   o Verifies that the corresponding action file exists
#

sub process_actions() {

    progress_message2 "Locating Action Files...";

    for my $file ( qw/actions.std actions/ ) {
	open_file( $file, 2 );

	while ( read_a_line( NORMAL_READ ) ) {
	    my ( $action, $options ) = split_line2( 'action file',
						    { action => 0, options => 1 },
						    {},    #Nopad
						    undef, #Columns
						    1 );   #Allow inline matches

	    my $type = ( $action eq $config{REJECT_ACTION} ? INLINE : ACTION );

	    my $opts = $type == INLINE ? NOLOG_OPT : 0;

	    my $state = '';
	    my $proto = 0;

	    if ( $action =~ /:/ ) {
		warning_message 'Default Actions are now specified in /etc/shorewall/shorewall.conf';
		$action =~ s/:.*$//;
	    }

	    fatal_error "Invalid Action Name ($action)" unless $action =~ /^[a-zA-Z][\w-]*!?$/;

	    if ( $options ne '-' ) {
		for ( split_list( $options, 'option' ) ) {
		    if ( /^state=(NEW|ESTABLISHED|RELATED|INVALID|UNTRACKED)$/ ) {
			if ( $file eq 'actions.std' ) {
			    $state = $1;
			} else {
			    fatal_error( q(The 'state' option is reserved for use in the actions.std file) );
			}
		    } elsif ( /^proto=(.+)$/ ) {
			fatal_error "Unknown Protocol ($1)" unless defined( $proto = resolve_proto( $1 ) );
		    } else {
			fatal_error "Invalid option ($_)" unless $options{$_};
			$opts |= $options{$_};
		    }
		}

		unless ( $type & INLINE ) {
		    $type = INLINE if $opts & INLINE_OPT;
		}

		fatal_error "Conflicting OPTIONS ($options)" if ( $opts & NOINLINE_OPT && $type == INLINE ) || ( $opts & INLINE_OPT && $opts & BUILTIN_OPT );
	    }

	    if ( my $actiontype = $targets{$action} ) {
		if ( ( $actiontype & ACTION ) && ( $type == INLINE ) ) {
		    if ( $actions{$action}{options} & NOINLINE_OPT ) {
			warning_message "'inline' option ignored on action $action -- that action may not be in-lined";
			next;
		    }

		    delete $actions{$action};
		    delete $targets{$action};
		} elsif ( ( $actiontype & INLINE ) && ( $type == ACTION ) && $opts & NOINLINE_OPT ) {
		    delete $actions{$action};
		    delete $targets{$action};
		} else {
		    warning_message "Duplicate Action Name ($action) Ignored" unless $actiontype & ( ACTION | INLINE );
		    next;
		}
	    }

	    if ( $opts & BUILTIN_OPT ) {
		warning_message( "The 'proto' option has no effect when specified on a builtin action" ) if $proto;

		my $actiontype = USERBUILTIN | OPTIONS;
		$actiontype   |= MANGLE_TABLE if $opts & MANGLE_OPT;
		$actiontype   |= RAW_TABLE    if $opts & RAW_OPT;
		$actiontype   |= NAT_TABLE    if $opts & NAT_OPT;
		#
		# For backward compatibility, we assume that user-defined builtins are valid in the filter table
		#
		$actiontype |= FILTER_TABLE if $opts & FILTER_OPT || ! ( $opts & ( MANGLE_OPT | RAW_OPT | NAT_OPT ) );

		if ( $builtin_target{$action} ) {
		    $builtin_target{$action} |= $actiontype;
		} else {
		    $builtin_target{$action}  = $actiontype;
		}

		$targets{$action} = $actiontype;

		make_terminating( $action ) if $opts & TERMINATING_OPT
	    } else {
		fatal_error "The 'raw' table may not be specified for non-builtin actions" if $opts & RAW_OPT;

		$type |= MANGLE_TABLE if $opts & MANGLE_OPT;
		
		if ( $opts & NAT_OPT ) {
		    fatal_error q(The 'mangle' and 'nat' options are mutually exclusive) if $opts & MANGLE_OPT;
		    $type |= NAT_TABLE;
		}

		my $actionfile = find_file( "action.$action" );

		fatal_error "Missing Action File ($actionfile)" unless -f $actionfile;

		new_action ( $action, $type, $opts, $actionfile , $state , $proto );
	    }
	}
    }

    if ( my $action = $config{REJECT_ACTION} ) {
	my $type = $targets{$action};
	fatal_error "REJECT_ACTION ($action) was not defined"  unless $type;
	fatal_error "REJECT_ACTION ($action) is not an action" unless $type == INLINE;
    }
}

#
# Create a policy action if it doesn't already exist
#
sub use_policy_action( $$ ) {
    my ( $normalized_target, $caller ) = @_;

    my $ref = use_action( 'filter', $normalized_target );

    if ( $ref ) {
	process_action( $normalized_target, $ref, $caller );
    } else {
	$ref = $usedactions{$normalized_target};
    }

    $ref;
}

#
# Process the REJECT_ACTION
#
sub process_reject_action() {
    my $rejectref = $filter_table->{reject};
    my $action    = $config{REJECT_ACTION};
    #
    # This gets called very early in the compilation process so we fake the section
    #
    $section = DEFAULTACTION_SECTION;

    if ( ( $targets{$action} || 0 ) == ACTION ) {
	add_ijump $rejectref, j => use_policy_action( $action, $rejectref->{name} );
    } else {
	progress_message2 "$doing $actions{$action}->{file} for chain reject...";

	process_inline( $action,      #Inline
			$rejectref,   #Chain
			'',           #Matches
			'',           #Matches1
			'',           #Log Level and Tag
			$action,      #Target
		        '',           #Param
			'-',          #Source
			'-',          #Dest
			'-',          #Proto
			'-',          #Ports
			'-',          #Sports
			'-',          #Original Dest
			'-',          #Rate
			'-',          #User
			'-',          #Mark
			'-',          #ConnLimit
			'-',          #Time
			'-',          #Headers
			'-',          #Condition
			'-',          #Helper
			0,            #Wildcard
	    );
    }

    $section = '';
}

################################################################################
# End of functions moved from the Actions module in 4.4.16
################################################################################
#
# Expand a macro rule from the rules file
#
sub process_macro ($$$$$$$$$$$$$$$$$$$$$) {
    my ($macro, $chainref, $matches, $matches1, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers, $condition, $helper, $wildcard ) = @_;

    my $generated = 0;


    my $macrofile    = $macros{$macro};
    my $save_matches = fetch_inline_matches;

    progress_message "..Expanding Macro $macrofile...";

    push_open $macrofile, 2, 1, no_comment, 2;

    macro_comment $macro;

    while ( read_a_line( NORMAL_READ ) ) {

	my ( $mtarget, $msource, $mdest, $mprotos, $mports, $msports, $morigdest, $mrate, $musers, $mmark, $mconnlimit, $mtime, $mheaders, $mcondition, $mhelper);

	if ( $file_format == 1 ) {
	    fatal_error( "FORMAT-1 macros are no longer supported" );
	} else {
	    ( $mtarget,
	      $msource,
	      $mdest,
	      $mprotos,
	      $mports,
	      $msports,
	      $morigdest,
	      $mrate,
	      $musers,
	      $mmark,
	      $mconnlimit,
	      $mtime,
	      $mheaders,
	      $mcondition,
	      $mhelper ) = split_line2( 'macro file',
					\%rulecolumns,
					$rule_commands,
					undef, #Columns
					1 );   #Allow inline matches
	}

	fatal_error 'TARGET must be specified' if $mtarget eq '-';

	if ( $mtarget =~ /^DEFAULTS?$/ ) {
	    $param = $msource unless supplied $param;
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

	fatal_error( "Invalid Action ($mtarget) in macro") unless $actiontype & ( ACTION + STANDARD + NATRULE + MACRO + CHAIN );

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

	for my $mp ( split_list( $mprotos, 'Protocol' ) ) {
	    for my $mu ( split_list( $musers, 'User/Group' ) ) {
		$generated |= process_rule( $chainref,
					    $matches,
					    $matches1,
					    $mtarget,
					    $param,
					    $msource,
					    $mdest,
					    merge_macro_column( $mp,         $proto ) ,
					    merge_macro_column( $mports,     $ports ) ,
					    merge_macro_column( $msports,    $sports ) ,
					    merge_macro_column( $morigdest,  $origdest ) ,
					    merge_macro_column( $mrate,      $rate ) ,
					    merge_macro_column( $mu,         $user ) ,
					    merge_macro_column( $mmark,      $mark ) ,
					    merge_macro_column( $mconnlimit, $connlimit) ,
					    merge_macro_column( $mtime,      $time ),
					    merge_macro_column( $mheaders,   $headers ),
					    merge_macro_column( $mcondition, $condition ),
					    merge_macro_column( $mhelper,    $helper ),
					    $wildcard
		                          );

		set_inline_matches( $save_matches );
	    }
	}

	progress_message "   Rule \"$currentline\" $done";
    }

    pop_open;

    progress_message "..End Macro $macrofile";

    return $generated;
}

#
# Expand an inline action rule from the rules file
#
sub process_inline ($$$$$$$$$$$$$$$$$$$$$$) {
    my ($inline, $chainref, $matches, $matches1, $loglevel, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers, $condition, $helper, $wildcard ) = @_;

    my $generated = 0;

    my ( $level, $tag ) = split( ':', $loglevel, 2 );

    my $oldparms   = push_action_params( $inline,
					 $chainref,
					 $param,
					 supplied $level ? $level : 'none',
					 defined  $tag   ? $tag   : '' ,
					 $chainref->{name} ,
				       );

    my $actionref    = $actions{$inline};
    my $inlinefile   = $actionref->{file};
    my $options      = $actionref->{options};
    my $nolog        = $options & NOLOG_OPT;
    my $save_matches = fetch_inline_matches;

    setup_audit_action( $inline ) if $options & AUDIT_OPT;

    progress_message "..Expanding inline action $inlinefile..." unless $inline eq $config{REJECT_ACTION};

    push_open $inlinefile, 2, 1, undef , 2;

    my $save_comment = push_comment;

    while ( read_a_line( NORMAL_READ ) ) {
	my  ( $mtarget,
	      $msource,
	      $mdest,
	      $mprotos,
	      $mports,
	      $msports,
	      $morigdest,
	      $mrate,
	      $musers,
	      $mmark,
	      $mconnlimit,
	      $mtime,
	      $mheaders,
	      $mcondition,
	      $mhelper ) = split_line2( 'inline action file',
					\%rulecolumns,
					$rule_commands,
					undef, #Columns
					1 );   #Allow inline matches


	fatal_error 'TARGET must be specified' if $mtarget eq '-';

	if ( $mtarget eq 'DEFAULTS' ) {
	    default_action_params( $chainref, split_list( $msource, 'defaults' ) );

	    if ( my $state = $actionref->{state} ) {
		my ( $action ) = get_action_params( 1 );

		if ( my $check = check_state( $state ) ) {
		    perl_action_helper( $action, $check == 1 ? state_match( $state ) : '' , $state );
		}
	    }

	    next;
	}

	$mtarget = merge_levels( join(':', @actparams{'chain','loglevel','logtag'}), $mtarget ) unless $nolog;

	my $action = isolate_basic_target $mtarget;

	fatal_error "Invalid or missing ACTION ($mtarget)" unless defined $action;

	my $actiontype = $targets{$action} || find_macro( $action );

	fatal_error( "Invalid Action ($mtarget) in inline action" ) unless $actiontype & ( ACTION + STANDARD + NATRULE + MACRO + CHAIN + INLINE + INLINERULE );

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

	for my $mp ( split_list( $mprotos, 'Protocol' ) ) {
	    for my $mu ( split_list( $musers, 'User/Group' ) ) {
		$generated |= process_rule( $chainref,
					    $matches,
					    $matches1,
					    $mtarget,
					    $param,
					    $msource,
					    $mdest,
					    merge_macro_column( $mp,          $proto ) ,
					    merge_macro_column( $mports,     $ports ) ,
					    merge_macro_column( $msports,    $sports ) ,
					    merge_macro_column( $morigdest,  $origdest ) ,
					    merge_macro_column( $mrate,      $rate ) ,
					    merge_macro_column( $mu,         $user ) ,
					    merge_macro_column( $mmark,      $mark ) ,
					    merge_macro_column( $mconnlimit, $connlimit) ,
					    merge_macro_column( $mtime,      $time ),
					    merge_macro_column( $mheaders,   $headers ),
					    merge_macro_column( $mcondition, $condition ),
					    merge_macro_column( $mhelper,    $helper ),
					    $wildcard
		                          );

		set_inline_matches( $save_matches );
	    }
	}

	progress_message "   Rule \"$currentline\" $done";
    }

    pop_comment( $save_comment );

    pop_open;

    progress_message "..End inline action $inlinefile";

    pop_action_params( $oldparms );

    return $generated;
}

#
# Confirm that we have AUDIT_TARGET capability and ensure the appropriate AUDIT chain.
#
sub verify_audit($;$$) {
    my ($target, $audit, $tgt ) = @_;

    require_capability 'AUDIT_TARGET', "$target rules", '';

    return ensure_audit_chain $target, $audit, $tgt;
}

#
# Once a rule has been expanded via wildcards (source and/or dest zone eq 'all'), it is processed by this function. If
# the target is a macro, the macro is expanded and this function is called recursively for each rule in the expansion.
# Similarly, if a new action tuple is encountered, this function is called recursively for each rule in the action
# body. In this latter case, a reference to the tuple's chain is passed in the first ($chainref) argument. A chain
# reference is also passed when rules are being generated during processing of a macro used as a default action.
#

sub process_rule ( $$$$$$$$$$$$$$$$$$$$ ) {
    my ( $chainref,   #reference to Action Chain if we are being called from process_action(); undef otherwise
	 $rule,       #Matches
	 $matches1,   #Matches after the ones generated by the columns
	 $target,
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
	 $headers,
	 $condition,
	 $helper,
	 $wildcard ) = @_;

    my ( $action, $loglevel)    = split_action $target;
    my ( $basictarget, $param ) = get_target_param $action;
    my $optimize = $wildcard ? ( $basictarget =~ /!$/ ? 0 : $config{OPTIMIZE} & 5 ) : 0;
    my $actiontype;
    my $inaction  = ''; # Set to true when we are processing rules in an action file
    my $inchain   = ''; # Set to true when a chain reference is passed.
    my $normalized_target;
    my $normalized_action;
    my $blacklist   = ( $section == BLACKLIST_SECTION );
    my $matches     = $rule;
    my $raw_matches = '';
    my $exceptionrule = '';
    my $usergenerated;
    my $prerule = '';
    my %save_nat_columns = %nat_columns;
    my $generated = 0;
    #
    # Subroutine for handling MARK and CONNMARK.
    #
    sub handle_mark( $$$ ) {
	my ( $target, $param, $marktype ) = @_;
	my $and_or = $param =~ s/^([|&])// ? $1 : '';

	require_capability( 'MARK_ANYWHERE', "The $target action", 's' );

	fatal_error "Mark Ranges are not supported in the rules file" if $param =~ /-/;
	#
	# A Single Mark
	#
	my $mark = $param;
	my $val;

	if ( supplied $mark ) {
	    if ( $marktype == SMALLMARK ) {
		$val = verify_small_mark( $mark );
	    } else {
		$val = validate_mark( $mark );
	    }
	} else {
	    $val = numeric_value( $mark = $globals{TC_MASK} );
	}

	$target = join( ' ', $target, $and_or eq '|' ? '--or-mark' : $and_or ? '--and-mark' : '--set-mark' );

	( $mark, my $mask ) = split '/', $mark;

	if ( supplied $mask ) {
	    $target = join( ' ', $target , join( '/', $mark , $mask ) );
	} else {
	    $target = join( ' ', $target , $mark );
	}

	$target;
    };

    if ( $inchain = defined $chainref ) {
	( $inaction, undef, undef, undef ) = split /:/, $normalized_action = $chainref->{action}, 4 if $chainref->{action};
    }

    $param = '' unless defined $param;

    if ( $basictarget eq 'INLINE' ) {
	( $action, $basictarget, $param, $loglevel, $raw_matches ) = handle_inline( FILTER_TABLE, 'filter', $action, $basictarget, $param, $loglevel );
    } else {
	$raw_matches = get_inline_matches(0);
    }
    #
    # Handle early matches
    #
    if ( $raw_matches =~ s/s*\+// ) {
	$prerule = $raw_matches;
	$raw_matches = '';
    }
    #
    # Determine the validity of the action
    #
    $actiontype = $targets{$basictarget} || find_macro( $basictarget );

    if ( $config{ MAPOLDACTIONS } ) {
	( $basictarget, $actiontype , $param ) = map_old_actions( $basictarget ) unless $actiontype || supplied $param;
    }

    fatal_error "Unknown ACTION ($action)" unless $actiontype;

    $usergenerated = $actiontype & IPTABLES;
    #
    # For now, we'll just strip the parens from the SOURCE and DEST. In a later release, we might be able to do something more with them
    #

    if ( $actiontype == MACRO ) {
	#
	# process_macro() will call process_rule() recursively for each rule in the macro body
	#
	fatal_error "Macro/Inline invocations nested too deeply" if ++$macro_nest_level > MAX_MACRO_NEST_LEVEL;

	$current_param = $param unless $param eq '' || $param eq 'PARAM';

	$generated = process_macro( $basictarget,
				    $chainref,
				    $rule . $raw_matches,
				    $matches1,
				    $target,
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
				    $headers,
				    $condition,
				    $helper,
				    $wildcard );

	$macro_nest_level--;
	goto EXIT;
    } elsif ( $actiontype & NFQ ) {
	$action = handle_nfqueue( $param,
				  1 # Allow 'bypass'
	    );
    } elsif ( $actiontype & SET ) {
	require_capability( 'IPSET_MATCH', 'SET and UNSET rules', '' );
	fatal_error "$action rules require a set name parameter" unless $param;
    } elsif ( ( $actiontype & AUDIT ) && ( $basictarget eq 'AUDIT' ) ) {
	require_capability ( 'AUDIT_TARGET', 'The AUDIT action', 's' );
	$param = $param eq '' ? 'drop' : $param;
	fatal_error "Invalid AUDIT type ($param) -- must be 'accept', 'drop' or 'reject'" unless $param =~ /^(?:accept|drop|reject)$/;
	$actiontype = STANDARD;
    } elsif ( ! $usergenerated ) {
	if ( $actiontype & NFLOG ) {
	    validate_level( $action );
	    $loglevel = supplied $loglevel ? join( ':', $action, $loglevel ) : $action;
	    $action   = 'LOG';
	} elsif ( ! ( $actiontype & (ACTION | INLINE | IPTABLES | TARPIT ) ) ) {
	    fatal_error "'builtin' actions may only be used in INLINE or IP[6]TABLES rules" if $actiontype == USERBUILTIN;
	    fatal_error "The $basictarget TARGET does not accept a parameter" unless $param eq '' || $actiontype & OPTIONS;
	}
    }
    #
    # We can now dispense with the postfix character
    #
    fatal_error "The +, - and ! modifiers are not allowed in the blrules file" if $action =~ s/[-+!]$// && $blacklist;
    
    unless ( $actiontype & ( ACTION | INLINE | IPTABLES | TARPIT ) ) {
	#
	# Catch empty parameter list
	#
	fatal_error "The $basictarget TARGET does not accept parameters" if $action =~ s/\(\)$//;
    }

    if ( $actiontype & (NATRULE | NONAT | NATONLY ) ) {
	$targets{$inaction} |= NATRULE if $inaction;
	fatal_error "NAT rules are only allowed in the NEW section" unless $section == NEW_SECTION;
    }

    if ( $actiontype & HELPER ) {
	fatal_error "HELPER rules are only allowed in the NEW section" unless $section == NEW_SECTION;
    }
    #
    # Take care of irregular syntax and targets
    #
    my $log_action = $action;

    unless ( $actiontype & ( ACTION | MACRO | NFLOG | NFQ | CHAIN | INLINE ) ) {
	my $bt = $basictarget;

	$bt =~ s/[-+!]$//;

	my %functions =
	    ( ACCEPT => sub() { 
		  if ( $blacklist ) {
		      $action = 'RETURN';
		  } elsif ( $helper ne '-' ) {
		      $actiontype |= HELPER if $section == NEW_SECTION;
		  }
	      } ,

	      AUDIT => sub() {
		  $action = "AUDIT --type $param";
	      } ,

	      CONNMARK => sub() {
		  $action = handle_mark( 'CONNMARK', $param, HIGHMARK );
	      } ,

	      REDIRECT => sub () {
		  my $z = $actiontype & NATONLY ? '' : firewall_zone;

		  if ( $dest eq '-' ) {
		      if ( $family == F_IPV4 ) {
			  $dest = ( $inchain ) ? '' : join( '', $z, '::' , $ports =~ /[:,]/ ? '' : $ports );
		      } else {
			  $dest = ( $inchain ) ? '' : join( '', $z, ':[]:' , $ports =~ /[:,]/ ? '' : $ports );
		      }
		  } elsif ( $inchain ) {
		      if ( $family == F_IPV4 ) {
			  $dest = ":$dest";
		      } else {
			  $dest = "[]:$dest";
		      }
		  } else {
		      if ( $family == F_IPV4 ) {
			  $dest = join( '', $z, '::', $dest )   unless $dest =~ /^[^\d].*:/;
		      } else {
			  $dest = join( '', $z, ':[]:', $dest ) unless $dest =~ /^[^\d].*:/;
		      }
		  }
	      } ,

	      REJECT => sub {
		  if ( supplied( $param ) ) {
		      my $option = $reject_options{$param};
		      fatal_error "Invalid REJECT option ($param)" unless $option;
		      if ( $option == 2 ) {
			  #
			  # tcp-reset
			  #
			  fatal_error "tcp-reset may only be used with PROTO tcp" unless ( resolve_proto( $proto ) || 0 ) == TCP;
			  $exceptionrule = '-p 6 ';
			  $param = 'tcp-reset';
		      }

		      $action = "REJECT --reject-with $param";
		  } else {		      
		      $action = 'reject';
		  }
	      },

	      CONTINUE => sub { $action = 'RETURN'; } ,

	      WHITELIST => sub {
		  fatal_error "'WHITELIST' may only be used in the blrules file" unless $blacklist;
		  $action = 'RETURN';
	      } ,

	      COUNT => sub { $action = ''; } ,

	      LOG => sub { fatal_error 'LOG requires a log level' unless supplied $loglevel; } ,

	      HELPER => sub { 
		  fatal_error "HELPER requires require that the helper be specified in the HELPER column" if $helper eq '-';
		  fatal_error "HELPER rules may only appear in the NEW section" unless $section == NEW_SECTION;
		  $action = ''; } ,

	      IPTABLES => sub {
		  if ( $param ) {
		      fatal_error "Unknown ACTION (IPTABLES)" unless $family == F_IPV4;
		      my ( $tgt, $options ) = split / /, $param, 2;
		      my $target_type = $builtin_target{$tgt};
		      fatal_error "Unknown target ($tgt)" unless $target_type;
		      fatal_error "The $tgt TARGET is not allowed in the filter table" unless $target_type & FILTER_TABLE;
		      $action = $param;
		  } else {
		      $action = '';
		  }
	      },

	      IP6TABLES => sub {
		  if ( $param ) {
		      fatal_error "Unknown ACTION (IP6TABLES)" unless $family == F_IPV6;
		      my ( $tgt, $options ) = split / /, $param, 2;
		      my $target_type = $builtin_target{$tgt};
		      fatal_error "Unknown target ($tgt)" unless $target_type;
		      fatal_error "The $tgt TARGET is not allowed in the filter table" unless $target_type & FILTER_TABLE;
		      $action = $param;
		  } else {
		      $action = '';
		  }
	      },

	      MARK => sub() {
		  $action = handle_mark( 'MARK', $param, HIGHMARK );
	      } ,

	      TARPIT => sub {
		  require_capability 'TARPIT_TARGET', 'TARPIT', 's';

		  fatal_error "TARPIT is only valid with PROTO tcp (6)" if ( resolve_proto( $proto ) || 0 ) != TCP;

		  if ( supplied $param ) {
		      fatal_error "TARPIT Parameter must be 'tarpit', 'honeypot' or 'reset'" unless $param =~ /^(tarpit|honeypot|reset)$/;
		      $action     = "TARPIT --$param";
		      $log_action = 'TARPIT';
		  } else {
		      $action = $log_action = 'TARPIT';
		  }

		  $exceptionrule = '-p 6 ';
	      },
	    );

	my $function = $functions{ $bt };

	if ( $function ) {
	    $function->();
	} elsif ( $actiontype & NATRULE && $helper ne '-' ) {
	    $actiontype |= HELPER;
	} elsif ( $actiontype & SET ) {
	    my %xlate = ( ADD => 'add-set' , DEL => 'del-set' );
	    my ( $setname, $flags, $timeout, $rest ) = split ':', $param, 4;

	    fatal_error "Invalid ADD/DEL parameter ($param)" if $rest;
	    $setname =~ s/^\+//;
	    fatal_error "Expected ipset name ($setname)" unless $setname =~ /^(6_)?[a-zA-Z][-\w]*$/;
	    fatal_error "Invalid flags ($flags)"         unless defined $flags && $flags =~ /^(dst|src)(,(dst|src)){0,5}$/;

	    $action = join( ' ', 'SET --' . $xlate{$basictarget} , $setname , $flags );

	    if ( supplied $timeout ) {
		fatal_error "A timeout may only be supplied in an ADD rule" unless $basictarget eq 'ADD';
		fatal_error "Invalid Timeout ($timeout)"                    unless $timeout && $timeout =~ /^\d+$/;

		$action .= " --timeout $timeout --exist";
	    }
	}
    }

    #
    # Isolate and validate source and destination zones
    #
    my $sourcezone = '-';
    my $destzone = '-';
    my $sourceref;
    my $destref;
    my $origdstports;

    unless ( $inchain ) {
	if ( $source =~ /^(.+?):(.*)/ ) {
	    fatal_error "Missing SOURCE Qualifier ($source)" if $2 eq '';
	    $sourcezone = $1;
	    $source = $2;
	} else {
	    $sourcezone = $source;
	    $source = $actiontype == INLINE ? '-' : ALLIP;
	}

	if ( $dest =~ /^(.*?):(.*)/ ) {
	    fatal_error "Missing DEST Qualifier ($dest)" if $2 eq '';
	    $destzone = $1;
	    $dest = $2;
	} elsif ( $dest =~ /.*\..*\./ ) {
	    #
	    # Appears to be an IPv4 address (no NAT in IPv6)
	    #
	    $destzone = '-';
	} else {
	    $destzone = $dest;
	    $dest = $actiontype == INLINE ? '-' : ALLIP;
	}

	fatal_error "Missing source zone" if $sourcezone eq '-' || $sourcezone =~ /^:/;
	fatal_error "Unknown source zone ($sourcezone)" unless $sourceref = defined_zone( $sourcezone );
	fatal_error 'USER/GROUP may only be specified when the SOURCE zone is $FW' unless $user eq '-' || $sourcezone eq firewall_zone;
    }

    if ( $actiontype & NATONLY ) {
	unless ( $destzone eq '-' || $destzone eq '' ) {
	    $destref = defined_zone( $destzone );

	    if ( $destref ) {
		warning_message "The destination zone ($destzone) is ignored in $log_action rules";
	    } else {
		$dest = join ':', $destzone, $dest;
		$destzone = '';
	    }
	}
    } elsif ( ! $inchain ) {
	fatal_error "Missing destination zone" if $destzone eq '-' || $destzone eq '';
	fatal_error "Unknown destination zone ($destzone)" unless $destref = defined_zone( $destzone );
    }

    my $restriction = NO_RESTRICT;

    unless ( $inchain ) {
	if ( $sourceref && ( $sourceref->{type} & ( FIREWALL | VSERVER ) ) ) {
	    $restriction = $destref && ( $destref->{type} & ( FIREWALL | VSERVER ) ) ? ALL_RESTRICT : OUTPUT_RESTRICT;
	} else {
	    $restriction = INPUT_RESTRICT if $destref && ( $destref->{type} & ( FIREWALL | VSERVER ) );
	}
    }

    #
    # For compatibility with older Shorewall versions
    #
    $origdest = ALLIP if $origdest eq 'all';

    #
    # Take care of chain
    #
    my $chain;

    if ( $inchain ) {
        #
        # We are generating rules in a chain -- get its name
        #
	$chain = $chainref->{name};
	#
	# If we are processing an inline action, we need the source zone for NAT.
	#
	$sourceref = find_zone( $chainref->{sourcezone} ) if $chainref->{sourcezone};
	#
	# And we need the dest zone for local/loopback/off-firewall/destonly checks
	#
	$destref   = find_zone( $chainref->{destzone}   ) if $chainref->{destzone};
    } elsif ( ! ( $actiontype & NATONLY ) ) {
	#
	# Check for illegal bridge port rule
	#
	if ( $destref->{type} & BPORT ) {
	    unless ( $sourceref->{bridge} eq $destref->{bridge} || single_interface( $sourcezone ) eq $destref->{bridge} ) {
		goto EXIT if $wildcard;
		fatal_error "Rules with a DESTINATION Bridge Port zone must have a SOURCE zone on the same bridge";
	    }
	}

	$chain = rules_chain( ${sourcezone}, ${destzone} );
	#
	# Ensure that the chain exists but don't mark it as referenced until after optimization is checked
	#
	( $chainref  = ensure_chain( 'filter', $chain ) )->{sourcezone} = $sourcezone;
	$chainref->{destzone} = $destzone;

	my $policy = $chainref->{policy};

	if ( $policy eq 'NONE' ) {
	    goto EXIT if $wildcard;
	    fatal_error "Rules may not override a NONE policy";
	}
	#
	# Handle Optimization level 1 when specified alone
	#
	if ( $optimize == 1 && $section == NEW_SECTION ) {
	    my $loglevel = $filter_table->{$chainref->{policychain}}{loglevel};
	    if ( $loglevel ne '' ) {
		goto EXIT if $target eq "${policy}:${loglevel}";
	    } else {
		goto EXIT if $basictarget eq $policy;
	    }
	}
	#
	# Mark the chain as referenced and add appropriate rules from earlier sections.
	#
	$chainref = ensure_rules_chain $chain;
	#
	# Handle rules in the BLACKLIST, ESTABLISHED, RELATED, INVALID and UNTRACKED sections
	#
	if ( $section & ( BLACKLIST_SECTION | ESTABLISHED_SECTION | RELATED_SECTION | INVALID_SECTION | UNTRACKED_SECTION ) ) {
	    my $auxchain = $section_functions{$section}->( $sourcezone, $destzone );
	    my $auxref   = $filter_table->{$auxchain};

	    unless ( $auxref ) {
		my $save_comment = push_comment;
		$auxref = new_chain 'filter', $auxchain;
		$auxref->{blacklistsection} = 1 if $blacklist;

		add_ijump( $chainref, j => $auxref, state_imatch( $section_states{$section} ) );
		pop_comment( $save_comment );
	    }

	    $chain    = $auxchain;
	    $chainref = $auxref;
	}
    }
    #
    # Handle 'local/loopback' warnings
    #
    unless ( $wildcard ) {
	if ( $sourceref ) {
	    warning_message( "The SOURCE zone in this rule is 'destonly'" ) if $sourceref->{destonly};

	    if ( $destref ) {
		warning_message( "\$FW to \$FW rules are ignored when there is a defined 'loopback' zone" ) if loopback_zones && $sourceref->{type} == FIREWALL && $destref->{type} == FIREWALL;
	    }
	}
    }
    #
    # Handle actions
    #
    my $actionchain; # Name of the action chain

    if ( $actiontype & ACTION ) {
	#
	# Verify action 'proto', if any
	#
	$proto = determine_action_protocol( $basictarget, $proto );
	#
	# Save NAT-oriented column contents
	#
	@nat_columns{'dest', 'proto', 'ports' } = ( $dest,
						    $proto eq '-' ? $nat_columns{proto} : $proto,
						    $ports eq '-' ? $nat_columns{ports} : $ports );
	#
	# Push the current column array onto the column stack
	#
        my @savecolumns = @columns;
	#
	# And store the (modified) columns into the columns array for use by perl_action[_tcp]_helper. We
	# only need the NAT-oriented columns
	#
	@columns = ( undef , undef, $dest, $proto, $ports);
	#
	# Handle 'section' option
	#
	$param = supplied $param ? join( ',' , $section_rmap{$section}, $param ) : $section_rmap{$section} if $actions{$basictarget}{options} & SECTION_OPT;
	#
	# Create the action:level:tag:param tuple.
	#
	$normalized_target = normalize_action( $basictarget, $loglevel, $param );

	fatal_error( "Action $basictarget invoked Recursively (" .  join( '->', map( external_name( $_ ), @actionstack , $normalized_target ) ) . ')' ) if $active{$basictarget};

	if ( my $ref = use_action( 'filter', $normalized_target ) ) {
	    #
	    # First reference to this tuple
	    #
	    my $savestatematch = $statematch;
	    $statematch        = '';
	    #
	    # process_action may modify both $normalized_target and $ref!!!
	    #
	    process_action( $normalized_target, $ref, $chain );
	    #
	    # Capture the name of the action chain
	    #
	    $actionchain = $ref->{name};
	    #
	    # Processing the action may determine that the action or one of it's dependents does NAT or HELPER, so:
	    #
	    #    - Refresh $actiontype
	    #    - Create the associated nat and/or table chain if appropriate.
	    #
	    ensure_chain( 'nat', $actionchain ) if ( $actiontype = $targets{$basictarget} ) & NATRULE;
	    ensure_chain( 'raw', $actionchain ) if ( $actiontype & HELPER );

	    $statematch = $savestatematch;
	} else {
	    #
	    # We've seen this tuple before
	    #
	    $actionchain = $usedactions{$normalized_target}->{name};
	}

	$action = $basictarget; # Remove params, if any, from $action.

	@columns = @savecolumns;
    } elsif ( $actiontype & INLINE ) {
	#
	# process_inline() will call process_rule() recursively for each rule in the action body
	#
	fatal_error "Macro/Inline invocations nested too deeply" if ++$macro_nest_level > MAX_MACRO_NEST_LEVEL;
	#
	# Push the current column array onto the column stack
	#
        my $savecolumns = [ ( $actionresult, @columns ) ];
	#
	# And store the (modified) columns into the columns array for use by perl_action[_tcp]_helper
	#
	@columns = ( $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time, $headers, $condition, $helper, $wildcard );

	$actionresult = 0;

	$generated = process_inline( $basictarget,
				     $chainref,
				     $prerule . $rule,
				     $matches1 . $raw_matches,
				     $loglevel,
				     $target,
				     $param,
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
				     $headers,
				     $condition,
				     $helper,
				     $wildcard ) || $actionresult;

	( $actionresult, @columns ) = @$savecolumns;;

	$macro_nest_level--;

	goto EXIT;
    }
    #
    # Generate Fixed part of the rule
    #
    if ( $actiontype & ( NATRULE | NONAT ) && ! ( $actiontype & NATONLY ) ) {
	#
	# Either a DNAT, REDIRECT or ACCEPT+ rule or an Action with NAT;
	# don't apply rate limiting twice
	#
	$rule .= join( '',
		       do_proto($proto, $ports, $sports),
		       do_user( $user ) ,
		       do_test( $mark , $globals{TC_MASK} ) ,
		       do_connlimit( $connlimit ),
		       do_time( $time ) ,
		       do_headers( $headers ) ,
		       do_condition( $condition , $chain ) ,
		       $raw_matches ,
		     );
    } elsif ( $section & ( ESTABLISHED_SECTION | INVALID_SECTION | RELATED_SECTION | UNTRACKED_SECTION ) ) {
	$rule .= join( '',
		       do_proto($proto, $ports, $sports),
		       do_ratelimit( $ratelimit, $basictarget ) ,
		       do_user( $user ) ,
		       do_test( $mark , $globals{TC_MASK} ) ,
		       do_connlimit( $connlimit ),
		       do_time( $time ) ,
		       do_headers( $headers ) ,
		       do_condition( $condition , $chain ) ,
		       do_helper( $helper ) ,
		       $matches1 . $raw_matches ,
		     );
    } else {
	$rule .= join( '',
		       do_proto($proto, $ports, $sports),
		       do_ratelimit( $ratelimit, $basictarget ) ,
		       do_user( $user ) ,
		       do_test( $mark , $globals{TC_MASK} ) ,
		       do_connlimit( $connlimit ),
		       do_time( $time ) ,
		       do_headers( $headers ) ,
		       do_condition( $condition , $chain ) ,
		       $matches1 . $raw_matches ,
		     );
    }

    unless ( $section & ( NEW_SECTION | DEFAULTACTION_SECTION ) ||
	     $inaction ||
	     $blacklist ||
	     $basictarget eq 'dropInvalid' ) {
	if ( $config{FASTACCEPT} ) {
	    fatal_error "Entries in the $section_rmap{$section} SECTION of the rules file not permitted with FASTACCEPT=Yes" unless
		( ( $section & ( UNTRACKED_SECTION | INVALID_SECTION | ALL_SECTION ) ) ||
		  ( $section & ( RELATED_SECTION ) ) && ( $config{RELATED_DISPOSITION} ne 'ACCEPT' || $config{RELATED_LOG_LEVEL} ) )
	     }

	fatal_error "$basictarget rules are not allowed in the $section_rmap{$section} SECTION" if $actiontype & ( NATRULE | NONAT );
	$rule .= state_match('ESTABLISHED') if $section == ESTABLISHED_SECTION;
    }
    #
    # Generate CT rules(s), if any
    #
    if ( $actiontype & HELPER ) {
	handle_helper_rule( $helper,
			    $source,
			    $origdest ? $origdest : $dest,
			    $proto,
			    $ports,
			    $sports,
			    $sourceref,
			    ( $actiontype & ACTION ) ? $actionchain : '',
			    $inchain ? $chain : '' ,
			    $user ,
			    $rule ,
			  );

	$targets{$inaction} |= HELPER if $inaction; 
    }

    # Generate NAT rule(s), if any
    #
    if ( $actiontype & NATRULE ) {
	require_capability( 'NAT_ENABLED' , "$basictarget rules", '' );
	#
	# Add the appropriate rule to the nat table
	#
	( $ports,
	  $origdstports,
	  $dest ) = handle_nat_rule( $dest,
				     $proto,
				     $ports,
				     $origdest,
				     ( $actiontype & ACTION ) ? $actionchain : '',
				     $action,
				     $sourceref,
				     $inaction ? $chain : '',
				     $rule,
				     $source,
				     ( $actiontype & ACTION ) ? '' : $loglevel,
				     $log_action,
				     $wildcard
				   );

	#
	# After NAT:
	#   - the destination port will be the server port ($ports) -- we did that above
	#   - the destination IP will be the server IP   ($dest)  -- also done above
	#   - there will be no log level (we log NAT rules in the nat table rather than in the filter table).
	#   - the target will be ACCEPT.
	#
	unless ( $actiontype & NATONLY ) {
	    $rule = join( '',
			  $matches,
			  do_proto( $proto, $ports, $sports ),
			  do_ratelimit( $ratelimit, 'ACCEPT' ),
			  do_user $user,
			  do_test( $mark , $globals{TC_MASK} ),
			  do_condition( $condition , $chain ),
			  $raw_matches,
			);
	    $loglevel = '';
	    $action   = 'ACCEPT';
	    $origdest = ALLIP if  $origdest =~ /[+]/;
	    $helper   = '-';
	}
    } elsif ( $actiontype & NONAT ) {
	#
	# NONAT or ACCEPT+
	#
	handle_nonat_rule( $action,
			   $source,
			   $dest,
			   $origdest,
			   $sourceref,
			   $inaction,
			   $chain,
			   $loglevel,
			   $log_action,
			   $rule,
			   $wildcard
			 );
    }

    #
    # Add filter table rule, unless this is a NATONLY rule type
    #
    unless ( $actiontype & NATONLY ) {

	if ( $actiontype & ACTION ) {
	    $action = $actionchain;

	    if ( $actions{$basictarget}{options} & LOGJUMP_OPT ) {
		$log_action = $basictarget;
	    } else {
		$loglevel = '';
	    }
	}

	if ( $origdest ) {
	    unless ( $origdest eq '-' ) {
		require_capability( 'CONNTRACK_MATCH', 'ORIGINAL DEST in a non-NAT rule', 's' ) unless $actiontype & NATRULE;
	    } else {
		$origdest = '';
	    }
	}

	$rule .= "-m conntrack --ctorigdstport $origdstports " if have_capability( 'NEW_CONNTRACK_MATCH' ) && $origdstports;

	verify_audit( $action ) if $actiontype & AUDIT;

	expand_rule( $chainref ,
		     $restriction ,
		     $prerule ,
		     $rule ,
		     $source ,
		     $dest ,
		     $origdest ,
		     $action ,
		     $loglevel ,
		     $log_action ,
		     $exceptionrule ,
		     $usergenerated && ! $loglevel )
	    unless unreachable_warning( $wildcard || $section == DEFAULTACTION_SECTION, $chainref );
    }

    $generated = 1;

  EXIT:
    {
      %nat_columns = %save_nat_columns;
    }

    return $generated;
}


sub check_state( $ );
#
# Check the passed connection state for conflict with the current section
#
# Returns non-zero value if the state is compatible with the section:
#
#   1:  Emit the rule with state match
#   2:  Emit the rule without 
#
sub check_state( $ ) {
    my $state = $_[0];

    if ( $section == BLACKLIST_SECTION ) {
	my $blacklist_states = $globals{BLACKLIST_STATES};
	return 1 if $blacklist_states eq 'ALL';
	return 2 if $blacklist_states eq $state;
	for ( split ',', $blacklist_states ) {
	    return 1 if $_ eq $state;
	}

	return 0;
    }

    my $chainref   = $actparams{0};
    my $name       = $chainref->{name};
    my $statechainref;

    if ( $name =~ /^([+_&])/ ) {
	#
	# This is a state chain
	#
	return $state eq 'RELATED'   ? 2 : 0 if $1 eq '+';
	return $state eq 'INVALID'   ? 2 : 0 if $1 eq '_';
	return $state eq 'UNTRACKED' ? 2 : 0;
    }

    my $sectionref = $chainref->{sections};

    if ( $state eq 'ESTABLISHED' ) {
	return ( $sectionref && $sectionref->{$state} ) ? 0 : $section == ESTABLISHED_SECTION ? 2 : 1;
    }

    if ( $state =~ /^(?:INVALID|UNTRACKED|RELATED|ESTABLISHED)$/ && $globals{"${state}_TARGET"} ) {
	#
	# One of the states that has its own state chain -- get the current action's chain
	#
	if ( $sectionref && $sectionref->{$state} ) {
	    #
	    # We're past that section -- see if there was a separate state chain
	    #
	    if ( my $statechainref = $filter_table->{"$statetable{$state}[0]$chainref->{name}"} ) {
		#
		# There was -- if the chain had a RETURN then we will emit the current rule; otherwise we won't
		#
		return has_return( $statechainref ) ? 1 : 0;
	    } else {
		#
		# There wasn't -- suppress the current rule
		#
		return 0;
	    }
	}
    }

    if ( $section & ( NEW_SECTION | DEFAULTACTION_SECTION ) ) {
	if ( $state eq 'NEW' ) {
	    #
	    # If an INVALID or UNTRACKED rule would be emitted then we must include the state match
	    #
	    for ( qw/INVALID UNTRACKED/ ) {
		return 1 if check_state( $_ );
	    }

	    2;
	} else {
	    $state =~ /^(?:INVALID|UNTRACKED)$/;
	}
    } elsif ( $sectionref ) {
	#
	# we're dealing with a rules chain
	#
	$state eq $section_rmap{$section} ? 2 : 1;
    } else {
	#
	# An action chain -- we can't predict where it will get invoked so populate it fully
	#
	1;
    }
}

#
# Helper for the perl_action_xxx functions
#
sub merge_target( $$ ) {
    my ( $ref, $target ) = @_;

    merge_levels( join( ':', @actparams{'chain','loglevel','logtag'}), $target );
}

#
# May be called by Perl code in action bodies (regular and inline) to generate a rule.
#
sub perl_action_helper($$;$$) {
    my ( $target, $matches, $isstatematch , $matches1 ) = @_;
    my $action   = $actparams{action};
    my $chainref = $actparams{0};
    my $result;

    assert( $chainref );

    $matches .= ' ' unless $matches =~ /^(?:.+\s)?$/;

    if ( $matches1 ) {
	$matches1 .= ' ' unless $matches1 =~ /^(?:.+\s)?$/;
    } else {
	$matches1 = '';
    }

    set_inline_matches( $target =~ /^INLINE(?::.*)?$/ ? $matches : '' );

    if ( $isstatematch ) {
	if ( $statematch ) {
	    if ( $statematch eq $isstatematch ) {
		#
		# Same match -- pretend this isn't a state match
		#
		$isstatematch = '';
	    } else {
		#
		# Different state -- can't possibly match
		#
		return;
	    }
	} else {
	    $statematch = $isstatematch;
	}
    }

    my $ref = $actions{$action};

    assert( $ref, $action );

    if ( $ref->{type} & INLINE ) {
	$result = &process_rule( $chainref,
				 $matches,
				 $matches1,
				 merge_target( $ref, $target ),
				 '',                              # CurrentParam
				 @columns );
    } else {
	if ( ( $targets{$target} || 0 ) & NATRULE ) {
	    $result = process_rule( $chainref,
				    $matches,
				    $matches1,
				    merge_target( $actions{$action}, $target ),
				    '',                               # Current Param
				    '-',                              # Source
				    merge_action_column(              # Dest
					$columns[2],			      
					$nat_columns{dest}
				    ),
				    merge_action_column(              #Proto
					$columns[3],
					$nat_columns{proto}
				    ),
				    merge_action_column(              #Ports
					$columns[4],
					$nat_columns{ports}),
				    '-',                              # Source Port(s)
				    '-',                              # Original Dest
				    '-',                              # Rate Limit
				    '-',                              # User
				    '-',                              # Mark
				    '-',                              # Connlimit
				    '-',                              # Time
				    '-',                              # Headers,
				    '-',                              # condition,
				    '-',                              # helper,
				    0,                                # Wildcard
		);
	} else {
	    $result = process_rule( $chainref,
				    $matches,
				    $matches1,
				    merge_target( $actions{$action}, $target ),
				    '',                               # Current Param
				    '-',                              # Source
				    '-',                              # Dest
				    '-',                              # Proto
				    '-',                              # Port(s)
				    '-',                              # Source Port(s)
				    '-',                              # Original Dest
				    '-',                              # Rate Limit
				    '-',                              # User
				    '-',                              # Mark
				    '-',                              # Connlimit
				    '-',                              # Time
				    '-',                              # Headers,
				    '-',                              # condition,
				    '-',                              # helper,
				    0,                                # Wildcard
		);
	}

	allow_optimize( $chainref );
    }
    #
    # Record that we generated a rule to avoid bogus warning
    #
    $actionresult ||= $result;

    $statematch = '' if $isstatematch;
}

#
# May be called by Perl code in action bodies (regular and inline) to generate a rule.
#
sub perl_action_tcp_helper($$) {
    my ( $target, $proto ) = @_;
    my $action   = $actparams{action};
    my $chainref = $actparams{0};
    my $result;
    my $passedproto = $columns[2];

    assert( $chainref );

    $proto .= ' ' unless $proto =~ /^(?:.+\s)?$/;

    set_inline_matches( '' ) if $config{INLINE_MATCHES};

    if ( $passedproto eq '-' || $passedproto eq 'tcp' || $passedproto eq '6' ) {
	#
	# For other protos, a 'no rule generated' warning will be issued
	#
	my $ref = $actions{$action};

	assert( $ref, $action );

	if ( $ref->{type} & INLINE ) {
	    $result = &process_rule( $chainref,
				     $proto,
				     '',
				     merge_target( $ref, $target ),
				     '',
				     @columns[0,1],
				     6,
				     @columns[3..LAST_COLUMN]
				   );
	} else {
	    $result = process_rule( $chainref,
				    $proto,
				    '',
				    merge_target( $actions{$action}, $target ),
				    '',                               # Current Param
				    '-',                              # Source
				    '-',                              # Dest
				    '-',                              # Proto
				    '-',                              # Port(s)
				    '-',                              # Source Port(s)
				    '-',                              # Original Dest
				    '-',                              # Rate Limit
				    '-',                              # User
				    '-',                              # Mark
				    '-',                              # Connlimit
				    '-',                              # Time
				    '-',                              # Headers,
				    '-',                              # condition,
				    '-',                              # helper,
				    0,                                # Wildcard
		                  );

	    allow_optimize( $chainref );
	}
	#
	# Record that we generated a rule to avoid bogus warning
	#
	$actionresult ||= $result;
    }
}

#
# Helper functions for process_raw_rule(). That function deals with the ugliness of wildcard zones ('all' and 'any') and zone lists.
#
# Process a SECTION header
#
sub process_section ($) {
    my $sect = shift;
    #
    # split_line2 has already verified that there are exactly two tokens on the line
    #
    fatal_error "Invalid SECTION ($sect)" unless defined $sections{$sect};
    fatal_error "Duplicate or out of order SECTION $sect" if $sections{$sect};

    if ( $sect eq 'BLACKLIST' ) {
	fatal_error "The BLACKLIST section has been eliminated. Please move your BLACKLIST rules to the 'blrules' file";
    } elsif ( $sect eq 'ESTABLISHED' ) {
        $sections{ALL} = 1;
    } elsif ( $sect eq 'RELATED' ) {
        @sections{'ALL','ESTABLISHED'} = ( 1, 1);
    } elsif ( $sect eq 'INVALID' ) {
        @sections{'ALL','ESTABLISHED','RELATED'} = ( 1, 1, 1 );
    } elsif ( $sect eq 'UNTRACKED' ) {
        @sections{'ALL','ESTABLISHED','RELATED', 'INVALID' } = ( 1, 1, 1, 1 );
    } elsif ( $sect eq 'NEW' ) {
        @sections{'ALL','ESTABLISHED','RELATED','INVALID','UNTRACKED', 'NEW'} = ( 1, 1, 1, 1, 1, 1 );
    }



    $next_section = $section_map{$sect};
}

sub next_section() {
    
    if ( $next_section == RELATED_SECTION ) {
	finish_section 'ESTABLISHED';
    } elsif ( $next_section == INVALID_SECTION ) {
	finish_section ( 'ESTABLISHED,RELATED' );
    } elsif ( $next_section == UNTRACKED_SECTION ) {
	finish_section ( 'ESTABLISHED,RELATED,INVALID' );
    } elsif ( $next_section == NEW_SECTION ) {
	finish_section ( 'ESTABLISHED,RELATED,INVALID,UNTRACKED' );
    }

    $section = $next_section;
}

#
# Build a source or destination zone list
#
sub build_zone_list( $$$\$\$ ) {
    my ($fw, $input, $which, $intrazoneref, $wildref ) = @_;
    my $any = ( $input =~ s/^any/all/ );
    my $exclude;
    my $rest;
    my %exclude;
    my @result;
    #
    # Handle Wildcards
    #
    if ( $input =~ /^(all[-+]*)(![^:]+)?(:.*)?$/ ) {
	$input   = $1;
	$exclude = $2;
	$rest    = $3;

	$$wildref = 1;

	if ( defined $exclude ) {
	    $exclude =~ s/!//;
	    fatal_error "Invalid exclusion list (!$exclude)" if $exclude =~ /^,|!|,,|,$/;
	    for ( split /,/, $exclude ) {
		fatal_error "Unknown zone ($_)" unless defined_zone $_;
		$exclude{$_} = 1;
	    }
	}

	unless ( $input eq 'all' ) {
	    if ( $input eq 'all+' ) {
		$$intrazoneref = 1;
	    } elsif ( ( $input eq 'all+-' ) || ( $input eq 'all-+' ) ) {
		$$intrazoneref = 1;
		$exclude{$fw} = 1;
	    } elsif ( $input eq 'all-' ) {
		$exclude{$fw} = 1;
	    } else {
		fatal_error "Invalid $which ($input)";
	    }
	}

	@result = grep ! $exclude{$_}, $any ? all_parent_zones : non_firewall_zones;

	unshift @result, $fw unless $exclude{$fw};

    } elsif ( $input =~ /^([^:]+,[^:]+)(:.*)?$/ ) {
	$input    = $1;
	$rest     = $2;
	$$wildref = 1;

	$$intrazoneref = ( $input =~ s/\+$// );

	@result = split_list $input, 'zone';
    } else {
	@result = ( $input );
    }

    if ( defined $rest ) {
	$_ .= $rest for @result;
    }

    @result;
}

#
# Process a Record in the rules file
#
sub process_raw_rule1( $$$$$$$$$$$$$$$ ) {
    my ( $target, $source, $dest, $protos, $ports, $sports, $origdest, $ratelimit, $users, $mark, $connlimit, $time, $headers, $condition, $helper ) = @_;
    if ( $source =~ /^none(:.*)?$/i || $dest =~ /^none(:.*)?$/i ) {
	progress_message "Rule \"$currentline\" ignored.";
	return 1;
    }

    my $intrazone = 0;
    my $wild      = 0;
    my $thisline  = $currentline; #We must save $currentline because it is overwritten by macro expansion
    my $action    = isolate_basic_target $target;
    my $fw        = firewall_zone;
    my @source    = build_zone_list ( $fw, $source, 'SOURCE', $intrazone, $wild );
    my @dest      = build_zone_list ( $fw, $dest,   'DEST'  , $intrazone, $wild );
    my @protos    = split_list1 $protos, 'Protocol';
    my @users     = split_list1 $users, 'USER/GROUP';
    my $generated = 0;

    $statematch = '';

    fatal_error "Invalid or missing ACTION ($target)" unless defined $action;

    if ( @protos > 1 ) {
	fatal_error "Inversion not allowed in a PROTO list" if $protos =~ /!/;
    }

    for $source ( @source ) {
	for $dest ( @dest ) {
	    my $sourcezone = (split( /:/, $source, 2 ) )[0];
	    my $destzone   = (split( /:/, $dest,   2 ) )[0];
	    $destzone = $action =~ /^REDIRECT/ ? $fw : '' unless defined_zone $destzone;
	    if ( ! $wild || $intrazone || ( $sourcezone ne $destzone ) ) {
		for my $proto ( @protos ) {
		    for my $user ( @users ) {
			if ( process_rule( undef,
					   '',
					   '',
					   $target,
					   '',
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
					   $headers,
					   $condition,
					   $helper,
					   $wild ) ) {
			    $generated = 1;
			}
		    }
		}
	    }
	}
    }

    warning_message  qq(Entry generated no $toolname rules) unless $generated;

    progress_message qq(   Rule "$thisline" $done);
}

sub process_raw_rule ( ) {
    my ( $target, $source, $dest, $protos, $ports, $sports, $origdest, $ratelimit, $users, $mark, $connlimit, $time, $headers, $condition, $helper )
	= split_line2( 'rules file',
		       \%rulecolumns,
		       $rule_commands,
		       undef, #Columns
		       1 );   #Allow inline matches


    fatal_error 'ACTION must be specified' if $target eq '-';
    #
    # Section Names are optional so once we get to an actual rule, we need to be sure that
    # we close off any missing sections.
    #
    next_section if $section != $next_section;

    my ( @source, @dest );

    if ( $source =~ /:\(.+\)/ ) {
	@source = split_list3( $source, 'SOURCE' );
    } else {
	@source = ( $source );
    }

    if ( $dest =~ /:\(.+\)/ ) {
	@dest = split_list3( $dest, 'DEST' );
    } else {
	@dest = ( $dest );
    }

    for $source ( @source ) {
	$source = join(':', $1, $2 ) if $source =~ /^(.+?):\((.+)\)$/;

	for $dest ( @dest ) {
	    $dest = join( ':', $1, $2 ) if $dest =~  /^(.+?):\((.+)\)$/;

	    process_raw_rule1( $target, $source, $dest, $protos, $ports, $sports, $origdest, $ratelimit, $users, $mark, $connlimit, $time, $headers, $condition, $helper );
	}
    }
}


sub intrazone_allowed( $$ ) {
    my ( $zone, $zoneref ) = @_;

    $zoneref->{complex} && $filter_table->{rules_chain( $zone, $zone )}{policy} ne 'NONE';
}

#
# Process the BLRules and Rules Files
#
sub process_rules() {
    my $blrules = 0;
    my @zones   = off_firewall_zones;
    #
    # Populate the state table
    #
    %statetable          = ( ESTABLISHED => [ '^', '',                           '',                          'ACCEPT' ] ,
			     RELATED     => [ '+', $config{RELATED_LOG_LEVEL},   $globals{RELATED_LOG_TAG},   $globals{RELATED_TARGET}   , $origin{RELATED_DISPOSITION}   , $origin{RELATED_LOG_LEVEL} ] ,
			     INVALID     => [ '_', $config{INVALID_LOG_LEVEL},   $globals{INVALID_LOG_TAG},   $globals{INVALID_TARGET}   , $origin{INVALID_DISPOSITION}   , $origin{INVALID_LOG_LEVEL} ] ,
			     UNTRACKED   => [ '&', $config{UNTRACKED_LOG_LEVEL}, $globals{UNTRACKED_LOG_TAG}, $globals{UNTRACKED_TARGET} , $origin{UNTRACKED_DISPOSITION} , $origin{UNTRACKED_LOG_LEVEL} ] ,
			   );
    %section_states = ( BLACKLIST_SECTION ,  $globals{BLACKLIST_STATES},
			ESTABLISHED_SECTION, 'ESTABLISHED',
			RELATED_SECTION,     'RELATED',
			INVALID_SECTION,     'INVALID',
			UNTRACKED_SECTION,   'UNTRACKED' );

    #
    # If A_REJECT was specified in shorewall[6].conf, the A_REJECT chain may already exist.
    #
    $usedactions{normalize_action_name( 'A_REJECT' )} = $filter_table->{A_REJECT} if $filter_table->{A_REJECT};
    #
    # Create zone-forwarding chains if required
    #
    for my $zone ( @zones ) {
	my $zoneref = find_zone( $zone );
	my $simple  =  @zones <= 2 && ! $zoneref->{complex};

	unless ( @zones <= 2 && ! $zoneref->{complex} ) {
	    #
	    # Complex zone or we have more than one non-firewall zone -- create a zone forwarding chain
	    #
	    new_standard_chain zone_forward_chain( $zone );
	}
    }
    #
    # Process the blrules file
    #
    $section = $next_section = BLACKLIST_SECTION;

    my $fn = open_file( 'blrules', 1, 1 );

    if ( $fn ) {
	first_entry( sub () {
			 my ( $level, $disposition , $tag ) = ( @config{'BLACKLIST_LOG_LEVEL', 'BLACKLIST_DISPOSITION' }, $globals{BLACKLIST_LOG_TAG} ) ;
			 my  $audit       = $disposition =~ /^A_/;
			 my  $target      = $disposition eq 'REJECT' ? 'reject' : $disposition;

			 progress_message2 "$doing $currentfilename...";

			 if ( supplied $level ) {
			     ensure_blacklog_chain( $target, $disposition, $level, $tag, $audit );
			     ensure_audit_blacklog_chain( $target, $disposition, $level ) if have_capability 'AUDIT_TARGET';
			 } elsif ( $audit ) {
			     require_capability 'AUDIT_TARGET', "BLACKLIST_DISPOSITION=$disposition", 's';
			     verify_audit( $disposition );
			 } elsif ( have_capability 'AUDIT_TARGET' ) {
			     verify_audit( 'A_' . $disposition );
			 }

			 $blrules = 1;
		     }
		   );

	process_raw_rule while read_a_line( NORMAL_READ );
    }

    $section      = NULL_SECTION;
    $next_section = NEW_SECTION;

    add_interface_options( $blrules );

    #
    # Handle MSS settings in the zones file
    #
    setup_zone_mss;

    $fn = open_file( 'rules', 1, 1 );

    if ( $fn ) {

	set_section_function( &process_section );

	first_entry "$doing $fn...";

	process_raw_rule while read_a_line( NORMAL_READ );

	clear_section_function;
    }
    #
    # No need to finish the NEW section since no rules need to be generated
    #
    $section = $next_section = DEFAULTACTION_SECTION;
}

sub process_mangle_inline( $$$$$$$$$$$$$$$$$$$$ ) {
    my ($inline, $chainref, $params, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability , $dscp , $state, $time, $conditional ) = @_;

    my $oldparms   = push_action_params( $inline,
					 $chainref,
					 $params,
					  'none',
					 '' ,
					 $chainref->{name} );

    my $inlinefile = $actions{$inline}{file};
    my $matches    = fetch_inline_matches;

    progress_message "..Expanding inline action $inlinefile...";

    push_open $inlinefile, 2, 1, undef , 2;

    my $save_comment = push_comment;

    while ( read_a_line( NORMAL_READ ) ) {
	my ( $moriginalmark, $msource, $mdest, $mprotos, $mports, $msports, $muser, $mtestval, $mlength, $mtos , $mconnbytes, $mhelper, $mheaders, $mprobability , $mdscp , $mstate, $mtime, $mconditional );
	if ( $family == F_IPV4 ) {
	    ( $moriginalmark, $msource, $mdest, $mprotos, $mports, $msports, $muser, $mtestval, $mlength, $mtos , $mconnbytes, $mhelper, $mprobability, $mdscp, $mstate, $mtime, $mconditional ) =
		split_line2( 'mangle file',
			     { mark => 0,
			       action => 0,
			       source => 1,
			       dest => 2,
			       proto => 3,
			       dport => 4,
			       sport => 5,
			       user => 6,
			       test => 7,
			       length => 8,
			       tos => 9,
			       connbytes => 10,
			       helper => 11,
			       probability => 12 , 
			       scp => 13,
			       state => 14,
			       time => 15,
			       switch => 16,
			     },
			     {},
			     17,
			     1 );
	    $headers = $mheaders = '-';
	} else {
	    ( $moriginalmark, $msource, $mdest, $mprotos, $mports, $msports, $muser, $mtestval, $mlength, $mtos , $mconnbytes, $mhelper, $mheaders, $mprobability, $mdscp, $mstate, $mtime, $mconditional ) =
		split_line2( 'mangle file',
			     { mark => 0,
			       action => 0,
			       source => 1,
			       dest => 2,
			       proto => 3,
			       dport => 4,
			       sport => 5,
			       user => 6,
			       test => 7,
			       length => 8,
			       tos => 9,
			       connbytes => 10,
			       helper => 11,
			       headers => 12,
			       probability => 13,
			       dscp => 14,
			       state => 15,
			       time => 16,
			       switch => 17,
			     },
			     {},
			     18,
			     1 );
	}

	fatal_error 'ACTION must be specified' if $moriginalmark eq '-';

	if ( $moriginalmark eq 'DEFAULTS' ) {
	    default_action_params( $chainref, split_list( $msource, 'defaults' ) );
	    next;
	}

	$msource = $source if $msource eq '-';
	$mdest   = $dest   if $mdest   eq '-';
	$mprotos = $protos if $mprotos eq '-';

	for my $proto (split_list( $mprotos, 'Protocol' ) ) {
	    process_mangle_rule1( $chainref,
				  $moriginalmark,
				  $msource,
				  $mdest,
				  $proto,
				  merge_macro_column( $mports,          $ports ),
				  merge_macro_column( $msports,         $sports ),
				  merge_macro_column( $muser,           $muser ),
				  merge_macro_column( $mtestval,        $testval ),
				  merge_macro_column( $mlength,         $length ),
				  merge_macro_column( $mtos ,           $tos ),
				  merge_macro_column( $mconnbytes,      $connbytes ),
				  merge_macro_column( $mhelper,         $helper ),
				  merge_macro_column( $mheaders,        $headers ),
				  merge_macro_column( $mprobability ,   $probability ),
				  merge_macro_column( $mdscp ,          $dscp ),
				  merge_macro_column( $mstate,          $state ),
				  merge_macro_column( $mtime,           $time ),
				  merge_macro_column( $mconditional,    $conditional ),
		);
	}

	progress_message "   Rule \"$currentline\" $done";

	set_inline_matches( $matches );
    }

    pop_comment( $save_comment );

    pop_open;

    progress_message "..End inline action $inlinefile";

    pop_action_params( $oldparms );
}

################################################################################
#   Code moved from the Tc module in Shorewall 5.0.7                           #
################################################################################
#
# Process a rule from the mangle file. When the target is an action name, this
# function will be called recursively for each rule in the action body. Recursive
# calls pass a chain reference in the first argument and the generated rule is
# appended to that chain. The chain with be the action's chain unless the action
# is inlined, in which case it will be the chain which invoked the action.
#
sub process_mangle_rule1( $$$$$$$$$$$$$$$$$$$ ) {
    my ( $chainref, $action, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability , $dscp , $state, $time, $condition) = @_;

    my %designators = (
	P => PREROUTING,
	I => INPUT,
	F => FORWARD,
	O => OUTPUT,
	T => POSTROUTING,
	R => REALPREROUTING,
	);

    my %chainlabels = ( 1  => 'PREROUTING',
			2  => 'INPUT',
			4  => 'FORWARD',
			8  => 'OUTPUT',
			16 => 'POSTROUTING' );

    my %chainnames = ( 1   => 'tcpre',
		       2   => 'tcin',
		       4   => 'tcfor',
		       8   => 'tcout',
		       16  => 'tcpost',
		       32  => 'sticky',
		       64  => 'sticko',
		       128 => 'PREROUTING',
	);

    my $inchain        = defined $chainref;
    my $inaction;
    my $target         = '';
    my $junk           = '';
    my $raw_matches    = '';
    my $chain          = 0;
    my $matches        = '';
    my $params         = '';
    my $done           = 0;
    my $default_chain  = 0;
    my $restriction    = NO_RESTRICT;
    my $exceptionrule  = '';
    my $device         = '';
    my $cmd;
    my $designator;
    my $ttl            = 0;
    my $fw             = firewall_zone;
    my $usergenerated;
    my $actiontype;
    my $commandref;
    my $prerule        = '';
    #
    # Subroutine for handling MARK and CONNMARK. We use an enclosure so as to keep visibility of the
    # function's local variables without making them static. process_mangle_rule1() is called
    # recursively, so static (our) variables cannot be used unless they are saved/restored during
    # recursion.
    #
    my $handle_mark_param = sub( ) {
	my ( $option, $marktype ) = @_;
	my $and_or = $params =~ s/^([|&])// ? $1 : '';

	if ( $params =~ /-/ ) {
	    #
	    # A Mark Range
	    #
	    fatal_error "'|' and '&' may not be used with a mark range" if $and_or;
	    fatal_error "A mark range is is not allowed with ACTION $cmd" if $cmd !~ /^(?:CONN)?MARK$/;
	    my ( $mark, $mark2 ) = split /-/, $params, 2;
	    my $markval = validate_mark $mark;
	    fatal_error "Invalid mark range ($mark-$mark2)" if $mark =~ m'/';
	    my $mark2val = validate_mark $mark2;
	    fatal_error "Invalid mark range ($mark-$mark2)" unless $markval < $mark2val;
	    require_capability 'STATISTIC_MATCH', 'A mark range', 's';
	    ( $mark2, my $mask ) = split '/', $mark2;
	    $mask = $globals{TC_MASK} unless supplied $mask;
	    
	    my $increment = 1;
	    my $shift     = 0;

	    $mask = numeric_value( $mask );

	    $increment <<= 1, $shift++ until $increment & $mask;

	    $mask = in_hex $mask;

	    my $marks = ( ( $mark2val - $markval ) >> $shift ) + 1;

	    $chain ||= $designator;
	    $chain ||= $default_chain;

	    $option ||= ( $and_or eq '|' ? '--or-mark' : $and_or ? '--and-mark' : '--set-mark' );

	    my $chainref = ensure_chain( 'mangle', $chain = $chainnames{$chain} );

	    $restriction |= $chainref->{restriction};

	    for ( my $packet = 0; $packet < $marks; $packet++, $markval += $increment ) {
		my $match = "-m statistic --mode nth --every $marks --packet $packet ";

		expand_rule( $chainref,
			     $restriction,
			     $prerule ,
			     do_proto( $proto, $ports, $sports ) .
			     $match .
			     do_user( $user ) .
			     do_test( $testval, $mask ) .
			     do_length( $length ) .
			     do_tos( $tos ) .
			     do_connbytes( $connbytes ) .
			     do_helper( $helper ) .
			     do_headers( $headers ) .
			     do_probability( $probability ) .
			     do_dscp( $dscp ) .
			     do_time( $time ) .
			     do_condition( $condition, $chainref->{name} ) .
			     state_match( $state ) .
			     $raw_matches ,
			     $source ,
			     $dest ,
			     '' ,
			     "$target $option " . join( '/', in_hex( $markval ) , $mask ) ,
			     '',
			     $target ,
			     $exceptionrule ,
			     ''  );
	    }

	    $done = 1;
	}  else {
	    #
	    # A Single Mark
	    #
	    my $mark = $params;
	    my $val;
	    if ( supplied $mark ) {
		if ( $marktype == SMALLMARK ) {
		    $val = verify_small_mark( $mark );
		} else {
		    $val = validate_mark( $mark );
		}
	    } else {
		$val = numeric_value( $mark = $globals{TC_MASK} );
	    }

	    if ( $config{PROVIDER_OFFSET} ) {
		my $limit = $globals{TC_MASK};
		unless ( have_capability 'FWMARK_RT_MASK' ) {
		    fatal_error "Marks <= $limit may not be set in the PREROUTING or OUTPUT chains when HIGH_ROUTE_MARKS=Yes"
			if $val && ( $chain && ( PREROUTING | OUTPUT ) ) && $val <= $globals{TC_MASK};
		}
	    }

	    if ( $option ) {
		$target = join( ' ', $target, $option );
	    } else {
		$target = join( ' ', $target, $and_or eq '|' ? '--or-mark' : $and_or ? '--and-mark' : '--set-mark' );
	    }

	    ( $mark, my $mask ) = split '/', $mark;

	    if ( supplied $mask ) {
		$target = join( ' ', $target , join( '/', $mark , $mask ) );
	    } else {
		$target = join( ' ', $target , $mark );
	    }
	}
    };
    #
    # Subroutine to handle ADD and DEL rules
    #
    my $ipset_command = sub () {
	my %xlate = ( ADD => 'add-set' , DEL => 'del-set' );

	require_capability( 'IPSET_MATCH', "$cmd rules", '' );
	fatal_error "$cmd rules require a set name parameter" unless $params;

	my ( $setname, $flags, $rest ) = split ':', $params, 3;
	fatal_error "Invalid ADD/DEL parameter ($params)" if $rest;
	$setname =~ s/^\+//;
	fatal_error "Expected ipset name ($setname)" unless $setname =~ /^(6_)?[a-zA-Z][-\w]*$/;
	fatal_error "Invalid flags ($flags)" unless defined $flags && $flags =~ /^(dst|src)(,(dst|src)){0,5}$/;
	$target = join( ' ', 'SET --' . $xlate{$cmd} , $setname , $flags );
    };

    my %commands = (
	ADD       => {
	    defaultchain   => PREROUTING,
	    allowedchains  => ALLCHAINS,
	    minparams      => 1,
	    maxparams      => 1,
	    function       => sub() {
		$ipset_command->();
	    }
	},

	CHECKSUM   => {
	    defaultchain   => POSTROUTING,
	    allowedchains  => POSTROUTING | FORWARD | OUTPUT,
	    minparams      => 0,
	    maxparams      => 0 ,
	    function       => sub() {
		$target = 'CHECKSUM --checksum-fill';
	    },
	},
       
	CLASSIFY   => {
	    defaultchain   => POSTROUTING,
	    allowedchains  => POSTROUTING | FORWARD | OUTPUT,
	    minparams      => 1,
	    maxparams      => 1,
	    function       => sub() {
		fatal_error "Valid class ID expected ($params)" unless $params =~ /^([0-9a-fA-F]+):([0-9a-fA-F]+)$/;

		my $classid = join( ':', normalize_hex( $1 ), normalize_hex( $2 ) );

		$target = "CLASSIFY --set-class $classid";

		if ( $config{TC_ENABLED} eq 'Internal' || $config{TC_ENABLED} eq 'Shared' ) {
		    fatal_error "Unknown Class ($params)" unless ( $device = $classids{$classid} );

		    fatal_error "IFB Classes may not be specified in tcrules" if @{$tcdevices{$device}{redirected}};

		    unless ( $tcclasses{$device}{hex_value $2}{leaf} ) {
			warning_message "Non-leaf Class ($params) - tcrule ignored";
			$done = 1;
		    }

		    if ( $dest eq '-' ) {
			$dest = $device;
		    } else {
			$dest = join( ':', $device, $dest ) unless $dest =~ /^[[:alpha:]]/;
		    }
		}
	    },
	},

	CONNMARK   => {
	    defaultchain   => 0,
	    allowedchains  => ALLCHAINS,
	    minparams      => 1,
	    maxparams      => 1,
	    function       => sub () {
		$target = 'CONNMARK';
		$handle_mark_param->('' , HIGHMARK );
	    },
	},

	CONTINUE   => {
	    defaultchain   => 0,
	    allowedchains  => ALLCHAINS,
	    minparams      => 0,
	    maxparams      => 0,
	    function       => sub () {
		$target = 'RETURN';
	    },
	},

	DEL       => {
	    defaultchain   => PREROUTING,
	    allowedchains  => ALLCHAINS,
	    minparams      => 1,
	    maxparams      => 1,
	    function       => sub() {
		$ipset_command->();
	    }
	},

	DIVERT     => {
	    defaultchain   => REALPREROUTING,
	    allowedchains  => PREROUTING | REALPREROUTING,
	    minparams      => 0,
	    maxparams      => 0,
	    function       => sub () {
		fatal_error 'DIVERT is only allowed in the PREROUTING chain' if $designator && 
		    $designator != PREROUTING &&
		    $designator != REALPREROUTING;
		my $mark = in_hex( $globals{TPROXY_MARK} ) . '/' . in_hex( $globals{TPROXY_MARK} );

		unless ( $divertref ) {
		    $divertref = new_chain( 'mangle', 'divert' );
		    add_ijump( $divertref , j => 'MARK', targetopts => "--set-mark $mark"  );
		    add_ijump( $divertref , j => 'ACCEPT' );
		}

		$target = 'divert';

		$matches = '! --tcp-flags FIN,SYN,RST,ACK SYN  -m socket --transparent ';
	    },
	},

	DIVERTHA   => {
	    defaultchain   => REALPREROUTING,
	    allowedchains  => PREROUTING | REALPREROUTING,
	    minparams      => 0,
	    maxparams      => 0,
	    function       => sub () {
		fatal_error 'DIVERTHA is only allowed in the PREROUTING chain' if $designator && $designator != PREROUTING;
		my $mark = in_hex( $globals{TPROXY_MARK} ) . '/' . in_hex( $globals{TPROXY_MARK} );

		unless ( $divertref ) {
		    $divertref = new_chain( 'mangle', 'divert' );
		    add_ijump( $divertref , j => 'MARK', targetopts => "--set-mark $mark"  );
		    add_ijump( $divertref , j => 'ACCEPT' );
		}

		$target = 'divert';

		$matches = '-m socket ';
	    },
	},

	DROP       => {
	    defaultchain   => 0,
	    allowedchains  => PREROUTING | FORWARD | OUTPUT | POSTROUTING,
	    minparams      => 0,
	    maxparams      => 0,
	    function       => sub() {
		$target = 'DROP';
	    }
	},

	DSCP       => {
	    defaultchain   => POSTROUTING,
	    allowedchains  => PREROUTING | FORWARD | OUTPUT | POSTROUTING,
	    minparams      => 1,
	    maxparams      => 1,
	    function       => sub () {
		require_capability 'DSCP_TARGET', 'The DSCP action', 's';
		my $dscp = numeric_value( $params );
		$dscp = $dscpmap{$params} unless defined $dscp;
		fatal_error( "Invalid DSCP ($params)" ) unless defined $dscp && $dscp <= 0x38 && ! ( $dscp & 1 );
		$target = 'DSCP --set-dscp ' . in_hex( $dscp );
	    },
	},

	ECN       => {
	    defaultchain   => POSTROUTING,
	    allowedchains  => ALLCHAINS,
	    minparams      => 0,
	    maxparams      => 0,
	    function       => sub() {
		fatal_error "The ECN target is only available with IPv4" if $family == F_IPV6;

		if ( $proto eq '-' ) {
		    $proto = TCP;
		} else {
		    $proto = resolve_proto( $proto ) || 0;
		    fatal_error "Only PROTO tcp (6) is allowed with the ECN action" unless $proto == TCP;
		}

		$target = 'ECN --ecn-tcp-remove';
	    }
	},

	HL        => {
	    defaultchain   => FORWARD,
	    allowedchains  => PREROUTING | FORWARD,
	    minparams      => 1,
	    maxparams      => 1,
	    function       => sub() {
		fatal_error "HL is not supported in IPv4 - use TTL instead" if $family == F_IPV4;

		$params =~ /^([-+]?(\d+))$/;

		fatal_error "Invalid HL specification( HL($params) )" unless supplied( $1 ) && ( $1 eq $2 || $2 != 0 ) && ( $params = abs $params ) < 256;

		$target = 'HL';

		if ( $1 =~ /^\+/ ) {
		    $target .= " --hl-inc $params";
		} elsif ( $1 =~ /\-/ ) {
		    $target .= " --hl-dec $params";
		} else {
		    $target .= " --hl-set $params";
		};
	    },
	},

	INLINE     => {
	    defaultchain   => 0,
	    allowedchains  => ALLCHAINS,
	    minparams      => 0,
	    maxparams      => 0,
	    function       => sub() {
		$target ||= '';
	    },
	},

	IMQ        => {
	    defaultchain   => PREROUTING,
	    allowedchains  => PREROUTING,
	    minparams      => 1,
	    maxparams      => 1,
	    function       => sub () {
		require_capability 'IMQ_TARGET', 'IMQ', 's';
		my $imq = numeric_value( $params );
		fatal_error "Invalid IMQ number ($params)" unless defined $imq;
		$target = "IMQ --todev $imq";
	    },
	},

	IPTABLES  => {
	    defaultchain   => 0,
	    allowedchains  => ALLCHAINS,
	    minparams      => 0,
	    maxparams      => 1,
	    function       => sub () {
		fatal_error "Invalid ACTION (IPTABLES)" unless $family == F_IPV4;
		my ( $tgt,  $options ) = split( ' ', $params, 2 );
		my $target_type = $builtin_target{$tgt};
		fatal_error "Unknown target ($tgt)" unless $target_type;
		fatal_error "The $tgt TARGET is not allowed in the mangle table" unless $target_type & MANGLE_TABLE;
		$target        = $params;
		$usergenerated = 1;
	    },
	},

	IP6TABLES => {
	    defaultchain   => 0,
	    allowedchains  => ALLCHAINS,
	    minparams      => 0,
	    maxparams      => 1,
	    function       => sub () {
		fatal_error "Invalid ACTION (IP6TABLES)" unless $family == F_IPV6;
		my ( $tgt,  $options ) = split( ' ', $params, 2 );
		my $target_type = $builtin_target{$tgt};
		fatal_error "Unknown target ($tgt)" unless $target_type;
		fatal_error "The $tgt TARGET is not allowed in the mangle table" unless $target_type & MANGLE_TABLE;
		$target        = $params;
		$usergenerated = 1;
	    },
	},

	IPMARK     => {
	    defaultchain   => 0,
	    allowedchains  => ALLCHAINS,
	    minparams      => 0,
	    maxparams      => 4,
	    function       => sub () {
		my ( $srcdst, $mask1, $mask2, $shift ) = ('src', 255, 0, 0 );

		require_capability 'IPMARK_TARGET', 'IPMARK', 's';
		
		my $val;

		if ( supplied $params ) {
		    my ( $sd, $m1, $m2, $s , $bad ) = split ',', $params;

		    fatal_error "Invalid IPMARK parameters ($params)" if $bad;
		    fatal_error "Invalid IPMARK parameter ($sd)" unless ( $sd eq 'src' || $sd eq 'dst' );
		    $srcdst = $sd;

		    if ( supplied $m1 ) {
			$val = numeric_value ($m1);
			fatal_error "Invalid Mask ($m1)" unless defined $val && $val && $val <= 0xffffffff;
			$mask1 = in_hex ( $val & 0xffffffff );
		    }

		    if ( supplied $m2 ) {
			$val = numeric_value ($m2);
			fatal_error "Invalid Mask ($m2)" unless defined $val && $val <= 0xffffffff;
			$mask2 = in_hex ( $val & 0xffffffff );
		    }

		    if ( defined $s ) {
			$val = numeric_value ($s);
			fatal_error "Invalid Shift Bits ($s)" unless defined $val && $val >= 0 && $val < 128;
			$shift = $s;
		    }
		};

		$target = "IPMARK --addr $srcdst --and-mask $mask1 --or-mask $mask2 --shift $shift";
	    },
	},

	MARK       => {
	    defaultchain   => 0,
	    allowedchains  => ALLCHAINS,
	    minparams      => 1,
	    maxparams      => 1,
	    mask           => in_hex( $globals{TC_MASK} ),
	    function       => sub () {
		$target = 'MARK';
		$handle_mark_param->('', , HIGHMARK );
	    },
	},

	NFLOG      => {
	    defaultchain  => 0,
	    allowedchains => ALLCHAINS,
	    minparams     => 0,
	    maxparams     => 3,
	    function      => sub () {
		$target = validate_level( "NFLOG($params)" );
	    }
	},

	RESTORE    => {
	    defaultchain   => 0,
	    allowedchains  => PREROUTING | INPUT | FORWARD | OUTPUT | POSTROUTING,
	    minparams      => 0,
	    maxparams      => 1,
	    function       => sub () {
		$target = 'CONNMARK ';
		if ( supplied $params ) {
		    $handle_mark_param->( '--restore-mark --mask ',
					  $config{TC_EXPERT} ? HIGHMARK : SMALLMARK );
		} else {
		    $target .= '--restore-mark --mask ' . in_hex( $globals{TC_MASK} );
		}
	    },
	},

	SAME       => {
	    defaultchain   => PREROUTING,
	    allowedchains  => PREROUTING | OUTPUT | STICKY | STICKO,
	    minparams      => 0,
	    maxparams      => 1,
	    function       => sub() {
		$target = ( $chain == OUTPUT ? 'sticko' : 'sticky' );
		$restriction = DESTIFACE_DISALLOW;
		ensure_mangle_chain( $target );
		if (supplied $params) {
		    $ttl = numeric_value( $params );
		    fatal_error "The SAME timeout must be positive" unless $ttl;
		} else {
		    $ttl = 300;
		}

		$sticky++;
	    },
	},

	SAVE       => {
	    defaultchain   => 0,
	    allowedchains  => PREROUTING | INPUT | FORWARD | OUTPUT | POSTROUTING,
	    minparams      => 0,
	    maxparams      => 1,
	    function       => sub () {
		$target = 'CONNMARK ';
		if ( supplied $params ) {
		    $handle_mark_param->( '--save-mark --mask ' ,
					  $config{TC_EXPERT} ? HIGHMARK : SMALLMARK );
		} else {
		    $target .= '--save-mark --mask ' . in_hex( $globals{TC_MASK} );
		}
	    },
	},

	TCPMSS     => {
	    defaultchain   => FORWARD,
	    allowedchains  => FORWARD | POSTROUTING,
	    minparams      => 0,
	    maxparams      => 2,
	    function       => sub () {
		if ( $proto eq '-' ) {
		    $proto = TCP;
		} else {
		    fatal_error 'TCPMSS only valid with TCP' unless $proto eq '6' || $proto eq 'tcp';
		}

		$target   = 'TCPMSS ';
		$matches .= '--tcp-flags SYN,RST SYN ';

		if ( supplied $params ) {
		    my ( $mss, $ipsec ) = split /,/, $params;

		    if ( supplied $mss ) {
			if ( $mss eq 'pmtu' ) {
			    $target .= '--clamp-mss-to-pmtu';
			} else {
			    my $num = numeric_value $mss;
			    fatal_error "Invalid MSS ($mss)" unless defined $num && $num >= 500 && $num < 65534;
			    $target .= "--set-mss $num";
			}
		    } else {
			$target .= '--clamp-mss-to-pmtu';
		    }
		    if ( supplied $ipsec && $ipsec ne 'all' ) {
			if ( $ipsec eq '-' || $ipsec eq 'none' ) {
			    $matches .= '-m policy --pol none --dir out ';
			} elsif ( $ipsec eq 'ipsec' ) {
			    $matches .= '-m policy --pol ipsec --dir out ';
			} else {
			    fatal_error "Invalid ipsec parameter ($ipsec)";
			}

			require_capability 'POLICY_MATCH', "The $ipsec ipsec option", 's';
		    }
		} else {
		    $target .= '--clamp-mss-to-pmtu';
		}
	    },
	},

	TOS        => {
	    defaultchain   => 0,
	    allowedchains  => PREROUTING | FORWARD | OUTPUT | POSTROUTING,
	    minparams      => 1,
	    maxparams      => 1,
	    function       => sub() {
		$target = 'TOS ' . decode_tos( $params , 2 );
	    },
	},

	TPROXY     => {
	    defaultchain   => REALPREROUTING,
	    allowedchains  => PREROUTING | REALPREROUTING,
	    minparams      => 0,
	    maxparams      => 2,
	    function       => sub() {
		require_capability( 'TPROXY_TARGET', 'Use of TPROXY', 's');

		fatal_error "TPROXY is not supported in FORMAT 1 tcrules files" if $file_format < 2;

		my ( $port, $ip, $bad );

		if ( $params ) {
		    ( $port, $ip ) = split /,/, $params, 2;
		}

		my $mark = in_hex( $globals{TPROXY_MARK} ) . '/' . in_hex( $globals{TPROXY_MARK} );

		if ( $port ) {
		    $port = validate_port( 'tcp', $port );
		} else {
		    $port = 0;
		}

		$target = "TPROXY --on-port $port";

		if ( supplied $ip ) {
		    if ( $family == F_IPV6 ) {
			if ( $ip =~ /^\[(.+)\]$/ || $ip =~ /^<(.+)>$/ ) {
			    $ip = $1;
			} elsif ( $ip =~ /^\[(.+)\]\/(\d+)$/ ) {
			    $ip = join( '/', $1, $2 );
			}
		    }

		    validate_address $ip, 1;
		    $target .= " --on-ip $ip";
		}

		$target .= " --tproxy-mark $mark";

		$exceptionrule = '-p tcp ';

	    },
	},

	TTL        => {
	    defaultchain   => FORWARD,
	    allowedchains  => PREROUTING | FORWARD,
	    minparams      => 1,
	    maxparams      => 1,
	    function       => sub() {
		fatal_error "TTL is not supported in IPv6 - use HL instead" if $family == F_IPV6;
		$target = 'TTL';

		$params =~ /^([-+]?(\d+))$/;

		fatal_error "Invalid TTL specification( TTL($params) )" unless supplied( $1 ) && ( $1 eq $2 || $2 != 0 ) && ( $params = abs $params ) < 256;

		if ( $1 =~ /^\+/ ) {
		    $target .= " --ttl-inc $params";
		} elsif ( $1 =~ /\-/ ) {
		    $target .= " --ttl-dec $params";
		} else {
		    $target .= " --ttl-set $params";
		}
	    },
	},
    );
    #
    # Subroutine for handling normal actions
    #
    my $actionref = {
	defaultchain      => 0,
	allowedchains     => ALLCHAINS ,
	minparams         => 0 ,
	maxparams         => 16 ,
	function          => sub() {
	    fatal_error( qq(Action $cmd may not be used in the mangle file) ) unless $actiontype & MANGLE_TABLE;
	    #
	    # Verify action 'proto', if any
	    #
	    $proto = determine_action_protocol( $cmd, $proto );
	    #
	    # Create the action:level:tag:param tuple.
	    #
	    my $normalized_target = normalize_action( $cmd, '', $params );
	    fatal_error( "Action $cmd invoked Recursively (" .  join( '->', map( external_name( $_ ), @actionstack , $normalized_target ) ) . ')' ) if $active{$cmd};

	    my $ref = use_action( 'mangle', $normalized_target );

	    if ( $ref ) {
		#
		# First reference to this tuple - process_action may modify both $normalized_target and $ref!!!
		#
		process_action( $normalized_target, $ref, $chainnames{$chain} );
		#
		# Capture the name of the action chain
		#
	    } else {
		#
		# We've seen this tuple before
		#
		$ref = $usedactions{$normalized_target};
	    }

	    $target = $ref->{name};
	    $commandref->{allowedchains} = $ref->{allowedchains};
	}
    };
    #
    # Subroutine to resolve which chain to use
    #
    my $resolve_chain = sub() {
	unless ( $chain ) {
	    $chain ||= $designator;
	    $chain ||= $commandref->{defaultchain};
	    $chain ||= $default_chain;
	}

	$chainref = ensure_chain( 'mangle', $chainnames{$chain} );
    };
    #
    #
    # Subroutine for handling inline actions
    #
    my $inlineref = {
	defaultchain         => 0,
	allowedchains        => ALLCHAINS ,
	minparams            => 0 ,
	maxparams            => 16 ,
	function             => sub() {
	    fatal_error( qq(Action $cmd may not be used in the mangle file) ) unless $actiontype & MANGLE_TABLE;

	    $resolve_chain->() unless $inchain;

	    process_mangle_inline( $cmd,
				   $chainref,
				   $params,
				   $source,
				   $dest,
				   $proto,
				   $ports,
				   $sports,
				   $user,
				   $testval,
				   $length,
				   $tos ,
				   $connbytes,
				   $helper,
				   $headers,
				   $probability ,
				   $dscp ,
				   $state,
				   $time,
				   $condition );
	    $done = 1;
	}
    };
    #
    # Function Body
    #
    if ( $inchain ) {
	( $inaction ) = split /:/, $chainref->{action} if $chainref->{action};
	#
	# Set chain type
	#
	$chain = $chainref->{chainnumber} || ACTIONCHAIN;
    }

    ( $cmd, $designator ) = split_action( $action );

    if ( supplied $designator ) {
	fatal_error "A chain designator may not be specified in an action body" if $inaction;
	my $temp = $designators{$designator};
	fatal_error "Invalid chain designator ( $designator )" unless $temp;
	$designator = $temp;
    }

    ( $cmd , $params ) = get_target_param1( $cmd );

    $actiontype = $builtin_target{$cmd} || $targets{$cmd} || 0;

    unless ( $commandref = $commands{$cmd} ) {
	if ( $actiontype & ACTION ) {
	    $commandref = $actionref;
	} elsif ( $actiontype & INLINE ) {
	    $commandref = $inlineref;
	} else {
	    fatal_error "Invalid ACTION ($cmd)";
	}
    }

    if ( $cmd eq 'INLINE' ) {
	( $target, $cmd, $params, $junk, $raw_matches ) = handle_inline( MANGLE_TABLE, 'mangle', $action, $cmd, $params, '' );
    } else {
	$raw_matches = get_inline_matches(0);
    }
    #
    # Handle early matches
    #
    if ( $raw_matches =~ s/s*\+// ) {
	$prerule = $raw_matches;
	$raw_matches = '';
    }

    if ( $source ne '-' ) {
	if ( $source eq $fw ) {
	    fatal_error 'Rules with SOURCE $FW must use the OUTPUT chain' if $designator && $designator != OUTPUT;
	    $chain = OUTPUT;
	    $source = '-';
	} elsif ( $source =~ s/^($fw):// ) {
	    fatal_error 'Rules with SOURCE $FW must use the OUTPUT chain' if $designator && $designator != OUTPUT;
	    $chain = OUTPUT;
	}
    }

    if ( $dest ne '-' ) {
	if ( $dest eq $fw ) {
	    fatal_error 'Rules with DEST $FW must use the INPUT chain' if $designator && $designator ne INPUT;
	    $chain = INPUT;
	    $dest = '-';
	} elsif ( $dest =~ s/^$fw\:// ) {
	    fatal_error 'Rules with DEST $FW must use the INPUT chain' if $designator && $designator ne INPUT;
	    $chain = INPUT;
	}
    }

    unless ( $default_chain ) {
	$default_chain = $config{MARK_IN_FORWARD_CHAIN} ? FORWARD : PREROUTING;
    }

    my @params = split_list1( $params, 'parameter' );

    if ( @params > $commandref->{maxparams} ) {
	if ( $commandref->{maxparams} == 1 ) {
	    fatal_error "The $cmd ACTION only accepts one parmeter";
	} else {
	    fatal_error "The $cmd ACTION only accepts $commandref->{maxparams} parmeters";
	}
    }
  
    if ( @params < $commandref->{minparams} ) {
	if ( $commandref->{maxparams} == 1 ) {
	    fatal_error "The $cmd requires a parameter";
	} else {
	    fatal_error "The $cmd ACTION requires at least $commandref->{maxparams} parmeters";
	}
    }

    if ( $state ne '-' ) {
	my @state = split_list( $state, 'state' );
	my %state = %validstates;

	for ( @state ) {
	    fatal_error "Invalid STATE ($_)"   unless exists $state{$_};
	    fatal_error "Duplicate STATE ($_)" if $state{$_}++;
	}
    }

    #
    # Call the command's processing function
    #
    $commandref->{function}->();

    unless ( $done ) {
	if ( $inchain ) {
	    if ( $chain == ACTIONCHAIN ) {
		fatal_error "$cmd rules are not allowed in the $chainlabels{$chain} chain" unless $commandref->{allowedchains} & $chainref->{allowedchains};
		$chainref->{allowedchains} &= $commandref->{allowedchains};
		$chainref->{allowedchains} &= (OUTPUT | POSTROUTING ) if $user ne '-';
	    } else {
		#
		# Inline within one of the standard chains
		#
		fatal_error "$cmd rules are not allowed in the $chainlabels{$chain} chain" unless $commandref->{allowedchains} & $chain;
		unless ( $chain == OUTPUT || $chain == POSTROUTING  ) {
		    fatal_error 'A USER/GROUP may only be specified when the SOURCE is $FW' unless $user eq '-';
		}
	    }
	} else {
	    $resolve_chain->();
	    fatal_error "$cmd rules are not allowed in the $chainlabels{$chain} chain" unless $commandref->{allowedchains} & $chain;
	    unless ( $chain == OUTPUT || $chain == POSTROUTING  ) {
		fatal_error 'A USER/GROUP may only be specified when the SOURCE is $FW' unless $user eq '-';
	    }

	    $chainref = ensure_chain( 'mangle', $chainnames{$chain} );
	}

	$restriction |= $chainref->{restriction};

	expand_rule( $chainref ,
		     $restriction,
		     $prerule,
		     do_proto( $proto, $ports, $sports) . $matches .
		     do_user( $user ) .
		     do_test( $testval, $globals{TC_MASK} ) .
		     do_length( $length ) .
		     do_tos( $tos ) .
		     do_connbytes( $connbytes ) .
		     do_helper( $helper ) .
		     do_headers( $headers ) .
		     do_probability( $probability ) .
		     do_dscp( $dscp ) .
		     state_match( $state ) .
		     do_time( $time ) .
		     do_condition( $condition, $chainref->{name} ) .
		     ( $ttl ? "-t $ttl " : '' ) .
		     $raw_matches ,
		     $source ,
		     $dest ,
		     '' ,
		     $target,
		     '' ,
		     $target ,
		     $exceptionrule ,
		     $usergenerated ,
		     '' , # Log Name
		     $device ,
		     $params
	    );
    }

    progress_message "  Mangle Rule \"$currentline\" $done";
}

#
# Intermediate processing of a tcrules entry
#
sub process_tc_rule1( $$$$$$$$$$$$$$$$ ) {
    my ( $originalmark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability , $dscp , $state ) = @_;

    my  %tcs = ( T => { designator => ':T',
			command    => '' 
		 } ,
		 CT => { designator => ':T',
			 command    => 'CONNMARK'
		 } ,
		 C  => { designator => '',
		         command    => 'CONNMARK' ,
		 } ,
		 P  => { designator => ':P',
			 command    => ''
		 } ,
		 CP => { designator => ':P' ,
			 command    => 'CONNMARK'
		 } ,
		 F =>  { designator => ':F',
			 command    => ''
		 } ,
		 CF => { designator => ':F' ,
			 command    => 'CONNMARK'
		 } ,
	);

    our  %tccmd;

    unless ( %tccmd ) {
	%tccmd = ( ADD =>      { match     => sub ( $ ) { $_[0] =~ /^ADD/ } 
		               },
		   DEL =>      { match     => sub ( $ ) { $_[0] =~ /^DEL/ }
		               },
	           SAVE =>     { match     => sub ( $ ) { $_[0] eq 'SAVE' } ,
			       } ,
		   RESTORE =>  { match     => sub ( $ ) { $_[0] eq 'RESTORE' },
			       } ,
		   CONTINUE => { match     => sub ( $ ) { $_[0] eq 'CONTINUE' },
			       } ,
		   SAME =>     { match     => sub ( $ ) { $_[0] =~ /^SAME(?:\(d+\))?$/ },
			       } ,
		   IPMARK =>   { match     => sub ( $ ) { $_[0] =~ /^IPMARK/ },
			       } ,
		   TPROXY =>   { match     => sub ( $ ) { $_[0] =~ /^TPROXY/ },
			       },
		   DIVERT =>   { match     => sub( $ ) { $_[0] =~ /^DIVERT/ },
			       },
		   TTL =>      { match     => sub( $ ) { $_[0] =~ /^TTL/ },
			       },
		   HL =>       { match     => sub( $ ) { $_[0] =~ /^HL/ },
			       },
		   IMQ =>      { match     => sub( $ ) { $_[0] =~ /^IMQ\(\d+\)$/ },
			       },
		   DSCP =>     { match     => sub( $ ) { $_[0] =~ /^DSCP\(\w+\)$/ },
			       },
		   TOS =>      { match     => sub( $ ) { $_[0] =~ /^TOS\(.+\)$/ },
			       },
		   CHECKSUM => { match     => sub( $ ) { $_[0] eq 'CHECKSUM' },
			       },
		   INLINE   => { match     => sub( $ ) { $_[0] eq 'INLINE' },
			       },
		   DROP =>      { match     => sub( $ ) { $_[0] eq 'DROP' },
			       },
		 );
    }

    fatal_error 'MARK must be specified' if $originalmark eq '-';

    my ( $mark, $designator, $remainder ) = split( /:/, $originalmark, 3 );

    fatal_error "Invalid MARK ($originalmark)" unless supplied $mark;

    my $command = '';

    if ( $remainder ) {
	if ( $originalmark =~ /^\w+\(?.*\)$/ ) {
	    $mark = $originalmark; # Most likely, an IPv6 address is included in the parameter list
	} else {
	    fatal_error "Invalid MARK ($originalmark)"
		unless ( $mark =~ /^([0-9a-fA-F]+)$/ &&
			 $designator =~ /^([0-9a-fA-F]+)$/ &&
			 $designator{$remainder} );
	    $mark       = join( ':', $mark, $designator );
	    $designator = $remainder;
	    $command    = 'CLASSIFY';
	}
    }

    my $tcsref;
    
    if ( $designator ) {
	my $tcsref = $tcs{$designator};

	if ( $tcsref ) {
	    $designator = $tcsref->{designator};
	    if ( my $cmd = $tcsref->{command} ) {
		$command |= $cmd;
	    }
	} else {
	    unless ( $command ) {
		fatal_error "Invalid MARK/CLASSIFY ($originalmark)" unless $mark =~ /^([0-9a-fA-F]+)$/ and $designator =~ /^([0-9a-fA-F]+)$/;
		$mark       = join( ':', $mark, $designator );
		$command    = 'CLASSIFY';
		$designator = '';
	    }
	}
    } else {
	$designator = '';
    }

    unless ( $command ) {
	{
	    my ( $cmd, $rest ) = split( '/', $mark, 2 );

	    if ( $cmd =~ /^([A-Z]+)(?:\((.+)\))?/ ) {
		if ( my $tccmd = $tccmd{$1} ) {
		    fatal_error "Invalid $1 ACTION ($originalmark)" unless $tccmd->{match}($cmd); 
		    $command = $1;
		    if ( supplied $rest ) {
			fatal_error "Invalid $1 ACTION ($originalmark)" if supplied $2;
			$mark = $rest;
		    } elsif ( supplied $2 ) {
			$mark = $2;
			if ( supplied $mark && $command eq 'IPMARK' ) {
			    my @params = split ',', $mark;
			    $params[1] = '0xff' unless supplied $params[1];
			    $params[2] = '0x00' unless supplied $params[2];
			    $params[3] = '0'    unless supplied $params[3];
			    $mark = join ',', @params;
			}
		    } else {
			$mark = '';
		    }
		}
	    } else {
		$command = 'MARK';
	    }
	}
    }
	
    $command = ( $command ? supplied $mark ? "$command($mark)" : $command : $mark ) . $designator;
    my $line = ( $family == F_IPV6 ?
		 "$command\t$source\t$dest\t$proto\t$ports\t$sports\t$user\t$testval\t$length\t$tos\t$connbytes\t$helper\t$headers\t$probability\t$dscp\t$state" :
		 "$command\t$source\t$dest\t$proto\t$ports\t$sports\t$user\t$testval\t$length\t$tos\t$connbytes\t$helper\t$probability\t$dscp\t$state" );
    #
    # Supress superfluous trailing dashes
    #
    $line =~ s/(?:\t-)+$//;

    my $raw_matches = fetch_inline_matches;

    if ( $raw_matches ne ' ' ) {
	if ( $command =~ /^INLINE/ || $config{INLINE_MATCHES} ) {
	    $line .= join( '', ' ;', $raw_matches );
	} else {
	    $line .= join( '', ' {', $raw_matches , ' }' );
	}
    }

    print $mangle "$line\n";
}

sub process_tc_rule( ) {
    my ( $originalmark, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability , $dscp , $state );
    if ( $family == F_IPV4 ) {
	( $originalmark, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $probability, $dscp, $state ) =
	    split_rawline2( 'tcrules file',
			    { mark => 0,
			      action => 0,
			      source => 1,
			      dest => 2,
			      proto => 3,
			      dport => 4,
			      sport => 5,
			      user => 6,
			      test => 7,
			      length => 8,
			      tos => 9,
			      connbytes => 10,
			      helper => 11,
			      probability => 12 , 
			      scp => 13,
			      state => 14 },
			    {},
			    15,
			    1 );
	$headers = '-';
    } else {
	( $originalmark, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability, $dscp, $state ) =
	    split_rawline2( 'tcrules file',
			    { mark => 0,
			      action => 0,
			      source => 1,
			      dest => 2,
			      proto => 3,
			      dport => 4,
			      sport => 5,
			      user => 6,
			      test => 7,
			      length => 8,
			      tos => 9,
			      connbytes => 10,
			      helper => 11,
			      headers => 12,
			      probability => 13,
			      dscp => 14,
			      state => 15 },
			    {},
			    16,
			    1 );
    }

    for my $proto (split_list( $protos, 'Protocol' ) ) {
	process_tc_rule1( $originalmark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability , $dscp , $state );
    }
}   

sub process_mangle_rule( $ ) {
    my ( $chainref ) = @_;
    my ( $originalmark, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability , $dscp , $state, $time, $conditional );
    if ( $family == F_IPV4 ) {
	( $originalmark, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $probability, $dscp, $state, $time, $conditional ) =
	    split_line2( 'mangle file',
			 { mark => 0,
			   action => 0,
			   source => 1,
			   dest => 2,
			   proto => 3,
			   dport => 4,
			   sport => 5,
			   user => 6,
			   test => 7,
			   length => 8,
			   tos => 9,
			   connbytes => 10,
			   helper => 11,
			   probability => 12 , 
			   scp => 13,
			   state => 14,
			   time => 15,
			   switch => 16,
			 },
			 {},
			 17,
	                 1 );
	$headers = '-';
    } else {
	( $originalmark, $source, $dest, $protos, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability, $dscp, $state, $time, $conditional ) =
	    split_line2( 'mangle file',
			 { mark => 0,
			   action => 0,
			   source => 1,
			   dest => 2,
			   proto => 3,
			   dport => 4,
			   sport => 5,
			   user => 6,
			   test => 7,
			   length => 8,
			   tos => 9,
			   connbytes => 10,
			   helper => 11,
			   headers => 12,
			   probability => 13,
			   dscp => 14,
			   state => 15,
			   time => 16,
			   switch => 17,
			 },
			 {},
			 18,
	                 1 );
    }

    for my $proto (split_list( $protos, 'Protocol' ) ) {
	process_mangle_rule1( $chainref, $originalmark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers, $probability , $dscp , $state, $time, $conditional );
    }
}

sub process_snat_inline( $$$$$$$$$$$$$$ ) {
    my ($inline, $chainref, $params, $loglevel, $source, $dest, $protos, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) = @_;

    my ( $level,
	 $tag )    = split( ':', $loglevel, 2 );
    my $oldparms   = push_action_params( $inline,
					 $chainref,
					 $params,
					 supplied $level ? $level : 'none',
					 defined  $tag   ? $tag   : '' ,
					 $chainref->{name} );

    my $actionref    = $actions{$inline};
    my $inlinefile   = $actionref->{file};
    my $options      = $actionref->{options};
    my $nolog        = $options & NOLOG_OPT;
    my $matches      = fetch_inline_matches;

    progress_message "..Expanding inline action $inlinefile...";

    push_open $inlinefile, 2, 1, undef , 2;

    my $save_comment = push_comment;

    while ( read_a_line( NORMAL_READ ) ) {
	my ( $maction, $msource, $mdest, $mprotos, $mports, $mipsec, $mmark, $muser, $mcondition, $morigdest, $mprobability) =
	    split_line2( 'snat file',
			 { action =>0,
			   source => 1,
			   dest => 2,
			   proto => 3,
			   port => 4,
			   ipsec => 5,
			   mark => 6,
			   user => 7,
			   switch => 8,
			   origdest => 9,
			   probability => 10,
			 },
			 {},
			 11,
			 1 );

	fatal_error 'ACTION must be specified' if $maction eq '-';

	if ( $maction eq 'DEFAULTS' ) {
	    default_action_params( $chainref, split_list( $msource, 'defaults' ) );
	    next;
	}

	$maction = merge_levels( join(':', @actparams{'chain','loglevel','logtag'}), $maction ) unless $nolog;

	$msource = $source if $msource eq '-';

	if ( $mdest eq '-' ) {
	    $mdest = $dest;
	} else {
	    $mdest = merge_inline_source_dest( $mdest, $dest );
	}

	$mprotos = $protos if $mprotos eq '-';

	for my $proto (split_list( $mprotos, 'Protocol' ) ) {
	    process_snat1( $chainref,
			   $maction,
			   $msource,
			   $mdest,
			   $proto,
			   merge_macro_column( $mports,          $ports ),
			   merge_macro_column( $mipsec,          $ipsec ),
			   merge_macro_column( $mmark,           $mark ),
			   merge_macro_column( $muser,           $user ),
			   merge_macro_column( $mcondition,      $condition ),
			   merge_macro_column( $morigdest ,      $origdest ),
			   merge_macro_column( $mprobability,    $probability ),
		);
	}

	progress_message "   Rule \"$currentline\" $done";

	set_inline_matches( $matches );
    }

    pop_comment( $save_comment );

    pop_open;

    progress_message "..End inline action $inlinefile";

    pop_action_params( $oldparms );
}

#
# Process a record in the snat file
#
sub process_snat1( $$$$$$$$$$$$ ) {
    my ( $chainref, $origaction, $source, $dest, $proto, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) = @_;

    my $inchain;
    my $inaction;
    my $pre_nat;
    my $add_snat_aliases = $family == F_IPV4 && $config{ADD_SNAT_ALIASES};
    my $destnets = '';
    my $baserule = '';
    my $inlinematches = get_inline_matches(0);
    my $prerule       = '';
    my $options       = '';
    my $addresses;
    my $target;
    my $params;
    my $actiontype;
    my $interfaces;
    my $normalized_action;
    my ( $action, $loglevel ) = split_action( $origaction );
    my $logaction;
    my $param;

    if ( $action =~ /^MASQUERADE(\+)?(?:\((.+)\))?$/ ) {
	$target     = 'MASQUERADE';
	$actiontype = $builtin_target{$action = $target};
	$pre_nat    = $1;
	$addresses  = ( $2 || '' );
	$options    = 'random' if $addresses =~ s/:?random$//;
	$add_snat_aliases = '';
	$logaction  = 'MASQ';
    } elsif ( $action =~ /^SNAT(\+)?\((.+)\)$/ ) {
	$pre_nat    = $1;
	$addresses  = $2;
	$target     = 'SNAT';
	$actiontype = $builtin_target{$action = $target};
	$options   .= ':persistent' if $addresses =~ s/:persistent//;
	$options   .= ':random'     if $addresses =~ s/:random//;
	$options   =~ s/^://;
	$logaction = 'SNAT';
    } elsif ( $action =~ /^CONTINUE(\+)?$/ ) {
	$add_snat_aliases = 0;
	$actiontype = $builtin_target{$target = 'RETURN'};
	$pre_nat    = $1;
	$logaction = 'RETURN';
    } elsif ( $action eq 'MASQUERADE' ) {
	$actiontype = $builtin_target{$target = 'MASQUERADE'};
	$add_snat_aliases = '';
	$logaction  = 'MASQ';
    } else {
	( $target , $params ) = get_target_param1( $action );

	$pre_nat = ( $target =~ s/\+$// );

	$actiontype = ( $targets{$target} || 0 );

	if ( $actiontype & LOGRULE ) {
	    $logaction = 'LOG';
	    if ( $target eq 'LOG' ) {
		fatal_error 'LOG requires a log level' unless supplied $loglevel;
	    } else {
		$target   = "$target($params)";
		validate_level( $action );
		$loglevel = supplied $loglevel ? join( ':', $target, $loglevel ) : $target;
		$target   = 'LOG';
	    }
	} else {
	    fatal_error "Invalid ACTION ($action)" unless $actiontype & ( ACTION | INLINE );
	    $logaction = '';
	}
    }

    if ( $inchain = defined $chainref ) {
	( $inaction, undef,undef,undef,$param ) = split( /:/, $normalized_action = $chainref->{action}) if $chainref->{action};
	fatal_error q('+' is not allowed within an action body) if $pre_nat;
    }
    #
    # Next, parse the DEST column
    #
    if ( $inaction ) {
	$destnets = $dest;
	assert( $param =~ /^(.*)\|/ );
	$interfaces=$1;
    } elsif ( $family == F_IPV4 ) {
	if ( $dest =~ /^([^:]+)::([^:]*)$/ ) {
	    $add_snat_aliases = 0;
	    $destnets = $2;
	    $interfaces = $1;
	} elsif ( $dest =~ /^([^:]+:[^:]+):([^:]+)$/ ) {
	    $destnets = $2;
	    $interfaces = $1;
	} elsif ( $dest =~ /^([^:]+):$/ ) {
	    $add_snat_aliases = 0;
	    $interfaces = $1;
	} elsif ( $dest =~ /^([^:]+):([^:]*)$/ ) {
	    my ( $one, $two ) = ( $1, $2 );
	    if ( $2 =~ /\./ || $2 =~ /^[+%!]/ ) {
		$interfaces = $one;
		$destnets = $two;
	    } else {
		$interfaces = $dest;
	    }
	} else {
	    $interfaces = $dest;
	}
    } elsif ( $dest =~ /^(.+?):(.+)$/ ) {
	$interfaces    = $1;
	$destnets      = $2;
    } else {
	$interfaces    = $dest;
    }
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

    for my $fullinterface ( split_list( $interfaces, 'interface' ) ) {
 
	my $rule = '';
	my $saveaddresses = $addresses;
	my $savetarget    = $target;
	my $savebaserule  = $baserule;
	my $interface = $fullinterface;

	$interface =~ s/:.*//;   #interface name may include 'alias'

	unless ( $inaction ) {
	    if ( $interface =~ /(.*)[(](\w*)[)]$/ ) {
		$interface    = $1;
		my $provider  = $2;

		fatal_error "Missing Provider ($dest)" unless supplied $provider;

		$dest =~ s/[(]\w*[)]//;
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

	    $chainref = ensure_chain('nat', $pre_nat ? snat_chain $interface : masq_chain $interface);
	}

	$baserule .= do_condition( $condition , $chainref->{name} );

	my $detectaddress = 0;
	my $exceptionrule = '';
	my $conditional   = 0;

	if ( $action eq 'SNAT' ) {
	    if ( $addresses eq 'detect' ) {
		my $variable = get_interface_address $interface;
		$target .= " --to-source $variable";

		if ( interface_is_optional $interface ) {
		    add_commands( $chainref,
				  '',
				  "if [ \"$variable\" != 0.0.0.0 ]; then" );
		    incr_cmd_level( $chainref );
		    $detectaddress = 1;
		}
	    } else {
		fatal_error "SNAT rules must spacify a new source address and/or new source ports" unless supplied $addresses;

		my $addrlist = '';
		my @addrs = split_list $addresses, 'address';

		fatal_error "Only one SNAT address may be specified" if @addrs > 1;

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
			if ( $interface =~ /^{([a-zA-Z_]\w*)}$/ ) {
			    #
			    # User-defined address variable
			    #
			    $conditional = conditional_rule( $chainref, $addr );
			    $addrlist .= ' --to-source ' . "\$${1}${ports} ";
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

			    $addrlist .= ' --to-source ' . $addr;
			}
		    } elsif ( $family == F_IPV4 ) {
			if ( $addr =~ /^.*\..*\..*\./ ) {
			    my ($ipaddr, $rest) = split ':', $addr, 2;
			    if ( $ipaddr =~ /^(.+)-(.+)$/ ) {
				validate_range( $1, $2 );
			    } else {
				validate_address $ipaddr, 0;
			    }

			    if ( supplied $rest ) {
				validate_portpair1( $proto, $rest );
				$addrlist .= " --to-source $addr";
			    } else {
				$addrlist .= " --to-source $ipaddr";
			    }

			    $exceptionrule = do_proto( $proto, '', '' ) if $addr =~ /:/;
			} else {
			    my $ports = $addr;
			    $ports =~ s/^://;
			    fatal_error "Missing Address or Port[-range] ($addr)" unless supplied $ports && $ports ne '-';
			    validate_portpair1( $proto, $ports );
			    $addrlist .= " --to-source :$ports";
			    $exceptionrule = do_proto( $proto, '', '' );
			}
		    } else {
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

			    $addrlist .= " --to-source $addr";
			} else {
			    if ( $addr =~ /^(.+)-(.+)$/ ) {
				validate_range( $1, $2 );
			    } else {
				validate_address $addr, 0;
			    }

			    $addrlist .= " --to-source $addr";
			}
		    }
		}

		$target .= $addrlist;
	    }
	} elsif ( $action eq 'MASQUERADE' ) {
	    if ( supplied $addresses ) {
		validate_portpair1($proto, $addresses );
		$target .= " --to-ports $addresses";
		$exceptionrule = do_proto( $proto, '', '' );
	    }
	}
	#
	# And Generate the Rule(s)
	#
	if ( $actiontype & INLINE ) {
	    fatal_error( qq(Action $target may not be used in the snat file) ) unless $actiontype & NAT_TABLE;

	    process_snat_inline( $target,
				 $chainref,
				 $params,
				 $loglevel,
				 $source,
				 supplied $destnets && $destnets ne '-' ? $inaction ? $destnets : join( ':', $interface, $destnets ) : $inaction ? '-' : $interface,
				 $proto,
				 $ports,
				 $ipsec,
				 $mark,
				 $user,
				 $condition,
				 $origdest,
				 $probability );
	} else {
	    if ( $actiontype & ACTION ) {
		fatal_error( qq(Action $target may not be used in the snat file) ) unless $actiontype & NAT_TABLE;
		#
		# Verify action 'proto', if any
		#
		$proto = determine_action_protocol( $target, $proto );
		#
		# Create the action:level:tag:param tuple. Since we don't allow logging out of nat POSTROUTING, we store
		# the interface name in the log tag
		#
		my $normalized_target = normalize_action( $target, "$loglevel", "$interface|$params" );
		fatal_error( "Action $target invoked Recursively (" .  join( '->', map( external_name( $_ ), @actionstack , $normalized_target ) ) . ')' ) if $active{$target};

		my $ref = use_action( 'nat', $normalized_target );

		if ( $ref ) {
		    #
		    # First reference to this tuple - process_action may modify both $normalized_target and $ref!!!
		    #
		    process_action( $normalized_target, $ref, $chainref->{name} );
		} else {
		    #
		    # We've seen this tuple before
		    #
		    $ref = $usedactions{$normalized_target};
		}

		$target = $ref->{name};

		if ( $actions{$target}{options} & LOGJUMP_OPT ) {
		    $logaction = $target;
		} else {
		    $loglevel = '';
		}
	    } else {
		for my $option ( split_list2( $options , 'option' ) ) {
		    if ( $option eq 'random' ) {
			$target .= ' --random';
			require_capability( 'MASQUERADE_TGT', "$action rules", '') if $family == F_IPV6;
		    } elsif ( $option eq 'persistent' ) {
			fatal_error( "':persistent' is not allowed in a MASQUERADE rule" ) if $action eq 'MASQUERADE';
			require_capability 'PERSISTENT_SNAT', ':persistent', 's';
			$target .= ' --persistent';
		    } else {
			fatal_error "Invalid $action option ($option)";
		    }
		}
	    }
	    #
	    # If there is no source or destination then allow all addresses
	    #
	    $source   = ALLIP if $source eq '-';
	    $destnets = ALLIP unless supplied $destnets && $destnets ne '-';

	    expand_rule( $chainref ,
			 POSTROUTE_RESTRICT ,
			 $prerule ,
			 $baserule . $inlinematches . $rule ,
			 $source ,
			 $destnets ,
			 $origdest ,
			 $target ,
			 $loglevel ,
			 $logaction ,
			 $exceptionrule ,
			 '' )
		unless unreachable_warning( 0, $chainref );

	    conditional_rule_end( $chainref ) if $detectaddress || $conditional;

	    if ( $add_snat_aliases && $addresses ) {
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

	$addresses = $saveaddresses;
	$target    = $savetarget;
	$baserule  = $savebaserule;
    }

    progress_message "   Snat record \"$currentline\" $done"

}

sub process_snat( )
{
    my ($action, $source, $dest, $protos, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) =
	split_line2( 'snat file',
		     { action => 0, source => 1, dest => 2, proto => 3, port => 4, ipsec => 5, mark => 6, user => 7, switch => 8, origdest => 9, probability => 10 },
		     {},    #Nopad
		     undef, #Columns
		     1 );   #Allow inline matches

    fatal_error 'ACTION must be specified' if $action eq '-';
    fatal_error 'DEST must be specified' if $dest eq '-';

    for my $proto ( split_list $protos, 'Protocol' ) {
	process_snat1( undef, $action, $source, $dest, $proto, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability );
    }
}

#
# Process the masq or snat file
#
sub setup_snat( $ ) # Convert masq->snat if true
{
    my $fn;
    my $have_masq;

    if ( $_[0] ) {
	convert_masq();
    } elsif ( $fn = open_file( 'masq', 1, 1 ) ) {
	first_entry( sub { progress_message2 "$doing $fn..."; require_capability 'NAT_ENABLED' , "a non-empty masq file" , 's'; } );
	process_one_masq(0), $have_masq = 1 while read_a_line( NORMAL_READ );
    }

    unless ( $have_masq ) {
	#
	# Masq file empty or didn't exist
	#
	if ( $fn = open_file( 'snat', 1, 1 ) ) {
	    first_entry( sub { progress_message2 "$doing $fn..."; require_capability 'NAT_ENABLED' , "a non-empty snat file" , 's'; } );
	    process_snat while read_a_line( NORMAL_READ );
	}
    }
}

1;
