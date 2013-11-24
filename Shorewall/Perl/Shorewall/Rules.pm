#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Rules.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010,2011,2012,2013 - Tom Eastep (teastep@shorewall.net)
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

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		  process_policies
		  apply_policy_rules
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
	       );

our @EXPORT_OK = qw( initialize process_rule );
our $VERSION = 'MODULEVERSION';
#
# Globals are documented in the initialize() function
#
our %sections;

our $section;

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

our %default_actions;

our %macros;

our $family;

our @builtins;

#
# Commands that can be embedded in a basic rule and how many total tokens on the line (0 => unlimited).
#
our $rule_commands   = { SECTION => 2 };
our $action_commands = { SECTION => 2, DEFAULTS => 2 };
our $macro_commands  = { SECTION => 2, DEFAULT => 2 };
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
#  Inline Action Table
#
our %inlines;
#
# Contains an entry for each used <action>:<level>[:<tag>] that maps to the associated chain.
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
# Used to handle recursive inline invocations.
#
our @columnstack;
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
    $family            = shift;
    #
    # Chains created as a result of entries in the policy file
    @policy_chains  = ();
    #
    # This is updated from the *_DEFAULT settings in shorewall.conf. Those settings were stored
    # in the %config hash when shorewall[6].conf was processed.
    #
    %default_actions  = ( DROP     => 'none' ,
		 	  REJECT   => 'none' ,
			  ACCEPT   => 'none' ,
			  QUEUE    => 'none' ,
			  NFQUEUE  => 'none' ,
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
    $section  = NULL_SECTION;
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
    # All builtin actions plus those mentioned in /etc/shorewall[6]/actions and /usr/share/shorewall[6]/actions
    #
    %actions           = ();
    #
    # Inline Actions -- value is file.
    #
    %inlines           = ();
    #
    # Action variants actually used. Key is <action>:<loglevel>:<tag>:<params>; value is corresponding chain name
    #
    %usedactions       = ();

    @columns           = ( ( '-' ) x LAST_COLUMN, 0 );
    @columnstack       = ();

    if ( $family == F_IPV4 ) {
	@builtins = qw/dropBcast allowBcast dropNotSyn rejNotSyn allowinUPnP forwardUPnP Limit/;
    } else {
	@builtins = qw/dropBcast allowBcast dropNotSyn rejNotSyn/;
    }
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
# Split the passed target into the basic target and parameter (previously duplicated in this file)
#
sub get_target_param( $ ) {
    my ( $target, $param ) = split '/', $_[0];

    unless ( defined $param ) {
	( $target, $param ) = ( $1, $2 ) if $target =~ /^(.*?)[(](.*)[)]$/;
    }

    ( $target, $param );
}

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
    my ($source, $dest, $chain1, $chainref, $policy, $intrazone) = @_;

    my $chainref1 = $filter_table->{$chain1};

    if ( $chainref1 ) {
	if ( $intrazone && $source eq $dest && $chainref1->{provisional} ) {
	    $chainref1->{policychain} = '';
	    $chainref1->{provisional} = '';
	}
    } else {
	$chainref1 = new_rules_chain $chain1;
    }

    unless ( $chainref1->{policychain} ) {
	if ( $config{EXPAND_POLICIES} ) {
	    #
	    # We convert the canonical chain into a policy chain, using the settings of the
	    # passed policy chain.
	    #
	    $chainref1->{policychain} = $chain1;
	    $chainref1->{loglevel}    = $chainref->{loglevel} if defined $chainref->{loglevel};
	    $chainref1->{audit}       = $chainref->{audit}    if defined $chainref->{audit};

	    if ( defined $chainref->{synparams} ) {
		$chainref1->{synparams}   = $chainref->{synparams};
		$chainref1->{synchain}    = $chainref->{synchain};
	    }

	    $chainref1->{default}     = $chainref->{default} if defined $chainref->{default};
	    $chainref1->{is_policy}   = 1;
	    push @policy_chains, $chainref1;
	} else {
	    $chainref1->{policychain} = $chainref->{name};
	}

	$chainref1->{policy} = $policy;
	$chainref1->{policypair} = [ $source, $dest ];
	$chainref1->{origin} = $chainref->{origin};
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

sub process_default_action( $$$$ ) {
    my ( $originalpolicy, $policy, $default, $level ) = @_;

    if ( supplied $default ) {
	my $default_option = ( $policy =~ /_DEFAULT$/ );
	my ( $def, $param ) = get_target_param( $default );

	if ( supplied $level ) {
	    validate_level( $level );
	} else {
	    $level = 'none';
	}

	if ( "\L$default" eq 'none' ) {
	    if ( supplied $param || ( supplied $level && $level ne 'none' ) ) {
		if ( $default_option ) {
		    fatal_error "Invalid setting (originalpolicy) for $policy";
		} else {
		    fatal_error "Invalid policy ($originalpolicy)";
		}
	    }

	    $default = 'none';
	} elsif ( $actions{$def} ) {
	    $default = supplied $param  ? normalize_action( $def, $level, $param  ) :
		       $level eq 'none' ? normalize_action_name $def :
		       normalize_action( $def, $level, '' );
	} elsif ( ( $targets{$def} || 0 ) == INLINE ) {
	    $default = $def;
	    $default = "$def($param)" if supplied $param;
	} elsif ( $default_option ) {
	    fatal_error "Unknown Action ($default) in $policy setting";
	} else {
	    fatal_error "Unknown Default Action ($default)";
	}

	$default = join( ':', $default, $level ) if $level ne 'none';
    } else {
	$default = $default_actions{$policy} || 'none';
    }

    $default;
}

#
# Process an entry in the policy file.
#
sub process_a_policy() {

    our %validpolicies;
    our @zonelist;

    my ( $client, $server, $originalpolicy, $loglevel, $synparams, $connlimit ) =
	split_line 'policy file', { source => 0, dest => 1, policy => 2, loglevel => 3, limit => 4, connlimit => 5 } ;

    $loglevel  = '' if $loglevel  eq '-';
    $synparams = '' if $synparams eq '-';
    $connlimit = '' if $connlimit eq '-';

    fatal_error 'SOURCE must be specified' if $client eq '-';
    fatal_error 'DEST must be specified'   if $server eq '-';
    fatal_error 'POLICY must be specified' if $originalpolicy eq '-';

    my $clientwild = ( "\L$client" =~ /^all(\+)?$/ );
    my $intrazone  = $clientwild && $1;

    fatal_error "Undefined zone ($client)" unless $clientwild || defined_zone( $client );

    my $serverwild = ( "\L$server" =~ /^all(\+)?/ );
    $intrazone ||= $serverwild && $1;

    fatal_error "Undefined zone ($server)" unless $serverwild || defined_zone( $server );

    my $audit = ( $originalpolicy =~ s/:audit$// );

    require_capability 'AUDIT_TARGET', ":audit", "s" if $audit;

    my ( $policy, $default, $level, $remainder ) = split( /:/, $originalpolicy, 4 );

    fatal_error "Invalid or missing POLICY ($originalpolicy)" unless $policy;

    fatal_error "Invalid default action ($default:$level:$remainder)" if defined $remainder;

    ( $policy , my $queue ) = get_target_param $policy;

    fatal_error "Invalid policy ($policy)" unless exists $validpolicies{$policy};

    if ( $audit ) {
	fatal_error "A $policy policy may not be audited" unless $auditpolicies{$policy};
    }

    $default = process_default_action( $originalpolicy, $policy, $default, $level );

    if ( defined $queue ) {
	fatal_error "Invalid policy ($policy($queue))" unless $policy eq 'NFQUEUE';
	require_capability( 'NFQUEUE_TARGET', 'An NFQUEUE Policy', 's' );
	my $queuenum = numeric_value( $queue );
	fatal_error "Invalid NFQUEUE queue number ($queue)" unless defined( $queuenum) && $queuenum <= 65535;
	$policy = "NFQUEUE --queue-num $queuenum";
    } elsif ( $policy eq 'NONE' ) {
	fatal_error "NONE policy not allowed with \"all\""
	    if $clientwild || $serverwild;
	fatal_error "NONE policy not allowed to/from firewall zone"
	    if ( zone_type( $client ) == FIREWALL ) || ( zone_type( $server ) == FIREWALL );
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
		fatal_error qq(Policy "$client $server $policy" duplicates earlier policy "@{$chainref->{policypair}} $chainref->{policy}");
	    }
	} elsif ( $chainref->{policy} ) {
	    fatal_error qq(Policy "$client $server $policy" duplicates earlier policy "@{$chainref->{policypair}} $chainref->{policy}");
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

    assert( $default );
    my $chainref1 = $usedactions{$default};
    $chainref->{default} = $chainref1 ? $chainref1->{name} : $default;

    $chainref->{origin} = shortlineinfo('');

    if ( $clientwild ) {
	if ( $serverwild ) {
	    for my $zone ( @zonelist ) {
		for my $zone1 ( @zonelist ) {
		    set_policy_chain $client, $server, rules_chain( ${zone}, ${zone1} ), $chainref, $policy, $intrazone;
		    print_policy $zone, $zone1, $policy, $chain;
		}
	    }
	} else {
	    for my $zone ( all_zones ) {
		set_policy_chain $client, $server, rules_chain( ${zone}, ${server} ), $chainref, $policy, $intrazone;
		print_policy $zone, $server, $policy, $chain;
	    }
	}
    } elsif ( $serverwild ) {
	for my $zone ( @zonelist ) {
	    set_policy_chain $client, $server, rules_chain( ${client}, ${zone} ), $chainref, $policy, $intrazone;
	    print_policy $client, $zone, $policy, $chain;
	}

    } else {
	print_policy $client, $server, $policy, $chain;
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
			  DROP   => undef,
			  CONTINUE => undef,
			  QUEUE => undef,
			  NFQUEUE => undef,
			  NONE => undef
			  );

    our %map = ( DROP_DEFAULT    => 'DROP' ,
		 REJECT_DEFAULT  => 'REJECT' ,
		 ACCEPT_DEFAULT  => 'ACCEPT' ,
		 QUEUE_DEFAULT   => 'QUEUE' ,
		 NFQUEUE_DEFAULT => 'NFQUEUE' );

    my $zone;
    my $firewall = firewall_zone;
    our @zonelist = $config{EXPAND_POLICIES} ? all_zones : ( all_zones, 'all' );

    for my $option ( qw( DROP_DEFAULT REJECT_DEFAULT ACCEPT_DEFAULT QUEUE_DEFAULT NFQUEUE_DEFAULT) ) {
	my $action = $config{$option};

	unless ( $action eq 'none' ) {
	    my ( $default, $level, $remainder ) = split( /:/, $action, 3 );
	    fatal_error "Invalid setting ( $action ) for $option" if supplied $remainder;
	    $action = process_default_action( $action, $option, $default, $level );
	}

	$default_actions{$map{$option}} = $action;
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
		    set_policy_chain( $zone,  $zone1, $name,  ensure_rules_chain( $name  ), 'NONE', 0 );
		    set_policy_chain( $zone1, $zone,  $name1, ensure_rules_chain( $name1 ), 'NONE', 0 );
		}
	    }
	} elsif ( $type == LOOPBACK ) {
	    for my $zone1 ( off_firewall_zones ) {
		unless ( $zone eq $zone1 || zone_type( $zone1 ) == LOOPBACK ) {
		    my $name  = rules_chain( $zone,  $zone1 );
		    my $name1 = rules_chain( $zone1, $zone  );
		    set_policy_chain( $zone,  $zone1, $name,  ensure_rules_chain( $name  ), 'NONE', 0 );
		    set_policy_chain( $zone1, $zone,  $name1, ensure_rules_chain( $name1 ), 'NONE', 0 );
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
sub process_inline ($$$$$$$$$$$$$$$$$$$$$);

sub policy_rules( $$$$$ ) {
    my ( $chainref , $target, $loglevel, $default, $dropmulticast ) = @_;

    unless ( $target eq 'NONE' ) {
	add_ijump $chainref, j => 'RETURN', d => '224.0.0.0/4' if $dropmulticast && $target ne 'CONTINUE' && $target ne 'ACCEPT';

	if ( $default && $default ne 'none' ) {
	    my ( $action ) = split ':', $default;

	    if ( ( $targets{$action} || 0 ) == ACTION ) {
		#
		# Default action is a regular action -- jump to the action chain
		#
		add_ijump $chainref, j => use_policy_action( $default, $chainref->{name} );
	    } else {
		#
		# Default action is an inline 
		#
		( $action, my $param ) = get_target_param( $action );

		process_inline( $action,      #Inline
				$chainref,    #Chain
				'',           #Matches
				$loglevel,    #Log Level and Tag
				$default,     #Target
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

	add_ijump( $chainref , j => 'AUDIT', targetopts => '--type ' . lc $target ) if $chainref->{audit};
	add_ijump( $chainref , g => $target eq 'REJECT' ? 'reject' : $target ) unless $target eq 'CONTINUE';
    }
}

sub report_syn_flood_protection() {
    progress_message_nocompress '      Enabled SYN flood Protection';
}

#
# Complete a policy chain - Add policy-enforcing rules and syn flood, if specified
#
sub default_policy( $$$ ) {
    my $chainref   = $_[0];
    my $policyref  = $filter_table->{$chainref->{policychain}};
    my $synparams  = $policyref->{synparams};
    my $default    = $policyref->{default};
    my $policy     = $policyref->{policy};
    my $loglevel   = $policyref->{loglevel};

    assert( $policyref );

    if ( $chainref eq $policyref ) {
	policy_rules $chainref , $policy, $loglevel , $default, $config{MULTICAST};
    } else {
	if ( $policy eq 'ACCEPT' || $policy eq 'QUEUE' || $policy =~ /^NFQUEUE/ ) {
	    if ( $synparams ) {
		report_syn_flood_protection;
		policy_rules $chainref , $policy , $loglevel , $default, $config{MULTICAST};
	    } else {
		add_ijump $chainref,  g => $policyref;
		$chainref = $policyref;
		policy_rules( $chainref, $policy, $loglevel, $default, $config{MULTICAST} ) if $default =~/^macro\./;
	    }
	} elsif ( $policy eq 'CONTINUE' ) {
	    report_syn_flood_protection if $synparams;
	    policy_rules $chainref , $policy , $loglevel , $default, $config{MULTICAST};
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
sub apply_policy_rules() {
    progress_message2 'Applying Policies...';

    for my $chainref ( @policy_chains ) {
	my $policy      = $chainref->{policy};

	unless ( $policy eq 'NONE' ) {
	    my $loglevel    = $chainref->{loglevel};
	    my $provisional = $chainref->{provisional};
	    my $default     = $chainref->{default};
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
		    ensure_rules_chain $name if ( $default ne 'none' ||
						  $loglevel          ||
						  $synparms          ||
						  $config{MULTICAST} ||
						  ! ( $policy eq 'ACCEPT' || $config{FASTACCEPT} ) );
		} else {
		    ensure_rules_chain $name;
		}
	    }

	    if ( $name =~ /^all[-2]|[-2]all$/ ) {
		run_user_exit $chainref;
		policy_rules $chainref , $policy, $loglevel , $default, $config{MULTICAST};
	    }
	}
    }

    for my $zone ( all_zones ) {
	for my $zone1 ( all_zones ) {
	    my $chainref = $filter_table->{rules_chain( ${zone}, ${zone1} )};

	    if ( $chainref->{referenced} ) {
		run_user_exit $chainref;
		default_policy $chainref, $zone, $zone1;
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

    run_user_exit $stdchainref;

    my $ruleschainref = $filter_table->{rules_chain( ${zone}, ${zone2} ) } || $filter_table->{rules_chain( 'all', 'all' ) };
    my ( $policy, $loglevel, $defaultaction ) = ( $default , 6, $config{$default . '_DEFAULT'} );
    my $policychainref;

    $policychainref = $filter_table->{$ruleschainref->{policychain}} if $ruleschainref;

    if ( $policychainref ) {
	( $policy, $loglevel, $defaultaction ) = @{$policychainref}{'policy', 'loglevel', 'default' };
	$stdchainref->{origin} = $policychainref->{origin};
    } elsif ( $defaultaction !~ /:/ ) {
	$defaultaction = join(":", $defaultaction, 'none', '', '' );
    }


    policy_rules $stdchainref , $policy , $loglevel, $defaultaction, 0;
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
			    'add' )
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
	    my ( $char, $level, $target ) = @{$statetable{$_}};
	    my $twochains = substr( $chainref->{name}, 0, 1 ) eq $char;

	    if ( $twochains || $level || $target ne 'ACCEPT' ) {
		if ( $level ) {
		    my $chain2ref;

		    if ( $twochains ) {
			$chain2ref = $chainref;
		    } else {
			$chain2ref = new_chain( 'filter', "${char}$chainref->{name}" );
		    }

		    log_rule( $level,
			      $chain2ref,
			      uc $target,
			      '' );

		    $target = ensure_audit_chain( $target ) if ( $targets{$target} || 0 ) & AUDIT;

		    add_ijump( $chain2ref, g => $target ) if $target;

		    $target = $chain2ref->{name} unless $twochains;
		}

		if ( $twochains ) {
		    add_ijump $chainref, g => $target if $target;
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

		    add_ijump( $chainref, j => $target, state_imatch $_ );
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
# Return ( action, level[:tag] ) from passed full action
#
sub split_action ( $ ) {
    my $action = $_[0];

    my @list   = split_list2( $action, 'ACTION' );

    fatal_error "Invalid ACTION ($action)" if @list > 3;

    ( shift @list, join( ':', @list ) );
}

#
# Create a normalized action name from the passed pieces.
#
# Internally, action invocations are uniquely identified by a 4-tuple that
# includes the action name, log level, log tag and params. The pieces of the tuple
# are separated by ":".
#
sub normalize_action( $$$ ) {
    my $action = shift;
    my $level  = shift;
    my $param  = shift;

    ( $level, my $tag ) = split ':', $level;

    $level = 'none' unless supplied $level;
    $tag   = ''     unless defined $tag;
    $param = ''     unless defined $param;
    $param = ''     if $param eq '-';

    join( ':', $action, $level, $tag, $param );
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
# Produce a recognizable target from a normalized action
#
sub externalize( $ ) {
    my ( $target, $level, $tag, $params ) = split /:/, shift, 4;

    $target  = join( '', $target, '(', $params , ')' ) if $params;
    $target .= ":$level" if $level && $level ne 'none';
    $target .= ":$tag"   if $tag;
    $target;
}

#
# Define an Action
#
sub new_action( $$$$ ) {

    my ( $action , $type, $noinline, $nolog ) = @_;

    fatal_error "Invalid action name($action)" if reserved_name( $action );

    $actions{$action} = { actchain => '' , noinline => $noinline, nolog => $nolog } if $type & ACTION;

    $targets{$action} = $type;
}

#
# Create and record a log action chain -- Log action chains have names
# that are formed from the action name by prepending a "%" and appending
# a 1- or 2-digit sequence number. In the functions that follow,
# the $chain, $level and $tag variable serves as arguments to the user's
# exit. We call the exit corresponding to the name of the action but we
# set $chain to the name of the iptables chain where rules are to be added.
# Similarly, $level and $tag contain the log level and log tag respectively.
#
# The maximum length of a chain name is 30 characters -- since the log
# action chain name is 2-3 characters longer than the base chain name,
# this function truncates the original chain name where necessary before
# it adds the leading "%" and trailing sequence number.
#
sub createlogactionchain( $$$$$ ) {
    my ( $normalized, $action, $level, $tag, $param ) = @_;
    my $chain = $action;
    my $actionref = $actions{$action};
    my $chainref;

    validate_level $level;

    assert( $actionref );

    $chain = substr $chain, 0, 28 if ( length $chain ) > 28;

    if ( $filter_table->{$chain} ) {
      CHECKDUP:
	{
	    $actionref->{actchain}++ while $chain_table{filter}{'%' . $chain . $actionref->{actchain}};
	    $chain = substr( $chain, 0, 27 ), redo CHECKDUP if ( $actionref->{actchain} || 0 ) >= 10 and length $chain == 28;
	}

	$usedactions{$normalized} = $chainref = new_standard_chain '%' . $chain . $actionref->{actchain}++;

	fatal_error "Too many invocations of Action $action" if $actionref->{actchain} > 99;
    } else {
	$usedactions{$normalized} = $chainref = new_standard_chain $chain;
    }

    $chainref->{action} = $normalized;

    if ( $config{CHAIN_SCRIPTS} ) {
	unless ( $targets{$action} & BUILTIN ) {

	    set_optflags( $chainref, DONT_OPTIMIZE );

	    my $file = find_file $chain;

	    if ( -f $file ) {
		progress_message "Running $file...";

		my @params = split /,/, $param;

		unless ( my $return = eval `cat $file` ) {
		    fatal_error "Couldn't parse $file: $@" if $@;
		    fatal_error "Couldn't do $file: $!"    unless defined $return;
		    fatal_error "Couldn't run $file";
		}
	    }
	}
    }

    $chainref;
}

sub createsimpleactionchain( $ ) {
    my $action  = shift;
    my $normalized = normalize_action_name( $action );

    return createlogactionchain( $normalized, $action, 'none', '', '' ) if $filter_table->{$action} || $nat_table->{$action};

    my $chainref = new_standard_chain $action;

    $usedactions{$normalized} = $chainref;

    $chainref->{action} = $normalized;

    if ( $config{CHAIN_SCRIPTS} ) {
	unless ( $targets{$action} & BUILTIN ) {

	    set_optflags( $chainref, DONT_OPTIMIZE );

	    my $file = find_file $action;

	    if ( -f $file ) {
		progress_message "Running $file...";

		my ( $level, $tag ) = ( '', '' );

		unless ( my $return = eval `cat $file` ) {
		    fatal_error "Couldn't parse $file: $@" if $@;
		    fatal_error "Couldn't do $file: $!"    unless defined $return;
		    fatal_error "Couldn't run $file";
		}
	    }
	}
    }

    $chainref;
}

#
# Create an action chain and run its associated user exit
#
sub createactionchain( $ ) {
    my $normalized = shift;

    my ( $target, $level, $tag, $param ) = split /:/, $normalized, 4;

    assert( defined $param );

    my $chainref;

    if ( $level eq 'none' && $tag eq '' && $param eq '' ) {
	createsimpleactionchain $target;
    } else {
	createlogactionchain $normalized, $target , $level , $tag, $param;
    }
}

#
# Mark an action as used and create its chain. Returns a reference to the chain if the chain was
# created on this call or 0 otherwise.
#
sub use_action( $ ) {
    my $normalized = shift;

    if ( $usedactions{$normalized} ) {
	0;
    } else {
	createactionchain $normalized;
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

    $macro =~ s/^macro.//;

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

#
# The following small functions generate rules for the builtin actions of the same name
#
sub dropBcast( $$$$ ) {
    my ($chainref, $level, $tag, $audit) = @_;

    my $target = require_audit ( 'DROP', $audit );

    if ( have_capability( 'ADDRTYPE' ) ) {
	if ( $level ne '' ) {
	    log_irule_limit( $level, $chainref, 'dropBcast' , 'DROP', [], $tag, 'add', addrtype => '--dst-type BROADCAST' );
	    if ( $family == F_IPV4 ) {
		log_irule_limit( $level, $chainref, 'dropBcast' , 'DROP', [], $tag, 'add', d => '224.0.0.0/4' );
	    } else {
		log_irule_limit( $level, $chainref, 'dropBcast' , 'DROP', [], $tag, 'add', d => IPv6_MULTICAST );
	    }
	}

	add_ijump $chainref, j => $target, addrtype => '--dst-type BROADCAST';
    } else {
	if ( $family == F_IPV4 ) {
	    add_commands $chainref, 'for address in $ALL_BCASTS; do';
	} else {
	    add_commands $chainref, 'for address in $ALL_ACASTS; do';
	}

	incr_cmd_level $chainref;
	log_irule_limit( $level, $chainref, 'dropBcast' , 'DROP', [], $tag, 'add', d => '$address' ) if $level ne '';
	add_ijump $chainref, j => $target, d => '$address';
	decr_cmd_level $chainref;
	add_commands $chainref, 'done';
    }

    if ( $family == F_IPV4 ) {
	log_irule_limit $level, $chainref, 'dropBcast' , 'DROP', [], $tag, 'add', d => '224.0.0.0/4' if $level ne '';
	add_ijump $chainref, j => $target, d => '224.0.0.0/4';
    } else {
	log_irule_limit( $level, $chainref, 'dropBcast' , 'DROP', [], $tag, 'add', d => IPv6_MULTICAST ) if $level ne '';
	add_ijump $chainref, j => $target, d => IPv6_MULTICAST;
    }
}

sub allowBcast( $$$$ ) {
    my ($chainref, $level, $tag, $audit) = @_;

    my $target = require_audit( 'ACCEPT', $audit );

    if ( $family == F_IPV4 && have_capability( 'ADDRTYPE' ) ) {
	if ( $level ne '' ) {
	    log_irule_limit( $level, $chainref, 'allowBcast' , 'ACCEPT', [], $tag, 'add', addrtype => '--dst-type BROADCAST' );
	    log_irule_limit( $level, $chainref, 'allowBcast' , 'ACCEPT', [], $tag, 'add', d => '224.0.0.0/4' );
	}

	add_ijump $chainref, j => $target, addrtype => '--dst-type BROADCAST';
    } else {
	if ( $family == F_IPV4 ) {
	    add_commands $chainref, 'for address in $ALL_BCASTS; do';
	} else {
	    add_commands $chainref, 'for address in $ALL_MACASTS; do';
	}

	incr_cmd_level $chainref;
	log_irule_limit( $level, $chainref, 'allowBcast' , 'ACCEPT', [], $tag, 'add', d => '$address' ) if $level ne '';
	add_ijump $chainref, j => $target, d => '$address';
	decr_cmd_level $chainref;
	add_commands $chainref, 'done';
    }

    if ( $family == F_IPV4 ) {
	log_irule_limit( $level, $chainref, 'allowBcast' , 'ACCEPT', [], $tag, 'add', d => '224.0.0.0/4' ) if $level ne '';
	add_ijump $chainref, j => $target, d => '224.0.0.0/4';
    } else {
	log_irule_limit( $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add',  d => IPv6_MULTICAST ) if $level ne '';
	add_ijump $chainref, j => $target, d => IPv6_MULTICAST;
    }
}

sub dropNotSyn ( $$$$ ) {
    my ($chainref, $level, $tag, $audit) = @_;

    my $target = require_audit( 'DROP', $audit );

    log_irule_limit( $level, $chainref, 'dropNotSyn' , 'DROP', [], $tag, 'add', p => '6 ! --syn' ) if $level ne '';
    add_ijump $chainref , j => $target, p => '6 ! --syn';
}

sub rejNotSyn ( $$$$ ) {
    my ($chainref, $level, $tag, $audit) = @_;

    warning_message "rejNotSyn is deprecated in favor of NotSyn(REJECT)";

    my $target = 'REJECT --reject-with tcp-reset';

    if ( supplied $audit ) {
	$target = require_audit( 'REJECT' , $audit );
    }

    log_irule_limit( $level, $chainref, 'rejNotSyn' , 'REJECT', [], $tag, 'add', p => '6 ! --syn' ) if $level ne '';
    add_ijump $chainref , j => $target, p => '6 ! --syn';
}

sub forwardUPnP ( $$$$ ) {
    my $chainref = set_optflags( 'forwardUPnP', DONT_OPTIMIZE );

    add_commands( $chainref , '[ -f ${VARDIR}/.forwardUPnP ] && cat ${VARDIR}/.forwardUPnP >&3' );
}

sub allowinUPnP ( $$$$ ) {
    my ($chainref, $level, $tag, $audit) = @_;

    my $target = require_audit( 'ACCEPT', $audit );

    if ( $level ne '' ) {
	log_irule_limit( $level, $chainref, 'allowinUPnP' , 'ACCEPT', [], $tag, 'add', p => '17 --dport 1900' );
	log_irule_limit( $level, $chainref, 'allowinUPnP' , 'ACCEPT', [], $tag, 'add', p => '6 --dport 49152' );
    }

    add_ijump $chainref, j => $target, p => '17 --dport 1900';
    add_ijump $chainref, j => $target, p => '6 --dport 49152';
}

sub Limit( $$$$ ) {
    my ($chainref, $level, $tag, $param ) = @_;

    my @param;

    if ( $param ) {
	@param = split /,/, $param;
    } else {
	@param = split /,/, $tag;
	$tag = '';
    }

    fatal_error 'Limit rules must include <set name>,<max connections>,<interval> as the log tag or as parameters' unless @param == 3;

    my $set   = $param[0];

    for ( @param[1,2] ) {
	fatal_error 'Max connections and interval in Limit rules must be numeric (' . join( ':', 'Limit', $level eq '' ? 'none' : $level, $tag ) . ')' unless /^\d+$/
    }

    my $count = $param[1] + 1;

    require_capability( 'RECENT_MATCH' , 'Limit rules' , '' );

    warning_message "The Limit action is deprecated in favor of per-IP rate limiting using the RATE LIMIT column";

    add_irule $chainref, recent => "--name $set --set";

    if ( $level ne '' ) {
	my $xchainref = new_chain 'filter' , "$chainref->{name}%";
	log_irule_limit( $level, $xchainref, $param[0], 'DROP', [], $tag, 'add' );
	add_ijump $xchainref, j => 'DROP';
	add_ijump $chainref,  j => $xchainref, recent => "--name $set --update --seconds $param[2] --hitcount $count";
    } else {
	add_ijump $chainref, j => 'DROP', recent => "--update --name $set --seconds $param[2] --hitcount $count";
    }

    add_ijump $chainref, j => 'ACCEPT';
}

my %builtinops = ( 'dropBcast'      => \&dropBcast,
		   'allowBcast'     => \&allowBcast,
		   'dropNotSyn'     => \&dropNotSyn,
		   'rejNotSyn'      => \&rejNotSyn,
		   'allowinUPnP'    => \&allowinUPnP,
		   'forwardUPnP'    => \&forwardUPnP,
		   'Limit'          => \&Limit,
		 );

sub process_rule ( $$$$$$$$$$$$$$$$$$$ );

#
# Populate an action invocation chain. As new action tuples are encountered,
# the function will be called recursively by process_rule().
#
sub process_action($$) {
    my ( $chainref, $caller ) = @_;
    my $wholeaction = $chainref->{action};
    my ( $action, $level, $tag, $param ) = split /:/, $wholeaction, 4;

    if ( $targets{$action} & BUILTIN ) {
	$level = '' if $level =~ /none!?/;
	$builtinops{$action}->( $chainref, $level, $tag, $param );
	return 0;
    } 

    my $actionfile = find_file "action.$action";

    fatal_error "Missing Action File ($actionfile)" unless -f $actionfile;

    progress_message2 "$doing $actionfile for chain $chainref->{name}...";

    push_open $actionfile, 2, 1;

    my $oldparms = push_action_params( $action, $chainref, $param, $level, $tag, $caller );

    my $nolog = $actions{$action}{nolog};

    $active{$action}++;
    push @actionstack, $wholeaction;

    my $save_comment = push_comment;

    while ( read_a_line( NORMAL_READ ) ) {

	my ($target, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers, $condition, $helper );

	if ( $file_format == 1 ) {
	    ($target, $source, $dest, $proto, $ports, $sports, $rate, $user, $mark ) =
		split_line1 'action file', { target => 0, source => 1, dest => 2, proto => 3, dport => 4, sport => 5, rate => 6, user => 7, mark => 8 }, $rule_commands;
	    $origdest = $connlimit = $time = $headers = $condition = $helper = '-';
	} else {
	    ($target, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers, $condition, $helper )
		= split_line1 'action file', \%rulecolumns, $action_commands;
	}

	fatal_error 'TARGET must be specified' if $target eq '-';

	if ( $target eq 'DEFAULTS' ) {
	    default_action_params( $action, split_list $source, 'defaults' ), next if $file_format == 2;
	    fatal_error 'DEFAULTS only allowed in FORMAT-2 actions';
	}

	process_rule( $chainref,
		      '',
		      $nolog ? $target : merge_levels( join(':', @actparms{'chain','loglevel','logtag'}), $target ),
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
    }

    pop_comment( $save_comment );

    $active{$action}--;
    pop @actionstack;

    pop_open;

    #
    # Pop the action parameters
    # Caller should delete record of this chain if the action parameters
    # were modified (and this function returns true
    #
    pop_action_params( $oldparms );
}

#
# This function is called prior to processing of the policy file. It:
#
# - Adds the builtin actions to the target table
# - Reads actions.std and actions (in that order) and for each entry:
#   o Adds the action to the target table
#   o Verifies that the corresponding action file exists
#

sub process_actions() {

    progress_message2 "Locating Action Files...";
    #
    # Add built-in actions to the target table and create those actions
    #
    $targets{$_} = new_action( $_ , ACTION + BUILTIN, 1, 0 ) for @builtins;

    for my $file ( qw/actions.std actions/ ) {
	open_file( $file, 2 );

	while ( read_a_line( NORMAL_READ ) ) {
	    my ( $action, $options ) = split_line 'action file' , { action => 0, options => 1 };

	    my $type     = ( $action eq $config{REJECT_ACTION} ? INLINE : ACTION );
	    my $noinline = 0;
	    my $nolog    = ( $type == INLINE ) || 0;
	    my $builtin  = 0;

	    if ( $action =~ /:/ ) {
		warning_message 'Default Actions are now specified in /etc/shorewall/shorewall.conf';
		$action =~ s/:.*$//;
	    }

	    fatal_error "Invalid Action Name ($action)" unless $action =~ /^[a-zA-Z][\w-]*$/;

	    if ( $options ne '-' ) {
		for ( split_list( $options, 'option' ) ) {
		    if ( $_ eq 'inline' ) {
			$type = INLINE;
		    } elsif ( $_ eq 'noinline' ) {
			$noinline = 1;
		    } elsif ( $_ eq 'nolog' ) {
			$nolog = 1;
		    } elsif ( $_ eq 'builtin' ) {
			$builtin = 1;
		    } else {
			fatal_error "Invalid option ($_)";
		    }
		}
	    }

	    fatal_error "Conflicting OPTIONS ($options)" if $noinline && $type == INLINE;

	    if ( my $actiontype = $targets{$action} ) {
		if ( ( $actiontype & ACTION ) && ( $type == INLINE ) ) {
		    if ( $actions{$action}->{noinline} ) {
			warning_message "'inline' option ignored on action $action -- that action may not be in-lined";
			next;
		    }
		    
		    delete $actions{$action};
		    delete $targets{$action};
		} else {
		    warning_message "Duplicate Action Name ($action) Ignored" unless $actiontype & ( ACTION | INLINE );
		    next;
		}
	    }

	    if ( $builtin ) {
		$targets{$action}         = USERBUILTIN + OPTIONS;
		$builtin_target{$action}  = 1;
	    } else {
		new_action $action, $type, $noinline, $nolog;

		my $actionfile = find_file( "action.$action" );

		fatal_error "Missing Action File ($actionfile)" unless -f $actionfile;

		$inlines{$action} = { file => $actionfile, nolog => $nolog } if $type == INLINE;
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
    my $ref = use_action( $_[0] );
    if ( $ref ) {
	delete $usedactions{$ref->{action}} if process_action( $ref, $_[1] );
    } else {
	$ref = $usedactions{$_[0]};
    }

    $ref;
}

#
# Process the REJECT_ACTION
#
sub process_reject_action() {
    my $rejectref = $filter_table->{reject};
    my $action    = $config{REJECT_ACTION};

    if ( ( $targets{$action} || 0 ) == ACTION ) {
	add_ijump $rejectref, j => use_policy_action( $action, $rejectref->{name} );
    } else {
	process_inline( $action,      #Inline
			$rejectref,   #Chain
			'',           #Matches
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
}

################################################################################
# End of functions moved from the Actions module in 4.4.16
################################################################################
#
# Expand a macro rule from the rules file
#
sub process_macro ($$$$$$$$$$$$$$$$$$$$) {
    my ($macro, $chainref, $matches, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers, $condition, $helper, $wildcard ) = @_;

    my $generated = 0;


    my $macrofile = $macros{$macro};

    progress_message "..Expanding Macro $macrofile...";

    push_open $macrofile, 2, 1, no_comment;

    macro_comment $macro;

    while ( read_a_line( NORMAL_READ ) ) {

	my ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $morigdest, $mrate, $muser, $mmark, $mconnlimit, $mtime, $mheaders, $mcondition, $mhelper);

	if ( $file_format == 1 ) {
	    ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split_line1 'macro file', \%rulecolumns, $rule_commands;
	    ( $morigdest, $mmark, $mconnlimit, $mtime, $mheaders, $mcondition, $mhelper ) = qw/- - - - - - -/;
	} else {
	    ( $mtarget,
	      $msource,
	      $mdest,
	      $mproto,
	      $mports,
	      $msports,
	      $morigdest,
	      $mrate,
	      $muser,
	      $mmark,
	      $mconnlimit,
	      $mtime,
	      $mheaders,
	      $mcondition,
	      $mhelper ) = split_line1 'macro file', \%rulecolumns, $rule_commands;
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

	$generated |= process_rule(
				   $chainref,
				   $matches,
				   $mtarget,
				   $param,
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
				   merge_macro_column( $mheaders,   $headers ),
				   merge_macro_column( $mcondition, $condition ),
				   merge_macro_column( $mhelper,    $helper ),
				   $wildcard
				  );

	progress_message "   Rule \"$currentline\" $done";
    }

    pop_open;

    progress_message "..End Macro $macrofile";

    return $generated;
}

#
# Expand an inline action rule from the rules file
#
sub process_inline ($$$$$$$$$$$$$$$$$$$$$) {
    my ($inline, $chainref, $matches, $loglevel, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers, $condition, $helper, $wildcard ) = @_;

    my $generated = 0;

    my ( $level, $tag ) = split( ':', $loglevel, 2 );

    my $oldparms   = push_action_params( $inline,
					 $chainref,
					 $param,
					 supplied $level ? $level : 'none',
					 defined  $tag   ? $tag   : '' ,
					 $chainref->{name} ,
				       );

    my $inlinefile = $inlines{$inline}{file};
    my $nolog      = $inlines{$inline}{nolog};

    progress_message "..Expanding inline action $inlinefile...";

    push_open $inlinefile, 2, 1;

    my $save_comment = push_comment;

    while ( read_a_line( NORMAL_READ ) ) {
	my  ( $mtarget,
	      $msource,
	      $mdest,
	      $mproto,
	      $mports,
	      $msports,
	      $morigdest,
	      $mrate,
	      $muser,
	      $mmark,
	      $mconnlimit,
	      $mtime,
	      $mheaders,
	      $mcondition,
	      $mhelper ) = split_line1 'inline action file', \%rulecolumns, $rule_commands;

	fatal_error 'TARGET must be specified' if $mtarget eq '-';

	if ( $mtarget eq 'DEFAULTS' ) {
	    default_action_params( $chainref, split_list( $msource, 'defaults' ) );
	    next;
	}

	$mtarget = merge_levels( join(':', @actparms{'chain','loglevel','logtag'}), $mtarget ) unless $nolog;

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

	$generated |= process_rule(
				   $chainref,
				   $matches,
				   $mtarget,
				   $param,
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
				   merge_macro_column( $mheaders,   $headers ),
				   merge_macro_column( $mcondition, $condition ),
				   merge_macro_column( $mhelper,    $helper ),
				   $wildcard
				  );

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

sub process_rule ( $$$$$$$$$$$$$$$$$$$ ) {
    my ( $chainref,   #reference to Action Chain if we are being called from process_action(); undef otherwise
	 $rule,       #Matches
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
    my $inaction  = ''; # Set to true when we are process rules in an action file
    my $inchain   = ''; # Set to true when a chain reference is passed.
    my $normalized_target;
    my $normalized_action;
    my $blacklist   = ( $section == BLACKLIST_SECTION );
    my $matches     = $rule;
    my $raw_matches = '';

    if ( $inchain = defined $chainref ) {
	( $inaction, undef, undef, undef ) = split /:/, $normalized_action = $chainref->{action}, 4 if $chainref->{action};
    }

    $param = '' unless defined $param;

    if ( $basictarget eq 'INLINE' ) {
	my $inline_matches = get_inline_matches;

	if ( $inline_matches =~ /^(.*\s+)?-j\s+(.+) $/ ) {
	    $raw_matches .= $1 if supplied $1;
	    $action = $2;
	    my ( $target ) = split ' ', $action;
	    fatal_error "Unknown jump target ($action)" unless $targets{$target} || $target eq 'MARK';
	    fatal_error "INLINE may not have a parameter when '-j' is specified in the free-form area" if $param ne '';
	} else {
	    $raw_matches .= $inline_matches;

	    if ( $param eq '' ) {
		$action = $loglevel ? 'LOG' : '';
	    } else {
		( $action, $loglevel )   = split_action $param;
		( $basictarget, $param ) = get_target_param $action;
		$param = '' unless defined $param;
	    }
	}
    }
    #
    # Determine the validity of the action
    #
    $actiontype = ( $targets{$basictarget} || find_macro ( $basictarget ) );

    if ( $config{ MAPOLDACTIONS } ) {
	( $basictarget, $actiontype , $param ) = map_old_actions( $basictarget ) unless $actiontype || supplied $param;
    }

    fatal_error "Unknown ACTION ($action)" unless $actiontype;

    if ( $actiontype == MACRO ) {
	#
	# process_macro() will call process_rule() recursively for each rule in the macro body
	#
	fatal_error "Macro/Inline invocations nested too deeply" if ++$macro_nest_level > MAX_MACRO_NEST_LEVEL;

	$current_param = $param unless $param eq '' || $param eq 'PARAM';

	my $generated = process_macro( $basictarget,
				       $chainref,
				       $rule . $raw_matches,
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

	return $generated;

    } elsif ( $actiontype & NFQ ) {
	require_capability( 'NFQUEUE_TARGET', 'NFQUEUE Rules', '' );
	my $paramval = $param eq '' ? 0 : numeric_value( $param );
	fatal_error "Invalid value ($param) for NFQUEUE queue number" unless defined($paramval) && $paramval <= 65535;
	$action = "NFQUEUE --queue-num $paramval";
    } elsif ( $actiontype & SET ) {
	require_capability( 'IPSET_MATCH', 'SET and UNSET rules', '' );
	fatal_error "$action rules require a set name parameter" unless $param;
    } elsif ( ( $actiontype & AUDIT ) && ( $basictarget eq 'AUDIT' ) ) {
	require_capability ( 'AUDIT_TARGET', 'The AUDIT action', 's' );
	$param = $param eq '' ? 'drop' : $param;
	fatal_error "Invalid AUDIT type ($param) -- must be 'accept', 'drop' or 'reject'" unless $param =~ /^(?:accept|drop|reject)$/;
	$actiontype = STANDARD;
    } elsif ( $actiontype & NFLOG ) {
	validate_level( $action );
	$loglevel = supplied $loglevel ? join( ':', $action, $loglevel ) : $action;
	$action   = 'LOG';
    } elsif ( ! ( $actiontype & (ACTION | INLINE) ) ) {
	fatal_error "'builtin' actions may only be used in INLINE rules" if $actiontype == USERBUILTIN;
	fatal_error "The $basictarget TARGET does not accept a parameter" unless $param eq '';
    }

    #
    # We can now dispense with the postfix character
    #
    fatal_error "The +, - and ! modifiers are not allowed in the blrules file" if $action =~ s/[-+!]$// && $blacklist;
    
    unless ( $actiontype & ( ACTION | INLINE) ) {
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

	      REJECT => sub { $action = 'reject'; } ,

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
	    );

	my $function = $functions{ $bt };

	if ( $function ) {
	    $function->();
	} elsif ( $actiontype & NATRULE && $helper ne '-' ) {
	    $actiontype |= HELPER;
	} elsif ( $actiontype & SET ) {
	    my %xlate = ( ADD => 'add-set' , DEL => 'del-set' );

	    my ( $setname, $flags, $rest ) = split ':', $param, 3;
	    fatal_error "Invalid ADD/DEL parameter ($param)" if $rest;
	    $setname =~ s/^\+//;
	    fatal_error "Expected ipset name ($setname)" unless $setname =~ /^(6_)?[a-zA-Z][-\w]*$/;
	    fatal_error "Invalid flags ($flags)" unless defined $flags && $flags =~ /^(dst|src)(,(dst|src)){0,5}$/;
	    $action = join( ' ', 'SET --' . $xlate{$basictarget} , $setname , $flags );
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
    } else {
	unless ( $inchain ) {
	    fatal_error "Missing destination zone" if $destzone eq '-' || $destzone eq '';
	    fatal_error "Unknown destination zone ($destzone)" unless $destref = defined_zone( $destzone );
	}
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
    } else {
	unless ( $actiontype & NATONLY ) {
	    #
	    # Check for illegal bridge port rule
	    #
	    if ( $destref->{type} & BPORT ) {
		unless ( $sourceref->{bridge} eq $destref->{bridge} || single_interface( $sourcezone ) eq $destref->{bridge} ) {
		    return 0 if $wildcard;
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
		return 0 if $wildcard;
		fatal_error "Rules may not override a NONE policy";
	    }
	    #
	    # Handle Optimization level 1 when specified alone
	    #
	    if ( $optimize == 1 && $section == NEW_SECTION ) {
		my $loglevel = $filter_table->{$chainref->{policychain}}{loglevel};
		if ( $loglevel ne '' ) {
		    return 0 if $target eq "${policy}:${loglevel}";
		} else {
		    return 0 if $basictarget eq $policy;
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
		    $auxref = new_chain 'filter', $auxchain;
		    $auxref->{blacklistsection} = 1 if $blacklist;

		    add_ijump( $chainref, j => $auxref, state_imatch( $section_states{$section} ) );
		}

		$chain    = $auxchain;
		$chainref = $auxref;
	    }
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
    my $delete_action;

    if ( $actiontype & ACTION ) {
	#
	# Create the action:level:tag:param tuple.
	#
	$normalized_target = normalize_action( $basictarget, $loglevel, $param );

	fatal_error( "Action $basictarget invoked Recursively (" .  join( '->', map( externalize( $_ ), @actionstack , $normalized_target ) ) . ')' ) if $active{$basictarget};

	if ( my $ref = use_action( $normalized_target ) ) {
	    #
	    # First reference to this tuple
	    #
	    my $savestatematch = $statematch;
	    $statematch        = '';

	    $delete_action = process_action( $ref, $chain );
	    #
	    # Processing the action may determine that the action or one of it's dependents does NAT or HELPER, so:
	    #
	    #    - Refresh $actiontype
	    #    - Create the associated nat and/or table chain if appropriate.
	    #
	    ensure_chain( 'nat', $ref->{name} ) if ( $actiontype = $targets{$basictarget} ) & NATRULE;
	    ensure_chain( 'raw', $ref->{name} ) if ( $actiontype & HELPER );

	    $statematch = $savestatematch;
	}

	$action = $basictarget; # Remove params, if any, from $action.
    } elsif ( $actiontype & INLINE ) {
	#
	# process_inline() will call process_rule() recursively for each rule in the macro body
	#
	fatal_error "Macro/Inline invocations nested too deeply" if ++$macro_nest_level > MAX_MACRO_NEST_LEVEL;

	$current_param = $param unless $param eq '' || $param eq 'PARAM';
	#
	# Push the current column array onto the column stack
	#
	push @columnstack, [ ( $actionresult, @columns ) ];
	#
	# And store the (modified) columns into the columns array for use by perl_action[_tcp]_helper
	#
	@columns = ( $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time, $headers, $condition, $helper, $wildcard );

	$actionresult = 0;

	my $generated = process_inline( $basictarget,
					$chainref,
					$rule . $raw_matches,
					$loglevel,
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
					$wildcard ) || $actionresult;

	( $actionresult, @columns ) = @{pop @columnstack};

	$macro_nest_level--;

	return $generated;
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
		       $raw_matches ,
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
		       $raw_matches ,
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
			    ( $actiontype & ACTION ) ? $usedactions{$normalized_target}->{name} : '',
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
				     ( $actiontype & ACTION ) ? $usedactions{$normalized_target}->{name} : '',
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
	    $action = $usedactions{$normalized_target}{name};
	    $loglevel = '';
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
		     '' ,
		     $rule ,
		     $source ,
		     $dest ,
		     $origdest ,
		     $action ,
		     $loglevel ,
		     $log_action ,
		     '' )
	    unless unreachable_warning( $wildcard || $section == DEFAULTACTION_SECTION, $chainref );
    }

    delete $usedactions{$normalized_target} if $delete_action;

    return 1;
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

    my $chainref   = $actparms{0};
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

    $ref->{inline} ? $target : merge_levels( join( ':', @actparms{'chain','loglevel','logtag'}), $target );
}

#
# May be called by Perl code in action bodies (regular and inline) to generate a rule.
#
sub perl_action_helper($$;$) {
    my ( $target, $matches, $isstatematch ) = @_;
    my $action   = $actparms{action};
    my $chainref = $actparms{0};
    my $result;

    assert( $chainref );

    $matches .= ' ' unless $matches =~ /^(?:.+\s)?$/;

    set_inline_matches $matches if $target =~ /^INLINE(?::.*)?$/;

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

    if ( my $ref = $inlines{$action} ) {
	$result = &process_rule( $chainref,
				 $matches,
				 merge_target( $ref, $target ),
				 '',                              # CurrentParam
				 @columns );
    } else {
	assert $actions{$action};

	$result = process_rule( $chainref,
				$matches,
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

    $statematch = '' if $isstatematch;
}

#
# May be called by Perl code in action bodies (regular and inline) to generate a rule.
#
sub perl_action_tcp_helper($$) {
    my ( $target, $proto ) = @_;
    my $action   = $actparms{action};
    my $chainref = $actparms{0};
    my $result;
    my $passedproto = $columns[2];

    assert( $chainref );

    $proto .= ' ' unless $proto =~ /^(?:.+\s)?$/;

    if ( $passedproto eq '-' || $passedproto eq 'tcp' || $passedproto eq '6' ) {
	#
	# For other protos, a 'no rule generated' warning will be issued
	#
	if ( my $ref = $inlines{$action} ) {
	    $result = &process_rule( $chainref,
				     $proto,
				     merge_target( $ref, $target ),
				     '',
				     @columns[0,1],
				     6,
				     @columns[3..LAST_COLUMN]
				   );
	} else {
	    $result = process_rule( $chainref,
				    $proto,
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
    # split_line1 has already verified that there are exactly two tokens on the line
    #
    fatal_error "Invalid SECTION ($sect)" unless defined $sections{$sect};
    fatal_error "Duplicate or out of order SECTION $sect" if $sections{$sect};

    if ( $sect eq 'BLACKLIST' ) {
	fatal_error "The BLACKLIST section has been eliminated. Please move your BLACKLIST rules to the 'blrules' file";
    } elsif ( $sect eq 'ESTABLISHED' ) {
	$sections{ALL} = 1;
    } elsif ( $sect eq 'RELATED' ) {
	@sections{'ALL','ESTABLISHED'} = ( 1, 1);
	finish_section 'ESTABLISHED';
    } elsif ( $sect eq 'INVALID' ) {
	@sections{'ALL','ESTABLISHED','RELATED'} = ( 1, 1, 1 );
	finish_section ( 'ESTABLISHED,RELATED' );
    } elsif ( $sect eq 'UNTRACKED' ) {
	@sections{'ALL','ESTABLISHED','RELATED', 'INVALID' } = ( 1, 1, 1, 1 );
	finish_section ( 'ESTABLISHED,RELATED,INVALID' );
    } elsif ( $sect eq 'NEW' ) {
	@sections{'ALL','ESTABLISHED','RELATED','INVALID','UNTRACKED', 'NEW'} = ( 1, 1, 1, 1, 1, 1 );
	finish_section ( 'ESTABLISHED,RELATED,INVALID,UNTRACKED' );
    }

    $section = $section_map{$sect};
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
sub process_raw_rule ( ) {
    my ( $target, $source, $dest, $protos, $ports, $sports, $origdest, $ratelimit, $users, $mark, $connlimit, $time, $headers, $condition, $helper )
	= split_line1 'rules file', \%rulecolumns, $rule_commands;

    fatal_error 'ACTION must be specified' if $target eq '-';

    section_warning, process_section( $source ), return 1 if $target eq 'SECTION';
    #
    # Section Names are optional so once we get to an actual rule, we need to be sure that
    # we close off any missing sections.
    #
    process_section( 'NEW' ) unless $section;

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
	fatal_error "Inversion not allowed in a PROTO list" if $protos =~ tr/!/!/;
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

sub intrazone_allowed( $$ ) {
    my ( $zone, $zoneref ) = @_;

    $zoneref->{complex} && $filter_table->{rules_chain( $zone, $zone )}{policy} ne 'NONE';
}

#
# Add jumps to the blacklst and blackout chains
#
sub classic_blacklist() {
    my $fw       = firewall_zone;
    my @zones    = off_firewall_zones;
    my @vservers = vserver_zones;
    my @state = $config{BLACKLISTNEWONLY} ? have_capability( 'RAW_TABLE' ) ? state_imatch 'NEW,INVALID,UNTRACKED' : state_imatch 'NEW,INVALID' : ();
    my $result;

    for my $zone ( @zones ) {
	my $zoneref = find_zone( $zone );
	my $simple  =  @zones <= 2 && ! $zoneref->{complex};

	if ( my $blackref = $filter_table->{blacklst} ) {
	    if ( $zoneref->{options}{in}{blacklist} ) {
		add_ijump ensure_rules_chain( rules_chain( $zone, $_ ) ) , j => $blackref , @state for firewall_zone, @vservers;

		if ( $simple ) {
		    #
		    # We won't create a zone forwarding chain for this zone so we must add blacklisting jumps to the rules chains
		    #
		    for my $zone1 ( @zones ) {
			my $ruleschain    = rules_chain( $zone, $zone1 );
			my $ruleschainref = $filter_table->{$ruleschain};

			if ( $zone ne $zone1 || intrazone_allowed( $zone, $zoneref ) ) {
			    add_ijump( ensure_rules_chain( $ruleschain ), j => $blackref, @state );
			}
		    }
		}

		$result = 1;
	    }

	    if ( $zoneref->{options}{out}{blacklist} ) {
		$blackref = $filter_table->{blackout};
		add_ijump ensure_rules_chain( rules_chain( firewall_zone, $zone ) ) , j => $blackref , @state;

		for my $zone1 ( @zones, @vservers ) {
		    my $ruleschain    = rules_chain( $zone1, $zone );
		    my $ruleschainref = $filter_table->{$ruleschain};

		    if ( ( $zone ne $zone1 || intrazone_allowed( $zone, $zoneref ) ) ) {
			add_ijump( ensure_rules_chain( $ruleschain ), j => $blackref, @state );
		    }
		}

		$result = 1;
	    }
	}

	unless ( $simple ) {
	    #
	    # Complex zone or we have more than one non-firewall zone -- create a zone forwarding chain
	    #
	    my $frwd_ref = new_standard_chain zone_forward_chain( $zone );

	    add_ijump( $frwd_ref , j => $filter_table->{blacklst}, @state ) if $filter_table->{blacklst} && $zoneref->{options}{in}{blacklist};
	}
    }

    $result;
}

#
# Process the BLRules and Rules Files
#
sub process_rules( $ ) {
    my $convert = shift;
    my $blrules = 0;
    #
    # Populate the state table
    #
    %statetable          = ( ESTABLISHED => [ '^', '',                           'ACCEPT'                 ] ,
			     RELATED     => [ '+', $config{RELATED_LOG_LEVEL},   $globals{RELATED_TARGET} ] ,
			     INVALID     => [ '_', $config{INVALID_LOG_LEVEL},   $globals{INVALID_TARGET} ] ,
			     UNTRACKED   => [ '&', $config{UNTRACKED_LOG_LEVEL}, $globals{UNTRACKED_TARGET} ] ,
			   );
    %section_states = ( BLACKLIST_SECTION ,  $globals{BLACKLIST_STATES},
			ESTABLISHED_SECTION, 'ESTABLISHED',
			RELATED_SECTION,     'RELATED',
			INVALID_SECTION,     'INVALID',
			UNTRACKED_SECTION,   'UNTRACKED' );
    #
    # Generate jumps to the classic blacklist chains
    #
    $blrules = classic_blacklist unless $convert;
    #
    # Process the blrules file
    #
    $section = BLACKLIST_SECTION;

    my $fn = open_file( 'blrules', 1, 1 );

    if ( $fn ) {
	first_entry( sub () {
			 my ( $level, $disposition ) = @config{'BLACKLIST_LOG_LEVEL', 'BLACKLIST_DISPOSITION' };
			 my  $audit       = $disposition =~ /^A_/;
			 my  $target      = $disposition eq 'REJECT' ? 'reject' : $disposition;

			 progress_message2 "$doing $currentfilename...";

			 if ( supplied $level ) {
			     ensure_blacklog_chain( $target, $disposition, $level, $audit );
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

    $section = NULL_SECTION;

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
    $section = DEFAULTACTION_SECTION;
}

1;
