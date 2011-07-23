#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Chains.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010,2011 - Tom Eastep (teastep@shorewall.net)
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
#  This is the low-level iptables module. It provides the basic services
#  of chain and rule creation. It is used by the higher level modules such
#  as Rules to create iptables-restore input.
#
package Shorewall::Chains;
require Exporter;

use Scalar::Util 'reftype';
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;
use Shorewall::IPAddrs;
use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		    add_rule
		    add_irule
		    add_jump
		    add_ijump
		    insert_rule
		    insert_irule
		    insert_ijump
		    rule_target
		    clear_rule_target
		    set_rule_target
		    set_rule_option
		    add_trule
		    add_commands
		    incr_cmd_level
		    decr_cmd_level
		    new_chain
		    new_manual_chain
		    ensure_manual_chain
		    ensure_audit_chain
		    require_audit
		    log_rule_limit
		    dont_optimize
		    dont_delete
		    dont_move
		    get_action_logging

		    %chain_table
		    $raw_table
		    $nat_table
		    $mangle_table
		    $filter_table
	       );

our %EXPORT_TAGS = (
		    internal => [  qw( STANDARD
				       NATRULE
				       BUILTIN
				       NONAT
				       NATONLY
				       REDIRECT
				       ACTION
				       MACRO
				       LOGRULE
				       NFQ
				       CHAIN
				       SET
				       AUDIT
				       NO_RESTRICT
				       PREROUTE_RESTRICT
				       DESTIFACE_DISALLOW
				       INPUT_RESTRICT
				       OUTPUT_RESTRICT
				       POSTROUTE_RESTRICT
				       ALL_RESTRICT
				       ALL_COMMANDS
				       NOT_RESTORE

				       state_imatch
				       initialize_chain_table
				       copy_rules
				       move_rules
				       insert_rule1
				       delete_jumps
				       add_tunnel_rule
				       process_comment
				       no_comment
				       macro_comment
				       clear_comment
				       push_comment
				       pop_comment
				       forward_chain
				       rules_chain
				       zone_forward_chain
				       use_forward_chain
				       input_chain
				       zone_input_chain
				       use_input_chain
				       output_chain
				       zone_output_chain
				       use_output_chain
				       masq_chain
				       syn_flood_chain
				       mac_chain
				       macrecent_target
				       dnat_chain
				       snat_chain
				       ecn_chain
				       notrack_chain
				       first_chains
				       reserved_name
				       find_chain
				       ensure_chain
				       ensure_accounting_chain
				       accounting_chainrefs
				       ensure_mangle_chain
				       ensure_nat_chain
				       ensure_raw_chain
				       new_standard_chain
				       new_builtin_chain
				       new_nat_chain
				       ensure_filter_chain
				       optimize_chain
				       check_optimization
				       optimize_ruleset
				       setup_zone_mss
				       newexclusionchain
				       newnonatchain
				       source_exclusion
				       dest_exclusion
				       clearrule
				       port_count
				       do_proto
				       do_mac
				       do_imac
				       verify_mark
				       verify_small_mark
				       validate_mark
				       do_test
				       do_ratelimit
				       do_connlimit
				       do_time
				       do_user
				       do_length
				       do_tos
				       do_connbytes
				       do_helper
				       do_headers
				       have_ipset_rules
				       record_runtime_address
				       conditional_rule
				       conditional_rule_end
				       match_source_dev
				       imatch_source_dev
				       match_dest_dev
				       imatch_dest_dev
				       iprange_match
				       match_source_net
				       imatch_source_net
				       match_dest_net
				       imatch_dest_net
				       match_orig_dest
				       match_ipsec_in
				       match_ipsec_out
				       do_ipsec_options
				       do_ipsec
				       log_rule
				       expand_rule
				       promote_blacklist_rules
				       addnatjump
				       set_chain_variables
				       mark_firewall_not_started
				       mark_firewall6_not_started
				       get_interface_address
				       get_interface_addresses
				       get_interface_bcasts
				       get_interface_acasts
				       get_interface_gateway
				       get_interface_mac
				       have_global_variables
				       set_global_variables
				       save_dynamic_chains
				       load_ipsets
				       create_netfilter_load
				       preview_netfilter_load
				       create_chainlist_reload
				       create_stop_load
				       %targets
				     ) ],
		   );

Exporter::export_ok_tags('internal');

our $VERSION = 'MODULEVERSION';

#
# Chain Table
#
#    %chain_table { <table> => { <chain1>  => { name         => <chain name>
#                                               table        => <table name>
#                                               is_policy    => undef|1 -- if 1, this is a policy chain
#                                               provisional  => undef|1 -- See below.
#                                               referenced   => undef|1 -- If 1, will be written to the iptables-restore-input.
#                                               builtin      => undef|1 -- If 1, one of Netfilter's built-in chains.
#                                               manual       => undef|1 -- If 1, a manual chain.
#                                               accounting   => undef|1 -- If 1, an accounting chain
#                                               dont_optimize=> undef|1 -- Don't optimize away if this chain is 'short'
#                                               dont_delete  => undef|1 -- Don't delete if this chain is not referenced
#                                               dont_move    => undef|1 -- Don't copy the rules of this chain somewhere else
#                                               log          => <logging rule number for use when LOGRULENUMBERS>
#                                               policy       => <policy>
#                                               policychain  => <name of policy chain> -- self-reference if this is a policy chain
#                                               policypair   => [ <policy source>, <policy dest> ] -- Used for reporting duplicated policies
#                                               loglevel     => <level>
#                                               synparams    => <burst/limit + connlimit>
#                                               synchain     => <name of synparam chain>
#                                               default      => <default action>
#                                               cmdlevel     => <number of open loops or blocks in runtime commands>
#                                               new          => undef|<index into @$rules where NEW section starts>
#                                               rules        => [ <rule1>
#                                                                 <rule2>
#                                                                 ...
#                                                               ]
#                                               logchains    => { <key1> = <chainref1>, ... }
#                                               references   => { <ref1> => <refs>, <ref2> => <refs>, ... }
#                                               blacklist    => <number of blacklist rules at the head of the rules array> ( 0 or 1 )
#                                               action       => <action tuple that generated this chain>
#                                               restricted   => Logical OR of restrictions of rules in this chain.
#                                               restriction  => Restrictions on further rules in this chain.
#                                               audit        => Audit the result.
#                                               filtered     => Number of filter rules at the front of an interface forward chain
#                                             } ,
#                                <chain2> => ...
#                              }
#                 }
#
#       'provisional' only applies to policy chains; when true, indicates that this is a provisional policy chain which might be
#       replaced. Policy chains created under the IMPLICIT_CONTINUE=Yes option are marked with provisional == 1 as are intra-zone
#       ACCEPT policies.
#
#       Only 'referenced' chains get written to the iptables-restore input.
#
#       'loglevel', 'synparams', 'synchain', 'audit' and 'default' only apply to policy chains.
#
our %chain_table;
our $raw_table;
our $nat_table;
our $mangle_table;
our $filter_table;
my  $comment;
my  @comments;
my  $export;

#
# Target Types
#
use constant { STANDARD => 1,              #defined by Netfilter
	       NATRULE  => 2,              #Involves NAT
	       BUILTIN  => 4,              #A built-in action
	       NONAT    => 8,              #'NONAT' or 'ACCEPT+'
	       NATONLY  => 16,             #'DNAT-' or 'REDIRECT-'
	       REDIRECT => 32,             #'REDIRECT'
	       ACTION   => 64,             #An action (may be built-in)
	       MACRO    => 128,            #A Macro
	       LOGRULE  => 256,            #'LOG','NFLOG'
	       NFQ      => 512,            #'NFQUEUE'
	       CHAIN    => 1024,           #Manual Chain
	       SET      => 2048,           #SET
	       AUDIT    => 4096,           #A_ACCEPT, etc
	   };
#
# Valid Targets -- value is a combination of one or more of the above
#
our %targets;

#
# expand_rule() restrictions
#
use constant { NO_RESTRICT         => 0,   # FORWARD chain rule     - Both -i and -o may be used in the rule
	       PREROUTE_RESTRICT   => 1,   # PREROUTING chain rule  - -o converted to -d <address list> using main routing table
	       INPUT_RESTRICT      => 4,   # INPUT chain rule       - -o not allowed
	       OUTPUT_RESTRICT     => 8,   # OUTPUT chain rule      - -i not allowed
	       POSTROUTE_RESTRICT  => 16,  # POSTROUTING chain rule - -i converted to -s <address list> using main routing table
	       ALL_RESTRICT        => 12,  # fw->fw rule            - neither -i nor -o allowed
	       DESTIFACE_DISALLOW  => 32,  # Don't allow dest interface. Similar to INPUT_RESTRICT but generates a more relevant error message
	       };
#
# See initialize() below for additional comments on these variables
#
my $iprangematch;
my %chainseq;
my $idiotcount;
my $idiotcount1;
my $warningcount;
my $hashlimitset;
my $global_variables;
my $ipset_rules;

#
# Determines the commands for which a particular interface-oriented shell variable needs to be set
#
use constant { ALL_COMMANDS => 1, NOT_RESTORE => 2 };

#
# These hashes hold the shell code to set shell variables. The key is the name of the variable; the value is the code to generate the variable's contents
#
my %interfaceaddr;         # First interface address
my %interfaceaddrs;        # All interface addresses
my %interfacenets;         # Networks routed out of the interface
my %interfacemacs;         # Interface MAC
my %interfacebcasts;       # Broadcast addresses associated with the interface (IPv4)
my %interfaceacasts;       # Anycast addresses associated with the interface (IPv6)
my %interfacegateways;     # Gateway of default route out of the interface

#
# Built-in Chains
#
my @builtins = qw(PREROUTING INPUT FORWARD OUTPUT POSTROUTING);

#
# Mode of the emitter (part of this module that converts rules in the chain table into iptables-restore input)
#
use constant { NULL_MODE => 0 ,   # Emitting neither shell commands nor iptables-restore input
	       CAT_MODE  => 1 ,   # Emitting iptables-restore input
	       CMD_MODE  => 2 };  # Emitting shell commands.

my $mode;
#
# Address Family
#
our $family;

#
# These are the current builtin targets
#
my  %builtin_target = ( ACCEPT      => 1,
			ACCOUNT     => 1,
			AUDIT       => 1,
			CHAOS       => 1,
			CHECKSUM    => 1,
			CLASSIFY    => 1,
		        CLUSTERIP   => 1,
			CONNMARK    => 1,
			CONNSECMARK => 1,
			COUNT       => 1,
			CT          => 1,
			DELUDE      => 1,
			DHCPMAC     => 1,
			DNAT        => 1,
			DNETMAP     => 1,
			DROP        => 1,
			DSCP        => 1,
			ECHO        => 1,
			ECN         => 1,
			HL          => 1,
			IDLETIMER   => 1,
			IPMARK      => 1,
			LOG         => 1,
			LOGMARK     => 1,
			MARK        => 1,
			MASQUERADE  => 1,
			MIRROR      => 1,
			NETMAP      => 1,
			NFLOG       => 1,
			NFQUEUE     => 1,
			NOTRACK     => 1,
			QUEUE       => 1,
			RATEEST     => 1,
			RAWDNAT     => 1,
			RAWSNAT     => 1,
			REDIRECT    => 1,
			REJECT      => 1,
			RETURN      => 1,
			SAME        => 1,
			SECMARK     => 1,
			SET         => 1,
			SNAT        => 1,
			STEAL       => 1,
			SYSRQ       => 1,
			TARPIT      => 1,
			TCPMSS      => 1,
			TCPOPTSTRIP => 1,
			TEE         => 1,
			TOS         => 1,
			TPROXY      => 1,
			TRACE       => 1,
			TTL         => 1,
			ULOG        => 1,
		        );

my %ipset_exists;

#
# Rules are stored in an internal form
#
#     {   mode       => CAT_MODE if rule is not part of a conditional block or loop
#                    => CMD_MODE if the rule contains a shell command or if it
#                                part of a loop or conditional block. If it is a
#                                shell command, the text of the command is in
#                                the cmd
#         cmd        => Shell command, if mode == CMD_MODE and cmdlevel == 0
#         cmdlevel   => nesting level within loops and conditional blocks. 
#                       determines indentation
#         simple     => true|false. If true, there are no matches or options
#         jump       => 'j', 'g' or '' (determines whether '-j' or '-g' is included
#         target     => Rule target, if jump is 'j' or 'g'.
#         targetopts => Target options. Only included if non-empty
#         rule       => String representation of rule for comparison
#         <option>   => iptables/ip6tables -A options (e.g., i => eth0)
#         <match>    => iptables match. Value may be a scalar or array.
#                       if an array, multiple "-m <match>"s will be generated
#    } 
#
# The following constants and hash are used to classify keys in a rule hash
#
use constant { UNIQUE      => 1,
	       TARGET      => 2,
	       EXCLUSIVE   => 4,
	       MATCH       => 8,
	       CONTROL     => 16 };

my %opttype = ( rule       => CONTROL,
		cmd        => CONTROL,

		dhcp       => UNIQUE,
		
	        mode       => CONTROL,
		cmdlevel   => CONTROL,
		simple     => CONTROL,

	        i          => UNIQUE,
		s          => UNIQUE,
		o          => UNIQUE,
		d          => UNIQUE,
		p          => UNIQUE,
		dport      => UNIQUE,
		sport      => UNIQUE,
		
		comment    => CONTROL,

		policy     => MATCH,
		state      => EXCLUSIVE,
		
		jump       => TARGET,
		target     => TARGET,
		targetopts => TARGET,
	      );

my %aliases = ( protocol        => 'p',
		source          => 's',
		destination     => 'd',
		jump            => 'j',
		goto            => 'g',
		'in-interface'  => 'i',
		'out-interface' => 'o',
		dport           => 'dport',
		sport           => 'sport',
	      );

my @unique_options = ( qw/p dport sport s d i o/ );
	     
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
sub initialize( $$$ ) {
    ( $family, my $hard, $export ) = @_;

    %chain_table = ( raw    => {},
		     mangle => {},
		     nat    => {},
		     filter => {} );

    $raw_table    = $chain_table{raw};
    $nat_table    = $chain_table{nat};
    $mangle_table = $chain_table{mangle};
    $filter_table = $chain_table{filter};
    #
    # Contents of last COMMENT line.
    #
    $comment  = '';
    @comments = ();
    #
    # Used to sequence chain names in each table.
    #
    %chainseq = () if $hard;
    #
    # Used to suppress duplicate match specifications for old iptables binaries.
    #
    $iprangematch = 0;
    #
    # Keep track of which interfaces have active 'address', 'addresses', 'networks', etc. variables
    #
    %interfaceaddr      = ();
    %interfaceaddrs     = ();
    %interfacenets      = ();
    %interfacemacs      = ();
    %interfacebcasts    = ();
    %interfaceacasts    = ();
    %interfacegateways  = ();

    $global_variables   = 0;
    $idiotcount         = 0;
    $idiotcount1        = 0;
    $warningcount       = 0;
    $hashlimitset       = 0;
    $ipset_rules        = 0 if $hard;

    %ipset_exists       = ();
    #
    # The chain table is initialized via a call to initialize_chain_table() after the configuration and capabilities have been determined.
    #
}

#
# Process a COMMENT line (in $currentline)
#
sub process_comment() {
    if ( have_capability( 'COMMENTS' ) ) {
	( $comment = $currentline ) =~ s/^\s*COMMENT\s*//;
	$comment =~ s/\s*$//;
    } else {
	warning_message "COMMENTs ignored -- require comment support in iptables/Netfilter" unless $warningcount++;
    }
}

#
# Returns True if there is a current COMMENT or if COMMENTS are not available.
#
sub no_comment() {
    $comment ? 1 : ! have_capability( 'COMMENTS' );
}

#
# Clear the $comment variable and the comment stack
#
sub clear_comment() {
    $comment  = '';
    @comments = ();
}

#
# Push and Pop comment stack
#
sub push_comment( $ ) {
    push @comments, $comment;
    $comment = shift;
}

sub pop_comment() {
    $comment = pop @comments;
}

#
# Set comment
#
sub set_comment( $ ) {
    $comment = shift;
}

#
# Set $comment to the passed unless there is a current comment
#
sub macro_comment( $ ) {
    my $macro = $_[0];

    $comment = $macro unless $comment || ! ( have_capability( 'COMMENTS' ) && $config{AUTO_COMMENT} );
}

#
# Functions to manipulate cmdlevel
#
sub incr_cmd_level( $ ) {
    $_[0]->{cmdlevel}++;
}

sub decr_cmd_level( $ ) {
    assert( --$_[0]->{cmdlevel} >= 0);
}

#
# Transform the passed iptables rule into an internal-form hash reference. 
# Most of the compiler has been converted to use the new form natively. 
# A few parts, mostly those dealing with expand_rule(), still generate 
# iptables command strings which are converted into the new form by
# transform_rule()
#
# First a helper for setting an individual option
#
sub set_rule_option( $$$ ) {
    my ( $ruleref, $option, $value ) = @_;

    assert( defined $value && reftype $ruleref );

    $ruleref->{simple} = 0;
    
    my $opttype = $opttype{$option} || MATCH;

    if ( exists $ruleref->{$option} ) {
	assert( defined $ruleref->{$option} );

	if ( $opttype == MATCH ) {
	    assert( $globals{KLUDGEFREE} );
	    $ruleref->{$option} = [ $ruleref->{$option} ] unless reftype $ruleref->{$option};
	    push @{$ruleref->{$option}}, ( reftype $value ? @$value : $value );
	} elsif ( $opttype == EXCLUSIVE ) {
	    $ruleref->{$option} .= ",$value";
	} elsif ( $opttype == UNIQUE ) {
	    fatal_error "Multiple $option settings in one rule is prohibited";
	} else {
	    assert(0);
	}
    } else {
	$ruleref->{$option} = $value;
    }
}

sub transform_rule( $ ) {
    my $input    = shift;
    my $ruleref  = { mode => CAT_MODE, target => '' };
    my $simple   = 1;

    $input =~ s/^\s*//;

    while ( $input ) {
	my $option;
	my $invert = '';
	
	if ( $input =~ s/^(!\s+)?-([psdjgiom])\s+// ) {
	    #
	    # Normal case of single-character
	    $invert = '!' if $1;
	    $option = $2;
	} elsif ( $input =~ s/^(!\s+)?--([^\s]+)\s*// ) {
	    $invert = '!' if $1;
	    my $opt = $option = $2;

	    fatal_error "Unrecognized iptables option ($opt}" unless $option = $aliases{$option};	    
	} else {
	    fatal_error "Unrecognized iptables option string ($input)";
	}

	if ( $option eq 'j' or $option eq 'g' ) {
	    $ruleref->{jump} = $option;
	    $input =~ s/([^\s]+)\s*//;
	    $ruleref->{target} = $1;
	    $option = 'targetopts';
	} else {
	    $simple = 0;
	    if ( $option eq 'm' ) {
		$input =~ s/(\w+)\s*//;
		$option = $1;
	    }
	}

	my $params = $invert;

      PARAM:
	{
	    while ( $input ne '' && $input !~ /^(?:!|-[psdjgiom])\s/ ) {
		last PARAM if $input =~ /^--([^\s]+)/ && $aliases{$1 || '' };
		$input =~ s/^([^\s]+)\s*//;
		my $token = $1;
		$params = $params eq '' ? $token : join( ' ' , $params, $token);	
	    }

	    if ( $input =~ /^(?:!\s+--([^\s]+)|!\s+[^-])/ ) {
		last PARAM if $aliases{$1 || ''};
		$params = $params eq '' ? '!' : join( ' ' , $params, '!' );
		$input =~ s/^!\s+//;
		redo PARAM;
	    }
	}

	set_rule_option( $ruleref, $option, $params ) unless $params eq '';
    }

    $ruleref->{simple} = $simple;

    $ruleref;
}

#
#  A couple of small functions for other modules to use to manipulate rules
#
sub rule_target( $ ) {
    shift->{target};
}

sub clear_rule_target( $ ) {
    my $ruleref = shift;

    assert( reftype $ruleref );

    delete $ruleref->{jump};
    delete $ruleref->{targetopts};
    $ruleref->{target} = '';

    1;
}

sub set_rule_target( $$$ ) {
    my ( $ruleref, $target, $opts) = @_;

    assert( reftype $ruleref );

    $ruleref->{jump}     = 'j';
    $ruleref->{target}   = $target;
    $ruleref->{targetopts} = $opts if defined $opts;

    1
}

#
# Convert an trule into iptables input
#
# First, a helper function that formats a single option
#
sub format_option( $$ ) {
    my ( $option, $value ) = @_;

    my $list = reftype $value ? $value : [ $value ];

    my $rule = '';

    s/\s*$//, $rule .= join( ' ' , ' -m', $option, $_ ) for @$list;

    $rule;
}
	
sub format_rule( $$;$ ) {
    my ( $chainref, $ruleref, $suppresshdr ) = @_;

    return $ruleref->{cmd} if exists $ruleref->{cmd};

    my $rule = $suppresshdr ? '' : "-A $chainref->{name}";
    
    for ( @unique_options ) {
	if ( exists $ruleref->{$_} ) {
	    my $value = $ruleref->{$_};

	    $rule .= ' !' if $value =~ s/^! //;
	    
	    if ( length == 1 ) {
		$rule .= join( '' , ' -', $_, ' ', $value );
	    } else {
		$rule .= join( '' , ' --', $_, ' ', $value );
	    }
	}
    }

    $rule .= format_option( 'state',   $ruleref->{state} )   if defined $ruleref->{state};  
    $rule .= format_option( 'policy',  $ruleref->{policy} )  if defined $ruleref->{policy};  

    $rule .= format_option( $_, $ruleref->{$_} ) for sort ( grep ! $opttype{$_}, keys %{$ruleref} );

    if ( $ruleref->{target} ) {
	$rule .= join( ' ', " -$ruleref->{jump}", $ruleref->{target} );
	$rule .= join( '', ' ', $ruleref->{targetopts} ) if $ruleref->{targetopts};
    }

    $rule .= join( '', ' -m comment --comment "', $ruleref->{comment}, '"' ) if $ruleref->{comment};

    $rule;
}

#
# Merge two rules.
#
sub merge_rules( $$$ ) {
    my ( $tableref, $toref, $fromref ) = @_;

    my $target = $fromref->{target};
    #
    # Since the 'to' rule is a jump to a chain containing the 'from' rule, we
    # assume that common unique option values are compatible (such as 'tcp' and
    # 'tcp ! syn').
    #
    for my $option ( @unique_options ) {
	$toref->{$option} = $fromref->{$option} if exists $fromref->{$option};
    }
		    
    for my $option ( grep ! $opttype{$_}, keys %$fromref ) {
	set_rule_option( $toref, $option, $fromref->{$option} );
    }

    unless ( $toref->{state} ) {
	set_rule_option ( $toref, 'state',   $fromref->{state} ) if $fromref->{state};
    }

    set_rule_option( $toref, 'policy', $fromref->{policy} ) if exists $fromref->{policy};

    $toref->{target}     = $target;
    $toref->{targetopts} = $fromref->{targetopts} if $fromref->{targetopts};
    $toref->{jump}       = 'j' unless $tableref->{$target};

    unless ( $toref->{comment} ) {
	$toref->{comment} = $fromref->{comment} if exists $fromref->{comment};
    }
}

#
# Trace a change to the chain table
#
 
sub trace( $$$$ ) {
    my ($chainref, $action, $rulenum, $message) = @_;

    my $heading = $rulenum ? 
	sprintf "                NF-(%s)-> %s:%s:%d", $action, $chainref->{table}, $chainref->{name}, $rulenum : 
	sprintf "                NF-(%s)-> %s:%s", $action, $chainref->{table}, $chainref->{name};

    my $length = length $heading;

    $message = format_rule( $chainref, $message ) if reftype $message;

    if ( $length < 48 ) {
	print $heading . ' ' x ( 48 - $length) . "$message\n";
    } else {
	print $heading . ' ' x 8 * ( ( $length + 8 ) / 8 ) . "$message\n";
    }
}

#
# Add run-time commands to a chain. Arguments are:
#
#    Chain reference , Command, ...
#
sub add_commands ( $$;@ ) {
    my $chainref    = shift @_;

    if ( $debug ) {
	my $rulenum = @{$chainref->{rules}};
	trace( $chainref, 'T', ++$rulenum, "$_\n" ) for @_;
    }

    push @{$chainref->{rules}}, { mode     => CMD_MODE,
				  cmd      => $_ ,
				  cmdlevel => $chainref->{cmdlevel} ,
				  target   => '', # Insure that all rules have a target
				} for @_;

    $chainref->{referenced} = 1;
}

#
# Transform the passed rule and add it to the end of the passed chain's rule list
#
sub push_rule( $$ ) {
    my $chainref = $_[0];
    my $ruleref  = transform_rule( $_[1] );

    $ruleref->{comment}  = "$comment" if $comment;
    $ruleref->{mode}     = CMD_MODE   if $ruleref->{cmdlevel} = $chainref->{cmdlevel};

    push @{$chainref->{rules}}, $ruleref;
    $chainref->{referenced} = 1;
    trace( $chainref, 'A', @{$chainref->{rules}}, "-A $chainref->{name} $_[1]" ) if $debug;

    $ruleref;
}

#
# Add a Transformed rule
#
sub add_trule( $$ ) {
    my ( $chainref, $ruleref ) = @_;

    assert( reftype $ruleref );
    push @{$chainref->{rules}}, $ruleref;
    $chainref->{referenced} = 1;

    trace( $chainref, 'A', @{$chainref->{rules}}, format_rule( $chainref, $ruleref ) ) if $debug;

    $ruleref;
}

#
# Post-process a rule having a port list. Split the rule into multiple rules if necessary
# to work within the 15-element limit imposed by iptables/Netfilter.
#
# The third argument ($dport) indicates what type of list we are spltting:
#
#      $dport == 1     Destination port list
#      $dport == 0     Source port list
#
# When expanding a Destination port list, each resulting rule is checked for the presence
# of a Source port list; if one is present, the function calls itself recursively with
# $dport == 0.
#
# The function calls itself recursively so we need a prototype.
#
sub handle_port_list( $$$$$$ );

sub handle_port_list( $$$$$$ ) {
    my ($chainref, $rule, $dport, $first, $ports, $rest) = @_;

    our $splitcount;

    if ( port_count( $ports ) > 15 ) {
	#
	# More than 15 ports specified
	#
	my @ports = split '([,:])', $ports;

	while ( @ports ) {
	    my $count = 0;
	    my $newports = '';

	    while ( @ports && $count < 15 ) {
		my ($port, $separator) = ( shift @ports, shift @ports );

		$separator ||= '';

		if ( ++$count == 15 ) {
		    if ( $separator eq ':' ) {
			unshift @ports, $port, ':';
			chop $newports;
			last;
		    } else {
			$newports .= $port;
		    }
		} else {
		    $newports .= "${port}${separator}";
		}
	    }

	    my $newrule = join( '', $first, $newports, $rest );

	    if ( $dport && $newrule =~  /^(.* --sports\s+)([^ ]+)(.*)$/ ) {
		handle_port_list( $chainref, $newrule, 0, $1, $2, $3 );
	    } else {
		push_rule ( $chainref, $newrule );
		$splitcount++;
	    }
	}
    } elsif ( $dport && $rule =~  /^(.* --sports\s+)([^ ]+)(.*)$/ ) {
	handle_port_list( $chainref, $rule, 0, $1, $2, $3 );
    } else {
	push_rule ( $chainref, $rule );
	$splitcount++;
    }
}

#
# This much simpler function splits a rule with an icmp type list into discrete rules
#
sub handle_icmptype_list( $$$$ ) {
    my ($chainref, $first, $types, $rest) = @_;
    my @ports = split ',', $types;
    our $splitcount;
    push_rule ( $chainref, join ( '', $first, shift @ports, $rest ) ), $splitcount++ while @ports;
}

#
# Add a rule to a chain. Arguments are:
#
#    Chain reference , Rule [, Expand-long-port-lists ]
#
#    Returns a reference to the generated internal-form rule
#
sub add_rule($$;$) {
    my ($chainref, $rule, $expandports) = @_;

    our $splitcount;

    assert( ! reftype $rule );

    $iprangematch = 0;
    #
    # Pre-processing the port lists as was done in Shorewall-shell results in port-list
    # processing driving the rest of rule generation.
    #
    # By post-processing each rule generated by expand_rule(), we avoid all of that
    # messiness and replace it with the following localized messiness.

    if ( $expandports ) {
	if ( $rule =~  /^(.* --dports\s+)([^ ]+)(.*)$/ ) {
	    #
	    # Rule has a --dports specification
	    #
	    handle_port_list( $chainref, $rule, 1, $1, $2, $3 )
	} elsif ( $rule =~  /^(.* --sports\s+)([^ ]+)(.*)$/ ) {
	    #
	    # Rule has a --sports specification
	    #
	    handle_port_list( $chainref, $rule, 0, $1, $2, $3 )
	} elsif ( $rule =~ /^(.* --icmp(?:v6)?-type\s*)([^ ]+)(.*)$/ ) {
	    #
	    # ICMP rule -- split it up if necessary
	    #
	    my ( $first, $types, $rest ) = ($1, $2, $3 );

	    if ( $types =~ /,/ ) {
		handle_icmptype_list( $chainref, $first, $types, $rest );
	    } else {
		push_rule( $chainref, $rule );
		$splitcount++;
	    }
	} else {
	    push_rule ( $chainref, $rule );
	    $splitcount++;
	}
    } else {
	push_rule( $chainref, $rule );
    }
}

#
# New add_rule implementation
#
sub push_matches {
    
    my $ruleref = shift;
    my $dont_optimize = 0;

    while ( @_ ) {
	my ( $option, $value ) = ( shift , shift );

	assert( defined $value );

	if ( exists $ruleref->{$option} ) {
	    my $curvalue = $ruleref->{$option};
	    $ruleref->{$option} = [ $curvalue ] unless reftype $curvalue;
	    push @{$ruleref->{$option}}, reftype $value ? @$value : $value;
	} else {
	    $ruleref->{$option} = $value;
	    $dont_optimize ||= $option =~ /^[piosd]$/ && $value =~ /^!/;
	}
    }

    $dont_optimize;
}

sub push_irule( $$$;@ ) {
    my ( $chainref, $jump, $target, @matches ) = @_;

    ( $target, my $targetopts ) = split ' ', $target, 2;

    my $ruleref       = {};
    
    $ruleref->{mode} = ( $ruleref->{cmdlevel} = $chainref->{cmdlevel} ) ? CMD_MODE : CAT_MODE;
 
    if ( $jump ) {
	$ruleref->{jump}       = $jump;
	$ruleref->{target}     = $target;
	$ruleref->{targetopts} = $targetopts if $targetopts;
    }

    if ( $comment ) {
	$ruleref->{comment} = $comment unless $ruleref->{comment};
    }

    $iprangematch = 0;

    $chainref->{referenced} = 1;

    unless ( $ruleref->{simple} = ! @matches ) {
	$chainref->{dont_optimize} = 1 if push_matches( $ruleref, @matches );
    }

    push @{$chainref->{rules}}, $ruleref;

    trace( $chainref, 'A', @{$chainref->{rules}}, format_rule( $chainref, $ruleref ) ) if $debug;

    $ruleref;
}

sub add_irule( $;@ ) {
    my ( $chainref, @matches ) = @_;

    push_irule( $chainref, '' => '', @matches );

}

#
# Make the first chain a referent of the second
#
sub add_reference ( $$ ) {
    my ( $fromref, $to ) = @_;

    my $toref = reftype $to ? $to : $chain_table{$fromref->{table}}{$to};

    assert($toref);

    $toref->{references}{$fromref->{name}}++;
}

#
# Delete a previously added reference
#
sub delete_reference( $$ ) {
    my ( $fromref, $to ) = @_;

    my $toref = reftype $to ? $to : $chain_table{$fromref->{table}}{$to};

    assert( $toref );

    delete $toref->{references}{$fromref->{name}} unless --$toref->{references}{$fromref->{name}} > 0;
}

#
# Insert a rule into a chain. Arguments are:
#
#    Chain reference , Rule Number, Rule
#
# In the first function, the rule number is zero-relative. In the second function,
# the rule number is one-relative. In the first function, if the rule number is < 0, then
# the rule is a jump to a blacklist chain (blacklst or blackout). The rule will be
# inserted at the front of the chain and the chain's 'blacklist' member incremented.
#
sub insert_rule1($$$)
{
    my ($chainref, $number, $rule) = @_;

    my $ruleref = transform_rule( $rule );

    $ruleref->{comment}  = "$comment" if $comment;
    assert( ! ( $ruleref->{cmdlevel} = $chainref->{cmdlevel}) );
    $ruleref->{mode} = CAT_MODE;

    if ( $number < 0 ) {
	$chainref->{blacklist}++;
	$number = 0;
    }

    splice( @{$chainref->{rules}}, $number, 0, $ruleref );

    trace( $chainref, 'I', ++$number, $ruleref ) if $debug;

    $iprangematch = 0;

    $chainref->{referenced} = 1;

    $ruleref;
}

sub insert_rule($$$) {
    my ($chainref, $number, $rule) = @_;

    insert_rule1( $chainref, $number - 1, $rule );
}

sub insert_irule( $$$$;@ ) {
    my ( $chainref, $jump, $target, $number, @matches ) = @_;

    my $ruleref = {};
   
    $ruleref->{mode} = ( $ruleref->{cmdlevel} = $chainref->{cmdlevel} ) ? CMD_MODE : CAT_MODE;
 
    if ( $jump ) {
	$jump = 'j' if $jump eq 'g' && ! have_capability 'GOTO_TARGET';
	( $target, my $targetopts ) = split ' ', $target, 2;
	$ruleref->{jump}       = $jump;
	$ruleref->{target}     = $target;
	$ruleref->{targetopts} = $targetopts if $targetopts;
    }

    unless ( $ruleref->{simple} = ! @matches ) {
	$chainref->{dont_optimize} = 1 if push_matches( $ruleref, @matches );
    }

    if ( $comment ) {
	$ruleref->{comment} = $comment unless $ruleref->{comment};
    }

    if ( $number < 0 ) {
	$chainref->{blacklist}++;
	$number = 0;
    }

    splice( @{$chainref->{rules}}, $number, 0, $ruleref );

    trace( $chainref, 'I', ++$number, format_rule( $chainref, $ruleref ) ) if $debug;

    $iprangematch = 0;

    $chainref->{referenced} = 1;

    $ruleref;
}

#
# Do final work to 'delete' a chain. We leave it in the chain table but clear
# the 'referenced', 'rules', 'references' and 'blacklist' members.
#
sub delete_chain( $ ) {
    my $chainref = shift;

    $chainref->{referenced}  = 0;
    $chainref->{blacklist}   = 0;
    $chainref->{rules}       = [];
    $chainref->{references}  = {};
    trace( $chainref, 'X', undef, '' ) if $debug;
    progress_message "  Chain $chainref->{name} deleted";
}

#
# This variety first deletes all references to the chain before deleting it.
#
sub delete_chain_and_references( $ ) {
    my $chainref = shift;
    #
    #  We're going to delete this chain but first, we must delete all references to it.
    #
    my $tableref = $chain_table{$chainref->{table}};
    my $name1    = $chainref->{name}; 
    for ( @{$chainref->{rules}} ) {
	decrement_reference_count( $tableref->{$_->{target}}, $name1 ) if $_->{target};
    }

    delete_chain $chainref;
}

#
# Insert a tunnel rule into the passed chain. Tunnel rules are inserted sequentially
# at the beginning of the 'NEW' section.
#
sub add_tunnel_rule ( $;@ ) {
    my $chainref = shift;

    insert_irule( $chainref, j => 'ACCEPT', $chainref->{new}++, @_ );
}

#
# Adjust reference counts after moving a rule from $name1 to $name2
#
sub adjust_reference_counts( $$$ ) {
    my ($toref, $name1, $name2) = @_;

    if ( $toref ) {
	delete $toref->{references}{$name1} unless --$toref->{references}{$name1} > 0;
	$toref->{references}{$name2}++;
    }
}

#
# Adjust reference counts after copying a jump with target $toref to chain $chain
#
sub increment_reference_count( $$ ) {
    my ($toref, $chain) = @_;

    $toref->{references}{$chain}++ if $toref;
}

sub decrement_reference_count( $$ ) {
    my ($toref, $chain) = @_;

    if ( $toref && $toref->{referenced} ) {
	assert($toref->{references}{$chain} > 0 );
	delete $toref->{references}{$chain} unless --$toref->{references}{$chain};
	delete_chain( $toref )              unless ( keys %{$toref->{references}} );
    }
}	

#
# Move the rules from one chain to another
#
# The rules generated by interface options are added to the interfaces's input chain and
# forward chain. Shorewall::Rules::generate_matrix() may decide to move those rules to
# the head of a rules chain (behind any blacklist rule already there).
#
sub move_rules( $$ ) {
    my ($chain1, $chain2 ) = @_;

    if ( $chain1->{referenced} ) {
	my $name1     = $chain1->{name};
	my $name2     = $chain2->{name};
	my $rules     = $chain2->{rules};
	my $count     = @{$chain1->{rules}};
	my $tableref  = $chain_table{$chain1->{table}};
	my $blacklist = $chain2->{blacklist};
	my $filtered;
	my $filtered1 = $chain1->{filtered};
	my $filtered2 = $chain2->{filtered};
	my @filtered1;
	my @filtered2;
	my $rule;

	assert( ! $chain1->{blacklist} );
	#
	# We allow '+' in chain names and '+' is an RE meta-character. Escape it.
	#
	for ( @{$chain1->{rules}} ) {
	    adjust_reference_counts( $tableref->{$_->{target}}, $name1, $name2 ) if $_->{target};
	}
	#
	# We set aside the filtered rules for the time being
	#
	$filtered = $filtered1;
	
	push @filtered1 , shift @{$chain1->{rules}} while $filtered--;

	$chain1->{filtered} = 0;
	
	$filtered = $filtered2;
	push @filtered2 , shift @{$chain2->{rules}} while $filtered--;

	if ( $debug ) {
	    my $rule = $blacklist + $filtered2;
	    trace( $chain2, 'A', ++$rule, $_ ) for @{$chain1->{rules}};
	}

	splice @$rules, $blacklist, 0, @{$chain1->{rules}};

	$chain2->{referenced} = 1;

	#
	# In a firewall->x policy chain, multiple DHCP ACCEPT rules can be moved to the head of the chain.
	# This hack avoids that.
	#
	if ( $blacklist ) {
	    my $rule = shift @{$rules};
	    shift @{$rules} while @{$rules} > 1 && $rules->[0]{dhcp} && $rules->[1]{dhcp};
	    unshift @{$rules}, $rule;
	} else {
	    shift @{$rules} while @{$rules} > 1 && $rules->[0]{dhcp} && $rules->[1]{dhcp};
	}

	#
	# Now insert the filter rules at the head of the chain (before blacklist rules)
	#

	if ( $filtered1 ) {
	    if ( $debug ) {
		$rule = $filtered2;
		$filtered = 0;
		trace( $chain2, 'I', ++$rule, $filtered1[$filtered++] ) while $filtered < $filtered1;
	    }

	    splice @{$rules}, 0, 0, @filtered1;   
	}
    
	#
	# Restore the filters originally in chain2 but drop duplicates of those from $chain1
	#
      FILTER:
	while ( @filtered2 ) {
	    $filtered = pop @filtered2;
	    
	    for ( $rule = 0; $rule < $filtered1; $rule++ ) {
		$filtered2--, next FILTER if ${$rules}[$rule] eq $filtered;
	    }
	    
	    unshift @{$rules}, $filtered;
	}
	   
	$chain2->{filtered} = $filtered1 + $filtered2;
	
	delete_chain $chain1;

	$count;
    }
}

#
# Replace the jump at the end of one chain (chain2) with the rules from another chain (chain1).
#
sub copy_rules( $$;$ ) {
    my ($chain1, $chain2, $nojump ) = @_;

    my $name1      = $chain1->{name};
    my $name       = $name1;
    my $name2      = $chain2->{name};
    my $blacklist1 = $chain1->{blacklist};
    my $blacklist2 = $chain2->{blacklist};
    my @rules1     = @{$chain1->{rules}};
    my $rules2     = $chain2->{rules};
    my $count      = @{$chain1->{rules}};
    my $tableref   = $chain_table{$chain1->{table}};
    #
    # We allow '+' in chain names and '+' is an RE meta-character. Escape it.
    #
    pop @$rules2 unless $nojump; # Delete the jump to chain1

    if ( $blacklist2 && $blacklist1 ) {
	#
	# Chains2 already has a blacklist jump -- delete the one at the head of chain1's rule list
	#
	my $rule = shift @rules1;

	my $chainb = $rule->{target};

	assert( $chainb =~ /^black/ );

	delete_reference $chain1, $chainb;

	assert( ! --$chain1->{blacklist} );
	$blacklist1 = 0;
    }
    #
    # Chain2 is now a referent of all of Chain1's targets
    #
    for ( @rules1 ) {
	increment_reference_count( $tableref->{$_->{target}}, $name2 ) if $_->{target};
    }

    if ( $blacklist1 ) {
	assert( $blacklist1 == 1 );

	trace( $chain2, 'A', 1 , $rules1[0]) if $debug;

 	unshift @$rules2, shift @rules1;

	$chain1->{blacklist} = 0;
	$chain2->{blacklist} = 1;
    }

    if ( $debug ) {
	my $rule = @$rules2;
	trace( $chain2, 'A', ++$rule, $_ ) for @rules1;
    }

    push @$rules2, @rules1;

    progress_message "  $count rules from $chain1->{name} appended to $chain2->{name}";

    unless ( --$chain1->{references}{$name2} ) {
	delete $chain1->{references}{$name2};
	delete_chain_and_references( $chain1 ) unless keys %{$chain1->{references}};
    }
}

#
# Name of canonical chain between an ordered pair of zones
#
sub rules_chain ($$) {
    join "$config{ZONE2ZONE}", @_;
}

#
# Forward Chain for an interface
#
sub forward_chain($)
{
    $_[0] . '_fwd';
}

#
# Forward Chain for a zone
#
sub zone_forward_chain($) {
    $_[0] . '_frwd';
}

#
# Returns true if we're to use the interface's forward chain
#
sub use_forward_chain($$) {
    my ( $interface, $chainref ) = @_;
    my $interfaceref = find_interface($interface);
    my $nets = $interfaceref->{nets};

    return 1 if @{$chainref->{rules}} && ( $config{OPTIMIZE} & 4096 );
    #
    # Use it if we already have jumps to it
    #
    return 1 if keys %{$chainref->{references}};
    #
    # We must use the interfaces's chain if the interface is associated with multiple zones
    #
    return 1 if ( keys %{interface_zones $interface} ) > 1;
    #
    # Use interface's chain if there are multiple nets on the interface
    #
    return 1 if $nets > 1;
    #
    # Use interface's chain if it is a bridge with ports
    #
    return 1 if $interfaceref->{ports};

    my $zone = $interfaceref->{zone};

    return 1 unless $zone;
    #
    # Interface associated with a single zone -- Must use the interface chain if
    #                                            the zone has  multiple interfaces
    #                                            and this interface has option rules
    $interfaceref->{options}{use_forward_chain} && keys %{ zone_interfaces( $zone ) } > 1;
}

#
# Input Chain for an interface
#
sub input_chain($)
{
    $_[0] . '_in';
}

#
# Input Chain for a zone
#
sub zone_input_chain($) {
    $_[0] . '_input';
}

#
# Returns true if we're to use the interface's input chain
#
sub use_input_chain($$) {
    my ( $interface, $chainref ) = @_;
    my $interfaceref = find_interface($interface);
    my $nets = $interfaceref->{nets};

    return 1 if @{$chainref->{rules}} && ( $config{OPTIMIZE} & 4096 );
    #
    # We must use the interfaces's chain if the interface is associated with multiple Zones
    #
    return 1 if ( keys %{interface_zones $interface} ) > 1;
    #
    # Use interface's chain if there are multiple nets on the interface
    #
    return 1 if $nets > 1;
    #
    # Use interface's chain if it is a bridge with ports
    #
    return 1 if $interfaceref->{ports};
    #
    # Don't need it if it isn't associated with any zone
    #
    return 0 unless $nets;

    my $zone = $interfaceref->{zone};

    return 1 unless $zone;
    #
    # Interface associated with a single zone -- Must use the interface chain if
    #                                            the zone has  multiple interfaces
    #                                            and this interface has option rules
    return 1 if $interfaceref->{options}{use_input_chain} && keys %{ zone_interfaces( $zone ) } > 1;
    #
    # Interface associated with a single zone -- use the zone's input chain if it has one
    #
    return 0 if $chainref;
    #
    # Use the <zone>->fw rules chain if it is referenced.
    #
    $chainref = $filter_table->{rules_chain( $zone, firewall_zone )};

    ! ( $chainref->{referenced} || $chainref->{is_policy} )
}

#
# Output Chain for an interface
#
sub output_chain($)
{
    $_[0] . '_out';
}

#
# Output Chain for a zone
#
sub zone_output_chain($) {
    $_[0] . '_output';
}

#
# Returns true if we're to use the interface's output chain
#
sub use_output_chain($$) {
    my ( $interface, $chainref)  = @_;
    my $interfaceref = find_interface($interface);
    my $nets = $interfaceref->{nets};

    return 1 if @{$chainref->{rules}} && ( $config{OPTIMIZE} & 4096 );
    #
    # We must use the interfaces's chain if the interface is associated with multiple Zones
    #
    return 1 if ( keys %{interface_zones $interface} ) > 1;
    #
    # Use interface's chain if there are multiple nets on the interface
    #
    return 1 if $nets > 1;
    #
    # Use interface's chain if it is a bridge with ports
    #
    return 1 if $interfaceref->{ports};
    #
    # Don't need it if it isn't associated with any zone
    #
    return 0 unless $nets;
    #
    # Interface associated with a single zone -- use the zone's output chain if it has one
    #
    return 0 if $chainref;
    #
    # Use the fw-><zone> rules chain if it is referenced.
    #
    $chainref = $filter_table->{rules_chain( firewall_zone , $interfaceref->{zone} )};

    ! ( $chainref->{referenced} || $chainref->{is_policy} )
}

#
# Masquerade Chain for an interface
#
sub masq_chain($)
{
    $_[0] . '_masq';
}

#
# Syn_flood_chain -- differs from the other _chain functions in that the argument is a chain table reference
#
sub syn_flood_chain ( $ ) {
    '@' . $_[0]->{synchain};
}

#
# MAC Verification Chain for an interface
#
sub mac_chain( $ )
{
    $_[0] . '_mac';
}

sub macrecent_target($)
{
     $config{MACLIST_TTL} ? $_[0] . '_rec' : 'RETURN';
}

#
# DNAT Chain from a zone
#
sub dnat_chain( $ )
{
    $_[0] . '_dnat';
}

#
# Notrack Chain from a zone
#
sub notrack_chain( $ )
{
    $_[0] . '_notrk';
}

#
# SNAT Chain to an interface
#
sub snat_chain( $ )
{
    $_[0] . '_snat';
}

#
# ECN Chain to an interface
#
sub ecn_chain( $ )
{
    $_[0] . '_ecn';
}

#
# First chains for an interface
#
sub first_chains( $ ) #$1 = interface
{
    my $c = $_[0];

    ( $c . '_fwd', $c . '_in' );
}

#
# Returns true if the passed name is that of a Shorewall-generated chain
#
sub reserved_name( $ ) {
    my $chain = shift;

    $builtin_target{$chain} || $config_files{$chain} || $chain =~ /^account(?:fwd|in|ing|out)$/;
}

#
# Create a new chain and return a reference to it.
#
sub new_chain($$)
{
    my ($table, $chain) = @_;

    assert( $chain_table{$table} && ! ( $chain_table{$table}{$chain} || $builtin_target{ $chain } ) );

    my $chainref = { name           => $chain,
		     rules          => [],
		     table          => $table,
		     loglevel       => '',
		     log            => 1,
		     cmdlevel       => 0,
		     references     => {},
		     blacklist      => 0,
		     filtered       => 0
		   };

    trace( $chainref, 'N', undef, '' ) if $debug;

    $chain_table{$table}{$chain} = $chainref;
}

#
# Find a chain
#
sub find_chain($$) {
    my ($table, $chain) = @_;

    assert( $table && $chain && $chain_table{$table} );

    $chain_table{$table}{$chain};
}

#
# Create a chain if it doesn't exist already
#
sub ensure_chain($$)
{
    &find_chain( @_ ) || &new_chain( @_ );
}

#
# Add a jump from the chain represented by the reference in the first argument to
# the target in the second argument. The third argument determines if a GOTO may be
# used rather than a jump. The optional fourth argument specifies any matches to be
# included in the rule and must end with a space character if it is non-null. The
# optional 5th argument causes long port lists to be split. The optional 6th
# argument, if passed, gives the 0-relative index where the jump is to be inserted.
#
sub add_jump( $$$;$$$ ) {
    my ( $fromref, $to, $goto_ok, $predicate, $expandports, $index ) = @_;

    $predicate |= '';

    my $toref;
    #
    # The second argument may be a scalar (chain name or builtin target) or a chain reference
    #
    if ( reftype $to ) {
	$toref = $to;
	$to    = $toref->{name};
    } else {
	#
	# Ensure that we have the chain unless it is a builtin like 'ACCEPT'
	#
	$toref = ensure_chain( $fromref->{table} , $to ) unless $builtin_target{$to} || $to =~ / --/; #If the target has options, it must be a builtin.
    }

    #
    # If the destination is a chain, mark it referenced
    #
    $toref->{referenced} = 1, add_reference $fromref, $toref if $toref;

    my $param = $goto_ok && $toref && have_capability( 'GOTO_TARGET' ) ? 'g' : 'j';

    $fromref->{dont_optimize} = 1 if $predicate =~ /! -[piosd] /;

    if ( defined $index ) {
	assert( ! $expandports );
	insert_rule1( $fromref, $index, join( '', $predicate, "-$param $to" ));
    } else {
	add_rule ($fromref, join( '', $predicate, "-$param $to" ), $expandports || 0 );
    }
}

#
# This function is used by expand_rule() to generate jumps that require splitting long port lists
#
# The global $splitcount is incremented each time that a rule is inserted in the split path.
# Rules in excess of the minimum (1) are accounted for here.
#
sub add_expanded_jump( $$$ ) {
    my ( $chainref, $toref, $rule ) = @_;
    our $splitcount = 0;
    add_jump( $chainref, $toref, 0, $rule, 1 );
    add_reference( $chainref, $toref ) while --$splitcount > 0;
}

sub add_ijump( $$$;@ ) {
    my ( $fromref, $jump, $to, @matches ) = @_;

    my $toref;
    #
    # The second argument may be a scalar (chain name or builtin target) or a chain reference
    #
    if ( reftype $to ) {
	$toref = $to;
	$to    = $toref->{name};
    } else {
	#
	# Ensure that we have the chain unless it is a builtin like 'ACCEPT'
	#
	$toref = ensure_chain( $fromref->{table} , $to ) unless $builtin_target{$to} || $to =~ / --/; #If the target has options, it must be a builtin.
    }

    #
    # If the destination is a chain, mark it referenced
    #
    if ( $toref ) {
	$toref->{referenced} = 1;
	add_reference $fromref, $toref;
	$jump = 'j' unless have_capability 'GOTO_TARGET';
	push_irule ($fromref, $jump => $to, @matches );
    } else {
	push_irule( $fromref, 'j' => $to, @matches );
    }
}

sub insert_ijump( $$$$;@ ) {
    my ( $fromref, $jump, $to, $index, @matches ) = @_;

    my $toref;
    #
    # The second argument may be a scalar (chain name or builtin target) or a chain reference
    #
    if ( reftype $to ) {
	$toref = $to;
	$to    = $toref->{name};
    } else {
	#
	# Ensure that we have the chain unless it is a builtin like 'ACCEPT'
	#
	$toref = ensure_chain( $fromref->{table} , $to ) unless $builtin_target{$to} || $to =~ / --/; #If the target has options, it must be a builtin.
    }

    #
    # If the destination is a chain, mark it referenced
    #
    if ( $toref ) {
	$toref->{referenced} = 1;
	add_reference $fromref, $toref;
	$jump = 'j' unless have_capability 'GOTO_TARGET';
	insert_irule ($fromref, $jump => $to, $index, @matches );
    } else {
	insert_irule( $fromref, 'j' => $to, $index, @matches );
    }
}

#
# Delete jumps previously added via add_ijump. If the target chain is empty, reset its
# referenced flag
#
sub delete_jumps ( $$ ) {
    my ( $fromref, $toref ) = @_;
    my $to    = $toref->{name};
    my $from  = $fromref->{name};
    my $rules = $fromref->{rules};
    my $refs  = $toref->{references}{$from};

    #
    # The 'from' chain may have had no references and has been deleted already so
    # we need to check
    #
    if ( $fromref->{referenced} ) {
	#
	#
	# A C-style for-loop with indexing seems to work best here, given that we are
	# deleting elements from the array over which we are iterating.
	#
	for ( my $rule = 0; $rule <= $#{$rules}; $rule++ ) {
	    if (  $rules->[$rule]->{target} eq $to ) {
		trace( $fromref, 'D', $rule + 1, $rules->[$rule] ) if $debug;
		splice(  @$rules, $rule, 1 );
		last unless --$refs > 0;
		$rule--;
	    }
	}

	assert( ! $refs );
    }

    delete $toref->{references}{$from};

    unless ( @{$toref->{rules}} ) {
	$toref->{referenced} = 0;
	trace ( $toref, 'X', undef, '' ) if $debug;
    }
}

#
# Set the dont_optimize flag for a chain
#
sub dont_optimize( $ ) {
    my $chain = shift;

    my $chainref = reftype $chain ? $chain : $filter_table->{$chain};

    $chainref->{dont_optimize} = 1;

    trace( $chainref, '!O', undef, '' ) if $debug;

    $chainref;
}

#
# Set the dont_optimize and dont_delete flags for a chain
#
sub dont_delete( $ ) {
    my $chain = shift;

    my $chainref = reftype $chain ? $chain : $filter_table->{$chain};

    $chainref->{dont_optimize} = $chainref->{dont_delete} = 1;

    trace( $chainref, '!OD', undef, '' ) if $debug;

    $chainref;
}

#
# Set the dont_move flag for a chain
#
sub dont_move( $ ) {
    my $chain = shift;

    my $chainref = reftype $chain ? $chain : $filter_table->{$chain};

    $chainref->{dont_move} = 1;

    trace( $chainref, '!M', undef, '' ) if $debug;

    $chainref;
}

#
# Create a filter chain if necessary.
#
# Return a reference to the chain's table entry.
#
sub ensure_filter_chain( $$ )
{
    my ($chain, $populate) = @_;

    my $chainref = ensure_chain 'filter', $chain;

    $chainref->{referenced} = 1;

    $chainref;
}

#
# Create an accounting chain if necessary and return a reference to its table entry.
#
sub ensure_accounting_chain( $$$ )
{
    my ($chain, $ipsec, $restriction ) = @_;

    my $table = $config{ACCOUNTING_TABLE};

    my $chainref = $chain_table{$table}{$chain};

    if ( $chainref ) {
	fatal_error "Non-accounting chain ($chain) used in an accounting rule" unless $chainref->{accounting};
	$chainref->{restriction} |= $restriction;
    } else {
	fatal_error "Chain name ($chain) too long" if length $chain > 29;
	fatal_error "Invalid Chain name ($chain)" unless $chain =~ /^[-\w]+$/ && ! ( $builtin_target{$chain} || $config_files{$chain} );
	$chainref = new_chain $table , $chain;
	$chainref->{accounting}  = 1;
	$chainref->{referenced}  = 1;
	$chainref->{restriction} = $restriction;
	$chainref->{restricted}  = NO_RESTRICT;
	$chainref->{ipsec}       = $ipsec;
	$chainref->{dont_optimize} = 1 unless $config{OPTIMIZE_ACCOUNTING};

	unless ( $chain eq 'accounting' ) {
	    my $file = find_file $chain;

	    if ( -f $file ) {
		progress_message "Running $file...";

		my ( $level, $tag ) = ( '', '' );

		unless ( my $return = eval `cat $file` ) {
		    fatal_error "Couldn't parse $file: $@" if $@;
		    fatal_error "Couldn't do $file: $!"    unless defined $return;
		    fatal_error "Couldn't run $file"       unless $return;
		}
	    }
	}
    }

    $chainref;
}

#
# Return a list of references to accounting chains
#
sub accounting_chainrefs() {
    grep $_->{accounting} , values %$filter_table;
}

sub ensure_mangle_chain($) {
    my $chain = $_[0];

    my $chainref = ensure_chain 'mangle', $chain;
    $chainref->{referenced} = 1;
    $chainref;
}

sub ensure_nat_chain($) {
    my $chain = $_[0];

    my $chainref = ensure_chain 'nat', $chain;
    $chainref->{referenced} = 1;
    $chainref;
}

sub ensure_raw_chain($) {
    my $chain = $_[0];

    my $chainref = ensure_chain 'raw', $chain;
    $chainref->{referenced} = 1;
    $chainref;
}

#
# Add a builtin chain
#
sub new_builtin_chain($$$)
{
    my ( $table, $chain, $policy ) = @_;

    my $chainref = new_chain $table, $chain;
    $chainref->{referenced}  = 1;
    $chainref->{policy}      = $policy;
    $chainref->{builtin}     = 1;
    $chainref->{dont_delete} = 1;
    $chainref->{dont_move}   = 1;
    $chainref;
}

sub new_standard_chain($) {
    my $chainref = new_chain 'filter' ,$_[0];
    $chainref->{referenced} = 1;
    $chainref;
}

sub new_nat_chain($) {
    my $chainref = new_chain 'nat' ,$_[0];
    $chainref->{referenced} = 1;
    $chainref;
}

sub new_manual_chain($) {
    my $chain = $_[0];
    fatal_error "Chain name ($chain) too long" if length $chain > 29;
    fatal_error "Invalid Chain name ($chain)" unless $chain =~ /^[-\w]+$/ && ! ( $builtin_target{$chain} || $config_files{$chain} );
    fatal_error "Duplicate Chain Name ($chain)" if $targets{$chain} || $filter_table->{$chain};
    $targets{$chain} = CHAIN;
    ( my $chainref = ensure_filter_chain( $chain, 0) )->{manual} = 1;
    $chainref;
}

sub ensure_manual_chain($) {
    my $chain = $_[0];
    my $chainref = $filter_table->{$chain} || new_manual_chain($chain);
    fatal_error "$chain exists and is not a manual chain" unless $chainref->{manual};
    $chainref;
}

#
# Create and populate the passed AUDIT chain if it doesn't exist. Return chain name
#

sub ensure_audit_chain( $;$$ ) {
    my ( $target, $action, $tgt ) = @_;

    push_comment( '' );

    my $ref = $filter_table->{$target};

    unless ( $ref ) {
	$ref = new_chain 'filter', $target;

	unless ( $action ) {
	    $action = $target;
	    $action =~ s/^A_//;
	}

	$tgt ||= $action;

	add_ijump $ref, j => 'AUDIT --type ' . lc $action;
	
	if ( $tgt eq 'REJECT' ) {
	    add_ijump $ref , g => 'reject';
	} else {
	    add_ijump $ref , j => $tgt;
	}
    }

    pop_comment;

    return $target;
}

#
# Return the appropriate target based on whether the second argument is 'audit'
#

sub require_audit($$;$) {
    my ($action, $audit, $tgt ) = @_;

    return $action unless supplied $audit && $audit ne '-';

    my $target = 'A_' . $action;

    fatal_error "Invalid parameter ($audit)" unless $audit eq 'audit';

    require_capability 'AUDIT_TARGET', 'audit', 's';

    return ensure_audit_chain $target, $action, $tgt;
}   
  
#
# Returns the Level and Tag for the current action chain
#
sub get_action_logging() {
    my $chainref = get_action_chain;
    my $wholeaction = $chainref->{action};
    my ( undef, $level, $tag, undef ) = split ':', $wholeaction;
    
    $level = '' if $level =~ /^none/;

    ( $level, $tag );
}

#
# Add all builtin chains to the chain table -- it is separate from initialize() because it depends on capabilities and configuration.
# The function also initializes the target table with the pre-defined targets available for the specfied address family.
#
sub initialize_chain_table($) {
    my $full = shift;

    if ( $family == F_IPV4 ) {
	#
	#   As new targets (Actions, Macros and Manual Chains) are discovered, they are added to the table
	#
	%targets = ('ACCEPT'          => STANDARD,
		    'ACCEPT+'         => STANDARD  + NONAT,
		    'ACCEPT!'         => STANDARD,
		    'A_ACCEPT'        => STANDARD  + AUDIT,
		    'A_ACCEPT+'       => STANDARD  + NONAT + AUDIT,
		    'NONAT'           => STANDARD  + NONAT + NATONLY,
		    'DROP'            => STANDARD,
		    'DROP!'           => STANDARD,
		    'A_DROP'          => STANDARD + AUDIT,
		    'A_DROP!'         => STANDARD + AUDIT,
		    'REJECT'          => STANDARD,
		    'REJECT!'         => STANDARD,
		    'A_REJECT'        => STANDARD + AUDIT,
		    'A_REJECT!'       => STANDARD + AUDIT,
		    'DNAT'            => NATRULE,
		    'DNAT-'           => NATRULE  + NATONLY,
		    'REDIRECT'        => NATRULE  + REDIRECT,
		    'REDIRECT-'       => NATRULE  + REDIRECT + NATONLY,
		    'LOG'             => STANDARD + LOGRULE,
		    'CONTINUE'        => STANDARD,
		    'CONTINUE!'       => STANDARD,
		    'COUNT'           => STANDARD,
		    'QUEUE'           => STANDARD,
		    'QUEUE!'          => STANDARD,
		    'NFQUEUE'         => STANDARD + NFQ,
		    'NFQUEUE!'        => STANDARD + NFQ,
		    'ADD'             => STANDARD + SET,
		    'DEL'             => STANDARD + SET,
		   );

	for my $chain ( qw(OUTPUT PREROUTING) ) {
	    new_builtin_chain 'raw', $chain, 'ACCEPT';
	}

	for my $chain ( qw(INPUT OUTPUT FORWARD) ) {
	    new_builtin_chain 'filter', $chain, 'DROP';
	}

	for my $chain ( qw(PREROUTING POSTROUTING OUTPUT) ) {
	    new_builtin_chain 'nat', $chain, 'ACCEPT';
	}

	for my $chain ( qw(PREROUTING INPUT OUTPUT ) ) {
	    new_builtin_chain 'mangle', $chain, 'ACCEPT';
	}

	if ( have_capability( 'MANGLE_FORWARD' ) ) {
	    for my $chain ( qw( FORWARD POSTROUTING ) ) {
		new_builtin_chain 'mangle', $chain, 'ACCEPT';
	    }
	}
    } else {
	#
	#   As new targets (Actions, Macros and Manual Chains) are discovered, they are added to the table
	#
	%targets = ('ACCEPT'          => STANDARD,
		    'ACCEPT!'         => STANDARD,
		    'DROP'            => STANDARD,
		    'DROP!'           => STANDARD,
		    'REJECT'          => STANDARD,
		    'REJECT!'         => STANDARD,
		    'LOG'             => STANDARD + LOGRULE,
		    'CONTINUE'        => STANDARD,
		    'CONTINUE!'       => STANDARD,
		    'COUNT'           => STANDARD,
		    'QUEUE'           => STANDARD,
		    'QUEUE!'          => STANDARD,
		    'NFQUEUE'         => STANDARD + NFQ,
		    'NFQUEUE!'        => STANDARD + NFQ,
		    'ADD'             => STANDARD + SET,
		    'DEL'             => STANDARD + SET,
		   );

	for my $chain ( qw(OUTPUT PREROUTING) ) {
	    new_builtin_chain 'raw', $chain, 'ACCEPT';
	}

	for my $chain ( qw(INPUT OUTPUT FORWARD) ) {
	    new_builtin_chain 'filter', $chain, 'DROP';
	}

	for my $chain ( qw(PREROUTING POSTROUTING OUTPUT) ) {
	    new_builtin_chain 'nat', $chain, 'ACCEPT';
	}

	for my $chain ( qw(PREROUTING INPUT OUTPUT FORWARD POSTROUTING ) ) {
	    new_builtin_chain 'mangle', $chain, 'ACCEPT';
	}
    }

    if ( $full ) {
	#
	# Create these chains early in case they are needed by Policy actions
	#
	dont_move   new_standard_chain 'reject';
    }
}

#
# Delete redundant ACCEPT rules from the end of a policy chain whose policy is ACCEPT
#
sub optimize_chain( $ ) {
    my $chainref = shift;

    if ( $chainref->{referenced} ) {
	my $rules    = $chainref->{rules};
	my $count    = 0;

	pop @$rules; # Pop the plain -j ACCEPT rule at the end of the chain

	pop @$rules, $count++ while @$rules && $rules->[-1]->{target} eq 'ACCEPT';

	if ( @${rules} ) {
	    add_ijump $chainref, j => 'ACCEPT';
	    my $type = $chainref->{builtin} ? 'builtin' : 'policy';
	    progress_message "  $count ACCEPT rules deleted from $type chain $chainref->{name}" if $count;
	} elsif ( $chainref->{builtin} ) {
	    $chainref->{policy} = 'ACCEPT';
	    trace( $chainref, 'P', undef, 'ACCEPT' ) if $debug;
	    $count++;
	    progress_message "  $count ACCEPT rules deleted from builtin chain $chainref->{name}";
	} else {
	    #
	    # The chain is now empty -- change all references to ACCEPT
	    #
	    $count = 0;

	    for my $fromref ( map $filter_table->{$_} , keys %{$chainref->{references}} ) {
		my $rule = 0;
		for ( @{$fromref->{rules}} ) {
		    $rule++;
		    if ( $_->{target} eq $chainref->{name} ) {
			$_->{target} = 'ACCEPT';
			$_->{jump}   = 'j';
			$count++;
			trace( $chainref, 'R', $rule, $_ ) if $debug;
		    }
		}
	    }

	    progress_message "  $count references to ACCEPT policy chain $chainref->{name} replaced";
	    delete_chain $chainref;
	}
    }
}

#
# Delete the references to the passed chain
#
sub delete_references( $ ) {
    my $toref = shift;
    my $table    = $toref->{table};
    my $count    = 0;
    my $rule;

    for my $fromref ( map $chain_table{$table}{$_} , keys %{$toref->{references}} ) {
	delete_jumps ($fromref, $toref );
    }

    if ( $count ) {
	progress_message "  $count references to empty chain $toref->{name} deleted";
    } else {
	progress_message "  Empty chain $toref->{name} deleted";
    }
    #
    # Make sure the above loop found all references
    #
    assert ( ! $toref->{referenced} );

    $count;
}

#
# Replace jumps to the passed chain with jumps to the passed target
#
sub replace_references( $$$ ) {
    my ( $chainref, $target, $targetopts ) = @_;
    my $tableref  = $chain_table{$chainref->{table}};
    my $count     = 0;
    my $name      = $chainref->{name};

    assert defined $target;

    my $targetref = $tableref->{$target};

    for my $fromref ( map $tableref->{$_} , keys %{$chainref->{references}} ) {
	if ( $fromref->{referenced} ) {
	    my $rule = 0;
	    for ( @{$fromref->{rules}} ) {
		$rule++;
		if ( $_->{target} eq $name ) {
		    $_->{target}     = $target;
		    $_->{targetopts} = $targetopts if $targetopts;

		    if ( $targetref ) {
			add_reference ( $fromref, $targetref );
		    } else {
			$_->{jump}   = 'j';
		    }

		    $count++;
		    trace( $fromref, 'R', $rule, $_ ) if $debug;
		}
	    }
	    #
	    # The passed chain is no longer referenced by chain $fromref
	    #
	    delete $chainref->{references}{$fromref->{name}};
	}
    }
    #
    # The passed chain is no longer referenced by the target chain
    #
    delete $targetref->{references}{$chainref->{name}} if $targetref;

    progress_message "  $count references to chain $chainref->{name} replaced" if $count;

    delete_chain $chainref;
}

#
# Replace jumps to the passed chain with jumps to the target of the passed rule while merging
# options and matches
#
sub replace_references1( $$ ) {
    my ( $chainref, $ruleref ) = @_;
    my $tableref  = $chain_table{$chainref->{table}};
    my $count     = 0;
    my $name      = $chainref->{name};
    my $target    = $ruleref->{target};

    for my $fromref ( map $tableref->{$_} , keys %{$chainref->{references}} ) {
	my $rule = 0;
	if ( $fromref->{referenced} ) {
	    for ( @{$fromref->{rules}} ) {
		$rule++;
		if ( $_->{target} eq $name ) {
		    #
		    # The target is the passed chain -- merge the two rules into one
		    #
		    merge_rules( $tableref, $_, $ruleref );

		    $count++;
		    trace( $fromref, 'R', $rule, $_ ) if $debug;
		}
	    }
	}

	delete $tableref->{$target}{references}{$chainref->{name}} if $tableref->{$target};
    }

    progress_message "  $count references to chain $chainref->{name} replaced" if $count;

    delete_chain $chainref;
}

#
# The passed builtin chain has a single rule. If the target is a user chain without 'dont"move', copy the rules from the
# chain to the builtin and return true; otherwise, do nothing and return false.
#
sub conditionally_copy_rules( $$ ) {
    my ( $chainref, $basictarget ) = @_;

    my $targetref = $chain_table{$chainref->{table}}{$basictarget};

    if ( $targetref && ! $targetref->{dont_move} ) {
	#
	# Move is safe -- start with an empty rule list
	#
	$chainref->{rules} = [];
	copy_rules( $targetref, $chainref );
	1;
    }
}

#
# The passed chain is branched to with a rule containing '-s'. If the chain has any rule that also contains '-s' then
# mark the chain as "don't optimize".
#
sub check_optimization( $ ) {

    if ( $config{OPTIMIZE} & 4 ) {
	my $chainref = shift;

	for ( @{$chainref->{rules}} ) {
	    dont_optimize $chainref, return 0 if $_->{s};
	}
    }

    1;
}

#
# Perform Optimization
#
sub optimize_level4( $$ ) {
    my ( $table, $tableref ) = @_;
    my $progress = 1;
    my $passes   = 0;
    #
    # Make repeated passes through each table looking for short chains (those with less than 2 entries)
    #
    # When an unreferenced chain is found, itis deleted unless its 'dont_delete' flag is set.
    # When an empty chain is found, delete the references to it.
    # When a chain with a single entry is found, replace it's references by its contents
    #
    # The search continues until no short chains remain
    # Chains with 'dont_optimize = 1' are exempted from optimization
    #
    while ( $progress ) {
	$progress = 0;
	$passes++;

	my @chains  = grep $_->{referenced}, values %$tableref;
	my $chains  = @chains; 
	
	progress_message "\n Table $table pass $passes, $chains referenced chains, level 4a...";

	for my $chainref ( @chains ) {
	    #
	    # If the chain isn't branched to, then delete it
	    #
	    unless ( $chainref->{dont_delete} || keys %{$chainref->{references}} ) {
		delete_chain $chainref;
		next;
	    }

	    unless ( $chainref->{dont_optimize} ) {
		my $numrules = @{$chainref->{rules}};

		if ( $numrules == 0 ) {
		    #
		    # No rules in this chain
		    #
		    if ( $chainref->{builtin} ) {
			#
			# Built-in -- mark it 'dont_optimize' so we ignore it in follow-on passes
			#
			$chainref->{dont_optimize} = 1;
		    } else {
			#
			# Not a built-in -- we can delete it and it's references
			#
			delete_references $chainref;
			$progress = 1;
		    }
		} elsif ( $numrules == 1 ) {
		    my $firstrule = $chainref->{rules}[0];
		    #
		    # Chain has a single rule
		    #
		    if ( $firstrule ->{simple} ) {
			#
			# Easy case -- the rule is a simple jump
			#
			if ( $chainref->{builtin} ) {
			    #
			    # A built-in chain. If the target is a user chain without 'dont_move',
			    # we can copy its rules to the built-in
			    #
			    if ( conditionally_copy_rules $chainref, $firstrule->{target} ) {
				#
				# Target was a user chain -- rules moved
				#
				$progress = 1;
			    } else {
				#
				# Target was a built-in. Ignore this chain in follow-on passes
				#
				$chainref->{dont_optimize} = 1;
			    }
			} else {
			    #
			    # Replace all references to this chain with references to the target
			    #
			    replace_references $chainref, $firstrule->{target}, $firstrule->{targetopts};
			    $progress = 1;
			}
		    } elsif ( $firstrule->{target} ) {
			#
			# Not so easy -- the rule contains matches
			#
			if ( $chainref->{builtin} || ! $globals{KLUDGEFREE} ) {
			    #
			    # This case requires a new rule merging algorithm. Ignore this chain for
			    # now.
			    #
			    $chainref->{dont_optimize} = 1;
			} else {
			    #
			    # Replace references to this chain with the target and add the matches
			    #
			    replace_references1 $chainref, $firstrule;
			    $progress = 1;
			}
		    }
		}
	    }
	}
    }

    #
    # In this loop, we look for chains that end in an unconditional jump. If the target of the jump
    # is subject to deletion (dont_delete = false), the jump is replaced by target's rules.
    #
    $progress = 1;

    while ( $progress ) {
	$progress = 0;
	$passes++;

	my @chains  = grep $_->{referenced}, values %$tableref;
	my $chains  = @chains; 
	
	progress_message "\n Table $table pass $passes, $chains referenced chains, level 4b...";

	for my $chainref ( @chains ) {
	    my $lastrule = $chainref->{rules}[-1];

	    if ( defined $lastrule && $lastrule->{simple} ) {
		#
		# Last rule is a simple branch
		my $targetref = $tableref->{$lastrule->{target}};

		if ( $targetref && ! ( $targetref->{builtin} || $targetref->{dont_move} ) ) {
		    copy_rules( $targetref, $chainref );
		    $progress = 1;
		}
	    }
	}
    }

    $passes;
}

#
# Delete duplicate chains replacing their references
#
sub optimize_level8( $$$ ) {
    my ( $table, $tableref , $passes ) = @_;
    my $progress = 1;
    my @chains   = ( grep $_->{referenced} && ! $_->{builtin}, values %{$tableref} );
    my @chains1  = @chains;
    my $chains   = @chains;
    my $chainseq = 0;
    my %renamed;

    $passes++;
    
    progress_message "\n Table $table pass $passes, $chains referenced user chains, level 8...";

    for my $chainref ( @chains ) {
	my $digest = '|';
	$digest .= ' |' . format_rule( $chainref, $_, 1 ) for @{$chainref->{rules}};
	$chainref->{digest} = $digest;
    }

    
	    
    for my $chainref ( @chains ) {
	my $rules    = $chainref->{rules};
	#
	# Shift the current $chainref off of @chains1
	#
	shift @chains1;
	#
	# Skip empty chains
	#
	for my $chainref1 ( @chains1 ) {
	    next unless @{$chainref1->{rules}};
	    next if $chainref1->{dont_delete};
	    if ( $chainref->{digest} eq $chainref1->{digest} ) {
		replace_references $chainref1, $chainref->{name}, undef;
		$renamed{ $chainref->{name} } = 1 unless $chainref->{name} =~ /^~/;
	    }
	}
    }

    my @renamed = keys %renamed;

    if ( @renamed ) {
	#
	# First create aliases for each renamed chain and change the {name} member.
	#
	for my $oldname ( @renamed ) {
	    my $newname = $renamed{ $oldname } = '~comb' . $chainseq++;

	    trace( $tableref->{$oldname}, 'RN', 0, " Renamed $newname" ) if $debug;
	    $tableref->{$newname} = $tableref->{$oldname};
	    $tableref->{$oldname}{name} = $newname;
	    progress_message "   Chain $oldname renamed to $newname";
	}
	#
	# Now adjust the references to point to the new name
	#
	while ( my ($chain, $chainref ) = each %$tableref ) {
	    my %references = %{$chainref->{references}};

	    while ( my ( $chain1, $chainref1 ) = each %references ) {
		if ( my $newname = $renamed{$chainref->{references}{$chain1}} ) {
		    $chainref->{references}{$newname} = $chainref->{references}{$chain1};
		    delete $chainref->{references}{$chain1};
		}
	    }
	}
	#
	# Delete the old names from the table
	#
	delete $tableref->{$_} for @renamed;
	#
	# And fix up the rules
	#
	for my $chainref ( values %$tableref ) {
	    my $rulenum = 0;

	    for ( @{$chainref->{rules}} ) {
		$rulenum++;

		if ( my $newname = $renamed{$_->{target}} ) {
		    $_->{target} = $newname;
		    trace( $chainref, 'R', $rulenum, $_ ) if $debug;
		}
	    }
	}
    }

    $passes;
}

sub optimize_ruleset() {
    for my $table ( qw/raw mangle nat filter/ ) {

	next if $family == F_IPV6 && $table eq 'nat';

	my $tableref = $chain_table{$table};
	my $passes   = 0;

	$passes =  optimize_level4( $table, $tableref )           if $config{OPTIMIZE} & 4;
	$passes =  optimize_level8( $table, $tableref , $passes ) if $config{OPTIMIZE} & 8;

	progress_message "  Table $table Optimized -- Passes = $passes";
	progress_message '';
    }
}

#
# Helper for set_mss
#
sub set_mss1( $$ ) {
    my ( $chain, $mss ) =  @_;
    my $chainref = ensure_chain 'filter', $chain;

    if ( $chainref->{policy} ne 'NONE' ) {
	my $match = have_capability( 'TCPMSS_MATCH' ) ? "-m tcpmss --mss $mss: " : '';
	insert_rule1 $chainref, 0, "-p tcp --tcp-flags SYN,RST SYN ${match}-j TCPMSS --set-mss $mss"
    }
}

#
# Set up rules to set MSS to and/or from zone "$zone"
#
sub set_mss( $$$ ) {
    my ( $zone, $mss, $direction) = @_;

    for my $z ( all_zones ) {
	if ( $direction eq '_in' ) {
	    set_mss1 rules_chain( ${zone}, ${z} ) , $mss;
	} elsif ( $direction eq '_out' ) {
	    set_mss1 rules_chain( ${z}, ${zone} ) , $mss;
	} else {
	    set_mss1 rules_chain( ${z}, ${zone} ) , $mss;
	    set_mss1 rules_chain( ${zone}, ${z} ) , $mss;
	}
    }
}

#
# Interate over all zones with 'mss=' settings adding TCPMSS rules as appropriate.
#
sub setup_zone_mss() {
    for my $zone ( all_zones ) {
	my $zoneref = find_zone( $zone );

	set_mss( $zone, $zoneref->{options}{in_out}{mss}, ''     ) if $zoneref->{options}{in_out}{mss};
	set_mss( $zone, $zoneref->{options}{in}{mss},     '_in'  ) if $zoneref->{options}{in}{mss};
	set_mss( $zone, $zoneref->{options}{out}{mss},    '_out' ) if $zoneref->{options}{out}{mss};
    }
}

sub newexclusionchain( $ ) {
    my $seq = $chainseq{$_[0]}++;
    "~excl${seq}";
}

sub newlogchain( $ ) {
    my $seq = $chainseq{$_[0]}++;
    "~log${seq}";
}

#
# If there is already a logging chain associated with the passed rules chain that matches these
# parameters, then return a reference to it.
#
# Otherwise, create such a chain and store a reference in chainref's 'logchains' hash. Return the
# reference.
#
sub logchain( $$$$$$ ) {
    my ( $chainref, $loglevel, $logtag, $exceptionrule, $disposition, $target ) = @_;
    my $key = join( ':', $loglevel, $logtag, $exceptionrule, $disposition, $target );
    my $logchainref = $chainref->{logchains}{$key};

    unless ( $logchainref ) {
	$logchainref = $chainref->{logchains}{$key} = new_chain $chainref->{table}, newlogchain( $chainref->{table} ) ;
	#
	# Now add the log rule and target rule without matches to the log chain.
	#
	log_rule_limit(
		       $loglevel ,
		       $logchainref ,
		       $chainref->{name} ,
		       $disposition ,
		       '',
		       $logtag,
		       'add',
		       '' );
	add_jump( $logchainref, $target, 0, $exceptionrule );
    }

    $logchainref;
}

sub newnonatchain() {
    my $seq = $chainseq{nat}++;
    "nonat${seq}";
}

#
# If the passed exclusion array is non-empty then:
#
#       Create a new exclusion chain in the table of the passed chain
#           (Note: If the chain is not in the filter table then a
#                  reference to the chain's chain table entry must be
#                  passed).
#
#       Add RETURN rules for each element of the exclusion array
#
#       Add a jump to the passed chain
#
#       Return the exclusion chain. The type of the returned value
#                                   matches what was passed (reference
#                                   or name).
#
# Otherwise
#
#       Return the passed chain.
#
# There are two versions of the function; one for source exclusion and
# one for destination exclusion.
#
sub source_exclusion( $$ ) {
    my ( $exclusions, $target ) = @_;

    return $target unless @$exclusions;

    my $table = reftype $target ? $target->{table} : 'filter';

    my $chainref = new_chain( $table , newexclusionchain( $table ) );

    add_ijump( $chainref, j => 'RETURN', imatch_source_net( $_ ) ) for @$exclusions;
    add_ijump( $chainref, g => $target );

    reftype $target ? $chainref : $chainref->{name};
}

sub dest_exclusion( $$ ) {
    my ( $exclusions, $target ) = @_;

    return $target unless @$exclusions;

    my $table = reftype $target ? $target->{table} : 'filter';

    my $chainref = new_chain( $table , newexclusionchain( $table ) );

    add_ijump( $chainref, j => 'RETURN', imatch_dest_net( $_ ) ) for @$exclusions;
    add_ijump( $chainref, g => $target );

    reftype $target ? $chainref : $chainref->{name};
}

sub clearrule() {
    $iprangematch = 0;
}

#
# Return the number of ports represented by the passed list
#
sub port_count( $ ) {
    ( $_[0] =~ tr/,:/,:/ ) + 1;
}

#
# Generate a state match
#
sub state_imatch( $ ) {
    my $state = shift;

    have_capability 'CONNTRACK_MATCH' ? ( conntrack => "--ctstate $state" ) : ( state => $state );
}

#
# Handle parsing of PROTO, DEST PORT(S) , SOURCE PORTS(S). Returns the appropriate match string.
#
# If the optional argument is true, port lists > 15 result in a fatal error.
#
sub do_proto( $$$;$ )
{
    my ($proto, $ports, $sports, $restricted ) = @_;

    my $output = '';

    $proto  = '' if $proto  eq '-';
    $ports  = '' if $ports  eq '-';
    $sports = '' if $sports eq '-';

    if ( $proto ne '' ) {

	my $synonly  = ( $proto =~ s/:syn$//i );
	my $invert   = ( $proto =~ s/^!// ? '! ' : '' );
	my $protonum = resolve_proto $proto;

	if ( defined $protonum ) {
	    #
	    # Protocol is numeric and <= 255 or is defined in /etc/protocols or NSS equivalent
	    #
	    fatal_error "'!0' not allowed in the PROTO column" if $invert && ! $protonum;

	    my $pname = proto_name( $proto = $protonum );
	    #
	    # $proto now contains the protocol number and $pname contains the canonical name of the protocol
	    #
	    unless ( $synonly ) {
		$output  = "${invert}-p ${proto} ";
	    } else {
		fatal_error '":syn" is only allowed with tcp' unless $proto == TCP && ! $invert;
		$output = "-p $proto --syn ";
	    }

	    fatal_error "SOURCE/DEST PORT(S) not allowed with PROTO !$pname" if $invert && ($ports ne '' || $sports ne '');

	  PROTO:
	    {
		if ( $proto == TCP || $proto == UDP || $proto == SCTP || $proto == DCCP || $proto == UDPLITE ) {
		    my $multiport = 0;

		    if ( $ports ne '' ) {
			$invert = $ports =~ s/^!// ? '! ' : '';
			if ( $ports =~ tr/,/,/ > 0 || $sports =~ tr/,/,/ > 0 || $proto == UDPLITE ) {
			    fatal_error "Port lists require Multiport support in your kernel/iptables" unless have_capability( 'MULTIPORT' );
			    fatal_error "Multiple ports not supported with SCTP" if $proto == SCTP;

			    if ( port_count ( $ports ) > 15 ) {
				if ( $restricted ) {
				    fatal_error "A port list in this file may only have up to 15 ports";
				} elsif ( $invert ) {
				    fatal_error "An inverted port list may only have up to 15 ports";
				}
			    }

			    $ports = validate_port_list $pname , $ports;
			    $output .= "-m multiport ${invert}--dports ${ports} ";
			    $multiport = 1;
			}  else {
			    fatal_error "Missing DEST PORT" unless supplied $ports;
			    $ports   = validate_portpair $pname , $ports;
			    $output .= "${invert}--dport ${ports} ";
			}
		    } else {
			$multiport = ( ( $sports =~ tr/,/,/ ) > 0 || $proto == UDPLITE );
		    }

		    if ( $sports ne '' ) {
			$invert = $sports =~ s/^!// ? '! ' : '';
			if ( $multiport ) {

			    if ( port_count( $sports ) > 15 ) {
				if ( $restricted ) {
				    fatal_error "A port list in this file may only have up to 15 ports";
				} elsif ( $invert ) {
				    fatal_error "An inverted port list may only have up to 15 ports";
				}
			    }

			    $sports = validate_port_list $pname , $sports;
			    $output .= "-m multiport ${invert}--sports ${sports} ";
			}  else {
			    fatal_error "Missing SOURCE PORT" unless supplied $sports;
			    $sports  = validate_portpair $pname , $sports;
			    $output .= "${invert}--sport ${sports} ";
			}
		    }

		    last PROTO;	}

		if ( $proto == ICMP ) {
		    fatal_error "ICMP not permitted in an IPv6 configuration" if $family == F_IPV6; #User specified proto 1 rather than 'icmp'
		    if ( $ports ne '' ) {
			$invert = $ports =~ s/^!// ? '! ' : '';

			my $types;

			if ( $ports =~ /,/ ) {
			    fatal_error "An inverted ICMP list may only contain a single type" if $invert;
			    $types = '';
			    for my $type ( split_list( $ports, 'ICMP type list' ) ) {
				$types = $types ? join( ',', $types, validate_icmp( $type ) ) : $type;
			    }
			} else {
			    $types = validate_icmp $ports;
			}

			$output .= "${invert}--icmp-type ${types} ";
		    }

		    fatal_error 'SOURCE PORT(S) not permitted with ICMP' if $sports ne '';

		    last PROTO; }

		if ( $proto == IPv6_ICMP ) {
		    fatal_error "IPv6_ICMP not permitted in an IPv4 configuration" if $family == F_IPV4;
		    if ( $ports ne '' ) {
			$invert = $ports =~ s/^!// ? '! ' : '';

			my $types;

			if ( $ports =~ /,/ ) {
			    fatal_error "An inverted ICMP list may only contain a single type" if $invert;
			    $types = '';
			    for my $type ( list_split( $ports, 'ICMP type list' ) ) {
				$types = $types ? join( ',', $types, validate_icmp6( $type ) ) : $type;
			    }
			} else {
			    $types = validate_icmp6 $ports;
			}

			$output .= "${invert}--icmpv6-type ${types} ";
		    }

		    fatal_error 'SOURCE PORT(S) not permitted with IPv6-ICMP' if $sports ne '';

		    last PROTO; }


		fatal_error "SOURCE/DEST PORT(S) not allowed with PROTO $pname" if $ports ne '' || $sports ne '';

	    } # PROTO

	} else {
	    fatal_error '":syn" is only allowed with tcp' if $synonly;

	    if ( $proto =~ /^(ipp2p(:(tcp|udp|all))?)$/i ) {
		my $p = $2 ? lc $3 : 'tcp';
		require_capability( 'IPP2P_MATCH' , "PROTO = $proto" , 's' );
		$proto = '-p ' . proto_name($p) . ' ';

		my $options = '';

		if ( $ports ne 'ipp2p' ) {
		    $options .= " --$_" for split /,/, $ports;
		}

		$options = have_capability( 'OLD_IPP2P_MATCH' ) ? ' --ipp2p' : ' --edk --kazaa --gnu --dc' unless $options;

		$output .= "${proto}-m ipp2p${options} ";
	    } else {
		fatal_error "Invalid/Unknown protocol ($proto)"
	    }
	}
    } else {
	#
	# No protocol
	#
	fatal_error "SOURCE/DEST PORT(S) not allowed without PROTO" if $ports ne '' || $sports ne '';
    }

    $output;
}


sub do_mac( $ ) {
    my $mac = $_[0];

    $mac =~ s/^(!?)~//;
    my $invert = ( $1 ? '! ' : '');
    $mac =~ tr/-/:/;

    fatal_error "Invalid MAC address ($mac)" unless $mac =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;

    "-m mac ${invert}--mac-source $mac ";
}

sub do_imac( $ ) {
    my $mac = $_[0];

    $mac =~ s/^(!?)~//;
    my $invert = ( $1 ? '! ' : '');
    $mac =~ tr/-/:/;

    fatal_error "Invalid MAC address ($mac)" unless $mac =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;

    ( mac => "${invert}--mac-source $mac" );
}

#
# Mark validatation functions
#
sub verify_mark( $ ) {
    my $mark  = $_[0];
    my $limit = $globals{TC_MASK} | $globals{PROVIDER_MASK};
    my $mask  = $globals{TC_MASK};
    my $value = numeric_value( $mark );

    fatal_error "Invalid Mark or Mask value ($mark)"
	unless defined( $value ) && $value <= $limit;

    if ( $value > $mask ) {
	#
	# Not a valid TC mark -- must be a provider mark or a user mark
	#
	fatal_error "Invalid Mark or Mask value ($mark)" unless ( $value & $globals{PROVIDER_MASK} ) == $value || ( $value & $globals{USER_MASK} ) == $value;
    }
}

sub verify_small_mark( $ ) {
    verify_mark ( (my $mark) = $_[0] );
    fatal_error "Mark value ($mark) too large" if numeric_value( $mark ) > $globals{TC_MAX};
}

sub validate_mark( $ ) {
    my $mark = shift;
    fatal_error "Missing MARK" unless supplied $mark;

    if ( $mark =~ '/' ) {
	my @marks = split '/', $mark;
	fatal_error "Invalid MARK ($mark)" unless @marks == 2;
	verify_mark $_ for @marks;
    } else {
	verify_mark $mark;
    }
}

#
# Generate an appropriate -m [conn]mark match string for the contents of a MARK column
#

sub do_test ( $$ )
{
    my ($testval, $mask) = @_;

    my $originaltestval = $testval;

    return '' unless defined $testval and $testval ne '-';

    $mask = '' unless defined $mask;

    my $invert = $testval =~ s/^!// ? '! ' : '';
    my $match  = $testval =~ s/:C$// ? "-m connmark ${invert}--mark" : "-m mark ${invert}--mark";

    fatal_error "Invalid MARK value ($originaltestval)" if $testval eq '/';

    validate_mark $testval;

    $testval = join( '/', $testval, in_hex($mask) ) unless ( $testval =~ '/' );

    "$match $testval ";
}

my %norate = ( DROP => 1, REJECT => 1 );

#
# Create a "-m limit" match for the passed LIMIT/BURST
#
sub do_ratelimit( $$ ) {
    my ( $rate, $action ) = @_;

    return '' unless $rate and $rate ne '-';

    fatal_error "Rate Limiting not available with $action" if $norate{$action};
    #
    # "-m hashlimit" match for the passed LIMIT/BURST
    #
    if ( $rate =~ /^[sd]:{1,2}/ ) {
	require_capability 'HASHLIMIT_MATCH', 'Per-ip rate limiting' , 's';

	my $limit = "-m hashlimit ";
	my $match = have_capability( 'OLD_HL_MATCH' ) ? 'hashlimit' : 'hashlimit-upto';
	my $units;

	if ( $rate =~ /^[sd]:((\w*):)?((\d+)(\/(sec|min|hour|day))?):(\d+)$/ ) {
	    fatal_error "Invalid Rate ($3)" unless $4;
	    fatal_error "Invalid Burst ($7)" unless $7;
	    $limit .= "--hashlimit $3 --hashlimit-burst $7 --hashlimit-name ";
	    $limit .= $2 ? $2 : 'shorewall' . $hashlimitset++;
	    $limit .= ' --hashlimit-mode ';
	    $units = $6;
	} elsif ( $rate =~ /^[sd]:((\w*):)?((\d+)(\/(sec|min|hour|day))?)$/ ) {
	    fatal_error "Invalid Rate ($3)" unless $4;
	    $limit .= "--$match $3 --hashlimit-name ";
	    $limit .= $2 ? $2 :  'shorewall' . $hashlimitset++;
	    $limit .= ' --hashlimit-mode ';
	    $units = $6;
	} else {
	    fatal_error "Invalid rate ($rate)";
	}

	$limit .= $rate =~ /^s:/ ? 'srcip ' : 'dstip ';

	if ( $units && $units ne 'sec' ) {
	    my $expire = 60000; # 1 minute in milliseconds

	    if ( $units ne 'min' ) {
		$expire *= 60; #At least an hour
		$expire *= 24 if $units eq 'day';
	    }

	    $limit .= "--hashlimit-htable-expire $expire ";
	}

	$limit;
    } elsif ( $rate =~ /^((\d+)(\/(sec|min|hour|day))?):(\d+)$/ ) {
	fatal_error "Invalid Rate ($1)" unless $2;
	fatal_error "Invalid Burst ($5)" unless $5;
	"-m limit --limit $1 --limit-burst $5 ";
    } elsif ( $rate =~ /^(\d+)(\/(sec|min|hour|day))?$/ )  {
	fatal_error "Invalid Rate (${1}${2})" unless $1;
	"-m limit --limit $rate ";
    } else {
	fatal_error "Invalid rate ($rate)";
    }
}

#
# Create a "-m connlimit" match for the passed CONNLIMIT
#
sub do_connlimit( $ ) {
    my ( $limit ) = @_;

    return '' if $limit eq '-';

    require_capability 'CONNLIMIT_MATCH', 'A non-empty CONNLIMIT', 's';

    my $invert =  $limit =~ s/^!// ? '' : '! '; # Note Carefully -- we actually do 'connlimit-at-or-below'

    if ( $limit =~ /^(\d+):(\d+)$/ ) {
	fatal_error "Invalid Mask ($2)" unless $2 > 0 || $2 < 31;
	"-m connlimit ${invert}--connlimit-above $1 --connlimit-mask $2 ";
    } elsif ( $limit =~ /^(\d+)$/ )  {
	"-m connlimit ${invert}--connlimit-above $limit ";
    } else {
	fatal_error "Invalid connlimit ($limit)";
    }
}

sub do_time( $ ) {
    my ( $time ) = @_;

    return '' if $time eq '-';

    require_capability 'TIME_MATCH', 'A non-empty TIME', 's';

    my $result = '-m time ';

    for my $element (split /&/, $time ) {
	fatal_error "Invalid time element list ($time)" unless defined $element && $element;

	if ( $element =~ /^(timestart|timestop)=(\d{1,2}:\d{1,2}(:\d{1,2})?)$/ ) {
	    $result .= "--$1 $2 ";
	} elsif ( $element =~ /^weekdays=(.*)$/ ) {
	    my $days = $1;
	    for my $day ( split /,/, $days ) {
		fatal_error "Invalid weekday ($day)" unless $day =~ /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$/ || ( $day =~ /^\d$/ && $day && $day <= 7);
	    }
	    $result .= "--weekday $days ";
	} elsif ( $element =~ /^monthdays=(.*)$/ ) {
	    my $days = $1;
	    for my $day ( split /,/, $days ) {
		fatal_error "Invalid day of the month ($day)" unless $day =~ /^\d{1,2}$/ && $day && $day <= 31;
	    }
	} elsif ( $element =~ /^(datestart|datestop)=(\d{4}(-\d{2}(-\d{2}(T\d{1,2}(:\d{1,2}){0,2})?)?)?)$/ ) {
	    $result .= "--$1 $2 ";
	} elsif ( $element =~ /^(utc|localtz)$/ ) {
	    $result .= "--$1 ";
	} else {
	    fatal_error "Invalid time element ($element)";
	}
    }

    $result;
}

#
# Create a "-m owner" match for the passed USER/GROUP
#
sub do_user( $ ) {
    my $user = $_[0];
    my $rule = '-m owner ';

    return '' unless defined $user and $user ne '-';

    if ( $user =~ /^(!)?(.*)\+(.*)$/ ) {
	$rule .= "! --cmd-owner $2 " if supplied $2;
	$user = "!$1";
    } elsif ( $user =~ /^(.*)\+(.*)$/ ) {
	$rule .= "--cmd-owner $2 " if supplied $2;
	$user = $1;
    }

    if ( $user =~ /^(!)?(.*):(.*)$/ ) {
	my $invert = $1 ? '! ' : '';
	my $group  = defined $3 ? $3 : '';
	if ( supplied $2 ) {
	    $user = $2;
	    fatal_error "Unknown user ($user)" unless $user =~ /^\d+$/ || $globals{EXPORT} || defined getpwnam( $user );
	    $rule .= "${invert}--uid-owner $user ";
	}

	if ( $group ne '' ) {
	    fatal_error "Unknown group ($group)" unless $group =~ /\d+$/ || $globals{EXPORT} || defined getgrnam( $group );
	    $rule .= "${invert}--gid-owner $group ";
	}
    } elsif ( $user =~ /^(!)?(.*)$/ ) {
	my $invert = $1 ? '! ' : '';
	$user   = $2;
	fatal_error "Invalid USER/GROUP (!)" if $user eq '';
	fatal_error "Unknown user ($user)" unless $user =~ /^\d+$/ || $globals{EXPORT} || defined getpwnam( $user );
	$rule .= "${invert}--uid-owner $user ";
    } else {
	fatal_error "Unknown user ($user)" unless $user =~ /^\d+$/ || $globals{EXPORT} || defined getpwnam( $user );
	$rule .= "--uid-owner $user ";
    }

    $rule;
}

#
# Create a "-m tos" match for the passed TOS
#
sub do_tos( $ ) {
    my $tos = $_[0];

    $tos ne '-' ? "-m tos --tos $tos " : '';
}

my %dir = ( O => 'original' ,
	    R => 'reply' ,
	    B => 'both' );

my %mode = ( P => 'packets' ,
	     B => 'bytes' ,
	     A => 'avgpkt' );

#
# Create a "-m connbytes" match for the passed argument
#
sub do_connbytes( $ ) {
    my $connbytes = $_[0];

    return '' if $connbytes eq '-';
    #                                                                    1     2      3        5       6
    fatal_error "Invalid CONNBYTES ($connbytes)" unless $connbytes =~ /^(!)? (\d+): (\d+)? ((:[ORB]) (:[PBA])?)?$/x;

    my $invert = $1 || ''; $invert = '! ' if $invert;
    my $min    = $2;       $min    = 0  unless defined $min;
    my $max    = $3;       $max    = '' unless defined $max; fatal_error "Invalid byte range ($min:$max)" if $max ne '' and $min > $max;
    my $dir    = $5 || 'B';
    my $mode   = $6 || 'B';

    $dir  =~ s/://;
    $mode =~ s/://;

    "-m connbytes ${invert}--connbytes $min:$max --connbytes-dir $dir{$dir} --connbytes-mode $mode{$mode} ";
}

#
# Create a soft "-m helper" match for the passed argument
#
sub do_helper( $ ) {
    my $helper = shift;

    return '' if $helper eq '-';

    qq(-m helper --helper "$helper" );
}

#
# Create a "-m length" match for the passed LENGTH
#
sub do_length( $ ) {
    my $length = $_[0];

    require_capability( 'LENGTH_MATCH' , 'A Non-empty LENGTH' , 's' );
    $length ne '-' ? "-m length --length $length " : '';
}

#
# Create a "-m -ipv6header" match for the passed argument
#
my %headers = ( hop          => 1,
		dst          => 1,
		route        => 1,
		frag         => 1,
		auth         => 1,
		esp          => 1,  
		none         => 1,
		'hop-by-hop' => 1,
		'ipv6-opts'  => 1,
		'ipv6-route' => 1,
		'ipv6-frag'  => 1,
		ah           => 1,
		'ipv6-nonxt' => 1,
		'protocol'   => 1,
		0            => 1,
		43           => 1,
		44           => 1,
		50           => 1,
		51           => 1,
		59           => 1,
		60           => 1,
		255          => 1 );

sub do_headers( $ ) {
    my $headers = shift;

    return '' if $headers eq '-';

    require_capability 'HEADER_MATCH', 'A non-empty HEADER column', 's';

    my $invert = $headers =~ s/^!// ? '! ' : "";

    my $soft   = '--soft ';

    if ( $headers =~ s/^exactly:// ) {
	$soft = '';
    } else {
	$headers =~ s/^any://;
    }

    for ( split_list $headers, "Header" ) {
	if ( $_ eq 'proto' ) {
	    $_ = 'protocol';
	} else {
	    fatal_error "Unknown IPv6 Header ($_)" unless $headers{$_};
	}
    }

    "-m ipv6header ${invert}--header ${headers} ${soft}";
}

#
# Match Source Interface
#
sub match_source_dev( $;$ ) {
    my ( $interface, $nodev ) = @_;;
    my $interfaceref =  known_interface( $interface );
    $interface = $interfaceref->{physical} if $interfaceref;
    return '' if $interface eq '+';
    if ( $interfaceref && $interfaceref->{options}{port} ) {
	if ( $nodev ) {
	    "-m physdev --physdev-in $interface ";
	} else {
	    my $bridgeref = find_interface $interfaceref->{bridge};
	    "-i $bridgeref->{physical} -m physdev --physdev-in $interface ";
	}
    } else {
	"-i $interface ";
    }
}

sub imatch_source_dev( $;$ ) {
    my ( $interface, $nodev ) = @_;;
    my $interfaceref =  known_interface( $interface );
    $interface = $interfaceref->{physical} if $interfaceref;
    return () if $interface eq '+';
    if ( $interfaceref && $interfaceref->{options}{port} ) {
	if ( $nodev ) {
	    ( physdev => "--physdev-in $interface" );
	} else {
	    my $bridgeref = find_interface $interfaceref->{bridge};
	    ( i => $bridgeref->{physical}, physdev => "--physdev-in $interface" );
	}
    } else {
	( i => $interface );
    }
}

#
# Match Dest device
#
sub match_dest_dev( $;$ ) {
    my ( $interface, $nodev ) = @_;;
    my $interfaceref =  known_interface( $interface );
    $interface = $interfaceref->{physical} if $interfaceref;
    return '' if $interface eq '+';
    if ( $interfaceref && $interfaceref->{options}{port} ) {
	if ( $nodev ) {
	    if ( have_capability( 'PHYSDEV_BRIDGE' ) ) {
		"-m physdev --physdev-is-bridged --physdev-out $interface ";
	    } else {
		"-m physdev --physdev-out $interface ";
	    }
	} else {
	    my $bridgeref = find_interface $interfaceref->{bridge};
	    
	    if ( have_capability( 'PHYSDEV_BRIDGE' ) ) {
		"-o $bridgeref->{physical} -m physdev --physdev-is-bridged --physdev-out $interface ";
	    } else {
		"-o $bridgeref->{physical} -m physdev --physdev-out $interface ";
	    }
	}
    } else {
	"-o $interface ";
    }
}

sub imatch_dest_dev( $;$ ) {
    my ( $interface, $nodev ) = @_;;
    my $interfaceref =  known_interface( $interface );
    $interface = $interfaceref->{physical} if $interfaceref;
    return () if $interface eq '+';
    if ( $interfaceref && $interfaceref->{options}{port} ) {
	if ( $nodev ) {
	    if ( have_capability( 'PHYSDEV_BRIDGE' ) ) {
		( physdev => "--physdev-is-bridged --physdev-out $interface" );
	    } else {
		( physdev => "--physdev-out $interface" );
	    }
	} else {
	    my $bridgeref = find_interface $interfaceref->{bridge};
	    
	    if ( have_capability( 'PHYSDEV_BRIDGE' ) ) {
		( o => $bridgeref->{physical}, physdev => "--physdev-is-bridged --physdev-out $interface" );
	    } else {
		( o => $bridgeref->{physical}, physdev => "--physdev-out $interface" );
	    }
	}
    } else {
	( o => $interface );
    }
}

#
# Avoid generating a second '-m iprange' in a single rule.
#
sub iprange_match() {
    my $match = '';

    require_capability( 'IPRANGE_MATCH' , 'Address Ranges' , '' );
    unless ( $iprangematch ) {
	$match = '-m iprange ';
	$iprangematch = 1 unless $globals{KLUDGEFREE};
    }

    $match;
}

#
# Get set flags (ipsets).
#
sub get_set_flags( $$ ) {
    my ( $setname, $option ) = @_;
    my $options = $option;

    require_capability( 'IPSET_MATCH' , 'ipset names in Shorewall configuration files' , '' );

    $ipset_rules++;

    $setname =~ s/^!//; # Caller has already taken care of leading !

    if ( $setname =~ /^(.*)\[([1-6])\]$/ ) {
	$setname  = $1;
	my $count = $2;
	$options .= ",$option" while --$count > 0;
    } elsif ( $setname =~ /^(.*)\[((src|dst)(,(src|dst))*)\]$/ ) {
	$setname = $1;
	$options = $2;
    }

    $setname =~ s/^\+//;

    unless ( $export || $> != 0 ) {
	unless ( $ipset_exists{$setname} ) {
	    warning_message "Ipset $setname does not exist" unless qt "ipset -L $setname";
	}

	$ipset_exists{$setname} = 1; # Suppress subsequent checks/warnings
    }

    fatal_error "Invalid ipset name ($setname)" unless $setname =~ /^(6_)?[a-zA-Z]\w*/;

    have_capability 'OLD_IPSET_MATCH' ? "--set $setname $options " : "--match-set $setname $options ";

}

sub have_ipset_rules() {
    $ipset_rules;
}

sub get_interface_address( $ );

sub record_runtime_address( $ ) {
    my $interface = shift;
    fatal_error "Unknown interface address variable (&$interface)" unless known_interface( $interface );
    fatal_error "Invalid interface address variable (&$interface)" if $interface =~ /\+$/;
    get_interface_address( $interface ) . ' ';
}

#
# If the passed address is a run-time address variable for an optional interface, then
# begin a conditional rule block that tests the address for nil. Returns 1 if a conditional
# block was opened. The caller stores the result, and if the result is true the caller 
# invokes conditional_rule_end() when the conditional block is complete.
#
sub conditional_rule( $$ ) {
    my ( $chainref, $address ) = @_;

    if ( $address =~ /^!?&(.+)$/ ) {
	my $interface = $1;
	if ( my $ref = known_interface $interface ) {
	    if ( $ref->{options}{optional} ) {
		my $variable = get_interface_address( $interface );
		add_commands( $chainref , "if [ $variable != " . NILIP . ' ]; then' );
		incr_cmd_level $chainref;
		return 1;
	    }
	};
    }

    0;
}

#
# End a conditional in a chain begun by conditional_rule(). Should only be called
# if conditional_rule() returned true.
#

sub conditional_rule_end( $ ) {
    my $chainref = shift;
    decr_cmd_level $chainref;
    add_commands( $chainref , "fi\n" );
}	

sub mysplit( $;$ );

#
# Match a Source.
#
sub match_source_net( $;$\$ ) {
    my ( $net, $restriction, $macref ) = @_;

    $restriction |= NO_RESTRICT;

    if ( ( $family == F_IPV4 && $net =~ /^(!?)(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) ||
	 ( $family == F_IPV6 && $net =~  /^(!?)(.*:.*)-(.*:.*)$/ ) ) {
	my ($addr1, $addr2) = ( $2, $3 );
	$net =~ s/!// if my $invert = $1 ? '! ' : '';
	validate_range $addr1, $addr2;
	return iprange_match . "${invert}--src-range $net ";
    }

    if ( $net =~ /^!?~/ ) {
	fatal_error "A MAC address($net) cannot be used in this context" if $restriction >= OUTPUT_RESTRICT;
	$$macref = 1 if $macref;
	return do_mac $net;
    }

    if ( $net =~ /^(!?)\+(6_)?[a-zA-Z][-\w]*(\[.*\])?/ ) {
	return join( '', '-m set ', $1 ? '! ' : '', get_set_flags( $net, 'src' ) );
    }

    if ( $net =~ /^\+\[(.+)\]$/ ) {
	my $result = '';
	my @sets = mysplit $1, 1;

	fatal_error "Multiple ipset matches requires the Repeat Match capability in your kernel and iptables" unless $globals{KLUDGEFREE};

	for $net ( @sets ) {
	    fatal_error "Expected ipset name ($net)" unless $net =~ /^(!?)(\+?)[a-zA-Z][-\w]*(\[.*\])?/;
	    $result .= join( '', '-m set ', $1 ? '! ' : '', get_set_flags( $net, 'src' ) );
	}

	return $result;
    }

    if ( $net =~ s/^!// ) {
	if ( $net =~ /^&(.+)/ ) {
	    return '! -s ' . record_runtime_address $1;
	}

	validate_net $net, 1;
	return "! -s $net ";
    }

    if ( $net =~ /^&(.+)/ ) {
	return '-s ' . record_runtime_address $1;
    }

    validate_net $net, 1;
    $net eq ALLIP ? '' : "-s $net ";
}

sub imatch_source_net( $;$\$ ) {
    my ( $net, $restriction, $macref ) = @_;

    $restriction |= NO_RESTRICT;

    if ( ( $family == F_IPV4 && $net =~ /^(!?)(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) ||
	 ( $family == F_IPV6 && $net =~  /^(!?)(.*:.*)-(.*:.*)$/ ) ) {
	my ($addr1, $addr2) = ( $2, $3 );
	$net =~ s/!// if my $invert = $1 ? '! ' : '';
	fatal_error "Address Ranges require the Multiple Match capability in your kernel and iptables" unless $globals{KLUDGEFREE};
	return ( iprange => "${invert}--src-range $net" );
    }

    if ( $net =~ /^!?~/ ) {
	fatal_error "A MAC address($net) cannot be used in this context" if $restriction >= OUTPUT_RESTRICT;
	$$macref = 1 if $macref;
	return do_imac $net;
    }

    if ( $net =~ /^(!?)\+(6_)?[a-zA-Z][-\w]*(\[.*\])?/ ) {
	return ( set => join( '', $1 ? '! ' : '', get_set_flags( $net, 'src' ) ) );
    }

    if ( $net =~ /^\+\[(.+)\]$/ ) {
	my @result = ();
	my @sets = mysplit $1, 1;

	fatal_error "Multiple ipset matches requires the Repeat Match capability in your kernel and iptables" unless $globals{KLUDGEFREE};

	for $net ( @sets ) {
	    fatal_error "Expected ipset name ($net)" unless $net =~ /^(!?)(\+?)[a-zA-Z][-\w]*(\[.*\])?/;
	    push @result, join( '', $1 ? '! ' : '', get_set_flags( $net, 'src' ) );
	}

	return ( s => \@result );
    }

    if ( $net =~ s/^!// ) {
	if ( $net =~ /^&(.+)/ ) {
	    return  ( s => '! ' . record_runtime_address $1 );
	}

	validate_net $net, 1;
	return ( s => "! $net " );
    }

    if ( $net =~ /^&(.+)/ ) {
	return ( s =>  record_runtime_address $1 );
    }

    validate_net $net, 1;
    $net eq ALLIP ? () : ( s => $net );
}

#
# Match a Destination.
#
sub match_dest_net( $ ) {
    my $net = $_[0];

    if ( ( $family == F_IPV4 && $net =~ /^(!?)(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) ||
	 ( $family == F_IPV6 && $net =~  /^(!?)(.*:.*)-(.*:.*)$/ ) ) {
	my ($addr1, $addr2) = ( $2, $3 );
	$net =~ s/!// if my $invert = $1 ? '! ' : '';
	validate_range $addr1, $addr2;
	return iprange_match . "${invert}--dst-range $net ";
    }

    if ( $net =~ /^(!?)\+(6_)?[a-zA-Z][-\w]*(\[.*\])?$/ ) {
	return join( '', '-m set ', $1 ? '! ' : '',  get_set_flags( $net, 'dst' ) );
    }

    if ( $net =~ /^\+\[(.+)\]$/ ) {
	my $result = '';
	my @sets = mysplit $1, 1;

	fatal_error "Multiple ipset matches requires the Repeat Match capability in your kernel and iptables" unless $globals{KLUDGEFREE};

	for $net ( @sets ) {
	    fatal_error "Expected ipset name ($net)" unless $net =~ /^(!?)(\+?)[a-zA-Z][-\w]*(\[.*\])?/;
	    $result .= join( '', '-m set ', $1 ? '! ' : '', get_set_flags( $net, 'dst' ) );
	}

	return $result;
    }

    if ( $net =~ s/^!// ) {
	if ( $net =~ /^&(.+)/ ) {
	    return '! -d ' . record_runtime_address $1;
	}
	
	validate_net $net, 1;
	return "! -d $net ";
    }

    if ( $net =~ /^&(.+)/ ) {
	return '-d ' . record_runtime_address $1;
    }

    validate_net $net, 1;
    $net eq ALLIP ? '' : "-d $net ";
}

sub imatch_dest_net( $ ) {
    my $net = $_[0];

    if ( ( $family == F_IPV4 && $net =~ /^(!?)(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) ||
	 ( $family == F_IPV6 && $net =~  /^(!?)(.*:.*)-(.*:.*)$/ ) ) {
	my ($addr1, $addr2) = ( $2, $3 );
	$net =~ s/!// if my $invert = $1 ? '! ' : '';
	validate_range $addr1, $addr2;
	require_capability( 'IPRANGE_MATCH' , 'Address Ranges' , '' );
	return ( iprange => "${invert}--dst-range $net" );
    }

    if ( $net =~ /^(!?)\+(6_)?[a-zA-Z][-\w]*(\[.*\])?$/ ) {
	return ( set => join( '', $1 ? '! ' : '',  get_set_flags( $net, 'dst' ) ) );
    }

    if ( $net =~ /^\+\[(.+)\]$/ ) {
	my @result;
	my @sets = mysplit $1, 1;

	fatal_error "Multiple ipset matches requires the Repeat Match capability in your kernel and iptables" unless $globals{KLUDGEFREE};

	for $net ( @sets ) {
	    fatal_error "Expected ipset name ($net)" unless $net =~ /^(!?)(\+?)[a-zA-Z][-\w]*(\[.*\])?/;
	    push @result , ( set => join( '', $1 ? '! ' : '', get_set_flags( $net, 'dst' ) ) );
	}

	return ( set => \@result );
    }

    if ( $net =~ s/^!// ) {
	if ( $net =~ /^&(.+)/ ) {
	    return ( d => '! ' . record_runtime_address $1 );
	}
	
	validate_net $net, 1;
	return ( d => "! $net " );
    }

    if ( $net =~ /^&(.+)/ ) {
	return ( d => record_runtime_address $1 );
    }

    validate_net $net, 1;
    $net eq ALLIP ? () : ( d =>  $net );
}

#
# Match original destination
#
sub match_orig_dest ( $ ) {
    my $net = $_[0];

    return '' if $net eq ALLIP;
    return '' unless have_capability( 'CONNTRACK_MATCH' );

    if ( $net =~ s/^!// ) {
	if ( $net =~ /^&(.+)/ ) {
	    $net = record_runtime_address $1;
	} else {
	    validate_net $net, 1;
	}

	have_capability( 'OLD_CONNTRACK_MATCH' ) ? "-m conntrack --ctorigdst ! $net " : "-m conntrack ! --ctorigdst $net ";
    } else {
	if ( $net =~ /^&(.+)/ ) {
	    $net = record_runtime_address $1;
	} else {
	    validate_net $net, 1;
	}

	$net eq ALLIP ? '' : "-m conntrack --ctorigdst $net ";
    }
}

#
# Match Source IPSEC
#
sub match_ipsec_in( $$ ) {
    my ( $zone , $hostref ) = @_;
    my @match;
    my $zoneref    = find_zone( $zone );
    my $optionsref = $zoneref->{options};

    unless ( $optionsref->{super} || $zoneref->{type} == VSERVER ) {
	my $match = '--dir in --pol ';

	if ( $zoneref->{type} == IPSEC ) {
	    $match .= "ipsec $optionsref->{in_out}{ipsec}$optionsref->{in}{ipsec}";
	} elsif ( have_ipsec ) {
	    $match .= "$hostref->{ipsec} $optionsref->{in_out}{ipsec}$optionsref->{in}{ipsec}";
	} else {
	    return ();
	}

	@match = ( policy => $match );
    }

    @match;
}

sub match_ipsec_out( $$ ) {
    my ( $zone , $hostref ) = @_;
    my @match;
    my $zoneref    = find_zone( $zone );
    my $optionsref = $zoneref->{options};

    unless ( $optionsref->{super} || $zoneref->{type} == VSERVER ) {
	my $match = '--dir out --pol ';

	if ( $zoneref->{type} == IPSEC ) {
	    $match .= "ipsec $optionsref->{in_out}{ipsec}$optionsref->{out}{ipsec}";
	} elsif ( have_ipsec ) {
	    $match .= "$hostref->{ipsec} $optionsref->{in_out}{ipsec}$optionsref->{out}{ipsec}"
	} else {
	    return ();
	}

	@match = ( policy => $match );
    }

    @match;
}

#
# Handle a unidirectional IPSEC Options
#
sub do_ipsec_options($$$)
{
    my %validoptions = ( strict       => NOTHING,
			 next         => NOTHING,
			 reqid        => NUMERIC,
			 spi          => NUMERIC,
			 proto        => IPSECPROTO,
			 mode         => IPSECMODE,
			 "tunnel-src" => NETWORK,
			 "tunnel-dst" => NETWORK,
		       );
    my ( $dir, $policy, $list ) = @_;
    my $options = "-m policy --pol $policy --dir $dir ";
    my $fmt;

    for my $e ( split_list $list, 'IPSEC option' ) {
	my $val    = undef;
	my $invert = '';

	if ( $e =~ /([\w-]+)!=(.+)/ ) {
	    $val    = $2;
	    $e      = $1;
	    $invert = '! ';
	} elsif ( $e =~ /([\w-]+)=(.+)/ ) {
	    $val = $2;
	    $e   = $1;
	}

	$fmt = $validoptions{$e};

	fatal_error "Invalid IPSEC Option ($e)" unless $fmt;

	if ( $fmt eq NOTHING ) {
	    fatal_error "Option \"$e\" does not take a value" if defined $val;
	} else {
	    fatal_error "Missing value for option \"$e\""        unless defined $val;
	    fatal_error "Invalid value ($val) for option \"$e\"" unless $val =~ /^($fmt)$/;
	}

	$options .= $invert;
	$options .= "--$e ";
	$options .= "$val " if defined $val;
    }

    $options;
}

#
# Handle a bi-directional IPSEC column
#
sub do_ipsec($$) {
    my ( $dir, $ipsec ) = @_;

    if ( $ipsec eq '-' ) {
	return '';
    }

    fatal_error "Non-empty IPSEC column requires policy match support in your kernel and iptables"  unless have_capability( 'POLICY_MATCH' );

    my @options = split_list $ipsec, 'IPSEC options';

    if ( @options == 1 ) {
	if ( lc( $options[0] ) =~ /^(yes|ipsec)$/ ) {
	    return do_ipsec_options $dir, 'ipsec', '';
	}

	if ( lc( $options[0] ) =~ /^(no|none)$/ ) {
	    return do_ipsec_options $dir, 'none', '';
	}
    }

    do_ipsec_options $dir, 'ipsec', join( ',', @options );
}

#
# Generate a log message
#
sub log_rule_limit( $$$$$$$$ ) {
    my ($level, $chainref, $chain, $disposition, $limit, $tag, $command, $matches ) = @_;

    my $prefix = '';

    $level = validate_level $level; # Do this here again because this function can be called directly from user exits.

    return 1 if $level eq '';

    $matches .= ' ' if $matches && substr( $matches, -1, 1 ) ne ' ';

    unless ( $matches =~ /-m limit / ) {
	$limit = $globals{LOGLIMIT} unless $limit && $limit ne '-';
	$matches .= $limit if $limit;
    }

    if ( $config{LOGFORMAT} =~ /^\s*$/ ) {
	if ( $level =~ '^ULOG' ) {
	    $prefix = "-j $level ";
	} elsif  ( $level =~ /^NFLOG/ ) {
	    $prefix = "-j $level ";
	} else {
	    $prefix = "-j LOG $globals{LOGPARMS}--log-level $level ";
	}
    } else {
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

	$disposition =~ s/\s+.*//;

	if ( $globals{LOGRULENUMBERS} ) {
	    $prefix = (sprintf $config{LOGFORMAT} , $chain , $chainref->{log}++, $disposition ) . $tag;
	} else {
	    $prefix = (sprintf $config{LOGFORMAT} , $chain , $disposition) . $tag;
	}

	if ( length $prefix > 29 ) {
	    $prefix = substr( $prefix, 0, 28 ) . ' ';
	    warning_message "Log Prefix shortened to \"$prefix\"";
	}

	if ( $level =~ '^ULOG' ) {
	    $prefix = "-j $level --ulog-prefix \"$prefix\" ";
	} elsif  ( $level =~ /^NFLOG/ ) {
	    $prefix = "-j $level --nflog-prefix \"$prefix\" ";
	} elsif ( $level =~ '^LOGMARK' ) {
	    $prefix = join( '', substr( $prefix, 0, 12 ) , ':' ) if length $prefix > 13;
	    $prefix = "-j $level --log-prefix \"$prefix\" ";
	} else {
	    $prefix = "-j LOG $globals{LOGPARMS}--log-level $level --log-prefix \"$prefix\" ";
	}
    }

    if ( $command eq 'add' ) {
	add_rule ( $chainref, $matches . $prefix , 1 );
    } else {
	insert_rule1 ( $chainref , 0 , $matches . $prefix );
    }
}

sub log_rule( $$$$ ) {
    my ( $level, $chainref, $disposition, $matches ) = @_;

    log_rule_limit $level, $chainref, $chainref->{name} , $disposition, $globals{LOGLIMIT}, '', 'add', $matches;
}

#
# If the destination chain exists, then at the end of the source chain add a jump to the destination.
#
sub addnatjump( $$;@ ) {
    my ( $source , $dest, @matches ) = @_;

    my $destref   = $nat_table->{$dest} || {};

    if ( $destref->{referenced} ) {
	add_ijump $nat_table->{$source} , j => $dest , @matches;
    } else {
	clearrule;
    }
}

#
# Split a comma-separated source or destination host list but keep [...] together. Used for spliting address lists
# where an element of the list might be +ipset[flag,...] or +[ipset[flag,...],...]
#
sub mysplit( $;$ ) {
    my ( $input, $loose ) = @_;

    my @input = split_list $input, 'host';

    return @input unless $input =~ /\[/;

    my $exclude = 0;

    my @result;

    while ( @input ) {
	my $element = shift @input;

	if ( $element =~ /\[/ ) {
	    while ( $element =~ tr/[/[/ > $element =~ tr/]/]/ ) {
		fatal_error "Missing ']' ($element)" unless @input;
		$element .= ( ',' . shift @input );
	    }

	    unless ( $loose ) {
		fatal_error "Invalid host list ($input)" if $exclude && $element =~ /!/;
		$exclude ||= $element =~ /^!/ || $element =~ /\]!/;
	    }

	    fatal_error "Mismatched [...] ($element)" unless $element =~ tr/[/[/ == $element =~ tr/]/]/;
	} else {
	    $exclude ||= $element =~ /!/ unless $loose;
	}

	push @result, $element;
    }

    @result;
}

#
# Set up the IPTABLES-related run-time variables
#
sub set_chain_variables() {
    if ( $family == F_IPV4 ) {
	my $checkname = 0;
	my $iptables  = $config{IPTABLES};

	if ( $iptables ) {
	    emit( qq(IPTABLES="$iptables"),
		  '[ -x "$IPTABLES" ] || startup_error "IPTABLES=$IPTABLES does not exist or is not executable"',
		);
	    $checkname = 1 unless $iptables =~ '/';
	} else {
	    emit( '[ -z "$IPTABLES" ] && IPTABLES=$(mywhich iptables) # /sbin/shorewall exports IPTABLES',
		  '[ -n "$IPTABLES" -a -x "$IPTABLES" ] || startup_error "Can\'t find iptables executable"'
		);
	    $checkname = 1;
	}

	if ( $checkname ) {
	    emit ( '',
		   'case $IPTABLES in',
		   '    */*)',
		   '        ;;',
		   '    *)',
		   '        IPTABLES=./$IPTABLES',
		   '        ;;',
		   'esac',
		   '',
		   'IP6TABLES=${IPTABLES%/*}/ip6tables'
		 );
	} else {
	    $iptables =~ s|/[^/]*$|/ip6tables|;
	    emit ( "IP6TABLES=$iptables" );
	}

	emit( 'IPTABLES_RESTORE=${IPTABLES}-restore',
	      '[ -x "$IPTABLES_RESTORE" ] || startup_error "$IPTABLES_RESTORE does not exist or is not executable"' );
    } else {
	if ( $config{IP6TABLES} ) {
	    emit( qq(IP6TABLES="$config{IP6TABLES}"),
		  '[ -x "$IP6TABLES" ] || startup_error "IP6TABLES=$IP6TABLES does not exist or is not executable"',
		);
	} else {
	    emit( '[ -z "$IP6TABLES" ] && IP6TABLES=$(mywhich ip6tables) # /sbin/shorewall6 exports IP6TABLES',
		  '[ -n "$IP6TABLES" -a -x "$IP6TABLES" ] || startup_error "Can\'t find ip6tables executable"'
		);
	}

	emit( 'IP6TABLES_RESTORE=${IP6TABLES}-restore',
	      '[ -x "$IP6TABLES_RESTORE" ] || startup_error "$IP6TABLES_RESTORE does not exist or is not executable"' );
    }

    if ( $config{IP} ) {
	emit( qq(IP="$config{IP}") ,
	      '[ -x "$IP" ] || startup_error "IP=$IP does not exist or is not executable"'
	    );
    } else {
	emit 'IP=ip';
    }

    if ( $config{TC} ) {
	emit( qq(TC="$config{TC}") ,
	      '[ -x "$TC" ] || startup_error "TC=$TC does not exist or is not executable"'
	    );
    } else {
	emit 'TC=tc';
    }

    if ( $config{IPSET} ) {
	emit( qq(IPSET="$config{IPSET}") ,
	      '[ -x "$IPSET" ] || startup_error "IPSET=$IPSET does not exist or is not executable"'
	    );
    } else {
	emit 'IPSET=ipset';
    }
}

#
# Emit code that marks the firewall as not started.
#
sub mark_firewall_not_started() {
    if ( $family == F_IPV4 ) {
	emit ( 'qt1 $IPTABLES -L shorewall -n && qt1 $IPTABLES -F shorewall && qt1 $IPTABLES -X shorewall' );
    } else {
	emit ( 'qt1 $IP6TABLES -L shorewall -n && qt1 $IP6TABLES -F shorewall && qt1 $IP6TABLES -X shorewall' );
    }
}

####################################################################################################################
# The following functions come in pairs. The first function returns the name of a run-time shell variable that
# will hold a piece of interface-oriented data detected at run-time. The second creates a code fragment to detect
# the information and stores it in a hash keyed by the interface name.
####################################################################################################################
#
# Returns the name of the shell variable holding the first address of the passed interface
#
sub interface_address( $ ) {
    my $variable = 'sw_' . chain_base( $_[0] ) . '_address';
    uc $variable;
}

#
# Record that the ruleset requires the first IP address on the passed interface
#
sub get_interface_address ( $ ) {
    my ( $logical ) = $_[0];

    my $interface = get_physical( $logical );
    my $variable = interface_address( $interface );
    my $function = interface_is_optional( $logical ) ? 'find_first_interface_address_if_any' : 'find_first_interface_address';

    $global_variables |= ALL_COMMANDS;

    $interfaceaddr{$interface} = "$variable=\$($function $interface)\n";

    "\$$variable";
}

#
# Returns the name of the shell variable holding the broadcast addresses of the passed interface
#
sub interface_bcasts( $ ) {
    my $variable = 'sw_' . chain_base( $_[0] ) . '_bcasts';
    uc $variable;
}

#
# Record that the ruleset requires the broadcast addresses on the passed interface
#
sub get_interface_bcasts ( $ ) {
    my ( $interface ) = get_physical $_[0];

    my $variable = interface_bcasts( $interface );

    $global_variables |= NOT_RESTORE;

    $interfacebcasts{$interface} = qq($variable="\$(get_interface_bcasts $interface) 255.255.255.255");

    "\$$variable";
}

#
# Returns the name of the shell variable holding the anycast addresses of the passed interface
#
sub interface_acasts( $ ) {
    my $variable = 'sw_' . chain_base( $_[0] ) . '_acasts';
    uc $variable;
}

#
# Record that the ruleset requires the anycast addresses on the passed interface
#
sub get_interface_acasts ( $ ) {
    my ( $interface ) = get_physical $_[0];

    $global_variables |= NOT_RESTORE;

    my $variable = interface_acasts( $interface );

    $interfaceacasts{$interface} = qq($variable="\$(get_interface_acasts $interface) ) . IPv6_MULTICAST;

    "\$$variable";
}

#
# Returns the name of the shell variable holding the gateway through the passed interface
#
sub interface_gateway( $ ) {
    my $variable = 'sw_' . chain_base( $_[0] ) . '_gateway';
    uc $variable;
}

#
# Record that the ruleset requires the gateway address on the passed interface
#
sub get_interface_gateway ( $ ) {
    my ( $logical ) = $_[0];

    my $interface = get_physical $logical;
    my $variable = interface_gateway( $interface );

    my $routine = $config{USE_DEFAULT_RT} ? 'detect_dynamic_gateway' : 'detect_gateway';

    $global_variables |= ALL_COMMANDS;

    if ( interface_is_optional $logical ) {
	$interfacegateways{$interface} = qq([ -n "\$$variable" ] || $variable=\$($routine $interface)\n);
    } else {
	$interfacegateways{$interface} = qq([ -n "\$$variable" ] || $variable=\$($routine $interface)
[ -n "\$$variable" ] || startup_error "Unable to detect the gateway through interface $interface"
);
    }

    "\$$variable";
}

#
# Returns the name of the shell variable holding the addresses of the passed interface
#
sub interface_addresses( $ ) {
    my $variable = 'sw_' . chain_base( $_[0] ) . '_addresses';
    uc $variable;
}

#
# Record that the ruleset requires the IP addresses on the passed interface
#
sub get_interface_addresses ( $ ) {
    my ( $logical ) = $_[0];

    my $interface = get_physical( $logical );
    my $variable = interface_addresses( $interface );

    $global_variables |= NOT_RESTORE;

    if ( interface_is_optional $logical ) {
	$interfaceaddrs{$interface} = qq($variable=\$(find_interface_addresses $interface)\n);
    } else {
	$interfaceaddrs{$interface} = qq($variable=\$(find_interface_addresses $interface)
[ -n "\$$variable" ] || startup_error "Unable to determine the IP address(es) of $interface"
);
    }

    "\$$variable";
}

#
# Returns the name of the shell variable holding the networks routed out of the passed interface
#
sub interface_nets( $ ) {
    my $variable = 'sw_' . chain_base( $_[0] ) . '_networks';
    uc $variable;
}

#
# Record that the ruleset requires the networks routed out of the passed interface
#
sub get_interface_nets ( $ ) {
    my ( $logical ) = $_[0];

    my $interface = physical_name( $logical );
    my $variable = interface_nets( $interface );

    $global_variables |= ALL_COMMANDS;

    if ( interface_is_optional $logical ) {
	$interfacenets{$interface} = qq($variable=\$(get_routed_networks $interface)\n);
    } else {
	$interfacenets{$interface} = qq($variable=\$(get_routed_networks $interface)
[ -n "\$$variable" ] || startup_error "Unable to determine the routes through interface \\"$interface\\""
);
    }

    "\$$variable";

}

#
# Returns the name of the shell variable holding the MAC address of the gateway for the passed provider out of the passed interface
#
sub interface_mac( $$ ) {
    my $variable = join( '_' , 'sw' , chain_base( $_[0] ) , chain_base( $_[1] ) , 'mac' );
    uc $variable;
}

#
# Record the fact that the ruleset requires MAC address of the passed gateway IP routed out of the passed interface for the passed provider number
#
sub get_interface_mac( $$$ ) {
    my ( $ipaddr, $logical , $table ) = @_;

    my $interface = get_physical( $logical );
    my $variable = interface_mac( $interface , $table );

    $global_variables |= NOT_RESTORE;

    if ( interface_is_optional $logical ) {
	$interfacemacs{$table} = qq($variable=\$(find_mac $ipaddr $interface)\n);
    } else {
	$interfacemacs{$table} = qq($variable=\$(find_mac $ipaddr $interface)
[ -n "\$$variable" ] || startup_error "Unable to determine the MAC address of $ipaddr through interface \\"$interface\\""
);
    }

    "\$$variable";
}

sub have_global_variables() {
    have_capability( 'ADDRTYPE' ) ? $global_variables : $global_variables | NOT_RESTORE;
}

#
# Generate setting of run-time global shell variables
#
sub set_global_variables( $ ) {

    my $setall = shift;

    emit $_ for values %interfaceaddr;
    emit $_ for values %interfacegateways;
    emit $_ for values %interfacemacs;

    if ( $setall ) {
	emit $_ for values %interfaceaddrs;
	emit $_ for values %interfacenets;

	unless ( have_capability( 'ADDRTYPE' ) ) {

	    if ( $family == F_IPV4 ) {
		emit 'ALL_BCASTS="$(get_all_bcasts) 255.255.255.255"';
		emit $_ for values %interfacebcasts;
	    } else {
		emit 'ALL_ACASTS="$(get_all_acasts)"';
		emit $_ for values %interfaceacasts;
	    }
	}
    }
}

#
# Issue an invalid list error message
#
sub invalid_network_list ( $$ ) {
    my ( $srcdst, $list ) = @_;
    fatal_error "Invalid $srcdst network list ($list)";
}

#
# Split a network element into the net part and exclusion part (if any)
#
sub split_network( $$$ ) {
    my ( $input, $srcdst, $list ) = @_;

    my @input = split '!', $input;
    my @result;

    if ( $input =~ /\[/ ) {
	while ( @input ) {
	    my $element = shift @input;

	    if ( $element =~ /\[/ ) {
		my $openbrackets;

		while ( ( $openbrackets = ( $element =~ tr/[/[/ ) ) > $element =~ tr/]/]/ ) {
		    fatal_error "Missing ']' ($element)" unless @input;
		    $element .= ( '!' . shift @input );
		}

		fatal_error "Mismatched [...] ($element)" unless $openbrackets == $element =~ tr/]/]/;
	    }

	    push @result, $element;
	}
    } else {
	@result = @input;
    }

    invalid_network_list( $srcdst, $list ) if @result > 2;
	
    @result;
}

#
# Handle SOURCE or DEST network list, including exclusion
#
sub handle_network_list( $$ ) {
    my ( $list, $srcdst ) = @_;

    my $nets = '';
    my $excl = '';
	
    my @nets = mysplit $list;

    for ( @nets ) {
	if ( /!/ ) {
	    if ( /^!(.*)$/ ) {
		invalid_network_list( $srcdst, $list) if ( $nets || $excl );
		$excl = $1;
	    } else {
		my ( $temp1, $temp2 ) = split_network $_, $srcdst, $list;
		$nets = $nets ? join(',', $nets, $temp1 ) : $temp1;
		if ( $temp2 ) {
		    invalid_network_list( $srcdst, $list) if $excl;
		    $excl = $temp2;
		}
	    }
	} elsif ( $excl ) {
	    $excl .= ",$_";
	} else {
	    $nets = $nets ? join(',', $nets, $_ ) : $_;
	}	    
    }

    ( $nets, $excl );

}

################################################################################################################
#
# This function provides a uniform way to generate Netfilter[6] rules (something the original Shorewall
# sorely needed).
#
# Returns the destination interface specified in the rule, if any.
#
sub expand_rule( $$$$$$$$$$;$ )
{
    my ($chainref ,    # Chain
	$restriction,  # Determines what to do with interface names in the SOURCE or DEST
	$rule,         # Caller's matches that don't depend on the SOURCE, DEST and ORIGINAL DEST
	$source,       # SOURCE
	$dest,         # DEST
	$origdest,     # ORIGINAL DEST
	$target,       # Target ('-j' part of the rule - may be empty)
	$loglevel ,    # Log level (and tag)
	$disposition,  # Primtive part of the target (RETURN, ACCEPT, ...)
	$exceptionrule,# Caller's matches used in exclusion case
	$logname,      # Name of chain to name in log messages
       ) = @_;

    my ($iiface, $diface, $inets, $dnets, $iexcl, $dexcl, $onets , $oexcl, $trivialiexcl, $trivialdexcl );
    my $chain = $chainref->{name};
    my $table = $chainref->{table};
    my $jump  = $target ? '-j ' . $target : '';
    my $mac;
    my $targetref;

    if ( $target ) {
	my ( $basic_target, $rest ) = split ' ', $target, 2;

	$targetref = $chain_table{$table}{$basic_target};
    }
    
    our @ends = ();
    #
    # In the generated rules, we sometimes need run-time loops or conditional blocks. This function is used
    # to define such a loop or block.
    #
    # $chainref = Reference to the chain
    # $command  = The shell command that begins the loop or conditional
    # $end      = The shell keyword ('done' or 'fi') that ends the loop or conditional
    #
    # All open loops and conditionals are closed just before expand_rule() exits
    #
    sub push_command( $$$ ) {
	my ( $chainref, $command, $end ) = @_;

	add_commands $chainref, $command;
	incr_cmd_level $chainref;
	push @ends, $end;
    }
    #
    # Trim disposition
    #
    $disposition =~ s/\s.*//;
    #
    # Handle Log Level
    #
    my $logtag;

    if ( $loglevel ne '' ) {
	( $loglevel, $logtag, my $remainder ) = split( /:/, $loglevel, 3 );

	fatal_error "Invalid log tag" if defined $remainder;

	if ( $loglevel =~ /^none!?$/i ) {
	    return if $disposition eq 'LOG';
	    $loglevel = $logtag = '';
	} else {
	    $loglevel = validate_level( $loglevel );
	    $logtag   = '' unless defined $logtag;
	}
    } elsif ( $disposition eq 'LOG' ) {
	fatal_error "LOG requires a level";
    }
    #
    # Isolate Source Interface, if any
    #
    if ( supplied $source ) {
	if ( $source eq '-' ) {
	    $source = '';
	} elsif ( $family == F_IPV4 ) {
	    if ( $source =~ /^~/ ) {
		$inets = $source;
	    } elsif ( $source =~ /^(.+?):(.+)$/ ) {
		$iiface = $1;
		$inets  = $2;
	    } elsif ( $source =~ /\+|&|~|\..*\./ ) {
		$inets = $source;
	    } else {
		$iiface = $source;
	    }
	} elsif  ( $source =~ /^(.+?):<(.+)>\s*$/ || $source =~ /^(.+?):\[(.+)\]\s*$/ || $source =~ /^(.+?):(!?\+.+)$/ ) {
	    $iiface = $1;
	    $inets  = $2;
	} elsif ( $source =~ /:/ ) {
	    if ( $source =~ /^<(.+)>$/ || $source =~ /^\[(.+)\]$/ ) {
		$inets = $1;
	    } else {
		$inets = $source;
	    }
	} elsif ( $source =~ /(?:\+|&|~|\..*\.)/ ) {
	    $inets = $source;
	} else {
	    $iiface = $source;
	}
    } else {
	$source = '';
    }

    #
    # Verify Interface, if any
    #
    if ( supplied $iiface ) {
	fatal_error "Unknown Interface ($iiface)" unless known_interface $iiface;

	if ( $restriction & POSTROUTE_RESTRICT ) {
	    #
	    # An interface in the SOURCE column of a masq file
	    #
	    fatal_error "Bridge ports may not appear in the SOURCE column of this file" if port_to_bridge( $iiface );
	    fatal_error "A wildcard interface ( $iiface) is not allowed in this context" if $iiface =~ /\+$/;

	    if ( $table eq 'nat' ) {
		warning_message qq(Using an interface as the masq SOURCE requires the interface to be up and configured when $Product starts/restarts) unless $idiotcount++;
	    } else {
		warning_message qq(Using an interface as the SOURCE in a T: rule requires the interface to be up and configured when $Product starts/restarts) unless $idiotcount1++;
	    }

	    push_command $chainref, join( '', 'for source in ', get_interface_nets( $iiface) , '; do' ), 'done';

	    $rule .= '-s $source ';
	} else {
	    if ( $restriction & OUTPUT_RESTRICT ) {
		if ( $chainref->{accounting} ) {
		    fatal_error "Source Interface ($iiface) not allowed in the $chainref->{name} chain";
		} else {
		    fatal_error "Source Interface ($iiface) not allowed when the SOURCE is the firewall";
		}
	    }
 
	    $chainref->{restricted} |= $restriction;
	    $rule .= match_source_dev( $iiface );
	}
    }

    #
    # Isolate Destination Interface, if any
    #
    if ( supplied $dest ) {
	if ( $dest eq '-' ) {
	    $dest = '';
	} elsif ( ( $restriction & PREROUTE_RESTRICT ) && $dest =~ /^detect:(.*)$/ ) {
	    #
	    # DETECT_DNAT_IPADDRS=Yes and we're generating the nat rule
	    #
	    my @interfaces = split /\s+/, $1;

	    if ( @interfaces > 1 ) {
		my $list = "";
		my $optional;

		for my $interface ( @interfaces ) {
		    $optional++ if interface_is_optional $interface;
		    $list = join( ' ', $list , get_interface_address( $interface ) );
		}

		push_command( $chainref , "for address in $list; do" , 'done' );

		push_command( $chainref , 'if [ $address != 0.0.0.0 ]; then' , 'fi' ) if $optional;

		$rule .= '-d $address ';
	    } else {
		my $interface = $interfaces[0];
		my $variable  = get_interface_address( $interface );

		push_command( $chainref , "if [ $variable != 0.0.0.0 ]; then" , 'fi') if interface_is_optional( $interface );

		$rule .= "-d $variable ";
	    }

	    $dest = '';
	} elsif ( $family == F_IPV4 ) {
	    if ( $dest =~ /^(.+?):(.+)$/ ) {
		$diface = $1;
		$dnets  = $2;
	    } elsif ( $dest =~ /\+|&|~|\..*\./ ) {
		$dnets = $dest;
	    } else {
		$diface = $dest;
	    }
	} elsif ( $dest =~ /^(.+?):<(.+)>\s*$/ || $dest =~ /^(.+?):\[(.+)\]\s*$/ || $dest =~ /^(.+?):(!?\+.+)$/ ) {
	    $diface = $1;
	    $dnets  = $2;
	} elsif ( $dest =~ /:/ ) {
	    if ( $dest =~ /^<(.+)>$/ || $dest =~ /^\[(.+)\]$/ ) {
		$dnets = $1;
	    } else {
		$dnets = $dest;
	    }
	} elsif ( $dest =~ /(?:\+|&|\..*\.)/ ) {
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
    if ( supplied $diface ) {
	fatal_error "Unknown Interface ($diface)" unless known_interface $diface;

	if ( $restriction & PREROUTE_RESTRICT ) {
	    #
	    # Dest interface -- must use routing table
	    #
	    fatal_error "A DEST interface is not permitted in the PREROUTING chain" if $restriction & DESTIFACE_DISALLOW;
	    fatal_error "Bridge port ($diface) not allowed" if port_to_bridge( $diface );
	    fatal_error "A wildcard interface ($diface) is not allowed in this context" if $diface =~ /\+$/;
	    push_command( $chainref , 'for dest in ' . get_interface_nets( $diface) . '; do', 'done' );
	    $rule .= '-d $dest ';
	} else {
	    fatal_error "Bridge Port ($diface) not allowed in OUTPUT or POSTROUTING rules" if ( $restriction & ( POSTROUTE_RESTRICT + OUTPUT_RESTRICT ) ) && port_to_bridge( $diface );
	    fatal_error "Destination Interface ($diface) not allowed when the destination zone is the firewall" if $restriction & INPUT_RESTRICT;
	    if ( $restriction & DESTIFACE_DISALLOW ) {
		if ( $chainref->{accounting} ) {
		    fatal_error "Destination Interface ($diface) not allowed in the $chainref->{name} chain";
		} else {
		    fatal_error "Destination Interface ($diface) not allowed in the mangle OUTPUT chain";
		}
	    }
	    
	    if ( $iiface ) {
		my $bridge = port_to_bridge( $diface );
		fatal_error "Source interface ($iiface) is not a port on the same bridge as the destination interface ( $diface )" if $bridge && $bridge ne source_port_to_bridge( $iiface );
	    }
	    
	    $chainref->{restricted} |= $restriction;
	    $rule .= match_dest_dev( $diface );
	}
    } else {
	$diface = '';
    }

    if ( $origdest ) {
	if ( $origdest eq '-' || ! have_capability( 'CONNTRACK_MATCH' ) ) {
	    $origdest = '';
	} elsif ( $origdest =~ /^detect:(.*)$/ ) {
	    #
	    # Either the filter part of a DNAT rule or 'detect' was given in the ORIG DEST column
	    #
	    my @interfaces = split /\s+/, $1;

	    if ( @interfaces > 1 ) {
		my $list = "";
		my $optional;

		for my $interface ( @interfaces ) {
		    $optional++ if interface_is_optional $interface;
		    $list = join( ' ', $list , get_interface_address( $interface ) );
		}

		push_command( $chainref , "for address in $list; do" , 'done' );

		push_command( $chainref , 'if [ $address != 0.0.0.0 ]; then' , 'fi' ) if $optional;

		$rule .= '-m conntrack --ctorigdst $address ';
	    } else {
		my $interface = $interfaces[0];
		my $variable  = get_interface_address( $interface );

		push_command( $chainref , "if [ $variable != 0.0.0.0 ]; then" , 'fi' ) if interface_is_optional( $interface );

		$rule .= "-m conntrack --ctorigdst $variable ";
	    }

	    $origdest = '';
	} else {
	    fatal_error "Invalid ORIGINAL DEST" if  $origdest =~ /^([^!]+)?,!([^!]+)$/ || $origdest =~ /.*!.*!/;

	    if ( $origdest =~ /^([^!]+)?!([^!]+)$/ ) {
		#
		# Exclusion
		#
		$onets = $1;
		$oexcl = $2;
	    } else {
		$oexcl = '';
		$onets = $origdest;
	    }

	    unless ( $onets ) {
		my @oexcl = mysplit $oexcl;
		if ( @oexcl == 1 ) {
		    $rule .= match_orig_dest( "!$oexcl" );
		    $oexcl = '';
		}
	    }
	}
    } else {
	$oexcl = '';
    }

    #
    # Determine if there is Source Exclusion
    #
    if ( $inets ) {
	( $inets, $iexcl ) = handle_network_list( $inets, 'SOURCE' );

	unless ( $inets || $iexcl =~ /^\+\[/ || ( $iiface && $restriction & POSTROUTE_RESTRICT ) ) {
	    my @iexcl = mysplit $iexcl, 1;
	    if ( @iexcl == 1 ) {
		$rule .= match_source_net "!$iexcl" , $restriction;
		$iexcl = '';
		$trivialiexcl = 1;
	    }
	}
    } else {
	$iexcl = '';
    }

    #
    # Determine if there is Destination Exclusion
    #
    if ( $dnets ) {
	( $dnets, $dexcl ) = handle_network_list( $dnets, 'DEST' );

	unless ( $dnets || $dexcl =~ /^\+\[/ ) {
	    my @dexcl = mysplit $dexcl, 1;
	    if ( @dexcl == 1 ) {
		$rule .= match_dest_net "!$dexcl";
		$dexcl = '';
		$trivialdexcl = 1;
	    }
	}
    } else {
	$dexcl = '';
    }

    $inets = ALLIP unless $inets;
    $dnets = ALLIP unless $dnets;
    $onets = ALLIP unless $onets;

    fatal_error "SOURCE interface may not be specified with a source IP address in the POSTROUTING chain"   if $restriction == POSTROUTE_RESTRICT && $iiface && ( $inets ne ALLIP || $iexcl || $trivialiexcl);
    fatal_error "DEST interface may not be specified with a destination IP address in the PREROUTING chain" if $restriction == PREROUTE_RESTRICT &&  $diface && ( $dnets ne ALLIP || $dexcl || $trivialdexcl);

    my ( $fromref, $done );

    if ( $iexcl || $dexcl || $oexcl ) {
	#
	# We have non-trivial exclusion
	#
	if ( $disposition eq 'RETURN' || $disposition eq 'CONTINUE' ) {
	    #
	    # We can't use an exclusion chain -- we mark those packets to be excluded and then condition the rules generated in the block below on the mark value
	    #
	    require_capability 'MARK_ANYWHERE' , 'Exclusion in ACCEPT+/CONTINUE/NONAT rules', 's' unless $table eq 'mangle';

	    fatal_error "Exclusion in ACCEPT+/CONTINUE/NONAT rules requires the Multiple Match capability in your kernel and iptables"
		if $rule =~ / -m mark / && ! $globals{KLUDGEFREE};
	    #
	    # Clear the exclusion bit
	    #
	    add_ijump $chainref , j => 'MARK --and-mark ' . in_hex( $globals{EXCLUSION_MASK} ^ 0xffffffff );
	    #
	    # Mark packet if it matches any of the exclusions
	    #
	    my $exclude = '-j MARK --or-mark ' . in_hex( $globals{EXCLUSION_MASK} );

	    for ( mysplit $iexcl ) {
		my $cond = conditional_rule( $chainref, $_ );
		add_rule $chainref, ( match_source_net $_ , $restriction, $mac ) . $exclude;
		conditional_rule_end( $chainref ) if $cond;
	    }

	    for ( mysplit $dexcl ) {
		my $cond = conditional_rule( $chainref, $_ );
		add_rule $chainref, ( match_dest_net $_ ) . $exclude;
		conditional_rule_end( $chainref ) if $cond;
	    }

	    for ( mysplit $oexcl ) {
		my $cond = conditional_rule( $chainref, $_ );
		add_rule $chainref, ( match_orig_dest $_ ) . $exclude;
		conditional_rule_end( $chainref ) if $cond;
	    }
	    #
	    # Augment the rule to include 'not excluded'
	    #
	    $rule .= '-m mark --mark 0/' . in_hex( $globals{EXCLUSION_MASK} ) . ' ';
	} else {
	    #
	    # Create the Exclusion Chain
	    #
	    my $echain = newexclusionchain( $table );

	    my $echainref = new_chain $table, $echain;
	    #
	    # Use the current rule and send all possible matches to the exclusion chain
	    #
	    for my $onet ( mysplit $onets ) {
		
		my $cond = conditional_rule( $chainref, $onet );

		$onet = match_orig_dest $onet;

		for my $inet ( mysplit $inets ) {

		    my $cond = conditional_rule( $chainref, $inet );

		    my $source_match = match_source_net( $inet, $restriction, $mac ) if $globals{KLUDGEFREE};

		    for my $dnet ( mysplit $dnets ) {
			$source_match = match_source_net( $inet, $restriction, $mac ) unless $globals{KLUDGEFREE};
			add_expanded_jump( $chainref, $echainref, join( '', $rule, $source_match, match_dest_net( $dnet ), $onet ) );
		    }

		    conditional_rule_end( $chainref ) if $cond;
		}

		conditional_rule_end( $chainref ) if $cond;
	    }
		
	    #
	    # Generate RETURNs for each exclusion
	    #
	    for ( mysplit $iexcl ) {
		my $cond = conditional_rule( $echainref, $_ );
		add_rule $echainref, ( match_source_net $_ , $restriction, $mac ) . '-j RETURN';
		conditional_rule_end( $echainref ) if $cond;
	    }

	    for ( mysplit $dexcl ) {
		my $cond = conditional_rule( $echainref, $_ );
		add_rule $echainref, ( match_dest_net $_ ) . '-j RETURN';
		conditional_rule_end( $echainref ) if $cond;
	    }

	    for ( mysplit $oexcl ) {
		my $cond = conditional_rule( $echainref, $_ );
		add_rule $echainref, ( match_orig_dest $_ ) . '-j RETURN';
		conditional_rule_end( $echainref ) if $cond;
	    }
	    #
	    # Log rule
	    #
	    log_rule_limit( $loglevel ,
			    $echainref ,
			    $chain,
			    $disposition eq 'reject' ? 'REJECT' : $disposition ,
			    '' ,
			    $logtag ,
			    'add' ,
			    '' )
		if $loglevel;
	    #
	    # Generate Final Rule
	    #
	    if ( $targetref ) {
		add_expanded_jump( $fromref = $echainref, $targetref, $exceptionrule );
	    } else {
		add_rule( $fromref = $echainref, $exceptionrule . $jump , 1 ) unless $disposition eq 'LOG';
	    }

	    $done = 1;
	}
    }

    unless ( $done ) {
	#
	# No non-trivial exclusions or we're using marks to handle them
	#
	for my $onet ( mysplit $onets ) {
	    my $cond = conditional_rule( $chainref, $onet );

	    $onet = match_orig_dest $onet;
	    
	    for my $inet ( mysplit $inets ) {
		my $source_match;

		my $cond = conditional_rule( $chainref, $inet );
		
		$source_match = match_source_net( $inet, $restriction, $mac ) if $globals{KLUDGEFREE};

		for my $dnet ( mysplit $dnets ) {
		    $source_match  = match_source_net( $inet, $restriction, $mac ) unless $globals{KLUDGEFREE};
		    my $dest_match = match_dest_net( $dnet );
		    my $matches = join( '', $rule, $source_match, $dest_match, $onet );

		    my $cond = conditional_rule( $chainref, $dnet );

		    if ( $loglevel eq '' ) {
			#
			# No logging -- add the target rule with matches to the rule chain
			#
			if ( $targetref ) {
			    add_expanded_jump( $fromref = $chainref, $targetref , $matches );
			} else {
			    add_rule( $fromref = $chainref, $matches . $jump , 1 );
			}
		    } elsif ( $disposition eq 'LOG' || $disposition eq 'COUNT' ) {
			#
			# The log rule must be added with matches to the rule chain
			#
			log_rule_limit(
				       $loglevel ,
				       $chainref ,
				       $chain,
				       $disposition eq 'reject' ? 'REJECT' : $disposition ,
				       '' ,
				       $logtag ,
				       'add' ,
				       $matches
				      );
		    } elsif ( $logname || $target =~ /^RETURN\b/ ) {
			log_rule_limit(
				       $loglevel ,
				       $chainref ,
				       $logname || $chain,
				       $disposition eq 'reject' ? 'REJECT' : $disposition ,
				       '',
				       $logtag,
				       'add',
				       $matches );

			if ( $targetref ) {
			    add_expanded_jump( $fromref = $chainref, $targetref, $matches );
			} else {
			    add_rule( $fromref = $chainref, $matches . $jump, 1 );
			}
		    } else {
			#
			# Find/Create a chain that both logs and applies the target action
			# and jump to the log chain if all of the rule's conditions are met
			#
			add_jump( $chainref,
				  logchain( $chainref, $loglevel, $logtag, $exceptionrule , $disposition, $target ),
				  $builtin_target{$disposition},
				  $matches,
				  1 );
		    }

		    conditional_rule_end( $chainref ) if $cond;
		}

		conditional_rule_end( $chainref ) if $cond;
	    }

	    conditional_rule_end( $chainref ) if $cond;
	}
    }

    $chainref->{restricted} |= INPUT_RESTRICT if $mac;

    while ( @ends ) {
	decr_cmd_level $chainref;
	add_commands $chainref, pop @ends;
    }

    $diface;
}

#
# Where a zone sharing a multi-zone interface has an 'in' blacklist rule, move the rule to the beginning of
# the associated interface chain
#
sub promote_blacklist_rules() {
    my $chainbref = $filter_table->{blacklst};

    return 1 unless $chainbref;

    my $promoted = 1;

    while ( $promoted ) {
	$promoted = 0;
	#
	# Copy 'blacklst''s references since they will change in the following loop
	#
	my @references = map $filter_table->{$_}, keys %{$chainbref->{references}};

	for my $chain1ref ( @references ) {
	    assert( $chain1ref->{blacklist} == 1 );

	    my $copied = 0;
	    my $rule   = $chain1ref->{rules}[0];
	    my $chain1 = $chain1ref->{name};

	    for my $chain2ref ( map $filter_table->{$_}, keys %{$chain1ref->{references}} ) {
		unless ( $chain2ref->{builtin} ) {
		    #
		    # This is not INPUT or FORWARD -- we wouldn't want to move the
		    # rule to the head of one of those chains
		    $copied++;
		    #
		    # Copy the blacklist rule to the head of the parent chain (after any
		    # filter rules) unless it already has a blacklist rule.
		    #
		    unless ( $chain2ref->{blacklist} ) {
			splice @{$chain2ref->{rules}}, $chain2ref->{filtered}, 0, $rule;
			add_reference $chain2ref, $chainbref;
			$chain2ref->{blacklist} = 1;
		    }
		}
	    }

	    if ( $copied ) {
		shift @{$chain1ref->{rules}};
		$chain1ref->{blacklist} = 0;
		delete_reference $chain1ref, $chainbref;
		$promoted = 1;
	    }
	}
    }
}

#
# The following code generates the input to iptables-restore from the contents of the
# @rules arrays in the chain table entries.
#
# We always write the iptables-restore input into a file then pass the
# file to iptables-restore. That way, if things go wrong, the user (and Shorewall support)
# has (have) something to look at to determine the error
#
# We may have to generate part of the input at run-time. The rules array in each chain
# table entry may contain both rules (begin with '-A') or shell source. We alternate between
# writing the rules ('-A') into the temporary file to be passed to iptables-restore
# (CAT_MODE) and and writing shell source into the generated script (CMD_MODE).
#
# The following two functions are responsible for the mode transitions.
#
sub enter_cat_mode() {
    emit '';
    emit 'cat >&3 << __EOF__';
    $mode = CAT_MODE;
}

sub enter_cmd_mode() {
    emit_unindented "__EOF__\n" if $mode == CAT_MODE;
    $mode = CMD_MODE;
}

#
# Emits the passed rule (input to iptables-restore) or command
#
sub emitr( $$ ) {
    my ( $chainref, $ruleref ) = @_;

    assert( $chainref );

    if ( $ruleref ) {
	if ( $ruleref->{mode} == CAT_MODE ) {
	    #
	    # A rule
	    #
	    enter_cat_mode unless $mode == CAT_MODE;
	    emit_unindented format_rule( $chainref, $ruleref );
	} else {
	    #
	    # A command
	    #
	    enter_cmd_mode unless $mode == CMD_MODE;
	    
	    if ( exists $ruleref->{cmd} ) {
		emit join( '', '    ' x $ruleref->{cmdlevel}, $ruleref->{cmd} );
	    } else {
		#
		# Must preserve quotes in the rule
		#
		( my $rule = format_rule( $chainref, $ruleref ) ) =~ s/"/\\"/g;
		
		emit join( '', '    ' x $ruleref->{cmdlevel} , 'echo "' , $rule, '" >&3' );
	    }
	}
    }
}

#
# These versions are used by 'preview'
#
sub enter_cat_mode1() {
    print "\n";
    emitstd "cat << __EOF__";
    $mode = CAT_MODE;
}

sub enter_cmd_mode1() {
    print "__EOF__\n\n" if $mode == CAT_MODE;
    $mode = CMD_MODE;
}

sub emitr1( $$ ) {
    my ( $chainref, $ruleref ) = @_;

    if ( $ruleref ) {
	if ( $ruleref->{mode} == CAT_MODE ) {
	    #
	    # A rule
	    #
	    enter_cat_mode1 unless $mode == CAT_MODE;

	    print format_rule( $chainref, $ruleref ) . "\n";
	} else {
	    #
	    # A command
	    #
	    enter_cmd_mode1 unless $mode == CMD_MODE;

	    if ( exists $ruleref->{cmd} ) {
		emitstd $ruleref->{cmd};
	    } else {
		( my $rule = format_rule( $chainref, $ruleref ) ) =~ s/"/\\"/g;
		
		emitstd join( '', '    ' x $ruleref->{cmdlevel} , 'echo "' , $rule, '" >&3' );
	    }
	}
    }
}

#
# Emit code to save the dynamic chains to hidden files in ${VARDIR}
#

sub save_dynamic_chains() {

    my $tool = $family == F_IPV4 ? '${IPTABLES}-save' : '${IP6TABLES}-save';

    emit ( 'if [ "$COMMAND" = restart -o "$COMMAND" = refresh ]; then' );
    push_indent;

emit <<"EOF";
if chain_exists 'UPnP -t nat'; then
    $tool -t nat | grep '^-A UPnP ' > \${VARDIR}/.UPnP
else
    rm -f \${VARDIR}/.UPnP
fi

if chain_exists forwardUPnP; then
    $tool -t filter | grep '^-A forwardUPnP ' > \${VARDIR}/.forwardUPnP
else
    rm -f \${VARDIR}/.forwardUPnP
fi

if chain_exists dynamic; then
    $tool -t filter | grep '^-A dynamic ' > \${VARDIR}/.dynamic
else
    rm -f \${VARDIR}/.dynamic
fi
EOF

    pop_indent;
    emit ( 'else' );
    push_indent;

emit <<"EOF";
rm -f \${VARDIR}/.UPnP
rm -f \${VARDIR}/.forwardUPnP

if [ "\$COMMAND" = stop -o "\$COMMAND" = clear ]; then
    if chain_exists dynamic; then
        $tool -t filter | grep '^-A dynamic ' > \${VARDIR}/.dynamic
    fi
fi
EOF
    pop_indent;

    emit ( 'fi' ,
	   '' );
}

sub ensure_ipset( $ ) {
    my $set = shift;

    if ( $family == F_IPV4 ) {
	if ( have_capability 'IPSET_V5' ) {
	    emit ( "    qt \$IPSET -L $set -n || \$IPSET -N $_ hash:ip family inet" );
	} else {
	    emit ( "    qt \$IPSET -L $set -n || \$IPSET -N $_ iphash" );
	}
    } else {
	emit ( "    qt \$IPSET -L $set -n || \$IPSET -N $_ hash:ip family inet6" );
    }
}
    

sub load_ipsets() {

    my @ipsets = all_ipsets;

    if ( @ipsets || ( $config{SAVE_IPSETS} && have_ipset_rules ) ) {
	emit ( '',
	       'local hack',
	       '',
	       'case $IPSET in',
	       '    */*)',
	       '        [ -x "$IPSET" ] || startup_error "IPSET=$IPSET does not exist or is not executable"',
	       '        ;;',
	       '    *)',
	       '        IPSET="$(mywhich $IPSET)"',
	       '        [ -n "$IPSET" ] || startup_error "The ipset utility cannot be located"' ,
	       '        ;;',
	       'esac' ,
	       '' ,
	       'if [ "$COMMAND" = start ]; then' );
	
	if ( $config{SAVE_IPSETS} ) {
	    emit ( '    if [ -f ${VARDIR}/ipsets.save ]; then' ,
		   '        $IPSET -F' ,
		   '        $IPSET -X' ,
		   '        $IPSET -R < ${VARDIR}/ipsets.save' ,
		   '    fi' );

	    if ( @ipsets ) {
		emit ( '' );
		ensure_ipset( $_ ) for @ipsets;
		emit ( '' );
	    }
	} else {
	    ensure_ipset( $_ ) for @ipsets;
	}

	emit ( 'elif [ "$COMMAND" = restore -a -z "$g_recovering" ]; then' );

	if ( $config{SAVE_IPSETS} ) {
	    emit( '    if [ -f $(my_pathname)-ipsets ]; then' ,
		  '        if chain_exists shorewall; then' ,
		  '            startup_error "Cannot restore $(my_pathname)-ipsets with Shorewall running"' ,
		  '        else' ,
		  '            $IPSET -F' ,
		  '            $IPSET -X' ,
		  '            $IPSET -R < $(my_pathname)-ipsets' ,
		  '        fi' ,
		  '    fi' ,
		);

	    if ( @ipsets ) {
		emit ( '' );
		ensure_ipset( $_ ) for @ipsets;
		emit ( '' );
	    }
	} else {
	    ensure_ipset( $_ ) for @ipsets;
	}
	
	if ( @ipsets ) {
	    emit ( 'elif [ "$COMMAND" = restart ]; then' );
	    ensure_ipset( $_ ) for @ipsets;
	}

	emit( 'elif [ "$COMMAND" = stop ]; then' );

	if ( @ipsets ) {
	    ensure_ipset( $_ ) for @ipsets;
	    emit( '' );
	}
	
	if ( $family == F_IPV4 ) {
	    emit ( '    if [ -f /etc/debian_version ] && [ $(cat /etc/debian_version) = 5.0.3 ]; then' ,
		   '        #',
		   '        # The \'grep -v\' is a hack for a bug in ipset\'s nethash implementation when xtables-addons is applied to Lenny' ,
		   '        #',
		   '        hack=\'| grep -v /31\'' ,
		   '    else' ,
		   '        hack=' ,
		   '    fi' ,
		   '',
		   '    if eval $IPSET -S $hack > ${VARDIR}/ipsets.tmp; then' ,
		   '        grep -qE -- "^(-N|create )" ${VARDIR}/ipsets.tmp && mv -f ${VARDIR}/ipsets.tmp ${VARDIR}/ipsets.save' ,
		   '    fi' );
	} else {
	    emit ( '    if eval $IPSET -S > ${VARDIR}/ipsets.tmp; then' ,
		   '        grep -qE -- "^(-N|create )" ${VARDIR}/ipsets.tmp && mv -f ${VARDIR}/ipsets.tmp ${VARDIR}/ipsets.save' ,
		   '    fi' );
	}
	    
	if ( @ipsets ) {
	    emit( 'elif [ "$COMMAND" = refresh ]; then' );
	    ensure_ipset( $_ ) for @ipsets;
	}

	emit ( 'fi' ,
	       '' );
    }
}

#
#
# Generate the netfilter input
#
sub create_netfilter_load( $ ) {
    my $test = shift;

    my @table_list;

    push @table_list, 'raw'    if have_capability( 'RAW_TABLE' );
    push @table_list, 'nat'    if have_capability( 'NAT_ENABLED' );
    push @table_list, 'mangle' if have_capability( 'MANGLE_ENABLED' ) && $config{MANGLE_ENABLED};
    push @table_list, 'filter';

    $mode = NULL_MODE;

    emit ( '#',
	   '# Create the input to iptables-restore/ip6tables-restore and pass that input to the utility',
	   '#',
	   'setup_netfilter()',
	   '{'
	   );

    push_indent;

    my $utility = $family == F_IPV4 ? 'iptables-restore' : 'ip6tables-restore';
    my $UTILITY = $family == F_IPV4 ? 'IPTABLES_RESTORE' : 'IP6TABLES_RESTORE';

    save_progress_message "Preparing $utility input...";

    emit '';

    emit "exec 3>\${VARDIR}/.${utility}-input";

    enter_cat_mode;

    my $date = localtime;

    unless ( $test ) {
	emit_unindented '#';
	emit_unindented "# Generated by Shorewall $globals{VERSION} - $date";
	emit_unindented '#';
    }

    for my $table ( @table_list ) {
	emit_unindented "*$table";

	my @chains;
	#
	# iptables-restore seems to be quite picky about the order of the builtin chains
	#
	for my $chain ( @builtins ) {
	    my $chainref = $chain_table{$table}{$chain};
	    if ( $chainref ) {
		assert( $chainref->{cmdlevel} == 0 );
		emit_unindented ":$chain $chainref->{policy} [0:0]";
		push @chains, $chainref;
	    }
	}
	#
	# First create the chains in the current table
	#
	for my $chain ( grep $chain_table{$table}{$_}->{referenced} , ( sort keys %{$chain_table{$table}} ) ) {
	    my $chainref =  $chain_table{$table}{$chain};
	    unless ( $chainref->{builtin} ) {
		assert( $chainref->{cmdlevel} == 0 );
		emit_unindented ":$chainref->{name} - [0:0]";
		push @chains, $chainref;
	    }
	}
	#
	# Then emit the rules
	#
	for my $chainref ( @chains ) {
	    emitr( $chainref, $_ ) for @{$chainref->{rules}};
	}
	#
	# Commit the changes to the table
	#
	enter_cat_mode unless $mode == CAT_MODE;
	emit_unindented 'COMMIT';
    }

    enter_cmd_mode;
    #
    # Now generate the actual ip[6]tables-restore command
    #
    emit(  'exec 3>&-',
	   '',
	   '[ -n "$DEBUG" ] && command=debug_restore_input || command=$' . $UTILITY,
	   '',
	   'progress_message2 "Running $command..."',
	   '',
	   "cat \${VARDIR}/.${utility}-input | \$command # Use this nonsensical form to appease SELinux",
	   'if [ $? != 0 ]; then',
	   qq(    fatal_error "iptables-restore Failed. Input is in \${VARDIR}/.${utility}-input"),
	   "fi\n"
	   );

    pop_indent;

    emit "}\n";
}

#
# Preview netfilter input
#
sub preview_netfilter_load() {

    my @table_list;

    push @table_list, 'raw'    if have_capability( 'RAW_TABLE' );
    push @table_list, 'nat'    if have_capability( 'NAT_ENABLED' );
    push @table_list, 'mangle' if have_capability( 'MANGLE_ENABLED' ) && $config{MANGLE_ENABLED};
    push @table_list, 'filter';

    $mode = NULL_MODE;

    push_indent;

    enter_cat_mode1;

    my $date = localtime;

    print "#\n# Generated by Shorewall $globals{VERSION} - $date\n#\n";

    for my $table ( @table_list ) {
	print "*$table\n";

	my @chains;
	#
	# iptables-restore seems to be quite picky about the order of the builtin chains
	#
	for my $chain ( @builtins ) {
	    my $chainref = $chain_table{$table}{$chain};
	    if ( $chainref ) {
		assert( $chainref->{cmdlevel} == 0 );
		print ":$chain $chainref->{policy} [0:0]\n";
		push @chains, $chainref;
	    }
	}
	#
	# First create the chains in the current table
	#
	for my $chain ( grep $chain_table{$table}{$_}->{referenced} , ( sort keys %{$chain_table{$table}} ) ) {
	    my $chainref =  $chain_table{$table}{$chain};
	    unless ( $chainref->{builtin} ) {
		assert( $chainref->{cmdlevel} == 0 );
		print ":$chainref->{name} - [0:0]\n";
		push @chains, $chainref;
	    }
	}
	#
	# Then emit the rules
	#
	for my $chainref ( @chains ) {
	    emitr1($chainref, $_ ) for @{$chainref->{rules}};
	}
	#
	# Commit the changes to the table
	#
	enter_cat_mode1 unless $mode == CAT_MODE;
	print "COMMIT\n";
    }

    enter_cmd_mode1;

    pop_indent;

    print "\n";
}

#
# Generate the netfilter input for refreshing a list of chains
#
sub create_chainlist_reload($) {

    my $chains = $_[0];

    my @chains;

    unless ( $chains eq ':none:' ) {
	if ( $chains eq ':refresh:' ) {
	    $chains = '';
	} else {
	    @chains =  split_list $chains, 'chain';
	}

	unless ( @chains ) {
	    @chains = qw( blacklst ) if $filter_table->{blacklst};
	    push @chains, 'blackout' if $filter_table->{blackout};
	    push @chains, 'mangle:' if have_capability( 'MANGLE_ENABLED' ) && $config{MANGLE_ENABLED};
	    $chains = join( ',', @chains ) if @chains;
	}
    }

    $mode = NULL_MODE;

    emit(  'chainlist_reload()',
	   '{'
	   );

    push_indent;

    if ( @chains ) {
	my $word = @chains == 1 ? 'chain' : 'chains';

	progress_message2 "Compiling iptables-restore input for $word @chains...";
	save_progress_message "Preparing iptables-restore input for $word @chains...";

	emit '';

	my $table = 'filter';

	my %chains;

	my %tables;

	for my $chain ( @chains ) {
	    ( $table , $chain ) = split ':', $chain if $chain =~ /:/;

	    fatal_error "Invalid table ( $table )" unless $table =~ /^(nat|mangle|filter|raw)$/;

	    $chains{$table} = {} unless $chains{$table};

	    if ( $chain ) {
		my $chainref;
		fatal_error "No $table chain found with name $chain" unless $chainref = $chain_table{$table}{$chain};
		fatal_error "Built-in chains may not be refreshed" if $chainref->{builtin};
		
		if ( $chainseq{$table} && @{$chainref->{rules}} ) {
		    $tables{$table} = 1;
		} else {
		    $chains{$table}{$chain} = $chainref;
		}
	    } else {
		$tables{$table} = 1;
	    }
	}

	for $table ( keys %tables ) {
	    while ( my ( $chain, $chainref ) = each %{$chain_table{$table}} ) {
		$chains{$table}{$chain} = $chainref if $chainref->{referenced} && ! $chainref->{builtin};
	    }
	}

	emit 'exec 3>${VARDIR}/.iptables-restore-input';

	enter_cat_mode;

	for $table ( qw(raw nat mangle filter) ) {
	    my $tableref=$chains{$table};

	    next unless $tableref;

	    @chains = sort keys %$tableref;

	    emit_unindented "*$table";

	    for my $chain ( @chains ) {
		my $chainref = $tableref->{$chain};
		emit_unindented ":$chainref->{name} - [0:0]";
	    }

	    for my $chain ( @chains ) {
		my $chainref = $tableref->{$chain};
		my @rules = @{$chainref->{rules}};
		my $name = $chainref->{name};

		@rules = () unless @rules;
		#
		# Emit the chain rules
		#
		emitr($chainref, $_) for @rules;
	    }
	    #
	    # Commit the changes to the table
	    #
	    enter_cat_mode unless $mode == CAT_MODE;

	    emit_unindented 'COMMIT';
	}

	enter_cmd_mode;

	#
	# Now generate the actual ip[6]tables-restore command
	#
	emit(  'exec 3>&-',
	       '' );

	if ( $family == F_IPV4 ) {
	    emit ( 'progress_message2 "Running iptables-restore..."',
		   '',
		   'cat ${VARDIR}/.iptables-restore-input | $IPTABLES_RESTORE -n # Use this nonsensical form to appease SELinux',
		   'if [ $? != 0 ]; then',
		   '    fatal_error "iptables-restore Failed. Input is in ${VARDIR}/.iptables-restore-input"',
		   "fi\n"
		 );
	} else {
	    emit ( 'progress_message2 "Running ip6tables-restore..."',
		   '',
		   'cat ${VARDIR}/.iptables-restore-input | $IP6TABLES_RESTORE -n # Use this nonsensical form to appease SELinux',
		   'if [ $? != 0 ]; then',
		   '    fatal_error "ip6tables-restore Failed. Input is in ${VARDIR}/.iptables-restore-input"',
		   "fi\n"
		 );
	}
    } else {
	emit('true');
    }

    pop_indent;

    emit "}\n";
}

#
# Generate the netfilter input to stop the firewall
#
sub create_stop_load( $ ) {
    my $test = shift;

    my @table_list;

    push @table_list, 'raw'    if have_capability( 'RAW_TABLE' );
    push @table_list, 'nat'    if have_capability( 'NAT_ENABLED' );
    push @table_list, 'mangle' if have_capability( 'MANGLE_ENABLED' ) && $config{MANGLE_ENABLED};
    push @table_list, 'filter';

    my $utility = $family == F_IPV4 ? 'iptables-restore' : 'ip6tables-restore';
    my $UTILITY = $family == F_IPV4 ? 'IPTABLES_RESTORE' : 'IP6TABLES_RESTORE';

    emit '';

    emit(  '[ -n "$DEBUG" ] && command=debug_restore_input || command=$' . $UTILITY,
	   '',
	   'progress_message2 "Running $command..."',
	   '',
	   '$command <<__EOF__' );

    $mode = CAT_MODE;

    unless ( $test ) {
	my $date = localtime;
	emit_unindented '#';
	emit_unindented "# Generated by Shorewall $globals{VERSION} - $date";
	emit_unindented '#';
    }

    for my $table ( @table_list ) {
	emit_unindented "*$table";

	my @chains;
	#
	# iptables-restore seems to be quite picky about the order of the builtin chains
	#
	for my $chain ( @builtins ) {
	    my $chainref = $chain_table{$table}{$chain};
	    if ( $chainref ) {
		assert( $chainref->{cmdlevel} == 0 );
		emit_unindented ":$chain $chainref->{policy} [0:0]";
		push @chains, $chainref;
	    }
	}
	#
	# First create the chains in the current table
	#
	for my $chain ( grep $chain_table{$table}{$_}->{referenced} , ( sort keys %{$chain_table{$table}} ) ) {
	    my $chainref =  $chain_table{$table}{$chain};
	    unless ( $chainref->{builtin} ) {
		assert( $chainref->{cmdlevel} == 0 );
		emit_unindented ":$chainref->{name} - [0:0]";
		push @chains, $chainref;
	    }
	}
	#
	# Then emit the rules
	#
	for my $chainref ( @chains ) {
	    emitr( $chainref, $_ ) for @{$chainref->{rules}};
	}
	#
	# Commit the changes to the table
	#
	emit_unindented 'COMMIT';
    }

    emit_unindented '__EOF__';
    #
    # Test result
    #
    emit ('',
	  'if [ $? != 0 ]; then',
	   '    error_message "ERROR: $command Failed."',
	   "fi\n"
	 );

}

1;
