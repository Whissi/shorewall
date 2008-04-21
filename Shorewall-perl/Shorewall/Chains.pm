#
# Shorewall-perl 4.1 -- /usr/share/shorewall-perl/Shorewall/Chains.pm
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
		  add_jump
		  insert_rule
		  new_chain
		  new_manual_chain
		  ensure_manual_chain
		  log_rule_limit

		  %chain_table
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
				       NO_RESTRICT
				       PREROUTE_RESTRICT
				       INPUT_RESTRICT
				       OUTPUT_RESTRICT
				       POSTROUTE_RESTRICT
				       ALL_RESTRICT
				       
				       add_command
				       add_commands
				       move_rules
				       process_comment
				       no_comment
				       macro_comment
				       clear_comment
				       incr_cmd_level
				       decr_cmd_level
				       chain_base 
				       forward_chain
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
				       dynamic_fwd
				       dynamic_in
				       dynamic_out
				       dynamic_chains
				       zone_dynamic_chain
				       dnat_chain
				       snat_chain
				       ecn_chain
				       first_chains
				       ensure_chain
				       ensure_accounting_chain
				       ensure_mangle_chain
				       ensure_nat_chain
				       new_standard_chain
				       new_builtin_chain
				       new_nat_chain
				       ensure_filter_chain
				       initialize_chain_table
				       finish_section
				       setup_zone_mss
				       newexclusionchain
				       clearrule
				       do_proto
				       mac_match
				       verify_mark
				       verify_small_mark
				       validate_mark
				       do_test
				       do_ratelimit
				       do_user
				       do_tos
				       do_connbytes
				       match_source_dev
				       match_dest_dev
				       iprange_match
				       match_source_net
				       match_dest_net
				       match_orig_dest
				       match_ipsec_in
				       match_ipsec_out
				       log_rule
				       expand_rule
				       addnatjump
				       get_interface_address
				       get_interface_addresses
				       get_interface_bcasts
				       get_interface_gateway
				       get_interface_mac
				       set_global_variables
				       create_netfilter_load
				       create_chainlist_reload
				       $section
				       %sections
				       %targets
				     ) ],
		   );

Exporter::export_ok_tags('internal');

our $VERSION = 4.1.5;

#
# Chain Table
#
#    %chain_table { <table> => { <chain1>  => { name         => <chain name>
#                                               table        => <table name>
#                                               is_policy    => undef|1 -- if 1, this is a policy chain
#                                               is_optional  => undef|1 -- See below.
#                                               referenced   => undef|1 -- If 1, will be written to the iptables-restore-input.
#                                               builtin      => undef|1 -- If 1, one of Netfilter's built-in chains.
#                                               manual       => undef|1 -- If 1, a manual chain.
#                                               accounting   => undef|1 -- If 1, an accounting chain
#                                               log          => <logging rule number for use when LOGRULENUMBERS>
#                                               policy       => <policy>
#                                               policychain  => <name of policy chain> -- self-reference if this is a policy chain
#                                               policypair   => [ <policy source>, <policy dest> ] -- Used for reporting duplicated policies
#                                               loglevel     => <level>
#                                               synparams    => <burst/limit>
#                                               synchain     => <name of synparam chain>
#                                               default      => <default action>
#                                               cmdlevel     => <number of open loops or blocks in runtime commands>
#                                               rules        => [ <rule1>
#                                                                 <rule2>
#                                                                 ...
#                                                               ]
#                                             } ,
#                                <chain2> => ...
#                              }
#                 }
#
#       'is_optional' only applies to policy chains; when true, indicates that this is a provisional policy chain which might be
#       replaced. Policy chains created under the IMPLICIT_CONTINUE=Yes option are marked with is_optional == 1.
#
#       Only 'referenced' chains get written to the iptables-restore input.
#
#       'loglevel', 'synparams', 'synchain' and 'default' only apply to policy chains.
#
our %chain_table;
our $nat_table;
our $mangle_table;
our $filter_table;
#
# It is a layer violation to keep information about the rules file sections in this module but in Shorewall, the rules file
# and the filter table are very closely tied. By keeping the information here, we avoid making several other modules dependent
# on Shorewall::Rules.
#
our %sections;
our $section;

our $comment;

use constant { STANDARD => 1,              #defined by Netfilter
	       NATRULE  => 2,              #Involves NAT
	       BUILTIN  => 4,              #A built-in action
	       NONAT    => 8,              #'NONAT' or 'ACCEPT+'
	       NATONLY  => 16,             #'DNAT-' or 'REDIRECT-'
	       REDIRECT => 32,             #'REDIRECT'
	       ACTION   => 64,             #An action (may be built-in)
	       MACRO    => 128,            #A Macro
	       LOGRULE  => 256,            #'LOG'
	       NFQ      => 512,            #'NFQUEUE'
	       CHAIN    => 1024,           #Manual Chain
	   };

our %targets;
#
# expand_rule() restrictions
#
use constant { NO_RESTRICT        => 0,   # FORWARD chain rule     - Both -i and -o may be used in the rule
	       PREROUTE_RESTRICT  => 1,   # PREROUTING chain rule  - -o converted to -d <address list> using main routing table
	       INPUT_RESTRICT     => 4,   # INPUT chain rule       - -o not allowed
	       OUTPUT_RESTRICT    => 8,   # OUTPUT chain rule      - -i not allowed
	       POSTROUTE_RESTRICT => 16,  # POSTROUTING chain rule - -i converted to -s <address list> using main routing table
	       ALL_RESTRICT       => 12   # fw->fw rule            - neither -i nor -o allowed
	       };
our $exclseq;
our $iprangematch;
our $chainseq;

our %interfaceaddr;
our %interfaceaddrs;
our %interfacenets;
our %interfacemacs;
our %interfacebcasts;
our %interfacegateways;

our @builtins = qw(PREROUTING INPUT FORWARD OUTPUT POSTROUTING);

#
# Mode of the generator.
#
use constant { NULL_MODE => 0 ,   # Generating neither shell commands nor iptables-restore input
	       CAT_MODE  => 1 ,   # Generating iptables-restore input
	       CMD_MODE  => 2 };  # Generating shell commands.

our $mode;

#
# Initialize globals -- we take this novel approach to globals initialization to allow
#                       the compiler to run multiple times in the same process. The
#                       initialize() function does globals initialization for this
#                       module and is called from an INIT block below. The function is
#                       also called by Shorewall::Compiler::compiler at the beginning of
#                       the second and subsequent calls to that function.
#

sub initialize() {
    %chain_table = ( raw    => {} ,
		     mangle => {},
		     nat    => {},
		     filter => {} );

    $nat_table    = $chain_table{nat};
    $mangle_table = $chain_table{mangle};
    $filter_table = $chain_table{filter};

    #
    # These get set to 1 as sections are encountered.
    #
    %sections = ( ESTABLISHED => 0,
		  RELATED     => 0,
		  NEW         => 0
		  );
    #
    # Current rules file section.
    #
    $section  = 'ESTABLISHED';
    #
    # Contents of last COMMENT line.
    #
    $comment = '';
    #
    #   As new targets (Actions and Macros) are discovered, they are added to the table
    #
    %targets = ('ACCEPT'          => STANDARD,
		'ACCEPT+'         => STANDARD  + NONAT,
		'ACCEPT!'         => STANDARD,
		'NONAT'           => STANDARD  + NONAT + NATONLY,
		'DROP'            => STANDARD,
		'DROP!'           => STANDARD,
		'REJECT'          => STANDARD,
		'REJECT!'         => STANDARD,
		'DNAT'            => NATRULE,
		'DNAT-'           => NATRULE  + NATONLY,
		'REDIRECT'        => NATRULE  + REDIRECT,
		'REDIRECT-'       => NATRULE  + REDIRECT + NATONLY,
		'LOG'             => STANDARD + LOGRULE,
		'CONTINUE'        => STANDARD,
		'CONTINUE!'       => STANDARD,
		'QUEUE'           => STANDARD,
		'QUEUE!'          => STANDARD,
                'NFQUEUE'         => STANDARD + NFQ,
                'NFQUEUE!'        => STANDARD + NFQ,
		'SAME'            => NATRULE,
		'SAME-'           => NATRULE  + NATONLY,
		'dropBcast'       => BUILTIN  + ACTION,
		'allowBcast'      => BUILTIN  + ACTION,
		'dropNotSyn'      => BUILTIN  + ACTION,
		'rejNotSyn'       => BUILTIN  + ACTION,
		'dropInvalid'     => BUILTIN  + ACTION,
		'allowInvalid'    => BUILTIN  + ACTION,
		'allowinUPnP'     => BUILTIN  + ACTION,
		'forwardUPnP'     => BUILTIN  + ACTION,
		'Limit'           => BUILTIN  + ACTION,
		);
    #
    # Used to sequence 'exclusion' chains with names 'excl0', 'excl1', ...
    #
    $exclseq = 0;
    #
    # Used to suppress duplicate match specifications.
    #
    $iprangematch = 0;
    #
    # Sequence for naming temporary chains
    #
    $chainseq = undef;
    #
    # Keep track of which interfaces have active 'address', 'addresses', 'networks', etc. variables
    #
    %interfaceaddr      = ();
    %interfaceaddrs     = ();
    %interfacenets      = ();
    %interfacemacs      = ();
    %interfacebcasts    = ();
    %interfacegateways  = ();
}

INIT {
    initialize;
}

#
# Add a run-time command to a chain. Arguments are:
#
#    Chain reference , Command
#

#
# Process a COMMENT line (in $currentline)
#
sub process_comment() {
    if ( $capabilities{COMMENTS} ) {
	( $comment = $currentline ) =~ s/^\s*COMMENT\s*//;
	$comment =~ s/\s*$//;
    } else {
	warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
    }
}

#
# Returns True if there is a current COMMENT or if COMMENTS are not available.
#
sub no_comment() {
    $comment ? 1 : $capabilities{COMMENTS} ? 0 : 1;
}

#
# Clear the $comment variable
#
sub clear_comment() {
    $comment = '';
}

#
# Set $comment to the passed unless there is a current comment
#
sub macro_comment( $ ) {
    my $macro = $_[0];
    
    $comment = $macro unless $comment || ! ( $capabilities{COMMENTS} && $config{AUTO_COMMENT} );
}

#
# Functions to manipulate cmdlevel
#
sub incr_cmd_level( $ ) {
    $_[0]->{cmdlevel}++;
}

sub decr_cmd_level( $ ) {
    fatal_error "Internal error in decr_cmd_level()" if --$_[0]->{cmdlevel} < 0;
}

sub add_command($$)
{
    my ($chainref, $command) = @_;

    push @{$chainref->{rules}}, join ('', '    ' x $chainref->{cmdlevel} , $command );

    $chainref->{referenced} = 1;
}

sub add_commands {
    my $chainref = shift @_;

    for my $command ( @_ ) {
	push @{$chainref->{rules}}, join ('', '    ' x $chainref->{cmdlevel} , $command );
    }

    $chainref->{referenced} = 1;
}

sub push_rule( $$ ) {
    my ($chainref, $rule) = @_;

    $rule .= qq( -m comment --comment "$comment") if $comment;

    if ( $chainref->{cmdlevel} ) {
	$rule =~ s/"/\\"/g; #Must preserve quotes in the rule
	add_command $chainref , qq(echo "-A $chainref->{name} $rule" >&3);
    } else {
	push @{$chainref->{rules}}, join( ' ', '-A' , $chainref->{name}, $rule );
	$chainref->{referenced} = 1;
    }
}

#
# Add a rule to a chain. Arguments are:
#
#    Chain reference , Rule [, Expand-long-dest-port-lists ]
#
sub add_rule($$;$)
{
    my ($chainref, $rule, $expandports) = @_;

    fatal_error 'Internal Error in add_rule()' if reftype $rule;

    $iprangematch = 0;
    #
    # Pre-processing the port lists as was done in Shorewall-shell results in port-list
    # processing driving the rest of rule generation.
    #
    # By post-processing each rule generated by expand_rule(), we avoid all of that
    # messiness and replace it with the following localized messiness.
    #
    # Because source ports are seldom specified and source port lists are rarer still,
    # we only worry about the destination ports.
    #
    if ( $expandports && $rule =~  '^(.* --dports\s+)([^ ]+)(.*)$' ) {
	#
	# Rule has a --dports specification
	#
	my ($first, $ports, $rest) = ( $1, $2, $3 );

	if ( ( $ports =~ tr/:,/:,/ ) > 15 ) {
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

		push_rule ( $chainref, join( '', $first, $newports, $rest ) );
	    }
	} else {
	    push_rule ( $chainref, $rule );
	}
    } else {
	push_rule ( $chainref, $rule );
    }
}

#
# Add a jump from the chain represented by the reference in the first argument to
# the target in the second argument. The optional third argument specifies any
# matches to be included in the rule and must end with a space character if it is non-null.
#

sub add_jump( $$;$ ) {
    my ( $fromref, $to, $predicate ) = @_;

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
	$toref = ensure_chain( $fromref->{table} , $to ) unless ( $targets{$to} || 0 ) & STANDARD;
    }
    
    #
    # If the destination is a chain, mark it referenced
    #
    $toref->{referenced} = 1 if $toref;

    add_rule ($fromref, join( '', $predicate, "-j $to" ) );
}

#
# Insert a rule into a chain. Arguments are:
#
#    Chain reference , Rule Number, Rule
#
sub insert_rule($$$)
{
    my ($chainref, $number, $rule) = @_;

    fatal_error 'Internal Error in insert_rule()' if $chainref->{cmdlevel};

    $rule .= "-m comment --comment \"$comment\"" if $comment;

    splice( @{$chainref->{rules}}, $number - 1, 0,  join( ' ', '-A', $chainref->{name}, $rule ) );

    $iprangematch = 0;

    $chainref->{referenced} = 1;

}

#
# Move the rules from one chain to another
#
# The rules generated by interface options are added to the interfaces's input chain and
# forward chain. Shorewall::Rules::generate_matrix() may decide to move those rules to
# a zone-oriented chain, hence this function.
#
# The source chain must not have any run-time code included in its rules. 
#
sub move_rules( $$ ) {
    my ($chain1, $chain2 ) = @_;

    if ( $chain1->{referenced} ) {
	my @rules = @{$chain1->{rules}};

	for ( @rules ) {
	    fatal_error "Internal Error in move_rules()" unless /^-A/;
	    s/ $chain1->{name} / $chain2->{name} /;
	}

	splice @{$chain2->{rules}}, 0, 0, @rules;

	$chain2->{referenced} = 1;
	$chain1->{referenced} = 0;
	$chain1->{rules}      = [];
    }
}

#
# Form the name of a chain.
#
sub chain_base($) {
    my $chain = $_[0];

    $chain =~ s/^@/at_/;
    $chain =~ tr/[.\-%@]/_/;
    $chain =~ s/\+$//;
    $chain;
}

sub chain_base_cond($) {
    $config{DYNAMIC_ZONES} ? chain_base($_[0]) : $_[0];
}

#
# Forward Chain for an interface
#
sub forward_chain($)
{
    chain_base_cond($_[0]) . '_fwd';
}

#
# Forward Chain for a zone
#
sub zone_forward_chain($) {
    chain_base($_[0]) . '_frwd';
}

#
# Returns true if we're to use the interface's forward chain
#
sub use_forward_chain($) {
    my $interface = $_[0];
    my $interfaceref = find_interface($interface);
    #
    # We must use the interfaces's chain if the interface is associated with multiple zone nets
    #
    $interfaceref->{nets} > 1;
}

#
# Input Chain for an interface
#
sub input_chain($)
{
    chain_base_cond($_[0]) . '_in';
}

#
# Input Chain for a zone
#
sub zone_input_chain($) {
    chain_base($_[0]) . '_input';
}

#
# Returns true if we're to use the interface's input chain
#
sub use_input_chain($) {
    my $interface = $_[0];
    my $interfaceref = find_interface($interface);
    my $nets = $interfaceref->{nets};
    #
    # We must use the interfaces's chain if the interface is associated with multiple zone nets
    #    
    return 1 if $nets > 1;
    #
    # Don't need it if it isn't associated with any zone
    #
    return 0 unless $nets;
    #
    # Interface associated with a single zone -- use the zone's input chain if it has one
    #
    my $chainref = $filter_table->{zone_input_chain $interfaceref->{zone}};

    return 0 if $chainref;
    #
    # Use the '<zone>2fw' chain if it is referenced.
    #
    $chainref = $filter_table->{join( '' , $interfaceref->{zone} , '2' , firewall_zone )};

    ! $chainref->{referenced};
}   

#
# Output Chain for an interface
#
sub output_chain($)
{
    chain_base_cond($_[0]) . '_out';
}

#
# Output Chain for a zone
#
sub zone_output_chain($) {
    chain_base($_[0]) . '_output';
}

#
# Returns true if we're to use the interface's output chain
#
sub use_output_chain($) {
    my $interface = $_[0];
    my $interfaceref = find_interface($interface);
    my $nets = $interfaceref->{nets};
    #
    # We must use the interfaces's chain if the interface is associated with multiple zone nets
    #    
    return 1 if $nets > 1;
    #
    # Don't need it if it isn't associated with any zone
    #
    return 0 unless $nets;
    #
    # Interface associated with a single zone -- use the zone's output chain if it has one
    #    
    my $chainref = $filter_table->{zone_output_chain $interfaceref->{zone}};

    return 0 if $chainref;
    #
    # Use the 'fw2<zone>' chain if it is referenced.
    #
    $chainref = $filter_table->{join( '', firewall_zone , '2', $interfaceref->{zone} )};

    ! $chainref->{referenced};
}

#
# Masquerade Chain for an interface
#
sub masq_chain($)
{
     chain_base_cond($_[0]) . '_masq';
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
    chain_base_cond($_[0]) . '_mac';
}

sub macrecent_target($)
{
     $config{MACLIST_TTL} ? chain_base_cond($_[0]) . '_rec' : 'RETURN';
}

#
# Functions for creating dynamic zone rules
#
sub dynamic_fwd( $ )
{
    chain_base_cond($_[0]) . '_dynf';
}

sub dynamic_in( $ )
{
    chain_base_cond($_[0]) . '_dyni';
}

sub dynamic_out( $ ) # $1 = interface
{
    chain_base_cond($_[0]) . '_dyno';
}

sub dynamic_chains( $ ) #$1 = interface
{
    my $c = chain_base_cond($_[0]);

    ( $c . '_dyni' , $c . '_dynf' , $c . '_dyno' );
}

sub zone_dynamic_chain( $ ) # $1 = zone
{
    $_[0] . '_dyn';

}
#
# DNAT Chain from a zone
#
sub dnat_chain( $ )
{
    chain_base_cond($_[0]) . '_dnat';
}

#
# SNAT Chain to an interface
#
sub snat_chain( $ )
{
    chain_base_cond($_[0]) . '_snat';
}

#
# ECN Chain to an interface
#
sub ecn_chain( $ )
{
    chain_base_cond($_[0]) . '_ecn';
}

#
# First chains for an interface
#
sub first_chains( $ ) #$1 = interface
{
    my $c = chain_base_cond($_[0]);

    ( $c . '_fwd', $c . '_in' );
}

#
# Create a new chain and return a reference to it.
#
sub new_chain($$)
{
    my ($table, $chain) = @_;

    warning_message "Internal error in new_chain()" if $chain_table{$table}{$chain};

    $chain_table{$table}{$chain} = { name      => $chain,
				     rules     => [],
				     table     => $table,
				     loglevel  => '',
				     log       => 1,
				     cmdlevel  => 0 };
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
	} elsif ( $section eq 'RELATED' ) {
	    finish_chain_section $chainref , 'ESTABLISHED';
	}
    }

    $chainref->{referenced} = 1;

    $chainref;
}

#
# Create an accounting chain if necessary. 
#
sub ensure_accounting_chain( $  )
{
    my ($chain) = @_;

    my $chainref = $filter_table->{$chain};

    if ( $chainref ) {
	fatal_error "Non-accounting chain ($chain) used in accounting rule"  if ! $chainref->{accounting};
    } else {
	$chainref = new_chain 'filter' , $chain unless $chainref;
	$chainref->{accounting} = 1;
	$chainref->{referenced} = 1;
    }

    $chainref;
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

#
# Add a builtin chain
#
sub new_builtin_chain($$$)
{
    my ( $table, $chain, $policy ) = @_;

    my $chainref = new_chain $table, $chain;
    $chainref->{referenced} = 1;
    $chainref->{policy}     = $policy;
    $chainref->{builtin}    = 1;
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
    fatal_error "Duplicate Chain Name ($chain)" if $targets{$chain} || $filter_table->{$chain};
    $targets{$chain} = CHAIN;
    ( my $chainref = ensure_filter_chain( $chain, 0) )->{manual} = 1;
    $chainref->{referenced} = 1;
    $chainref;
}

sub ensure_manual_chain($) {
    my $chain = $_[0];
    my $chainref = $filter_table->{$chain} || new_manual_chain($chain);
    fatal_error "$chain exists and is not a manual chain" unless $chainref->{manual};
    $chainref;
}

#
# Add all builtin chains to the chain table
#
#
sub initialize_chain_table()
{
    for my $chain qw(OUTPUT PREROUTING) {
	new_builtin_chain 'raw', $chain, 'ACCEPT';
    }

    for my $chain qw(INPUT OUTPUT FORWARD) {
	new_builtin_chain 'filter', $chain, 'DROP';
    }

    for my $chain qw(PREROUTING POSTROUTING OUTPUT) {
	new_builtin_chain 'nat', $chain, 'ACCEPT';
    }

    for my $chain qw(PREROUTING INPUT OUTPUT ) {
	new_builtin_chain 'mangle', $chain, 'ACCEPT';
    }

    if ( $capabilities{MANGLE_FORWARD} ) {
	for my $chain qw( FORWARD POSTROUTING ) {
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
    my $savecomment = $comment;
    
    $comment = '';

    add_rule $chainref, "-m state --state $state -j ACCEPT" unless $config{FASTACCEPT};

    if ($sections{NEW} ) {
	if ( $chainref->{is_policy} ) {
	    if ( $chainref->{synparams} ) {
		my $synchainref = ensure_chain 'filter', syn_flood_chain $chainref;
		if ( $section eq 'DONE' ) {
		    if ( $chainref->{policy} =~ /^(ACCEPT|CONTINUE|QUEUE|NFQUEUE)/ ) {
			add_rule $chainref, "-p tcp --syn -j $synchainref->{name}";
		    }
		} else {
		    add_rule $chainref, "-p tcp --syn -j $synchainref->{name}";
		}
	    }
	} else {
	    my $policychainref = $filter_table->{$chainref->{policychain}};
	    if ( $policychainref->{synparams} ) {
		my $synchainref = ensure_chain 'filter', syn_flood_chain $policychainref;
		add_rule $chainref, "-p tcp --syn -j $synchainref->{name}";
	    }
	}
    }

    $comment = $savecomment;
}

#
# Do section-end processing
#
sub finish_section ( $ ) {
    my $sections = $_[0];

    for my $section ( split /,/, $sections ) {
	$sections{$section} = 1;
    }

    for my $zone ( all_zones ) {
	for my $zone1 ( all_zones ) {
	    my $chainref = $chain_table{'filter'}{"${zone}2${zone1}"};
	    if ( $chainref->{referenced} ) {
		finish_chain_section $chainref, $sections;
	    }
	}
    }
}

#
# Helper for set_mss
#
sub set_mss1( $$ ) {
    my ( $chain, $mss ) =  @_;
    my $chainref = ensure_chain 'filter', $chain;

    if ( $chainref->{policy} ne 'NONE' ) {
	my $match = $capabilities{TCPMSS_MATCH} ? "-m tcpmss --mss $mss: " : '';
	insert_rule $chainref, 1, "-p tcp --tcp-flags SYN,RST SYN ${match}-j TCPMSS --set-mss $mss"
    }
}

#
# Set up rules to set MSS to and/or from zone "$zone"
#
sub set_mss( $$$ ) {
    my ( $zone, $mss, $direction) = @_;

    for my $z ( all_zones ) {
	if ( $direction eq '_in' ) {
	    set_mss1 "${zone}2${z}" , $mss;
	} elsif ( $direction eq '_out' ) {
	    set_mss1 "${z}2${zone}", $mss;
	} else {
	    set_mss1 "${z}2${zone}", $mss;
	    set_mss1 "${zone}2${z}", $mss;
	}
    }
}

#
# Interate over non-firewall zones and interfaces with 'mss=' setting adding TCPMSS rules as appropriate. 
#
sub setup_zone_mss() {
    for my $zone ( all_zones ) {
	my $zoneref = find_zone( $zone );

	set_mss( $zone, $zoneref->{options}{in_out}{mss}, ''     ) if $zoneref->{options}{in_out}{mss};
	set_mss( $zone, $zoneref->{options}{in}{mss},     '_in'  ) if $zoneref->{options}{in}{mss};
	set_mss( $zone, $zoneref->{options}{out}{mss},    '_out' ) if $zoneref->{options}{out}{mss};
    }
}

sub newexclusionchain() {
    my $seq = $exclseq++;
    "excl${seq}";
}

sub clearrule() {
    $iprangematch = 0;
}

#
# Handle parsing of PROTO, DEST PORT(S) , SOURCE PORTS(S). Returns the appropriate match string.
#
sub do_proto( $$$ )
{
    my ($proto, $ports, $sports ) = @_;
    #
    # Return the number of ports represented by the passed list
    #
    sub port_count( $ ) {
	( $_[0] =~ tr/,:/,:/ ) + 1;
    }

    my $output = '';

    $proto  = '' if $proto  eq '-';
    $ports  = '' if $ports  eq '-';
    $sports = '' if $sports eq '-';

    if ( $proto ne '' ) {
	
	my $synonly = ( $proto =~ s/:syn$//i );

	my $protonum = resolve_proto $proto;

	if ( defined $protonum ) {	    
	    #
	    # Protocol is numeric and <= 65535 or is defined in /etc/protocols or NSS equivalent
	    #
	    my $pname = proto_name( $proto = $protonum );
	    #
	    # $proto now contains the protocol number and $pname contains the canonical name of the protocol
	    #
	    unless ( $synonly ) {
		$output  = "-p $proto ";
	    } else {
		fatal_error '":syn" is only allowed with tcp' unless $proto == TCP;
		$output = "-p $proto --syn ";
	    }

	  PROTO:
	    {

		if ( $proto == TCP || $proto == UDP || $proto == SCTP ) {
		    my $multiport = 0;

		    if ( $ports ne '' ) {
			if ( $ports =~ tr/,/,/ > 0 || $sports =~ tr/,/,/ > 0 ) {
			    fatal_error "Port lists require Multiport support in your kernel/iptables" unless $capabilities{MULTIPORT};
			    fatal_error "Multiple ports not supported with SCTP" if $proto == SCTP;
			    $ports = validate_port_list $pname , $ports;
			    $output .= "-m multiport --dports $ports ";
			    $multiport = 1;
			}  else {
			    $ports   = validate_portpair $pname , $ports;
			    $output .= "--dport $ports ";
			}
		    } else {
			$multiport = ( ( $sports =~ tr/,/,/ ) > 0 );
		    }
		    
		    if ( $sports ne '' ) {
			if ( $multiport ) {
			    fatal_error "Too many entries in SOURCE PORT(S) list" if port_count( $sports ) > 15;
			    $sports = validate_port_list $pname , $sports;
			    $output .= "-m multiport --sports $sports ";
			}  else {
			    $sports  = validate_portpair $pname , $sports;
			    $output .= "--sport $sports ";
			}
		    }
		    
		    last PROTO;	}
	    
		if ( $proto == ICMP ) {
		    if ( $ports ne '' ) {
			fatal_error 'Multiple ICMP types are not permitted' if $ports =~ /,/;
			$ports = validate_icmp $ports;
			$output .= "--icmp-type $ports ";
		    }
		
		    fatal_error 'SOURCE PORT(S) not permitted with ICMP' if $sports ne '';

		    last PROTO; }

		fatal_error "SOURCE/DEST PORT(S) not allowed with PROTO $pname" if $ports ne '' || $sports ne '';

	    } # PROTO

	} else {
	    fatal_error '":syn" is only allowed with tcp' if $synonly;
	
	    if ( $proto =~ /^(ipp2p(:(tcp|udp|all))?)$/i ) {
		my $p = $2 ? lc $3 : 'tcp';
		require_capability( 'IPP2P_MATCH' , "PROTO = $proto" , 's' );
		$proto = '-p ' . proto_name($p) . ' ';
		$ports = 'ipp2p' unless $ports;
		$output .= "${proto}-m ipp2p --$ports ";
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

sub mac_match( $ ) {
    my $mac = $_[0];

    $mac =~ s/^(!?)~//;
    my $invert = ( $1 ? '! ' : '');
    $mac =~ tr/-/:/;

    fatal_error "Invalid MAC address ($mac)" unless $mac =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;

    "--match mac --mac-source ${invert}$mac ";
}

#
# Mark validatation functions
#
sub verify_mark( $ ) {
    my $mark  = $_[0];
    my $limit = $config{HIGH_ROUTE_MARKS} ? 0xFFFF : 0xFF;
    my $value = numeric_value( $mark );

    fatal_error "Invalid Mark or Mask value ($mark)"
	unless defined( $value ) && $value <= $limit;

    fatal_error "Invalid High Mark or Mask value ($mark)"
	if ( $value > 0xFF && $value & 0xFF );
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

    if ( $rate =~ /^(\d+(\/(sec|min|hour|day))?):(\d+)$/ ) {
	"-m limit --limit $1 --limit-burst $4 ";
    } elsif ( $rate =~ /^(\d+)(\/(sec|min|hour|day))?$/ )  {
	"-m limit --limit $rate ";
    } else {
	fatal_error "Invalid rate ($rate)";
    }
}

#
# Create a "-m owner" match for the passed USER/GROUP
#
sub do_user( $ ) {
    my $user = $_[0];
    my $rule = '-m owner ';

    return '' unless defined $user and $user ne '-';

    if ( $user =~ /^(!)?(.*)\+(.*)$/ ) {
	$rule .= "! --cmd-owner $2 " if defined $2 && $2 ne '';
	$user = "!$1";
    } elsif ( $user =~ /^(.*)\+(.*)$/ ) {
	$rule .= "--cmd-owner $2 " if defined $2 && $2 ne '';
	$user = $1;
    }

    if ( $user =~ /^!(.*):(.*)$/ ) {
	$rule .= "! --uid-owner $1 " if defined $1 && $1 ne '';
	$rule .= "! --gid-owner $2 " if defined $2 && $2 ne '';
    } elsif ( $user =~ /^(.*):(.*)$/ ) {
	$rule .= "--uid-owner $1 " if defined $1 && $1 ne '';
	$rule .= "--gid-owner $2 " if defined $2 && $2 ne '';
    } elsif ( $user =~ /^!(.*)$/ ) {
	fatal_error "Invalid USER/GROUP (!)" if $1 eq '';
	$rule .= "! --uid-owner $1 ";
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
    my $min    = $2;       $min    = 0 unless defined $min;
    my $max    = $3 || ''; fatal_error "Invalid byte range ($min:$max)" if $max ne '' and $min > $max;
    my $dir    = $5 || 'B'; 
    my $mode   = $6 || 'B'; 
    
    $dir  =~ s/://;
    $mode =~ s/://;

    "${invert}-m connbytes --connbytes $min:$max --connbytes-dir $dir{$dir} --connbytes-mode $mode{$mode} ";
}

#
# Match Source Interface
#
sub match_source_dev( $ ) {
    my $interface = shift;
    my $interfaceref =  known_interface( $interface );
    if ( $interfaceref && $interfaceref->{options}{port} ) {
	"-i $interfaceref->{bridge} -m physdev --physdev-in $interface ";
    } else {
	"-i $interface ";
    }
}

#
# Match Dest device
#
sub match_dest_dev( $ ) {
    my $interface = shift;
    my $interfaceref =  known_interface( $interface );
    if ( $interfaceref && $interfaceref->{options}{port} ) {
	if ( $capabilities{PHYSDEV_BRIDGE} ) {
	    "-o $interfaceref->{bridge} -m physdev --physdev-is-bridged --physdev-out $interface ";
	} else {
	    "-o $interfaceref->{bridge} -m physdev --physdev-out $interface ";
	}
    } else {
	"-o $interface ";
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
	$iprangematch = 1 unless $capabilities{KLUDGEFREE};
    }

    $match;
}

#
# Get set flags (ipsets).
#
sub get_set_flags( $$ ) {
    my ( $setname, $option ) = @_;
    my $options = $option;

    if ( $setname =~ /^(.*)\[([1-6])\]$/ ) {
	$setname  = $1;
	my $count = $2;
	$options .= ",$option" while --$count > 0;
    } elsif ( $setname =~ /^(.*)\[(.*)\]$/ ) {
	$setname = $1;
	$options = $2;
    }

    $setname =~ s/^\+//;

    fatal_error "Invalid ipset name ($setname)" unless $setname =~ /^[a-zA-Z]\w*/;

    "--set $setname $options "
}

#
# Match a Source. Handles IP addresses and ranges and MAC addresses
#
sub match_source_net( $;$ ) {
    my ( $net, $restriction) = @_;

    $restriction |= NO_RESTRICT;

    if ( $net =~ /^(!?)(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) {
	my ($addr1, $addr2) = ( $2, $3 );
	$net =~ s/!// if my $invert = $1 ? '! ' : '';
	validate_range $addr1, $addr2;
	iprange_match . "${invert}--src-range $net ";
    } elsif ( $net =~ /^!?~.*$/ ) {
	fatal_error "MAC address cannot be used in this context" if $restriction >= OUTPUT_RESTRICT;	
	mac_match $net;
    } elsif ( $net =~ /^(!?)\+/ ) {
	require_capability( 'IPSET_MATCH' , 'ipset names in Shorewall configuration files' , '' );
	join( '', '-m set ', $1 ? '! ' : '', get_set_flags( $net, 'src' ) );
    } elsif ( $net =~ /^!/ ) {
	$net =~ s/!//;
	validate_net $net, 1;
	"-s ! $net ";
    } else {
	validate_net $net, 1;
	$net eq ALLIPv4 ? '' : "-s $net ";
    }
}

#
# Match a Source. Currently only handles IP addresses and ranges
#
sub match_dest_net( $ ) {
    my $net = $_[0];

    if ( $net =~ /^(!?)(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) {
	my ($addr1, $addr2) = ( $2, $3 );
	$net =~ s/!// if my $invert = $1 ? '! ' : '';
	validate_range $addr1, $addr2;
	iprange_match . "${invert}--dst-range $net ";
    } elsif ( $net =~ /^(!?)\+/ ) {
	require_capability( 'IPSET_MATCH' , 'ipset names in Shorewall configuration files' , '');
	join( '', '-m set ', $1 ? '! ' : '',  get_set_flags( $net, 'dst' ) );
    } elsif ( $net =~ /^!/ ) {
	$net =~ s/!//;
	validate_net $net, 1;
	"-d ! $net ";
    } else {
	validate_net $net, 1;
	$net eq ALLIPv4 ? '' : "-d $net ";
    }
}

#
# Match original destination
#
sub match_orig_dest ( $ ) {
    my $net = $_[0];

    return '' if $net eq ALLIPv4;
    return '' unless $capabilities{CONNTRACK_MATCH};

    if ( $net =~ /^!/ ) {
	$net =~ s/!//;
	validate_net $net, 1;
	"-m conntrack --ctorigdst ! $net ";
    } else {
	validate_net $net, 1;
	$net eq ALLIPv4 ? '' : "-m conntrack --ctorigdst $net ";
    }
}

#
# Match Source IPSEC
#
sub match_ipsec_in( $$ ) {
    my ( $zone , $hostref ) = @_;
    my $match = '-m policy --dir in --pol ';
    my $zoneref    = find_zone( $zone );
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
    my $zoneref    = find_zone( $zone );
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

    my $prefix = '';

    $level = validate_level $level; # Do this here again because this function can be called directly from user exits.

    return 1 if $level eq '';
    
    $predicates .= ' ' if $predicates && substr( $predicates, -1, 1 ) ne ' ';

    unless ( $predicates =~ /-m limit / ) {
	$limit = $globals{LOGLIMIT} unless $limit && $limit ne '-';
	$predicates .= $limit if $limit;
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
	} else {
	    $prefix = "-j LOG $globals{LOGPARMS}--log-level $level --log-prefix \"$prefix\" ";
	}
    }

    if ( $command eq 'add' ) {
	add_rule ( $chainref, $predicates . $prefix , 1 );
    } else {
	insert_rule ( $chainref , 1 , $predicates . $prefix );
    }
}

sub log_rule( $$$$ ) {
    my ( $level, $chainref, $disposition, $predicates ) = @_;

    log_rule_limit $level, $chainref, $chainref->{name} , $disposition, $globals{LOGLIMIT}, '', 'add', $predicates;
}

#
# Split a comma-separated source or destination host list but keep [...] together.
#
sub mysplit( $ ) {
    my @input = split_list $_[0], 'host';

    return @input unless $_[0] =~ /\[/;

    my @result;

    while ( @input ) {
	my $element = shift @input;

	if ( $element =~ /\[/ ) {
	    while ( substr( $element, -1, 1 ) ne ']' ) {
		last unless @input;
		$element .= ( ',' . shift @input );
	    }

	    fatal_error "Invalid Host List ($_[0])" unless substr( $element, -1, 1 ) eq ']';
	}

	push @result, $element;
    }

    @result;
}

#
# Returns the name of the shell variable holding the first address of the passed interface
#
sub interface_address( $ ) {
    my $variable = chain_base( $_[0] ) . '_address';
    uc $variable;
}

#
# Record that the ruleset requires the first IP address on the passed interface
#
sub get_interface_address ( $ ) {
    my ( $interface ) = $_[0];

    my $variable = interface_address( $interface );
    my $function = interface_is_optional( $interface ) ? 'find_first_interface_address_if_any' : 'find_first_interface_address';

    $interfaceaddr{$interface} = "$variable=\$($function $interface)\n";

    "\$$variable";
}

#
# Returns the name of the shell variable holding the broadcast addresses of the passed interface
#
sub interface_bcasts( $ ) {
    my $variable = chain_base( $_[0] ) . '_bcasts';
    uc $variable;
}

#
# Record that the ruleset requires the broadcast addresses on the passed interface
#
sub get_interface_bcasts ( $ ) {
    my ( $interface ) = $_[0];

    my $variable = interface_bcasts( $interface );

    $interfacebcasts{$interface} = qq($variable="\$(get_interface_bcasts $interface) 255.255.255.255");

    "\$$variable";
}

#
# Returns the name of the shell variable holding the gateway through the passed interface
#
sub interface_gateway( $ ) {
    my $variable = chain_base( $_[0] ) . '_gateway';
    uc $variable;
}

#
# Record that the ruleset requires the gateway address on the passed interface
#
sub get_interface_gateway ( $ ) {
    my ( $interface ) = $_[0];

    my $variable = interface_gateway( $interface );

    if ( interface_is_optional $interface ) {
	$interfacegateways{$interface} = qq([ -n "\$$variable" ] || $variable=\$(detect_gateway $interface)\n);
    } else {
	$interfacegateways{$interface} = qq([ -n "\$$variable" ] || $variable=\$(detect_gateway $interface)
[ -n "\$$variable" ] || fatal_error "Unable to detect the gateway through interface $interface"
);
    }

    "\$$variable";
}

#
# Returns the name of the shell variable holding the addresses of the passed interface
#
sub interface_addresses( $ ) {
    my $variable = chain_base( $_[0] ) . '_addresses';
    uc $variable;
}

#
# Record that the ruleset requires the IP addresses on the passed interface
#
sub get_interface_addresses ( $ ) {
    my ( $interface ) = $_[0];

    my $variable = interface_addresses( $interface );

    if ( interface_is_optional $interface ) {
	$interfaceaddrs{$interface} = qq($variable=\$(find_interface_addresses $interface)\n);
    } else {
	$interfaceaddrs{$interface} = qq($variable=\$(find_interface_addresses $interface)
[ -n "\$$variable" ] || fatal_error "Unable to determine the IP address(es) of $interface"
);
    }

    "\$$variable";
}

#
# Returns the name of the shell variable holding the networks routed out of the passed interface
#
sub interface_nets( $ ) {
    my $variable = chain_base( $_[0] ) . '_networks';
    uc $variable;
}

#
# Record that the ruleset requires the networks routed out of the passed interface
#
sub get_interface_nets ( $ ) {
    my ( $interface ) = $_[0];

    my $variable = interface_nets( $interface );

    if ( interface_is_optional $interface ) {
	$interfacenets{$interface} = qq($variable=\$(get_routed_networks $interface)\n);
    } else {
	$interfacenets{$interface} = qq($variable=\$(get_routed_networks $interface)
[ -n "\$$variable" ] || fatal_error "Unable to determine the routes through interface \\"$interface\\""
);
    }

    "\$$variable";

}

#
# Returns the name of the shell variable holding the MAC address of the gateway for the passed provider out of the passed interface
#
sub interface_mac( $$ ) {
    my $variable = join( '_' , chain_base( $_[0] ) , chain_base( $_[1] ) , 'mac' );
    uc $variable;
}

#
# Record the fact that the ruleset requires MAC address of the passed gateway IP routed out of the passed interface for the passed provider number
#
sub get_interface_mac( $$$ ) {
    my ( $ipaddr, $interface , $table ) = @_;

    my $variable = interface_mac( $interface , $table );

    if ( interface_is_optional $interface ) {
	$interfacemacs{$table} = qq($variable=\$(find_mac $ipaddr $interface)\n);
    } else {
	$interfacemacs{$table} = qq($variable=\$(find_mac $ipaddr $interface)
[ -n "\$$variable" ] || fatal_error "Unable to determine the MAC address of $ipaddr through interface \\"$interface\\""
);
    }

    "\$$variable";
}

#
# This function provides a uniform way to generate rules (something the original Shorewall sorely needed).
#
# Returns the destination interface specified in the rule, if any.
#
sub expand_rule( $$$$$$$$$$ )
{
    my ($chainref ,    # Chain
	$restriction,  # Determines what to do with interface names in the SOURCE or DEST
	$rule,         # Caller's matches that don't depend on the SOURCE, DEST and ORIGINAL DEST
	$source,       # SOURCE
	$dest,         # DEST
	$origdest,     # ORIGINAL DEST
	$target,       # Target ('-j' part of the rule)
	$loglevel ,    # Log level (and tag)
	$disposition,  # Primative part of the target (RETURN, ACCEPT, ...)
	$exceptionrule # Caller's matches used in exclusion case
       ) = @_;

    my ($iiface, $diface, $inets, $dnets, $iexcl, $dexcl, $onets , $oexcl );
    my $chain = $chainref->{name};

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

	add_command $chainref, $command;
	incr_cmd_level $chainref;
	push @ends, $end;
    }
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
    # Mark Target as referenced, if it's a chain
    #
    if ( $disposition ) {
	my $targetref = $chain_table{$chainref->{table}}{$disposition};
	$targetref->{referenced} = 1 if $targetref;
    }

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
    # Verify Interface, if any
    #
    if ( $iiface ) {
	fatal_error "Unknown Interface ($iiface)" unless known_interface $iiface;

	if ( $restriction & POSTROUTE_RESTRICT ) {
	    #
	    # An interface in the SOURCE column of a masq file
	    #
	    fatal_error "Bridge ports may not appear in the SOURCE column of this file" if port_to_bridge( $iiface );

	    my $networks = get_interface_nets ( $iiface );

	    push_command $chainref, join( '', 'for source in ', $networks, '; do' ), 'done';

	    $rule .= '-s $source ';
	    
	} else {
	    fatal_error "Source Interface ($iiface) not allowed when the source zone is the firewall zone" if $restriction & OUTPUT_RESTRICT;
	    $rule .= match_source_dev( $iiface );
	}
    }

    #
    # Isolate Destination Interface, if any
    #
    if ( $dest ) {
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
	fatal_error "Unknown Interface ($diface)" unless known_interface $diface;

	if ( $restriction & PREROUTE_RESTRICT ) {
	    #
	    # ADDRESS 'detect' in the masq file.
	    #
	    fatal_error "Bridge port ($diface) not allowed" if port_to_bridge( $diface );
	    push_command( $chainref , 'for dest in ' . get_interface_addresses( $diface) . '; do', 'done' );
	    $rule .= '-d $dest ';
	} else {
	    fatal_error "Bridge Port ($diface) not allowed in OUTPUT or POSTROUTING rules" if ( $restriction & ( POSTROUTE_RESTRICT + OUTPUT_RESTRICT ) ) && port_to_bridge( $diface );
	    fatal_error "Destination Interface ($diface) not allowed when the destination zone is the firewall zone" if $restriction & INPUT_RESTRICT;

	    if ( $iiface ) {
		my $bridge = port_to_bridge( $diface );
		fatal_error "Source interface ($iiface) is not a port on the same bridge as the destination interface ( $diface )" if $bridge && $bridge ne source_port_to_bridge( $iiface );
	    }

	    $rule .= match_dest_dev( $diface );
	}
    } else {
	$diface = '';
    }

    if ( $origdest ) {
	if ( $origdest eq '-' || ! $capabilities{CONNTRACK_MATCH} ) {
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
	fatal_error "Invalid SOURCE" if $inets =~ /^([^!]+)?,!([^!]+)$/ || $inets =~ /.*!.*!/;

	if ( $inets =~ /^([^!]+)?!([^!]+)$/ ) {
	    $inets = $1;
	    $iexcl = $2;
	} else {
	    $iexcl = '';
	}

	unless ( $inets || ( $iiface && $restriction & POSTROUTE_RESTRICT ) ) {
	    my @iexcl = mysplit $iexcl;
	    if ( @iexcl == 1 ) {
		$rule .= match_source_net "!$iexcl" , $restriction;
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
	fatal_error "Invalid DEST" if  $dnets =~ /^([^!]+)?,!([^!]+)$/ || $dnets =~ /.*!.*!/;

	if ( $dnets =~ /^([^!]+)?!([^!]+)$/ ) {
	    $dnets = $1;
	    $dexcl = $2;
	} else {
	    $dexcl = '';
	}

	unless ( $dnets ) {
	    my @dexcl = mysplit $dexcl;
	    if ( @dexcl == 1 ) {
		$rule .= match_dest_net "!$dexcl";
		$dexcl = '';
	    }
	}
    } else {
	$dexcl = '';
    }

    $inets = ALLIPv4 unless $inets;
    $dnets = ALLIPv4 unless $dnets;
    $onets = ALLIPv4 unless $onets;

    fatal_error "Input interface may not be specified with a source IP address in the POSTROUTING chain"      if $restriction == POSTROUTE_RESTRICT && $iiface && $inets ne ALLIPv4;
    fatal_error "Output interface may not be specified with a destination IP address in the PREROUTING chain" if $restriction == PREROUTE_RESTRICT &&  $diface && $dnets ne ALLIPv4;

    if ( $iexcl || $dexcl || $oexcl ) {
	#
	# We have non-trivial exclusion -- need to create an exclusion chain
	#
	fatal_error "Exclusion is not possible in ACCEPT+/CONTINUE/NONAT rules" if $disposition eq 'RETURN';

	my $echain = newexclusionchain;

	#
	# Use the current rule and sent all possible matches to the exclusion chain
	#
	for my $onet ( mysplit $onets ) {
	    $onet = match_orig_dest $onet;
	    for my $inet ( mysplit $inets ) {
		for my $dnet ( mysplit $dnets ) {
		    #
		    # We evaluate the source net match in the inner loop to accomodate systems without $capabilities{KLUDGEFREE}
		    #
		    add_rule( $chainref, join( '', $rule, match_source_net( $inet, $restriction ), match_dest_net( $dnet ), $onet, "-j $echain" ), 1 );
		}
	    }
	}

	#
	# Create the Exclusion Chain
	#
	my $echainref = new_chain $chainref->{table}, $echain;

	#
	# Generate RETURNs for each exclusion
	#
	add_rule $echainref, ( match_source_net $_ , $restriction ) . '-j RETURN' for ( mysplit $iexcl );
	add_rule $echainref, ( match_dest_net $_ ) .   '-j RETURN' for ( mysplit $dexcl );
	add_rule $echainref, ( match_orig_dest $_ ) .  '-j RETURN' for ( mysplit $oexcl );
	#
	# Log rule
	#
	log_rule_limit $loglevel , $echainref , $chain, $disposition , '',  $logtag , 'add' , '' if $loglevel;
	#
	# Generate Final Rule
	#
	add_rule( $echainref, $exceptionrule . $target, 1 ) unless $disposition eq 'LOG';
    } else {
	#
	# No exclusions
	#
	for my $onet ( mysplit $onets ) {
	    $onet = match_orig_dest $onet;
	    for my $inet ( mysplit $inets ) {
		#
		# We defer evaluating the source net match to accomodate system without $capabilities{KLUDGEFREE}
		#
		for my $dnet ( mysplit $dnets ) {
		    if ( $loglevel ne '' ) {
			log_rule_limit
			    $loglevel ,
			    $chainref ,
			    $chain,
			    $disposition ,
			    '' ,
			    $logtag ,
			    'add' ,
			    join( '', $rule, match_source_net( $inet , $restriction ) , match_dest_net( $dnet ), $onet );
		    }

		    unless ( $disposition eq 'LOG' ) {
			add_rule( 
				 $chainref,
				 join( '', $rule, match_source_net ($inet , $restriction ), match_dest_net( $dnet ), $onet, $target  ) ,
				 1 );
		    }
		}
	    }
	}
    }

    while ( @ends ) {
	decr_cmd_level $chainref;
	add_command $chainref, pop @ends;
    }

    $diface;
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

sub emit_comment() {
    emit  ( '#',
	    '# Establish the values of shell variables used in the following function calls',
	    '#' );
    our $emitted_comment = 1;
}

sub emit_test() {
    emit ( 'if [ "$COMMAND" != restore ]; then' ,
	   '' );
    push_indent;
    our $emitted_test = 1;
}
    
#
# Generate setting of global variables
#
sub set_global_variables() {

    our ( $emitted_comment, $emitted_test ) = (0, 0);

    for ( values %interfaceaddr ) {
	emit_comment unless $emitted_comment;
	emit $_;
    }

    for ( values %interfacegateways ) {
	emit_comment unless $emitted_comment;
	emit $_;
    }    

    for ( values %interfacemacs ) {
	emit_comment unless $emitted_comment;
	emit $_;
    }    

    for ( values %interfaceaddrs ) {
	emit_comment unless $emitted_comment;
	emit_test    unless $emitted_test;
	emit $_;
    }

    for ( values %interfacenets ) {
	emit_comment unless $emitted_comment;
	emit_test    unless $emitted_test;
	emit $_;
    }

    unless ( $capabilities{ADDRTYPE} ) {
	emit_comment unless $emitted_comment;
	emit_test    unless $emitted_test;
	emit 'ALL_BCASTS="$(get_all_bcasts) 255.255.255.255"';

	for ( values %interfacebcasts ) {
	    emit $_;
	}
    }

    pop_indent,	emit "fi\n" if $emitted_test;

}

#
# What follows is the code that generates the input to iptables-restore
#
# We always write the iptables-restore input into a file then pass the
# file to iptables-restore. That way, if things go wrong, the user (and Shorewall support)
# has (have) something to look at to determine the error
#
# We may have to generate part of the input at run-time. The rules array in each chain
# table entry may contain rules (begin with '-A') or shell source. We alternate between
# writing the rules ('-A') into the temporary file to be bassed to iptables-restore
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
sub emitr( $ ) {
    my $rule = $_[0];

    if ( $rule && substr( $rule, 0, 2 ) eq '-A' ) {
	#
	# A rule
	#
	enter_cat_mode unless $mode == CAT_MODE;
	emit_unindented $rule;
    } else {
	#
	# A command
	#
	enter_cmd_mode unless $mode == CMD_MODE;
	emit $rule;
    }
}

#
# Generate the netfilter input
#
sub create_netfilter_load() {

    my @table_list;

    push @table_list, 'raw'    if $capabilities{RAW_TABLE};
    push @table_list, 'nat'    if $capabilities{NAT_ENABLED};
    push @table_list, 'mangle' if $capabilities{MANGLE_ENABLED} && $config{MANGLE_ENABLED};
    push @table_list, 'filter';

    $mode = NULL_MODE;

    emit ( 'setup_netfilter()',
	   '{'
	   );

    push_indent;

    save_progress_message "Preparing iptables-restore input...";

    emit '';

    emit 'exec 3>${VARDIR}/.iptables-restore-input';

    enter_cat_mode;

    for my $table ( @table_list ) {
	emit_unindented "*$table";

	my @chains;
	#
	# iptables-restore seems to be quite picky about the order of the builtin chains
	#
	for my $chain ( @builtins ) {
	    my $chainref = $chain_table{$table}{$chain};
	    if ( $chainref ) {
		fatal_error "Internal error in create_netfilter_load()" if $chainref->{cmdlevel};
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
		fatal_error "Internal error in create_netfilter_load()" if $chainref->{cmdlevel};
		emit_unindented ":$chainref->{name} - [0:0]";
		push @chains, $chainref;
	    }
	}
	#
	# Then emit the rules
	#
	for my $chainref ( @chains ) {
	    emitr $_ for ( @{$chainref->{rules}} );
	}
	#
	# Commit the changes to the table
	#
	enter_cat_mode unless $mode == CAT_MODE;
	emit_unindented 'COMMIT';
    }

    enter_cmd_mode;
    #
    # Now generate the actual iptables-restore command
    #
    emit(  'exec 3>&-',
	   '',
	   '[ -n "$DEBUG" ] && command=debug_restore_input || command=$IPTABLES_RESTORE',
	   '',
	   'progress_message2 "Running $command..."',
	   '',
	   'cat ${VARDIR}/.iptables-restore-input | $command # Use this nonsensical form to appease SELinux',
	   'if [ $? != 0 ]; then',
	   '    fatal_error "iptables-restore Failed. Input is in ${VARDIR}/.iptables-restore-input"',
	   "fi\n"
	   );

    pop_indent;

    emit "}\n";
}

#
# Generate the netfilter input for refreshing a list of chains
#
sub create_chainlist_reload($) {

    my $chains = $_[0];

    my @chains = split_list $chains, 'chain';

    unless ( @chains ) {
	@chains = qw( blacklst ) if $filter_table->{blacklst};
	push @chains, 'mangle:' if $capabilities{MANGLE_ENABLED} && $config{MANGLE_ENABLED};
	$chains = join( ',', @chains ) if @chains;
    }

    $mode = NULL_MODE;

    emit(  'chainlist_reload()',
	   '{'
	   );

    push_indent;

    if ( @chains ) {
	if ( @chains == 1 ) {
	    progress_message2 "Compiling iptables-restore input for chain @chains...";
	    save_progress_message "Preparing iptables-restore input for chain @chains...";
	} else {
	    progress_message2 "Compiling iptables-restore input for chains $chains...";
	    save_progress_message "Preparing iptables-restore input for chains $chains...";
	}

	emit '';

	my $table = 'filter';
	
	my %chains;
    
	for my $chain ( @chains ) {
	    ( $table , $chain ) = split ':', $chain if $chain =~ /:/;
	    
	    fatal_error "Invalid table ( $table )" unless $table =~ /^(nat|mangle|filter)$/;

	    $chains{$table} = [] unless $chains{$table};

	    if ( $chain ) {
		fatal_error "No $table chain found with name $chain" unless  $chain_table{$table}{$chain};
		fatal_error "Built-in chains may not be refreshed" if $chain_table{table}{$chain}{builtin};
		push @{$chains{$table}}, $chain;
	    } else {
		while ( my ( $chain, $chainref ) = each %{$chain_table{$table}} ) {
		    push @{$chains{$table}}, $chain if $chainref->{referenced} && ! $chainref->{builtin};
		}
	    }
	}

	emit 'exec 3>${VARDIR}/.iptables-restore-input';

	enter_cat_mode;
	
	for $table qw(nat mangle filter) {
	    next unless $chains{$table};

	    emit_unindented "*$table";

	    my $tableref=$chain_table{$table};

	    @chains = sort @{$chains{$table}};

	    for my $chain ( @chains ) {
		my $chainref = $tableref->{$chain};
		emit_unindented ":$chainref->{name} - [0:0]";
	    }
	
	    for my $chain ( @chains ) {
		my $chainref = $tableref->{$chain};
		my @rules = @{$chainref->{rules}};
		
		@rules = () unless @rules;
		#
		# Emit the chain rules
		#
		emitr $_ for ( @rules );
	    }
	    #
	    # Commit the changes to the table
	    #
	    enter_cat_mode unless $mode == CAT_MODE;
	    
	    emit_unindented 'COMMIT';
	}

	enter_cmd_mode;

	#
	# Now generate the actual iptables-restore command
	#
	emit(  'exec 3>&-',
	       '',
	       'progress_message2 "Running iptables-restore..."',
	       '',
	       'cat ${VARDIR}/.iptables-restore-input | $IPTABLES_RESTORE -n # Use this nonsensical form to appease SELinux',
	       'if [ $? != 0 ]; then',
	       '    fatal_error "iptables-restore Failed. Input is in ${VARDIR}/.iptables-restore-input"',
	       "fi\n"
	    );
    } else {
	emit('true');
    }

    pop_indent;

    emit "}\n";
}

1;
