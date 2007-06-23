#
# Shorewall-perl 4.0 -- /usr/share/shorewall-perl/Shorewall/Chains.pm
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
#  This is the low-level iptables module. It provides the basic services 
#  of chain and rule creation. It is used by the higher level modules such
#  as Rules to create iptables-restore input.
#
package Shorewall::Chains;
require Exporter;

use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Ports;
use Shorewall::Zones;
use Shorewall::Interfaces;
use Shorewall::IPAddrs;

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
		  INPUT_RESTRICT
		  OUTPUT_RESTRICT
		  POSTROUTE_RESTRICT
		  ALL_RESTRICT

		  process_comment
		  push_cmd_mode
		  pop_cmd_mode
		  add_command
		  add_commands
		  mark_referenced
		  add_file
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
		  setup_zone_mss
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
		  match_source_dev
		  match_dest_dev
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
		  get_interface_address
		  get_interface_addresses
		  set_global_variables
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
our @EXPORT_OK = qw( initialize );
our $VERSION = 1.00;

#
# Chain Table
#
#    @policy_chains is a list of references to policy chains in the filter table
#
#    %chain_table { <table> => { <chain1>  => { name         => <chain name>
#                                               table        => <table name>
#                                               is_policy    => 0|1
#                                               is_optionsl  => 0|1
#                                               referenced   => 0|1
#                                               policy       => <policy>
#                                               loglevel     => <level>
#                                               synparams    => <burst/limit>
#                                               default      => <default action>
#                                               policy_chain => <ref to policy chain -- self-reference if this is a policy chain>
#                                               loopcount    => <number of open loops in runtime commands>
#                                               cmdcount     => <number of client open loops or blocks in runtime commands>
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
#       replaced. Policy chains created under the IMPLICIT_CONTINUE=Yes option are optional.
#
#       Only 'referenced' chains get written to the iptables-restore input.
#
#       'loglevel', 'synparams' and 'default' only apply to policy chains.
#
our @policy_chains;
our %chain_table;
our $nat_table;
our $mangle_table;
our $filter_table;
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

our @builtins = qw(PREROUTING INPUT FORWARD OUTPUT POSTROUTING);

#
# State of the generator.
#
use constant { NULL_STATE => 0 ,   # Generating neither shell commands nor iptables-restore input
	       CAT_STATE  => 1 ,   # Generating iptables-restore input
	       CMD_STATE  => 2 };  # Generating shell commands.

our $state;

#
# Initialize globals -- we take this novel approach to globals initialization to allow
#                       the compiler to run multiple times in the same process. The
#                       initialize() function does globals initialization for this
#                       module and is called from an INIT block below. The function is
#                       also called by Shorewall::Compiler::compiler at the beginning of
#                       the second and subsequent calls to that function. 
#

sub initialize() {
    @policy_chains = ();
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
    %targets = ('ACCEPT'       => STANDARD,
		'ACCEPT+'      => STANDARD  + NONAT,
		'ACCEPT!'      => STANDARD,
		'NONAT'        => STANDARD  + NONAT + NATONLY,
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
		'CONTINUE!'    => STANDARD,
		'QUEUE'        => STANDARD,
		'QUEUE!'       => STANDARD,
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
    # Keep track of which interfaces have active 'address', 'addresses' and 'networks' variables
    #
    %interfaceaddr  = ();
    %interfaceaddrs = ();
    %interfacenets  = ();
    #
    # State of the generator.
    #
    $state = NULL_STATE;
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
# Process a COMMENT line (in $line) 
#
sub process_comment() {
    if ( $capabilities{COMMENTS} ) {
	( $comment = $line ) =~ s/^\s*COMMENT\s*//;
    } else {
	warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
    }
}
#
# Functions to manipulate cmdcount
#
sub push_cmd_mode( $ ) {
    $_[0]->{cmdcount}++;
}

sub pop_cmd_mode( $ ) {
    fatal_error "Internal error in pop_cmd_mode()" if --$_[0]->{cmdcount} < 0;
}

sub add_command($$)
{
    my ($chainref, $command) = @_;

    push @{$chainref->{rules}}, join ('', '~', '    ' x ( $chainref->{loopcount} + $chainref->{cmdcount} ), $command );

    $chainref->{referenced} = 1;
}

sub add_commands {
    my $chainref = shift @_;
   
    for my $command ( @_ ) {
	push @{$chainref->{rules}}, join ('', '~', '    ' x ( $chainref->{loopcount} + $chainref->{cmdcount} ), $command );
    }

    $chainref->{referenced} = 1;
}

sub mark_referenced( $ ) {
    my $chainref = shift @_;

    $chainref->{referenced} = 1;
}

#
# Copy a file into a chain's rules as a set of run-time commands
#

sub add_file( $$ ) {
    my $chainref = $_[0];
    my $file     = find_file $_[1];

    if ( -f $file ) {
	open EF , '<', $file or fatal_error "Unable to open $file: $!";

	add_commands( $chainref, 
		      qq(progress_message "Processing $file..."),
		      '' );

	while ( $line = <EF> ) {
	    chomp $line;
	    add_command $chainref, $line;
	}

	add_command $chainref, '';

	close EF;
    }
}    

#
# Add a rule to a chain. Arguments are:
#
#    Chain reference , Rule
#
sub add_rule($$)
{
    my ($chainref, $rule) = @_;

    $iprangematch = 0;

    if ( $chainref->{loopcount} || $chainref->{cmdcount} ) {
	$rule .= " -m comment --comment \\\"$comment\\\"" if $comment;
	add_command $chainref , qq(echo "-A $chainref->{name} $rule" >&3);
    } else {
	$rule .= " -m comment --comment \"$comment\"" if $comment;
	push @{$chainref->{rules}}, $rule;
	$chainref->{referenced} = 1;
    }
}

#
# Insert a rule into a chain. Arguments are:
#
#    Table , Chain , Rule Number, Rule
#
sub insert_rule($$$)
{
    my ($chainref, $number, $rule) = @_;

    fatal_error 'Internal Error in insert_rule()' if $chainref->{loopcount} || $chainref->{cmdcount};

    $rule .= "-m comment --comment \"$comment\"" if $comment;

    splice @{$chainref->{rules}}, $number - 1, 0,  $rule;

    $iprangematch = 0;

    $chainref->{referenced} = 1;

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

#
# Forward Chain for an interface
#
sub forward_chain($)
{
    chain_base( $_[0] ) . '_fwd';
}

#
# Input Chain for an interface
#
sub input_chain($)
{
    chain_base( $_[0] ) . '_in';
}

#
# Output Chain for an interface
#
sub output_chain($)
{
    chain_base( $_[0] ) . '_out';
}

#
# Masquerade Chain for an interface
#
sub masq_chain($)
{
    chain_base( $_[0] ) . '_masq';
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
    chain_base( $_[0] ) . '_mac';
}

sub macrecent_target($)
{
     $config{MACLIST_TTL} ? chain_base( $_[0] ) . '_rec' : 'RETURN';
}

#
# Functions for creating dynamic zone rules
#
sub dynamic_fwd( $ )
{
    chain_base( $_[0] ) . '_dynf';
}

sub dynamic_in( $ )
{
    chain_base( $_[0] ) . '_dyni';
}

sub dynamic_out( $ ) # $1 = interface
{
    chain_base( $_[0] ) . '_dyno';
}

sub dynamic_chains( $ ) #$1 = interface
{
    my $c = chain_base( $_[0] );

    [ $c . '_dyni' , $c . '_dynf' , $c . '_dyno' ];
}

#
# DNAT Chain from a zone
#
sub dnat_chain( $ )
{
    chain_base( $_[0] ) . '_dnat';
}

#
# SNAT Chain to an interface
#
sub snat_chain( $ )
{
    chain_base( $_[0] ) . '_snat';
}

#
# ECN Chain to an interface
#
sub ecn_chain( $ )
{
    chain_base( $_[0] ) . '_ecn';
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

    $chain_table{$table}{$chain} = { name      => $chain,
				     rules     => [],
				     table     => $table,
				     loglevel  => '',
				     log       => 1,
				     loopcount => 0,
				     cmdcount  => 0 };
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
	} elsif ( $section eq 'RELATED' ) {
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
	    my $policychainref = $filter_table->{$chainref->{policychain}};
	    if ( $policychainref->{synparams} ) {
		my $synchainref = ensure_chain 'filter', syn_chain $policychainref->{name};
		add_rule $chainref, "-p tcp --syn -j $synchainref->{name}";
	    }
	}
    }
}

#
# Do section-end processing
#
sub finish_section ( $ ) {
    my $sections = $_[0];

    for my $section ( split /,/, $sections ) {
	$sections{$section} = 1;
    }

    for my $zone ( @zones ) {
	for my $zone1 ( @zones ) {
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

    for my $z ( @zones ) {
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
# Interate over non-firewall zones adding TCPMSS rules as appropriate
#
sub setup_zone_mss() {
    for my $zone ( @zones ) {
	my $zoneref = $zones{$zone};

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

sub validate_proto( $ ) {
    my $proto = $_[0];
    my $value = $protocols{$proto};
    return $value if defined $value;
    return $proto if $proto =~ /^(\d+)$/ && $proto <= 65535;
    return $proto if $proto eq 'all';
    fatal_error "Invalid/Unknown protocol ($proto)";
}

sub validate_portpair( $ ) {
    my $portpair = $_[0];

    fatal_error "Invalid port range ($portpair)" if $portpair =~ tr/:/:/ > 1;

    $portpair = "0$portpair"       if substr( $portpair,  0, 1 ) eq ':';
    $portpair = "${portpair}65535" if substr( $portpair, -1, 1 ) eq ':';

    my @ports = split/:/, $portpair, 2;

    for my $port ( @ports ) {
	my $value = $services{$port};
	
	unless ( defined $value ) {
	    $value = $port if $port =~ /^(\d+)$/ && $port <= 65535;
	}
	    
	fatal_error "Invalid/Unknown port/service ($port)" unless defined $value;
	
	$port = $value;
    }

    if ( @ports == 2 ) {
	fatal_error "Invalid port range ($portpair)" unless $ports[0] < $ports[1];
    }

    join ':', @ports;

}

sub validate_port_list( $ ) {
    my $result = '';

    for my $port ( split/,/, $_[0] ) {
	my $value = validate_portpair( $port );
	$result = $result ? join ',', $result, $value : $value;
    }

    $result;
}

my %icmp_types = ( any                          => 'any',
		   'echo-reply'                 => 0,
		   'destination-unreachable'    => 3,
		   'network-unreachable'        => '3/0',
		   'host-unreachable'           => '3/1',
		   'protocol-unreachable'       => '3/2',
		   'port-unreachable'           => '3/3',
		   'fragmentation-needed'       => '3/4',
		   'source-route-failed'        => '3/5',
		   'network-unknown'            => '3/6',
		   'host-unknown'               => '3/7',
		   'network-prohibited'         => '3/9',
		   'host-prohibited'            => '3/10',
		   'TOS-network-unreachable'    => '3/11',
		   'TOS-host-unreachable'       => '3/12',
		   'communication-prohibited'   => '3/13',
		   'host-precedence-violation'  => '3/14',
		   'precedence-cutoff'          => '3/15',
		   'source-quench'              => 4,
		   'redirect'                   => 5,
		   'network-redirect'           => '5/0',
		   'host-redirect'              => '5/1',
		   'TOS-network-redirect'       => '5/2',
		   'TOS-host-redirect'          => '5/3',
		   'echo-request'               => '8',
		   'router-advertisement'       => 9,
		   'router-solicitation'        => 10,
		   'time-exceeded'              => 11,
		   'ttl-zero-during-transit'    => '11/0',
		   'ttl-zero-during-reassembly' => '11/1',
		   'parameter-problem'          => 12,
		   'ip-header-bad'              => '12/0',
		   'required-option-missing'    => '12/1',
		   'timestamp-request'          => 13,
		   'timestamp-reply'            => 14,
		   'address-mask-request'       => 17,
		   'address-mask-reply'         => 18 );

sub validate_icmp( $ ) {
    my $type = $_[0];

    my $value = $icmp_types{$type};

    return $value if defined $value;

    if ( $type =~ /^(\d+)(\/(\d+))?$/ ) {
	return $type if $1 < 256 && ( ! $2 || $3 < 256 );
    }

    fatal_error "Invalid ICMP Type ($type)"
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

    if ( $proto ) {
	if ( $proto =~ /^(((tcp|6)((:syn)?))|(udp|17))$/ ) {

	    if ( $4 ) {
		$output = '-p 6 --syn ';
	    } else {
		$proto   = $protocols{$proto} if defined $protocols{$proto};
		$output  = "-p $proto ";
	    }

	    my $multiport = 0;

	    if ( $ports ne '' ) {
		if ( $ports =~ tr/,/,/ > 0 || $sports =~ tr/,/,/ > 0 ) {
		    fatal_error "Port list requires Multiport support in your kernel/iptables ($ports)" unless $capabilities{MULTIPORT};
		    fatal_error "Too many entries in port list ($ports)" if port_count( $ports ) > 15;
		    $ports = validate_port_list $ports;
		    $output .= "-m multiport --dports $ports ";
		    $multiport = 1;
		}  else {
		    $ports   = validate_portpair $ports;
		    $output .= "--dport $ports ";
		}
	    } else {
		$multiport = ( ( $sports =~ tr/,/,/ ) > 0 );
	    }

	    if ( $sports ne '' ) {
		if ( $multiport ) {	
		    fatal_error "Too many entries in port list ($sports)" if port_count( $sports ) > 15;
		    $sports = validate_port_list $sports;
		    $output .= "-m multiport --sports $sports ";
		}  else {
		    $sports  = validate_portpair $sports;
		    $output .= "--sport $sports ";
		}
	    }
	} elsif ( $proto =~ /^(icmp|1)$/i ) {
	    fatal_error 'Multiple ICMP types are not permitted' if $ports =~ /,/;
	    $output .= "-p icmp ";

	    if ( $ports ne '' ) {
		$ports = validate_icmp $ports;
		$output .= "--icmp-type $ports ";
	    }

	    fatal_error 'SOURCE PORT(S) not permitted with ICMP' if $sports ne '';
	} elsif ( $proto =~ /^(ipp2p(:(tcp|udp|all))?)$/i ) {
	    require_capability( 'IPP2P_MATCH' , 'PROTO = ipp2p' , 's' );
	    $proto = $2 ? $3 : 'tcp';
	    $ports = 'ipp2p' unless $ports;
	    $output .= "-p $proto -m ipp2p --$ports ";
	} else {
	    fatal_error "SOURCE/DEST PORT(S) not allowed with PROTO $proto" if $ports ne '' || $sports ne '';
	    $proto = validate_proto $proto;
	    $output .= "-p $proto ";
	}
    } elsif ( $ports ne '' || $sports ne '' ) {
	fatal_error "SOURCE/DEST PORT(S) not allowed without PROTO"
    }

    $output;
}

sub mac_match( $ ) {
    my $mac = $_[0];

    $mac =~ s/^(!?)~//;
    $mac =~ s/^!// if my $invert = ( $1 ? '! ' : '');
    $mac =~ tr/-/:/;

    "--match mac --mac-source ${invert}$mac ";
}

#
# Convert value to decimal number
#
sub numeric_value ( $ ) {
    my $mark = $_[0];
    fatal_error "Invalid Numeric Value ($mark)" unless "\L$mark" =~ /^(0x[a-f0-9]+|0[0-7]*|[1-9]\d*)$/;
    $mark =~ /^0x/ ? hex $mark : $mark =~ /^0/ ? oct $mark : $mark;
}

#
# Mark validatation functions
#
sub verify_mark( $ ) {
    my $mark  = $_[0];
    my $limit = $config{HIGH_ROUTE_MARKS} ? 0xFFFF : 0xFF;

    fatal_error "Invalid Mark or Mask value ($mark)"
	unless numeric_value( $mark ) <= $limit;
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
    my $match  = $testval =~ s/:C$// ? "-m connmark ${invert}--mark" : "-m mark ${invert}--mark";

    validate_mark $testval;

    $testval .= '/0xFF' unless ( $testval =~ '/' );

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

    if ( $rate =~ /^(\d+(\/(sec|hour|day))?):(\d+)$/ ) {
	"-m limit --limit $1 --limit-burst $4 ";
    } elsif ( $rate =~ /^(\d+)(\/(sec|hour|day))?$/ )  {
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

    $tos ne '-' ? "-m tos --tos $tos " : '';
}

#
# Match Source Interface
#
sub match_source_dev( $ ) {
    my $interface = shift;
    my $interfaceref =  $interfaces{$interface};
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
    my $interfaceref =  $interfaces{$interface};
    if ( $interfaceref && $interfaceref->{options}{port} ) {
	"-o $interfaceref->{bridge} -m physdev --physdev-out $interface ";
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

    fatal_error "Your kernel and/or iptables does not include ipset match ($setname)" unless $capabilities{IPSET_MATCH};

    if ( $setname =~ /(.*)\[([1-6])\]$/ ) {
	$setname  = $1;
	my $count = $2;
	$options .= ",$option" while --$count > 0;
    } elsif ( $setname =~ /(.+)\[(.*)\]$/ ) {
	$setname = $1;
	$options = $2;
    }

    $setname =~ s/^\+//;

    "--set $setname $options "
}

#
# Match a Source. Currently only handles IP addresses and ranges
#
sub match_source_net( $ ) {
    my $net = $_[0];

    if ( $net =~ /^(!?)(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) {
	my ($addr1, $addr2) = ( $2, $3 );
	$net =~ s/!// if my $invert = $1 ? '! ' : '';
	validate_range $addr1, $addr2;
	iprange_match . "${invert}--src-range $net ";
    } elsif ( $net =~ /^(!?)~(.*)$/ ) {
	( $net = $2 ) =~ tr/-/:/;
	my $invert = $1 ? '! ' : '';
	"-m mac --mac-source ${invert}$net ";
    } elsif ( $net =~ /^(!?)\+/ ) {
	require_capability( 'IPSET_MATCH' , 'ipset names in Shorewall configuration files' , '' );
	join( '', '-m set ', $1 ? '! ' : '', get_set_flags( $net, 'src' ) );
    } elsif ( $net =~ /^!/ ) {
	$net =~ s/!//;
	validate_net $net;
	validate_net $net;
	"-s ! $net ";
    } else {
	validate_net $net;
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
	validate_net $net;
	"-d ! $net ";
    } else {
	validate_net $net;
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

    unless ( $predicates =~ /-m limit / ) {
	$limit = $globals{LOGLIMIT} unless $limit && $limit ne '-';
	$predicates .= $limit if $limit;
    }

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

    if ( $globals{LOGRULENUMBERS} ) {
	$prefix = (sprintf $config{LOGFORMAT} , $chain , $chainref->{log}++, $disposition ) . $tag;
    } else {
	$prefix = (sprintf $config{LOGFORMAT} , $chain , $disposition) . $tag;
    }

    if ( length $prefix > 29 ) {
	$prefix = substr $prefix, 0, 29;
	warning_message "Log Prefix shortened to \"$prefix\"";
    }

    if ( $chainref->{loopcount} || $chainref->{cmdcount} ) {
	#
	# The rule will be converted to an "echo" shell command. We must insure that the 
	# quotes are preserved in the iptables-input file.
	#
	if ( $level eq 'ULOG' ) {
	    $prefix = "-j ULOG $globals{LOGPARMS}--ulog-prefix \\\"$prefix\\\" ";
	} else {
	    $prefix = "-j LOG $globals{LOGPARMS}--log-level $level --log-prefix \\\"$prefix\\\" ";
	}
    } else {
	if ( $level eq 'ULOG' ) {
	    $prefix = "-j ULOG $globals{LOGPARMS}--ulog-prefix \"$prefix\" ";
	} else {
	    $prefix = "-j LOG $globals{LOGPARMS}--log-level $level --log-prefix \"$prefix\" ";
	}
    }

    if ( $command eq 'add' ) {
	add_rule ( $chainref, $predicates . $prefix );
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
    my @input = split /,/, $_[0];

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
    chain_base( $_[0] ) . '_address';
}

#
# Record that the ruleset requires the first IP address on the passed interface
#
sub get_interface_address ( $ ) {
    my ( $interface ) = $_[0];

    my $variable = interface_address( $interface );
    my $function = interface_is_optional( $interface ) ? 'find_first_interface_address_if_any' : 'find_first_interface_address';

    $interfaceaddr{$interface} = "$variable=\$($function $interface)";

    "\$$variable";
}

#
# Returns the name of the shell variable holding the addresses of the passed interface
#
sub interface_addresses( $ ) {
    chain_base( $_[0] ) . '_addresses';
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
    chain_base( $_[0] ) . '_networks';
}

#
# Record that the ruleset requires the first IP address on the passed interface
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

	    add_command( $chainref , join( '', 'for source in ', $networks, '; do' ) );

	    $rule .= '-s $source ';
	    #
	    # While $loopcount > 0, calls to 'add_rule()' will be converted to calls to 'add_command()'
	    #
	    $chainref->{loopcount}++;
	} else {
	    fatal_error "Source Interface ($iiface) not allowed when the source zone is $firewall_zone" if $restriction & OUTPUT_RESTRICT;
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

		for my $interface ( @interfaces ) {
		    $list = join( ' ', $list , get_interface_address( $interface ) );
		}

		add_command( $chainref , "for address in $list; do" );

		$rule .= '-d $address ';
		$chainref->{loopcount}++;
	    } else {
		$rule .= join ( '', '-d ', get_interface_address( $interfaces[0] ), ' ' );
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
	    add_command( $chainref , 'for dest in ' . get_interface_addresses( $diface) . '; do' );
	    $rule .= '-d $dest ';
	    $chainref->{loopcount}++;
	} else {
	    fatal_error "Bridge Port ($diface) not allowed in OUTPUT or POSTROUTING rules" if ( $restriction & ( POSTROUTE_RESTRICT + OUTPUT_RESTRICT ) ) && port_to_bridge( $diface );
	    fatal_error "Destination Interface ($diface) not allowed when the destination zone is $firewall_zone" if $restriction & INPUT_RESTRICT;

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

		for my $interface ( @interfaces ) {
		    $list = join( ' ', $list , get_interface_address( $interface ) );
		}

		add_command( $chainref , "for address in $list; do" );
		$rule .= '-m conntrack --ctorigdst $address ';
		$chainref->{loopcount}++;
	    } else {
		get_interface_address $interfaces[0];
		$rule .= join( '', '-m conntrack --ctorigdst $', interface_address ( $interfaces[0] ), ' ' );
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
		    $rule .= "-m conntrack --ctorigdst ! $oexcl ";
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
		$rule .= match_source_net "!$iexcl";
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
		    # We defer evaluating the source net match to accomodate system without $capabilities{KLUDGEFREE}
		    #
		    add_rule $chainref, join( '', $rule, match_source_net( $inet), match_dest_net( $dnet ), $onet, "-j $echain" );
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
	for my $net ( mysplit $iexcl ) {
	    add_rule $echainref, ( match_source_net $net ) . '-j RETURN';
	}

	for my $net ( mysplit $dexcl ) {
	    add_rule $echainref, ( match_dest_net $net ) . '-j RETURN';
	}

	for my $net ( mysplit $oexcl ) {
	    add_rule $echainref, ( match_orig_dest $net ) . '-j RETURN';
	}
	#
	# Log rule
	#
	log_rule_limit $loglevel , $echainref , $chain, $disposition , '',  $logtag , 'add' , '' if $loglevel;
	#
	# Generate Final Rule
	#
	add_rule( $echainref, $exceptionrule . $target ) unless $disposition eq 'LOG';
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
			    join( '', $rule, match_source_net( $inet) , match_dest_net( $dnet ), $onet );
		    }

		    unless ( $disposition eq 'LOG' ) {
			add_rule
			    $chainref,
			    join( '', $rule, match_source_net ($inet), match_dest_net( $dnet ), $onet, $target  );
		    }
		}
	    }
	}
    }

    while ( $chainref->{loopcount} > 0 ) {
	$chainref->{loopcount}--;
	add_command $chainref, 'done';
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
# What follows is the code that generates the input to iptables-restore
#

#
# Emits the passed 'rule'
#
sub emitr( $ ) {
    my $rule = $_[0];

    if ( substr( $rule, 0, 1 ) eq '~' ) {
	#
	# A command
	#
	unless ( $state == CMD_STATE ) {
	    emit_unindented "__EOF__\n" if $state == CAT_STATE;
	    $state = CMD_STATE;
	}

	$rule = substr( $rule, 1 );

	emit $rule;
    } else {
	unless ( $state == CAT_STATE ) {
	    emit '';
	    emit 'cat >&3 << __EOF__';
	    $state = CAT_STATE;
	}

	emit_unindented $rule;
    }
}

my $emitted_comment = 0;

sub emit_comment() {
    unless ( $emitted_comment ) {
	emitj ( '#',
		'# Establish the values of shell variables used in the following function calls',
		'#' );
	$emitted_comment = 1;
    }
}

#
# Generate setting of global variables
#
sub set_global_variables() {

    for ( values %interfaceaddr ) {
	emit_comment;
	emit $_;
    }

    for ( values %interfaceaddrs ) {
	emit_comment;
	emit $_;
    }

    for ( values %interfacenets ) {
	emit_comment;
	emit $_;
    }

}

#
# Generate the netfilter input
#
sub create_netfilter_load() {

    emitj( 'setup_netfilter()',
	   '{'
	   );

    push_indent;

    save_progress_message "Preparing iptables-restore input...";

    emit '';
    #
    # We always write the input into a file then pass the file to iptables-restore. That way, if things go wrong,
    # the user (and Shorewall support) has something to look at to determine the error
    #
    emit 'exec 3>${VARDIR}/.iptables-restore-input';

    my @table_list;

    push @table_list, 'raw'    if $capabilities{RAW_TABLE};
    push @table_list, 'nat'    if $capabilities{NAT_ENABLED};
    push @table_list, 'mangle' if $capabilities{MANGLE_ENABLED};
    push @table_list, 'filter';

    for my $table ( @table_list ) {
	emitr "*$table";

	my @chains;
	#
	# iptables-restore seems to be quite picky about the order of the builtin chains
	#
	for my $chain ( @builtins ) {
	    my $chainref = $chain_table{$table}{$chain};
	    if ( $chainref ) {
		emitr ":$chain $chainref->{policy} [0:0]";
		push @chains, $chainref;
	    }
	}
	#
	# First create the chains in the current table
	#
	for my $chain ( grep $chain_table{$table}{$_}->{referenced} , ( sort keys %{$chain_table{$table}} ) ) {
	    my $chainref =  $chain_table{$table}{$chain};
	    unless ( $chainref->{builtin} ) {
		emitr ":$chainref->{name} - [0:0]";
		push @chains, $chainref;
	    }
	}
	#
	# then emit the rules
	#
	for my $chainref ( @chains ) {
	    my $name = $chainref->{name};
	    for my $rule ( @{$chainref->{rules}} ) {
		$rule = "-A $name $rule" unless substr( $rule, 0, 1) eq '~';
		emitr $rule;
	    }
	}
	#
	# Commit the changes to the table
	#
	emitr 'COMMIT';
    }

    emit_unindented '__EOF__' unless $state == CMD_STATE;
    emit '';
    #
    # Now generate the actual iptabes-restore command
    #
    emitj( 'exec 3>&-',
	   '',
	   'progress_message2 "Running iptables-restore..."',
	   '',
	   'iptables-restore < ${VARDIR}/.iptables-restore-input'
	 );

    emitj( 'if [ $? != 0 ]; then',
	   '    fatal_error "iptables-restore Failed. Input is in ${VARDIR}/.iptables-restore-input"',
	   "fi\n"
	   );

    pop_indent;

    emit "}\n";
}

1;
