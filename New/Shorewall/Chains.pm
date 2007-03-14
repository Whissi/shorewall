package Shorewall::Chains;
require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw( add_rule
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
		  
		  @policy_chains 
		  %chain_table 
		  $nat_table 
		  $mangle_table 
		  $filter_table );
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
my @policy_chains;
my %chain_table = ( raw    => {} , 
		    mangle => {},
		    nat    => {},
		    filter => {} );

my $nat_table    = $chain_table{nat};
my $mangle_table = $chain_table{mangle};
my $filter_table = $chain_table{filter};

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
	    my $chainref = $chain_table{'filter'}{"${zone}2${zone1}"};
	    if ( $chainref->{referenced} ) {
		finish_chain_section $chainref, $sections;
	    }
	}
    }
}

1;
