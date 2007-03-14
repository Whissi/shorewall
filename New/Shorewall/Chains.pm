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
		  cynamic_chains
		  dnat_chain
		  snat_chain
		  ecn_chain
		  first_chains
		  
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

1;
