#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Policy.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010 - Tom Eastep (teastep@shorewall.net)
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
#   This module deals with the /etc/shorewall/policy file.
#
package Shorewall::Policy;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;
use Shorewall::Chains qw( :DEFAULT :internal) ;
use Shorewall::Actions;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( validate_policy apply_policy_rules complete_standard_chain setup_syn_flood_chains save_policies optimize_policy_chains);
our @EXPORT_OK = qw(  );
our $VERSION = '4.4_16';

# @policy_chains is a list of references to policy chains in the filter table

our @policy_chains;

#
# Called by the compiler
#
sub initialize() {
    @policy_chains = ();
}

#
# Convert a chain into a policy chain.
#
sub convert_to_policy_chain($$$$$)
{
    my ($chainref, $source, $dest, $policy, $provisional ) = @_;

    $chainref->{is_policy}   = 1;
    $chainref->{policy}      = $policy;
    $chainref->{provisional} = $provisional;
    $chainref->{policychain} = $chainref->{name};
    $chainref->{policypair}  = [ $source, $dest ];
}

#
# Create a new policy chain and return a reference to it.
#
sub new_policy_chain($$$$)
{
    my ($source, $dest, $policy, $provisional) = @_;

    my $chainref = new_chain( 'filter', rules_chain( ${source}, ${dest} ) );

    convert_to_policy_chain( $chainref, $source, $dest, $policy, $provisional );

    $chainref;
}

#
# Set the passed chain's policychain and policy to the passed values.
#
sub set_policy_chain($$$$$)
{
    my ($source, $dest, $chain1, $chainref, $policy ) = @_;

    my $chainref1 = $filter_table->{$chain1};

    $chainref1 = new_chain 'filter', $chain1 unless $chainref1;

    unless ( $chainref1->{policychain} ) {
	if ( $config{EXPAND_POLICIES} ) {
	    #
	    # We convert the canonical chain into a policy chain, using the settings of the
	    # passed policy chain.
	    #
	    $chainref1->{policychain} = $chain1;
	    $chainref1->{loglevel}    = $chainref->{loglevel} if defined $chainref->{loglevel};

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
    }
}

#
# Process the policy file
#
use constant { PROVISIONAL => 1 };

sub add_or_modify_policy_chain( $$ ) {
    my ( $zone, $zone1 ) = @_;
    my $chain    = rules_chain( ${zone}, ${zone1} );
    my $chainref = $filter_table->{$chain};

    if ( $chainref ) {
	unless( $chainref->{is_policy} ) {
	    convert_to_policy_chain( $chainref, $zone, $zone1, 'CONTINUE', PROVISIONAL );
	    push @policy_chains, $chainref;
	}
    } else {
	push @policy_chains, ( new_policy_chain $zone, $zone1, 'CONTINUE', PROVISIONAL );
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

sub process_a_policy() {

    our %validpolicies;
    our @zonelist;

    my ( $client, $server, $originalpolicy, $loglevel, $synparams, $connlimit ) = split_line 3, 6, 'policy file';

    $loglevel  = '' if $loglevel  eq '-';
    $synparams = '' if $synparams eq '-';
    $connlimit = '' if $connlimit eq '-';

    my $clientwild = ( "\L$client" eq 'all' );

    fatal_error "Undefined zone ($client)" unless $clientwild || defined_zone( $client );

    my $serverwild = ( "\L$server" eq 'all' );

    fatal_error "Undefined zone ($server)" unless $serverwild || defined_zone( $server );

    my ( $policy, $default, $remainder ) = split( /:/, $originalpolicy, 3 );

    fatal_error "Invalid or missing POLICY ($originalpolicy)" unless $policy;

    fatal_error "Invalid default action ($default:$remainder)" if defined $remainder;

    ( $policy , my $queue ) = get_target_param $policy;
    
    if ( $default ) {
	if ( "\L$default" eq 'none' ) {
	    $default = 'none';
	} else {
	    my $defaulttype = $targets{$default} || 0;
	    
	    if ( $defaulttype & ACTION ) {
		use_action( normalize_action_name $default );
	    } else {
		fatal_error "Unknown Default Action ($default)";
	    }
	}
    } else {
	$default = $default_actions{$policy} || '';
    }

    fatal_error "Invalid policy ($policy)" unless exists $validpolicies{$policy};

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
	if ( zone_type( $server ) == BPORT ) {
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
	    convert_to_policy_chain( $chainref, $client, $server, $policy, 0 );
	    push @policy_chains, ( $chainref ) unless $config{EXPAND_POLICIES} && ( $clientwild || $serverwild );
	}
    } else {
	$chainref = new_policy_chain $client, $server, $policy, 0;
	push @policy_chains, ( $chainref ) unless $config{EXPAND_POLICIES} && ( $clientwild || $serverwild );
    }

    $chainref->{loglevel}  = validate_level( $loglevel ) if defined $loglevel && $loglevel ne '';

    if ( $synparams ne '' || $connlimit ne '' ) {
	my $value = '';
	fatal_error "Invalid CONNLIMIT ($connlimit)" if $connlimit =~ /^!/;
	$value  = do_ratelimit $synparams, 'ACCEPT'  if $synparams ne '';
	$value .= do_connlimit $connlimit            if $connlimit ne '';
	$chainref->{synparams} = $value;
	$chainref->{synchain}  = $chain
    }

    $chainref->{default} = $default if $default;

    if ( $clientwild ) {
	if ( $serverwild ) {
	    for my $zone ( @zonelist ) {
		for my $zone1 ( @zonelist ) {
		    set_policy_chain $client, $server, rules_chain( ${zone}, ${zone1} ), $chainref, $policy;
		    print_policy $zone, $zone1, $policy, $chain;
		}
	    }
	} else {
	    for my $zone ( all_zones ) {
		set_policy_chain $client, $server, rules_chain( ${zone}, ${server} ), $chainref, $policy;
		print_policy $zone, $server, $policy, $chain;
	    }
	}
    } elsif ( $serverwild ) {
	for my $zone ( @zonelist ) {
	    set_policy_chain $client, $server, rules_chain( ${client}, ${zone} ), $chainref, $policy;
	    print_policy $client, $zone, $policy, $chain;
	}

    } else {
	print_policy $client, $server, $policy, $chain;
    }
}

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

sub validate_policy()
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

    for my $option qw( DROP_DEFAULT REJECT_DEFAULT ACCEPT_DEFAULT QUEUE_DEFAULT NFQUEUE_DEFAULT) {
	my $action = $config{$option};
	next if $action eq 'none';
	my $actiontype = $targets{$action};
												 
	if ( defined $actiontype ) {
	    fatal_error "Invalid setting ($action) for $option" unless $actiontype & ACTION;
	} else {
	    fatal_error "Default Action $option=$action not found";
	}

	use_action( normalize_action_name $action );

	$default_actions{$map{$option}} = $action;
    }

    for $zone ( all_zones ) {
	push @policy_chains, ( new_policy_chain $zone,         $zone, 'ACCEPT', PROVISIONAL );
	push @policy_chains, ( new_policy_chain firewall_zone, $zone, 'NONE',   PROVISIONAL ) if zone_type( $zone ) == BPORT;

	my $zoneref = find_zone( $zone );

	if ( $config{IMPLICIT_CONTINUE} && ( @{$zoneref->{parents}} || $zoneref->{type} == VSERVER ) ) {
	    for my $zone1 ( all_zones ) {
		unless( $zone eq $zone1 ) {
		    add_or_modify_policy_chain( $zone, $zone1 );
		    add_or_modify_policy_chain( $zone1, $zone );
		}
	    }
	}
    }

    if ( my $fn = open_file 'policy' ) {
	first_entry "$doing $fn...";
	process_a_policy while read_a_line;
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
sub policy_rules( $$$$$ ) {
    my ( $chainref , $target, $loglevel, $default, $dropmulticast ) = @_;

    unless ( $target eq 'NONE' ) {
	add_rule $chainref, "-d 224.0.0.0/4 -j RETURN" if $dropmulticast && $target ne 'CONTINUE' && $target ne 'ACCEPT';
	add_jump $chainref, $default, 0 if $default && $default ne 'none';
	log_rule $loglevel , $chainref , $target , '' if $loglevel ne '';
	fatal_error "Null target in policy_rules()" unless $target;

	add_jump( $chainref , $target eq 'REJECT' ? 'reject' : $target, 1 ) unless $target eq 'CONTINUE';
    }
}

sub report_syn_flood_protection() {
    progress_message_nocompress '      Enabled SYN flood protection';
}

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
		add_jump $chainref,  $policyref, 1;
		$chainref = $policyref;
	    }
	} elsif ( $policy eq 'CONTINUE' ) {
	    report_syn_flood_protection if $synparams;
	    policy_rules $chainref , $policy , $loglevel , $default, $config{MULTICAST};
	} else {
	    report_syn_flood_protection if $synparams;
	    add_jump $chainref , $policyref, 1;
	    $chainref = $policyref;
	}
    }

    progress_message_nocompress "   Policy $policy from $_[1] to $_[2] using chain $chainref->{name}";

}

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
		    ensure_filter_chain $name, 1 if $default ne 'none' || $loglevel || $synparms || $config{MULTICAST} || ! ( $policy eq 'ACCEPT' || $config{FASTACCEPT} );
		} else {
		    ensure_filter_chain $name, 1;
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

    add_rule $stdchainref, "$globals{STATEMATCH} ESTABLISHED,RELATED -j ACCEPT" unless $config{FASTACCEPT};

    run_user_exit $stdchainref;

    my $ruleschainref = $filter_table->{rules_chain( ${zone}, ${zone2} ) } || $filter_table->{rules_chain( 'all', 'all' ) };
    my ( $policy, $loglevel, $defaultaction ) = ( $default , 6, $config{$default . '_DEFAULT'} );
    my $policychainref;

    $policychainref = $filter_table->{$ruleschainref->{policychain}} if $ruleschainref;

    ( $policy, $loglevel, $defaultaction ) = @{$policychainref}{'policy', 'loglevel', 'default' } if $policychainref;

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
	    log_rule_limit( $level ,
			    $synchainref ,
			    $chainref->{name} ,
			    'DROP',
			    $globals{LOGLIMIT} || '-m limit --limit 5/min --limit-burst 5 ' ,
			    '' ,
			    'add' ,
			    '' )
		if $level ne '';
	    add_rule $synchainref, '-j DROP';
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

    if ( @{$outputrules} && $outputrules->[-1] =~ /-j ACCEPT/ ) {
	optimize_chain( $filter_table->{OUTPUT} );
    }

    progress_message '  Policy chains optimized';
    progress_message '';
}

1;
