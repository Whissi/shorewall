#
# Shorewall-perl 4.0 -- /usr/share/shorewall-perl/Shorewall/Policy.pm
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
#   This module deals with the /etc/shorewall/policy file.
#
package Shorewall::Policy;
require Exporter;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Chains;
use Shorewall::Actions;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( validate_policy apply_policy_rules complete_standard_chain sub setup_syn_flood_chains );
our @EXPORT_OK = qw(  );
our $VERSION = '4.03';

# @policy_chains is a list of references to policy chains in the filter table

our @policy_chains;

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
}

INIT {
    initialize;
}

#
# Convert a chain into a policy chain.
#
sub convert_to_policy_chain($$$$$)
{
    my ($chainref, $source, $dest, $policy, $optional ) = @_;

    $chainref->{is_policy}   = 1;
    $chainref->{policy}      = $policy;
    $chainref->{is_optional} = $optional;
    $chainref->{policychain} = $chainref->{name};
    $chainref->{policypair}  = [ $source, $dest ];
}

#
# Create a new policy chain and return a reference to it.
#
sub new_policy_chain($$$$)
{
    my ($source, $dest, $policy, $optional) = @_;

    my $chainref = new_chain( 'filter', IPv4, "${source}2${dest}" );

    convert_to_policy_chain( $chainref, $source, $dest, $policy, $optional );

    $chainref;
}

#
# Set the passed chain's policychain and policy to the passed values.
#
sub set_policy_chain($$$$$)
{
    my ($source, $dest, $chain1, $chainref, $policy ) = @_;

    my $chainref1 = $filter_table->{4}{$chain1};

    $chainref1 = new_chain 'filter', IPv4, $chain1 unless $chainref1;

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
use constant { OPTIONAL => 1 };

sub add_or_modify_policy_chain( $$ ) {
    my ( $zone, $zone1 ) = @_;
    my $chain    = "${zone}2${zone1}";
    my $chainref = $filter_table->{4}{$chain};
    
    if ( $chainref ) {
	unless( $chainref->{is_policy} ) {
	    convert_to_policy_chain( $chainref, $zone, $zone1, 'CONTINUE', OPTIONAL );
	    push @policy_chains, $chainref;
	}
    } else {
	push @policy_chains, ( new_policy_chain $zone, $zone1, 'CONTINUE', OPTIONAL );
    }
}    

sub print_policy($$$$) {
    my ( $source, $dest, $policy , $chain ) = @_;
    unless ( ( $source eq 'all' ) || ( $dest eq 'all' ) ) {
	if ( $policy eq 'CONTINUE' ) {
	    my ( $sourceref, $destref ) = ( find_zone($source) ,find_zone( $dest ) );
	    warning_message "CONTINUE policy between two un-nested zones ($source, $dest)" if ! ( @{$sourceref->{parents}} || @{$destref->{parents}} );
	}
	progress_message "   Policy for $source to $dest is $policy using chain $chain" unless $source eq $dest;
    }
}

sub validate_policy()
{
    my %validpolicies = (
			  ACCEPT => undef,
			  REJECT => undef,
			  DROP   => undef,
			  CONTINUE => undef,
			  QUEUE => undef,
			  NFQUEUE => undef,
			  NONE => undef
			  );

    my %map = ( DROP_DEFAULT    => 'DROP' ,
		REJECT_DEFAULT  => 'REJECT' ,
		ACCEPT_DEFAULT  => 'ACCEPT' ,
		QUEUE_DEFAULT   => 'QUEUE' ,
	        NFQUEUE_DEFAULT => 'NFQUEUE' );

    my $zone;

    for my $option qw/DROP_DEFAULT REJECT_DEFAULT ACCEPT_DEFAULT QUEUE_DEFAULT NFQUEUE_DEFAULT/ {
	my $action = $config{$option};
	next if $action eq 'none';
	my $actiontype = $targets{$action};

	if ( defined $actiontype ) {
	    fatal_error "Invalid setting ($action) for $option" unless $actiontype & ACTION;
	} else {
	    fatal_error "Default Action $option=$action not found";
	}

	unless ( $usedactions{$action} ) {
	    $usedactions{$action} = 1;
	    createactionchain $action;
	}

	$default_actions{$map{$option}} = $action;
    }

    for $zone ( all_zones ) {
	push @policy_chains, ( new_policy_chain $zone, $zone, 'ACCEPT', OPTIONAL );

	if ( $config{IMPLICIT_CONTINUE} && ( @{find_zone( $zone )->{parents}} ) ) {
	    for my $zone1 ( all_zones ) {
		unless( $zone eq $zone1 ) {
		    add_or_modify_policy_chain( $zone, $zone1 );
		    add_or_modify_policy_chain( $zone1, $zone );
		}
	    }
	}
    }

    my $fn = open_file 'policy';

    my $first_entry = 1;

    while ( read_a_line ) {

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	my ( $client, $server, $policy, $loglevel, $synparams ) = split_line 3, 5, 'policy file';

	$loglevel  = '' if $loglevel  eq '-';
	$synparams = '' if $synparams eq '-';

	my $clientwild = ( "\L$client" eq 'all' );

	fatal_error "Undefined zone $client" unless $clientwild || defined_zone( $client );

	my $serverwild = ( "\L$server" eq 'all' );

	fatal_error "Undefined zone $server" unless $serverwild || defined_zone( $server );

	( $policy , my ( $default, $remainder ) ) = split( /:/, $policy, 3 );

	fatal_error "Invalid default action ($default:$remainder)" if defined $remainder;

	( $policy , my $queue ) = split( '/' , $policy );

	if ( $default ) {
	    if ( "\L$default" eq 'none' ) {
		$default = 'none';
	    } else {
		my $defaulttype = $targets{$default} || 0;

		if ( $defaulttype & ACTION ) {
		    unless ( $usedactions{$default} ) {
			$usedactions{$default} = 1;
			createactionchain $default;
		    }
		} else {
		    fatal_error "Unknown Default Action ($default)";
		}
	    }
	} else {
	    $default = $default_actions{$policy} || '';
	}

	fatal_error "Invalid policy $policy" unless exists $validpolicies{$policy};

	if ( defined $queue ) {
	    fatal_error "Invalid policy ($policy/$queue)" unless $policy eq 'NFQUEUE';
	    require_capability( 'NFQUEUE_TARGET', 'An NFQUEUE Policy', 's' ); 
	    $queue = numeric_value( $queue );
	    fatal_error "Invalid NFQUEUE queue number ($queue)" if $queue > 65535;
	    $policy = "$policy/$queue";
	} elsif ( $policy eq 'NONE' ) {
	    fatal_error "NONE policy not allowed with \"all\""
		if $clientwild || $serverwild;
	    fatal_error "NONE policy not allowed to/from firewall zone"
		if ( zone_type( $client ) == ZT_FIREWALL ) || ( zone_type( $server ) == ZT_FIREWALL );
	}

	unless ( $clientwild || $serverwild ) {
	    if ( zone_type( $server ) & ZT_BPORT ) {
		fatal_error "Invalid policy - DEST zone is a Bridge Port zone but the SOURCE zone is not associated with the same bridge"
		    unless find_zone( $client )->{bridge} eq find_zone( $server)->{bridge} || single_interface( $client ) eq find_zone( $server )->{bridge};
	    }
	}

	my $chain = "${client}2${server}";
	my $chainref;

	if ( defined $filter_table->{4}{$chain} ) {
	    $chainref = $filter_table->{4}{$chain};

	    if ( $chainref->{is_policy} ) {
		if ( $chainref->{is_optional} ) {
		    $chainref->{is_optional} = 0;
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

	if ( $synparams ne '' ) {
	    $chainref->{synparams} = do_ratelimit $synparams, 'ACCEPT';
	    $chainref->{synchain}  = $chain
	}

	$chainref->{default}   = $default if $default;

	if ( $clientwild ) {
	    if ( $serverwild ) {
		for my $zone ( all_zones , 'all' ) {
		    for my $zone1 ( all_zones , 'all' ) {
			set_policy_chain $client, $server, "${zone}2${zone1}", $chainref, $policy;
			print_policy $zone, $zone1, $policy, $chain;
		    }
		}
	    } else {
		for my $zone ( all_zones ) {
		    set_policy_chain $client, $server, "${zone}2${server}", $chainref, $policy;
		    print_policy $zone, $server, $policy, $chain;
		}
	    }
	} elsif ( $serverwild ) {
	    for my $zone ( all_zones , 'all' ) {
		set_policy_chain $client, $server, "${client}2${zone}", $chainref, $policy;
		print_policy $client, $zone, $policy, $chain;
	    }

	} else {
	    print_policy $client, $server, $policy, $chain;
	}
    }
}

#
# Policy Rule application
#
sub policy_rules( $$$$ ) {
    my ( $chainref , $target, $loglevel, $default ) = @_;

    unless ( $target eq 'NONE' ) {
	add_rule $chainref, "-j $default" if $default && $default ne 'none';
	log_rule $loglevel , $chainref , $target , '' if $loglevel ne '';
	fatal_error "Null target in policy_rules()" unless $target;
	if ( $target eq 'REJECT' ) {
	    $target = 'reject';
	} elsif ( $target =~ /^NFQUEUE/ ) {
	    my $queue = ( split( '/', $target) )[1] || 0;
	    $target = "NFQUEUE --queue-num $queue";
	}

	add_rule( $chainref , "-j $target" ) unless $target eq 'CONTINUE';
    }
}

sub report_syn_flood_protection() {
    progress_message '      Enabled SYN flood protection';
}

sub default_policy( $$$ ) {
    my $chainref   = $_[0];
    my $policyref  = $filter_table->{4}{$chainref->{policychain}};
    my $synparams  = $policyref->{synparams};
    my $default    = $policyref->{default};
    my $policy     = $policyref->{policy};
    my $loglevel   = $policyref->{loglevel};

    fatal_error "No default policy for $_[1] to zone $_[2]" unless $policyref;

    if ( $chainref eq $policyref ) {
	policy_rules $chainref , $policy, $loglevel , $default;
    } else {
	if ( $policy eq 'ACCEPT' || $policy eq 'QUEUE' || $policy =~ /^NFQUEUE/ ) {
	    if ( $synparams ) {
		report_syn_flood_protection;
		policy_rules $chainref , $policy , $loglevel , $default;
	    } else {
		add_rule $chainref,  "-j $policyref->{name}";
		$chainref = $policyref;
	    }
	} elsif ( $policy eq 'CONTINUE' ) {
	    report_syn_flood_protection if $synparams;
	    policy_rules $chainref , $policy , $loglevel , $default;
	} else {
	    report_syn_flood_protection if $synparams;
	    add_rule $chainref , "-j $policyref->{name}";
	    $chainref = $policyref;
	}
    }

    progress_message "   Policy $policy from $_[1] to $_[2] using chain $chainref->{name}";

}

sub apply_policy_rules() {
    progress_message2 'Applying Policies...';

    for my $chainref ( @policy_chains ) {
	my $policy = $chainref->{policy};
	my $loglevel = $chainref->{loglevel};
	my $optional = $chainref->{is_optional};
	my $default  = $chainref->{default};
	my $name     = $chainref->{name};

	if ( $policy ne 'NONE' ) {
	    if ( ! $chainref->{referenced} && ( ! $optional && $policy ne 'CONTINUE' ) ) {
		ensure_filter_chain $name, 1;
	    }

	    if ( $name =~ /^all2|2all$/ ) {
		run_user_exit $chainref;
		policy_rules $chainref , $policy, $loglevel , $default;
	    }

	}
    }

    for my $zone ( all_zones ) {
	for my $zone1 ( all_zones ) {
	    my $chainref = $filter_table->{4}{"${zone}2${zone1}"};

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
sub complete_standard_chain ( $$$ ) {
    my ( $stdchainref, $zone, $zone2 ) = @_;

    add_rule $stdchainref, '-m state --state ESTABLISHED,RELATED -j ACCEPT' unless $config{FASTACCEPT};

    run_user_exit $stdchainref;

    my $ruleschainref = $filter_table->{4}{"${zone}2${zone2}"};
    my ( $policy, $loglevel, $default ) = ( 'DROP', 6, $config{DROP_DEFAULT} );
    my $policychainref;

    $policychainref = $filter_table->{4}{$ruleschainref->{policychain}} if $ruleschainref;

    ( $policy, $loglevel, $default ) = @{$policychainref}{'policy', 'loglevel', 'default' } if $policychainref;

    policy_rules $stdchainref , $policy , $loglevel, $default;
}

#
# Create and populate the synflood chains corresponding to entries in /etc/shorewall/policy
#
sub setup_syn_flood_chains() {
    for my $chainref ( @policy_chains ) {
	my $limit = $chainref->{synparams};
	if ( $limit && ! $filter_table->{4}{syn_flood_chain $chainref} ) {
	    my $level = $chainref->{loglevel};
	    my $synchainref = new_chain 'filter' , IPv4, syn_flood_chain $chainref;
	    add_rule $synchainref , "${limit}-j RETURN";
	    log_rule_limit $level , $synchainref , $chainref->{name} , 'DROP', '-m limit --limit 5/min --limit-burst 5 ' , '' , 'add' , ''
		if $level ne '';
	    add_rule $synchainref, '-j DROP';
	}
    }
}

1;
