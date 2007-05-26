#
# Shorewall-perl 3.9 -- /usr/share/shorewall-perl/Shorewall/Policy.pm
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
#   This module deals with the /etc/shorewall/policy file.
#
package Shorewall::Policy;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Chains;
use Shorewall::Actions;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( validate_policy apply_policy_rules complete_standard_chain );
our @EXPORT_OK = qw(  );
our @VERSION = 1.00;


#
# Create a new policy chain and return a reference to it.
#
sub new_policy_chain($$$)
{
    my ($chain, $policy, $optional) = @_;

    my $chainref = new_chain 'filter', $chain;

    $chainref->{is_policy}   = 1;
    $chainref->{policy}      = $policy;
    $chainref->{is_optional} = $optional;
    $chainref->{policychain} = $chainref;
}

#
# Set the passed chain's policychain and policy to the passed values.
#
sub set_policy_chain($$$)
{
    my ($chain1, $chainref, $policy) = @_;

    my $chainref1 = $filter_table->{$chain1};
    $chainref1 = new_chain 'filter', $chain1 unless $chainref1;
    unless ( $chainref1->{policychain} ) {
	$chainref1->{policychain} = $chainref;
	$chainref1->{policy} = $policy;
    }
}

#
# Process the policy file
#
sub validate_policy()
{
    sub print_policy($$$$)
    {
	my ( $source, $dest, $policy , $chain ) = @_;
	progress_message "   Policy for $source to $dest is $policy using chain $chain"
	    unless ( $source eq $dest ) || ( $source eq 'all' ) || ( $dest eq 'all' );
    }

    my %validpolicies = (
			  ACCEPT => undef,
			  REJECT => undef,
			  DROP   => undef,
			  CONTINUE => undef,
			  QUEUE => undef,
			  NONE => undef
			  );

    my %map = ( DROP_DEFAULT   => 'DROP' ,
		REJECT_DEFAULT => 'REJECT' ,
		ACCEPT_DEFAULT => 'ACCEPT' ,
		QUEUE_DEFAULT  => 'QUEUE' );

    my $zone;

    use constant { OPTIONAL => 1 };

    for my $option qw/DROP_DEFAULT REJECT_DEFAULT ACCEPT_DEFAULT QUEUE_DEFAULT/ {
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

    for $zone ( @zones ) {
	push @policy_chains, ( new_policy_chain "${zone}2${zone}", 'ACCEPT', OPTIONAL );

	if ( $config{IMPLICIT_CONTINUE} && ( @{$zones{$zone}{parents}} ) ) {
	    for my $zone1 ( @zones ) {
		next if $zone eq $zone1;
		push @policy_chains, ( new_policy_chain "${zone}2${zone1}", 'CONTINUE', OPTIONAL );
		push @policy_chains, ( new_policy_chain "${zone1}2${zone}", 'CONTINUE', OPTIONAL );
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

	fatal_error "Undefined zone $client" unless $clientwild || $zones{$client};

	my $serverwild = ( "\L$server" eq 'all' );

	fatal_error "Undefined zone $server" unless $serverwild || $zones{$server};

	( $policy , my ( $default, $remainder ) ) = split( /:/, $policy, 3 );

	fatal_error "Invalid default action ($default:$remainder)" if defined $remainder;

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

	if ( $policy eq 'NONE' ) {
	    fatal_error "$client $server $policy $loglevel $synparams: NONE policy not allowed with \"all\""
		if $clientwild || $serverwild;
	    fatal_error "$client, $server, $policy, $loglevel, $synparams: NONE policy not allowed to/from firewall zone"
		if ( $zones{$client}{type} eq 'firewall' ) || ( $zones{$server}{type} eq 'firewall' );
	}

	my $chain = "${client}2${server}";
	my $chainref;

	if ( defined $filter_table->{$chain} ) {
	    $chainref = $filter_table->{$chain};

	    if ( $chainref->{is_policy} ) {
		if ( $chainref->{is_optional} ) {
		    $chainref->{is_optional} = 0;
		    $chainref->{policy} = $policy;
		} else {
		    fatal_error "Duplicate policy: $client $server $policy";
		}
	    } else {
		$chainref->{is_policy} = 1;
		$chainref->{policy} = $policy;
		$chainref->{policy_chain} = $chainref;
		push @policy_chains, ( $chainref );
	    }
	} else {
	    $chainref = new_policy_chain $chain, $policy, 0;
	    push @policy_chains, ( $chainref );
	}

	$chainref->{loglevel}  = $loglevel                         if defined $loglevel && $loglevel ne '';
	$chainref->{synparams} = do_ratelimit $synparams, 'ACCEPT' if $synparams ne '';
	$chainref->{default}   = $default                          if $default;

	if ( $clientwild ) {
	    if ( $serverwild ) {
		for my $zone ( @zones , 'all' ) {
		    for my $zone1 ( @zones , 'all' ) {
			set_policy_chain "${zone}2${zone1}", $chainref, $policy;
			print_policy $zone, $zone1, $policy, $chain;
		    }
		}
	    } else {
		for my $zone ( @zones ) {
		    set_policy_chain "${zone}2${server}", $chainref, $policy;
		    print_policy $zone, $server, $policy, $chain;
		}
	    }
	} elsif ( $serverwild ) {
	    for my $zone ( @zones , 'all' ) {
		set_policy_chain "${client}2${zone}", $chainref, $policy;
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

    add_rule $chainref, "-j $default" if $default && $default ne 'none';

    log_rule $loglevel , $chainref , $target , '' if $loglevel ne '';

    fatal_error "Null target in policy_rules()" unless $target;

    add_rule $chainref , ( '-j ' . ( $target eq 'REJECT' ? 'reject' : $target ) ) unless $target eq 'CONTINUE';
}

sub report_syn_flood_protection() {
    progress_message '      Enabled SYN flood protection';
}

sub default_policy( $$$ ) {
    my $chainref   = $_[0];
    my $policyref  = $chainref->{policychain};
    my $synparams  = $policyref->{synparams};
    my $default    = $policyref->{default};
    my $policy     = $policyref->{policy};
    my $loglevel   = $policyref->{loglevel};

    fatal_error "No default policy for $_[1] to zone $_[2]" unless $policyref;

    if ( $chainref eq $policyref ) {
	policy_rules $chainref , $policy, $loglevel , $default;
    } else {
	if ( $policy eq 'ACCEPT' || $policy eq 'QUEUE' ) {
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

    for my $zone ( @zones ) {
	for my $zone1 ( @zones ) {
	    my $chainref = $filter_table->{"${zone}2${zone1}"};

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

    run_user_exit $stdchainref;

    my $ruleschainref = $filter_table->{"${zone}2${zone2}"};
    my ( $policy, $loglevel, $default ) = ( 'DROP', 6, $config{DROP_DEFAULT} );
    my $policychainref;

    $policychainref = $ruleschainref->{policychain} if $ruleschainref;

    ( $policy, $loglevel, $default ) = @{$policychainref}{'policy', 'loglevel', 'default' } if $policychainref;

    policy_rules $stdchainref , $policy , $loglevel, $default;
}

1;
