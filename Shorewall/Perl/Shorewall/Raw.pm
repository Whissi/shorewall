#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Raw.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2009,2010,2011 - Tom Eastep (teastep@shorewall.net)
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
#   This module contains the code that handles the /etc/shorewall/conntrack file.
#
package Shorewall::Raw;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_conntrack );
our @EXPORT_OK = qw( handle_helper_rule );
our $VERSION = 'MODULEVERSION';

my %valid_ctevent = ( new => 1, related => 1, destroy => 1, reply => 1, assured => 1, protoinfo => 1, helper => 1, mark => 1, natseqinfo => 1, secmark => 1 );

#
# Notrack
#
sub process_conntrack_rule( $$$$$$$$$ ) {

    my ($chainref, $zoneref, $action, $source, $dest, $proto, $ports, $sports, $user ) = @_;

    require_capability 'RAW_TABLE', 'conntrack rules', '';

    $proto  = ''    if $proto  eq 'any';
    $ports  = ''    if $ports  eq 'any' || $ports  eq 'all';
    $sports = ''    if $sports eq 'any' || $sports eq 'all';

    my $zone;
    my $restriction = PREROUTE_RESTRICT;

    unless ( $chainref ) {
	#
	# Entry in the conntrack file
	#
	if ( $zoneref ) {
	    $zone = $zoneref->{name};
	} else {
	    ($zone, $source) = split /:/, $source, 2;
	    $zoneref = find_zone ( $zone );
	}

	$chainref = ensure_raw_chain( notrack_chain $zone );
	$restriction = OUTPUT_RESTRICT if $zoneref->{type} == FIREWALL || $zoneref->{type} == VSERVER;
	fatal_error 'USER/GROUP is not allowed unless the SOURCE zone is $FW or a Vserver zone' if $user ne '-' && $restriction != OUTPUT_RESTRICT;
    }

    my $target = $action;
    my $exception_rule = '';
    my $rule = do_proto( $proto, $ports, $sports ) . do_user ( $user );

    if ( $action eq 'NOTRACK' ) {
	#
	# A patch that deimplements the NOTRACK target has been posted on the
	# Netfilter development list
	#
	$action = 'CT --notrack' if have_capability 'CT_TARGET';
    } else {
	(  $target, my ( $option, $args, $junk ) ) = split ':', $action, 4;

	fatal_error "Invalid notrack ACTION ( $action )" if $junk || $target ne 'CT';

	require_capability 'CT_TARGET', 'CT entries in the conntrack file', '';

	if ( $option eq 'notrack' ) {
	    fatal_error "Invalid conntrack ACTION ( $action )" if supplied $args;
	    $action = 'CT --notrack';
	} else {
	    fatal_error "Invalid or missing CT option and arguments" unless supplied $option && supplied $args;

	    if ( $option eq 'helper' ) {
		my $modifiers = '';

		if ( $args =~ /^([-\w.]+)\((.+)\)$/ ) {
		    $args      = $1;
		    $modifiers = $2;
		}

		fatal_error "Invalid helper' ($args)" if $args =~ /,/;
		validate_helper( $args, $proto );
		$action = "CT --helper $helpers_aliases{$args}";
		$exception_rule = do_proto( $proto, '-', '-' );

		for my $mod ( split_list1( $modifiers, 'ctevents' ) ) {
		    fatal_error "Invalid helper option ($mod)" unless $mod =~ /^(\w+)=(.+)$/;
		    $mod    = $1;
		    my $val = $2;
		    
		    if ( $mod eq 'ctevents' ) {
			for ( split_list( $val, 'ctevents' ) ) {
			    fatal_error "Invalid 'ctevents' event ($_)" unless $valid_ctevent{$_};
			}

			$action .= " --ctevents $val";
		    } elsif ( $mod eq 'expevents' ) {
			fatal_error "Invalid expevent argument ($val)" unless $val eq 'new';
			$action .= ' --expevents new';
		    } else {
			fatal_error "Invalid helper option ($mod)";
		    }
		}
	    } else {
		fatal_error "Invalid CT option ($option)";
	    }
	}
    }

    expand_rule( $chainref ,
		 $restriction ,
		 $rule,
		 $source ,
		 $dest ,
		 '' ,
		 $action ,
		 '' ,
		 $target ,
		 $exception_rule );

    progress_message "  Conntrack rule \"$currentline\" $done";
}

sub handle_helper_rule( $$$$$$$$$$$ ) {
    my ( $helper, $source, $dest, $proto, $ports, $sports, $sourceref, $action_target, $actionchain, $user, $rule ) = @_;

    if ( $helper ne '-' ) {
	fatal_error "A HELPER is not allowed with this ACTION" if $action_target;
	#
	# This means that an ACCEPT or NAT rule with a helper is being processed
	#
	process_conntrack_rule( $actionchain ? ensure_raw_chain( $actionchain ) : undef ,
				$sourceref ,
				"CT:helper:$helper",
				$source ,
				$dest ,
				$proto ,
				$ports ,
				$sports ,
				$user );
    } else {
	assert( $action_target );
	#
	# The target is an action
	#
	if ( $actionchain ) {
	    #
	    # And the source is another action chain
	    #
	    expand_rule( ensure_raw_chain( $actionchain ) ,
			 PREROUTE_RESTRICT ,
			 $rule ,
			 $source ,
			 $dest ,
			 '' ,
			 $action_target ,
			 '',
			 'CT' ,
			 '' );
	} else {
	    expand_rule( ensure_raw_chain( notrack_chain( $sourceref->{name} ) ) ,
			 ( $sourceref->{type} == FIREWALL || $sourceref->{type} == VSERVER ?
			   OUTPUT_RESTRICT :
			   PREROUTE_RESTRICT ) ,
			 $rule ,
			 $source ,
			 $dest ,
			 '' ,
			 $action_target ,
			 '' ,
			 'CT' ,
			 '' );
	}
    }
}

sub process_format( $ ) {
    my $format = shift;

    fatal_error q(FORMAT must be '1' or '2') unless $format =~ /^[12]$/;

    $format;
}

sub setup_conntrack() {

    for my $name ( qw/notrack conntrack/ ) {

	my $fn = open_file( $name );

	if ( $fn ) {

	    my $format = 1;

	    my $action = 'NOTRACK';

	    my $empty = 1;

	    first_entry( "$doing $fn..." );

	    while ( read_a_line( NORMAL_READ ) ) {
		my ( $source, $dest, $proto, $ports, $sports, $user );

		if ( $format == 1 ) {
		    ( $source, $dest, $proto, $ports, $sports, $user ) = split_line1 'Conntrack File', { source => 0, dest => 1, proto => 2, dport => 3, sport => 4, user => 5 };

		    if ( $source eq 'FORMAT' ) {
			$format = process_format( $dest );
			next;
		    }
		} else {
		    ( $action, $source, $dest, $proto, $ports, $sports, $user ) = split_line1 'Conntrack File', { action => 0, source => 1, dest => 2, proto => 3, dport => 4, sport => 5, user => 6 }, { COMMENT => 0, FORMAT => 2 };

		    if ( $action eq 'FORMAT' ) {
			$format = process_format( $source );
			$action = 'NOTRACK';
			next;
		    }
		}

		if ( $action eq 'COMMENT' ) {
		    process_comment;
		    next;
		}

		$empty = 0;

		if ( $source eq 'all' ) {
		    for my $zone (all_zones) {
			process_conntrack_rule( undef, undef, $action, $zone, $dest, $proto, $ports, $sports, $user );
		    }
		} else {
		    process_conntrack_rule( undef, undef, $action, $source, $dest, $proto, $ports, $sports, $user );
		}
	    }

	    clear_comment;

	    if ( $name eq 'notrack') {
		if ( $empty ) {
		    if ( unlink( $fn ) ) {
			warning_message "Empty notrack file ($fn) removed";
		    } else {
			warning_message "Unable to remove empty notrack file ($fn): $!";
		    }
		} else {
		    warning_message "Non-empty notrack file ($fn); please move its contents to the conntrack file";
		}
	    }
	}
    }
}

1;
