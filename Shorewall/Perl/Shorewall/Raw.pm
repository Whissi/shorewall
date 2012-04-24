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
#   This module contains the code that handles the /etc/shorewall/notrack file.
#
package Shorewall::Raw;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_notrack );
our @EXPORT_OK = qw( );
our $VERSION = 'MODULEVERSION';

my %valid_ctevent = ( new => 1, related => 1, destroy => 1, reply => 1, assured => 1, protoinfo => 1, helper => 1, mark => 1, natseqinfo => 1, secmark => 1 );

#
# Notrack
#
sub process_notrack_rule( $$$$$$$ ) {

    my ($action, $source, $dest, $proto, $ports, $sports, $user ) = @_;

    $proto  = ''    if $proto  eq 'any';
    $ports  = ''    if $ports  eq 'any' || $ports  eq 'all';
    $sports = ''    if $sports eq 'any' || $sports eq 'all';

    ( my $zone, $source) = split /:/, $source, 2;
    my $zoneref  = find_zone $zone;
    my $chainref = ensure_raw_chain( notrack_chain $zone );
    my $restriction = $zoneref->{type} == FIREWALL || $zoneref->{type} == VSERVER ? OUTPUT_RESTRICT : PREROUTE_RESTRICT;

    fatal_error 'USER/GROUP is not allowed unless the SOURCE zone is $FW or a Vserver zone' if $user ne '-' && $restriction != OUTPUT_RESTRICT;
    require_capability 'RAW_TABLE', 'Notrack rules', '';

    my $target = $action;
    my $exception_rule = '';
    my $rule = do_proto( $proto, $ports, $sports ) . do_user ( $user );

    unless ( $action eq 'NOTRACK' ) {
	(  $target, my ( $option, $args, $junk ) ) = split ':', $action, 4;

	fatal_error "Invalid notrack ACTION ( $action )" if $junk || $target ne 'CT';

	require_capability 'CT_TARGET', 'CT entries in the notrack file', '';

	if ( $option eq 'notrack' ) {
	    fatal_error "Invalid notrack ACTION ( $action )" if supplied $args;
	    $action = 'CT --notrack';
	} else {
	    fatal_error "Invalid or missing CT option and arguments" unless supplied $option && supplied $args;

	    if ( $option eq 'helper' ) {
		fatal_error "Invalid helper' ($args)" if $args =~ /,/;
		validate_helper( $args, $proto );
		$action = "CT --helper $args";
		$exception_rule = do_proto( $proto, '-', '-' );
	    } elsif ( $option eq 'ctevents' ) {
		for ( split ',', $args ) {
		    fatal_error "Invalid 'ctevents' event ($_)" unless $valid_ctevent{$_};
		}

		$action = "CT --ctevents $args";
	    } elsif ( $option eq 'expevent' ) {
		fatal_error "Invalid expevent argument ($args)" unless $args eq 'new';
	    } elsif ( $option eq 'zone' ) {
		fatal_error "Invalid zone id ($args)" unless $args =~ /^\d+$/;
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

    progress_message "  Notrack rule \"$currentline\" $done";

    $globals{UNTRACKED} = 1;
}

sub process_format( $ ) {
    my $format = shift;

    fatal_error q(FORMAT must be '1' or '2') unless $format =~ /^[12]$/;

    $format;
}

sub setup_notrack() {

    my $format = 1;
    my $action = 'NOTRACK';

    if ( my $fn = open_file 'notrack' ) {

	first_entry "$doing $fn...";

	my $nonEmpty = 0;

	while ( read_a_line( NORMAL_READ ) ) {
	    my ( $source, $dest, $proto, $ports, $sports, $user );

	    if ( $format == 1 ) {
		( $source, $dest, $proto, $ports, $sports, $user ) = split_line1 'Notrack File', { source => 0, dest => 1, proto => 2, dport => 3, sport => 4, user => 5 };

		if ( $source eq 'FORMAT' ) {
		    $format = process_format( $dest );
		    next;
		}

		if ( $source eq 'COMMENT' ) {
		    process_comment;
		    next;
		}
	    } else {
		( $action, $source, $dest, $proto, $ports, $sports, $user ) = split_line1 'Notrack File', { action => 0, source => 1, dest => 2, proto => 3, dport => 4, sport => 5, user => 6 }, { COMMENT => 0, FORMAT => 2 };

		if ( $action eq 'FORMAT' ) {
		    $format = process_format( $source );
		    $action = 'NOTRACK';
		    next;
		}

		if ( $action eq 'COMMENT' ) {
		    process_comment;
		    next;
		}
	    }

	    process_notrack_rule $action, $source, $dest, $proto, $ports, $sports, $user;
	}

	clear_comment;
    }
}

1;
