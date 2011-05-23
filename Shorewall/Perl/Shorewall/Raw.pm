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
our $VERSION = '4.4_14';

#
# Notrack
#
sub process_notrack_rule( $$$$$$ ) {

    my ($source, $dest, $proto, $ports, $sports, $user ) = @_;

    $proto  = ''    if $proto  eq 'any';
    $ports  = ''    if $ports  eq 'any' || $ports  eq 'all';
    $sports = ''    if $sports eq 'any' || $sports eq 'all';

    ( my $zone, $source) = split /:/, $source, 2;
    my $zoneref  = find_zone $zone;
    my $chainref = ensure_raw_chain( notrack_chain $zone );
    my $restriction = $zoneref->{type} == FIREWALL || $zoneref->{type} == VSERVER ? OUTPUT_RESTRICT : PREROUTE_RESTRICT;

    fatal_error 'USER/GROUP is not allowed unless the SOURCE zone is $FW or a Vserver zone' if $user ne '-' && $restriction != OUTPUT_RESTRICT;
    require_capability 'RAW_TABLE', 'Notrack rules', '';

    my $rule = do_proto( $proto, $ports, $sports ) . do_user ( $user );

    expand_rule
	$chainref ,
	$restriction ,
	$rule ,
	$source ,
	$dest ,
	'' ,
	'NOTRACK' ,
	'' ,
	'NOTRACK' ,
	'' ;

    progress_message "  Notrack rule \"$currentline\" $done";

    $globals{UNTRACKED} = 1;
}

sub setup_notrack() {

    if ( my $fn = open_file 'notrack' ) {

	first_entry "$doing $fn...";

	my $nonEmpty = 0;

	while ( read_a_line ) {

	    my ( $source, $dest, $proto, $ports, $sports, $user ) = split_line1 1, 6, 'Notrack File';

	    if ( $source eq 'COMMENT' ) {
		process_comment;
	    } else {
		process_notrack_rule $source, $dest, $proto, $ports, $sports, $user;
	    }
	}

	clear_comment;
    }
}

1;
