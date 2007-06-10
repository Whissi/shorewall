#
# Shorewall-perl 3.9 -- /usr/share/shorewall-perl/Shorewall/Accounting.pm
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
#   This module contains the code that handles the /etc/shorewall/accounting
#   file.
#
package Shorewall::Accounting;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_accounting );
our @EXPORT_OK = qw( );
our @VERSION = 1.00;

#
# Accounting
#
sub process_accounting_rule( $$$$$$$$$ ) {
    
    our $jumpchainref;

    my ($action, $chain, $source, $dest, $proto, $ports, $sports, $user, $mark ) = @_;

    sub accounting_error() {
	warning_message "Invalid Accounting rule";
    }

    sub jump_to_chain( $ ) {
	my $jumpchain = $_[0];
	$jumpchainref = ensure_chain( 'filter', $jumpchain );
	mark_referenced $jumpchainref;
	"-j $jumpchain";
    }

    unless ( $chain and $chain ne '-' ) {
	$chain = $source =~ /^$firewall_zone:?/ ? 'accountout' : 'accounting';
    }

    my $chainref = ensure_filter_chain $chain , 0;

    my $target = '';

    $proto  = ''    if $proto  eq 'any';
    $ports  = ''    if $ports  eq 'any' || $ports  eq 'all';
    $sports = ''    if $sports eq 'any' || $sports eq 'all';

    my $rule = do_proto( $proto, $ports, $sports ) . do_user ( $user ) . do_test ( $mark, 0xFF );
    my $rule2 = 0;

    unless ( $action eq 'COUNT' ) {
	if ( $action eq 'DONE' ) {
	    $target = '-j RETURN';
	} else {
	    ( $action, my $cmd ) = split /:/, $action;
	    if ( $cmd ) {
		if ( $cmd eq 'COUNT' ) {
		    $rule2=1;
		    $target = jump_to_chain $action;
		} elsif ( $cmd ne 'JUMP' ) {
		    accounting_error;
		}
	    } else {
		$target = jump_to_chain $action;
	    }
	}
    }

    $source = ALLIPv4 if $source eq 'any' || $source eq 'all';
    $dest   = ALLIPv4 if $dest   eq 'any' || $dest   eq 'all';

    expand_rule
	$chainref ,
	NO_RESTRICT ,
	$rule ,
	$source ,
	$dest ,
	'' ,
	$target ,
	'' ,
	'' ,
	'' ;

    if ( $rule2 ) {
	expand_rule
	    $jumpchainref ,
	    NO_RESTRICT ,
	    $rule ,
	    $source ,
	    $dest ,
	    '' ,
	    '' ,
	    '' ,
	    '' ,
	    '' ;
    }
}

sub setup_accounting() {
    
    my $first_entry = 1;

    my $fn = open_file 'accounting';

    while ( read_a_line ) {

	my ( $action, $chain, $source, $dest, $proto, $ports, $sports, $user, $mark ) = split_line 1, 9, 'Accounting File';

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	process_accounting_rule $action, $chain, $source, $dest, $proto, $ports, $sports, $user, $mark;
    }

    if ( $filter_table->{accounting} ) {
	for my $chain ( qw/INPUT FORWARD/ ) {
	    insert_rule $filter_table->{$chain}, 1, '-j accounting';
	    insert_rule $filter_table->{$chain}, 2, '-m state --state ESTABLISHED,RELATED -j ACCEPT' if $config{FASTACCEPT};
	}
    } elsif ( $config{FASTACCEPT} ) {
	for my $chain ( qw/INPUT FORWARD/ ) {
	    insert_rule $filter_table->{$chain}, 1, '-m state --state ESTABLISHED,RELATED -j ACCEPT';
	}
    }

    if ( $filter_table->{accountout} ) {
	insert_rule $filter_table->{OUTPUT}, 1, '-j accountout';
	insert_rule $filter_table->{OUTPUT}, 2, '-m state --state ESTABLISHED,RELATED -j ACCEPT' if $config{FASTACCEPT};
    } elsif ( $config{FASTACCEPT} ) {
	insert_rule $filter_table->{OUTPUT}, 1, '-m state --state ESTABLISHED,RELATED -j ACCEPT';
    }
}

1;
