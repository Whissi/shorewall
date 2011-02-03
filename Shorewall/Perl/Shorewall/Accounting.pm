#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Accounting.pm
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
#   This module contains the code that handles the /etc/shorewall/accounting
#   file.
#
package Shorewall::Accounting;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_accounting );
our @EXPORT_OK = qw( );
our $VERSION = '4.4.17';

#
# Per-IP accounting tables. Each entry contains the associated network.
#
our %tables;

#
# Called by the compiler to [re-]initialize this module's state
#
sub initialize() {
    our $jumpchainref;
    $jumpchainref = undef;
    %tables       = ();
}

#
# Accounting
#
sub process_accounting_rule( ) {

    our $jumpchainref;

    my ($action, $chain, $source, $dest, $proto, $ports, $sports, $user, $mark, $ipsec, $headers ) = split_line1 1, 11, 'Accounting File';

    if ( $action eq 'COMMENT' ) {
	process_comment;
	return 0;
    }

    our $disposition = '';

    sub reserved_chain_name($) {
	$_[0] =~ /^acc(?:ount(?:ing|out)|ipsecin|ipsecout)$/;
    }

    sub ipsec_chain_name($) {
	if ( $_[0] =~ /^accipsec(in|out)$/ ) {
	    $1;
	}
    }

    sub check_chain( $ ) {
	my $chainref = shift;
	fatal_error "A non-accounting chain ($chainref->{name}) may not appear in the accounting file" if $chainref->{policy};
    }

    sub accounting_error() {
	fatal_error "Invalid Accounting rule";
    }

    sub jump_to_chain( $ ) {
	my $jumpchain = $_[0];
	fatal_error "Jumps to the $jumpchain chain are not allowed" if reserved_chain_name( $jumpchain );
	$jumpchainref = ensure_accounting_chain( $jumpchain, 0 );
	check_chain( $jumpchainref );
	$disposition = $jumpchain;
	$jumpchain;
    }

    my $target = '';

    $proto  = ''    if $proto  eq 'any';
    $ports  = ''    if $ports  eq 'any' || $ports  eq 'all';
    $sports = ''    if $sports eq 'any' || $sports eq 'all';

    my $rule = do_proto( $proto, $ports, $sports ) . do_user ( $user ) . do_test ( $mark, $globals{TC_MASK} ) . do_headers( $headers );
    my $rule2 = 0;
    my $jump  = 0;

    unless ( $action eq 'COUNT' ) {
	if ( $action eq 'DONE' ) {
	    $target = 'RETURN';
	} elsif ( $action =~ /^ACCOUNT\(/ ) {
	    if ( $action =~ /^ACCOUNT\((.+)\)$/ ) {
		require_capability 'ACCOUNT_TARGET' , 'ACCOUNT Rules' , '';
		my ( $table, $net, $rest ) = split/,/, $1;
		fatal_error "Invalid Network Address (${net},${rest})" if defined $rest;
		fatal_error "Missing Table Name"             unless defined $table && $table ne '';;
		fatal_error "Invalid Table Name ($table)"    unless $table =~ /^([-\w.]+)$/;
		fatal_error "Missing Network Address"        unless defined $net;
		fatal_error "Invalid Network Address ($net)" unless defined $net   && $net =~ '/(\d+)$';
		fatal_error "Netmask ($1) out of range"      unless $1 >= 8;
		validate_net $net, 0;

		my $prevnet = $tables{$table};
		if ( $prevnet ) {
		    fatal_error "Previous net associated with $table ($prevnet) does not match this one ($net)" unless $net eq $prevnet;
		} else {
		    $tables{$table} = $net;
		}

		$target = "ACCOUNT --addr $net --tname $table";
	    } else {
		fatal_error "Invalid ACCOUNT Action";
	    }
	} else {
	    ( $action, my $cmd ) = split /:/, $action;
	    if ( $cmd ) {
		if ( $cmd eq 'COUNT' ) {
		    $rule2 = 1;
		} elsif ( $cmd eq 'JUMP' ) {
		    $jump = 1;
		} else {
		    accounting_error;
		}
	    }

	    $target = jump_to_chain $action;
	}
    }

    my $restriction = NO_RESTRICT;

    $source = ALLIP if $source eq 'any' || $source eq 'all';

    if ( have_bridges ) {
	my $fw = firewall_zone;

	if ( $source =~ /^$fw:?(.*)$/ ) {
	    $source = $1 ? $1 : ALLIP;
	    $restriction = OUTPUT_RESTRICT;
	    $chain = 'accountout' unless $chain and $chain ne '-';
	    $dest = ALLIP if $dest   eq 'any' || $dest   eq 'all';
	} else {
	    $chain = 'accounting' unless $chain and $chain ne '-';
	    if ( $dest eq 'any' || $dest eq 'all' || $dest eq ALLIP ) {
		expand_rule(
			    ensure_filter_chain( 'accountout' , 0 ) ,
			    OUTPUT_RESTRICT ,
			    $rule ,
			    $source ,
			    $dest = ALLIP ,
			    '' ,
			    $target ,
			    '' ,
			    $disposition ,
			    ''  );
	    }
	}
    } else {
	$chain = 'accounting' unless $chain and $chain ne '-';
	$dest = ALLIP if $dest   eq 'any' || $dest   eq 'all';
    }

    my $chainref = $filter_table->{$chain};
    my $dir;

    if ( ! $chainref ) {
	$chainref = ensure_accounting_chain $chain, 0;
	$dir      = ipsec_chain_name( $chain );

	if ( $ipsec ne '-' ) {
	    if ( $dir ) {
		$rule .= do_ipsec( $dir, $ipsec );
		$chainref->{ipsec} = $dir;
	    } else {
		fatal_error "Adding an IPSEC rule to an unreferenced accounting chain is not allowed";
	    }
	} else {
	    warning_message "Adding rule to unreferenced accounting chain $chain" unless reserved_chain_name( $chain );
	    $chainref->{ipsec} = $dir;
	}
    } elsif ( $ipsec ne '-' ) {
	$dir = $chainref->{ipsec};
	fatal_error "Adding an IPSEC rule into a non-IPSEC chain is not allowed" unless $dir;
	$rule .= do_ipsec( $dir , $ipsec );
    }

    $restriction = $dir eq 'in' ? INPUT_RESTRICT : OUTPUT_RESTRICT if $dir;

    expand_rule
	$chainref ,
	$restriction ,
	$rule ,
	$source ,
	$dest ,
	'' ,
	$target ,
	'' ,
	$disposition ,
	'' ;

    if ( $rule2 || $jump ) {
	if ( $chainref->{ipsec} ) {
	    if ( $jumpchainref->{ipsec} ) {
		fatal_error "IPSEC in/out mismatch on chains $chain and $jumpchainref->{name}";
	    } else {
		fatal_error "$jumpchainref->{name} is not an IPSEC chain" if keys %{$jumpchainref->{references}} > 1;
		$jumpchainref->{ipsec} = $chainref->{ipsec};
	    }
	} elsif ( $jumpchainref->{ipsec} ) {
	    fatal_error "Jump from a non-IPSEC chain to an IPSEC chain not allowed";
	} else {
	    $jumpchainref->{ipsec} = $chainref->{ipsec};
	}

    }

    if ( $rule2 ) {
	expand_rule
	    $jumpchainref ,
	    $restriction ,
	    $rule ,
	    $source ,
	    $dest ,
	    '' ,
	    '' ,
	    '' ,
	    '' ,
	    '' ;
    }

    return 1;
}

sub setup_accounting() {

    if ( my $fn = open_file 'accounting' ) {

	first_entry "$doing $fn...";

	my $nonEmpty = 0;

	$nonEmpty |= process_accounting_rule while read_a_line;

	clear_comment;

	if ( have_bridges ) {
	    if ( $filter_table->{accounting} ) {
		for my $chain ( qw/INPUT FORWARD/ ) {
		    add_jump( $filter_table->{$chain}, 'accounting', 0, '', 0, 0 );
		}
	    }

	    if ( $filter_table->{accountout} ) {
		add_jump( $filter_table->{OUTPUT}, 'accountout', 0, '', 0, 0 );
	    }
	} elsif ( $filter_table->{accounting} ) {
	    for my $chain ( qw/INPUT FORWARD OUTPUT/ ) {
		add_jump( $filter_table->{$chain}, 'accounting', 0, '', 0, 0 );
	    }
	}

	if ( $filter_table->{accipsecin} ) {
	    for my $chain ( qw/INPUT FORWARD/ ) {
		add_jump( $filter_table->{$chain}, 'accipsecin', 0,  '', 0, 0 );
	    }
	}

	if ( $filter_table->{accipsecout} ) {
	    for my $chain ( qw/FORWARD OUTPUT/ ) {
		add_jump( $filter_table->{$chain}, 'accipsecout', 0, '', 0, 0 );
	    }
	}

	for ( accounting_chainrefs ) {
	    warning_message "Accounting chain $_->{name} has no references" unless keys %{$_->{references}};
	}
    }
}

1;
