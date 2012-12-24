#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Accounting.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010,2011 - Tom Eastep (teastep@shorewall.net)
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
our $VERSION = 'MODULEVERSION';

#
# Per-IP accounting tables. Each entry contains the associated network.
#
our %tables;

our $jumpchainref;
our %accountingjumps;
our $asection;
our $defaultchain;
our $ipsecdir;
our $defaultrestriction;
our $restriction;
our $sectionname;
our $acctable;

#
# Sections in the Accounting File
#

use constant {
	      LEGACY      => 0,
	      PREROUTING  => 1,
	      INPUT       => 2,
	      OUTPUT      => 3,
	      FORWARD     => 4,
	      POSTROUTING => 5
	  };
#
# Map names to values
#
our %asections = ( PREROUTING  => PREROUTING,
		   INPUT       => INPUT,
		   FORWARD     => FORWARD,
		   OUTPUT      => OUTPUT,
		   POSTROUTING => POSTROUTING
		 );

#
# Called by the compiler to [re-]initialize this module's state
#
sub initialize() {
    $jumpchainref       = undef;
    %tables             = ();
    %accountingjumps    = ();
    #
    # The section number is initialized to a value less thatn LEGACY. It will be set to LEGACY if a
    # the first non-commentary line in the accounting file isn't a section header
    #
    # This allows the section header processor to quickly check for correct order
    #
    $asection           = -1;
    #
    # These are the legacy values
    #
    $defaultchain       = 'accounting';
    $ipsecdir           = '';
    $defaultrestriction = NO_RESTRICT;
    $sectionname        = '';
}

#
# Process a SECTION header
#
sub process_section ($) {
    $sectionname = shift;
    my $newsect  = $asections{$sectionname};
    #
    # read_a_line has already verified that there are exactly two tokens on the line
    #
    fatal_error "Invalid SECTION ($sectionname)"                   unless defined $newsect;
    fatal_error "SECTION not allowed after un-sectioned rules"     unless $asection;
    fatal_error "Duplicate or out-of-order SECTION ($sectionname)" if     $newsect <= $asection;

    if ( $sectionname eq 'INPUT' ) {
	$defaultchain = 'accountin';
	$ipsecdir     = 'in';
	$defaultrestriction = INPUT_RESTRICT;
    } elsif ( $sectionname eq 'OUTPUT' ) {
	$defaultchain = 'accountout';
	$ipsecdir     = 'out';
	$defaultrestriction = OUTPUT_RESTRICT;
    } elsif ( $sectionname eq 'FORWARD' ) {
	$defaultchain = 'accountfwd';
	$ipsecdir     = '';
	$defaultrestriction = NO_RESTRICT;
     } else {
	 fatal_error "The $sectionname SECTION is not allowed when ACCOUNTING_TABLE=filter" unless $acctable eq 'mangle';
	 if ( $sectionname eq 'PREROUTING' ) {
	     $defaultchain = 'accountpre';
	     $ipsecdir     = 'in';
	     $defaultrestriction = PREROUTE_RESTRICT;
	 } else {
	     $defaultchain = 'accountpost';
	     $ipsecdir     = 'out';
	     $defaultrestriction = POSTROUTE_RESTRICT;
	 }
     }

    $asection = $newsect;
}

#
# Accounting
#
sub process_accounting_rule( ) {

    $acctable = $config{ACCOUNTING_TABLE};

    $jumpchainref = 0;

    my ($action, $chain, $source, $dest, $proto, $ports, $sports, $user, $mark, $ipsec, $headers ) =
	split_line1 'Accounting File', { action => 0, chain => 1, source => 2, dest => 3, proto => 4, dport => 5, sport => 6, user => 7, mark => 8, ipsec => 9, headers => 10 };

    fatal_error 'ACTION must be specified' if $action eq '-';

    $asection = LEGACY if $asection < 0;

    our $disposition = '';

    sub reserved_chain_name($) {
	$_[0] =~ /^acc(?:ount(?:fwd|in|ing|out|pre|post)|ipsecin|ipsecout)$/;
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
	$jumpchainref = ensure_accounting_chain( $jumpchain, 0, $defaultrestriction );
	check_chain( $jumpchainref );
	$disposition = $jumpchain;
	$jumpchain;
    }

    my $target = '';

    $proto  = ''    if $proto  eq 'any';
    $ports  = ''    if $ports  eq 'any' || $ports  eq 'all';
    $sports = ''    if $sports eq 'any' || $sports eq 'all';

    fatal_error "USER/GROUP may only be specified in the OUTPUT section" unless $user eq '-' || $asection == OUTPUT;

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
		fatal_error "Missing Table Name"                       unless supplied $table;
		fatal_error "Invalid Table Name ($table)"              unless $table =~ /^([-\w.]+)$/;
		fatal_error "Missing Network Address"                  unless defined $net;
		fatal_error "Invalid Network Address ($net)"           unless defined $net   && $net =~ '/(\d+)$';
		fatal_error "Netmask ($1) out of range"                unless $1 >= 8;
		validate_net $net, 0;

		my $prevnet = $tables{$table};

		if ( $prevnet ) {
		    fatal_error "Previous net associated with $table ($prevnet) does not match this one ($net)" unless compare_nets( $net , $prevnet );
		} else {
		    $tables{$table} = $net;
		}

		$target = "ACCOUNT --addr $net --tname $table";
	    } else {
		fatal_error "Invalid ACCOUNT Action";
	    }
	} elsif ( $action =~ /^NFLOG/ ) {
	    $target = validate_level $action;
	} elsif ( $action =~ /^NFACCT\((\w+)\)$/ ) {
	    require_capability 'NFACCT_MATCH', 'The NFACCT action', 's';
	    $nfobjects{$1} = 1;
	    $target = '';
	    $rule .= "-m nfacct --nfacct-name $1 ";
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

    $restriction = $defaultrestriction;

    if ( $source eq 'any' || $source eq 'all' ) {
        $source = ALLIP;
    } else {
	fatal_error "MAC addresses only allowed in the INPUT and FORWARD sections" if $source =~ /~/ && ( $asection == OUTPUT || ! $asection );
    }

    if ( have_bridges && ! $asection ) {
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
			    ensure_rules_chain ( 'accountout' ) ,
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
	$chain = $defaultchain unless $chain and $chain ne '-';
	$dest = ALLIP if $dest   eq 'any' || $dest   eq 'all';
    }

    my $chainref = $chain_table{$config{ACCOUNTING_TABLE}}{$chain};
    my $dir = $ipsecdir;

    if ( $asection && $ipsec ne '-' ) {
	if ( $ipsecdir ) {
	    fatal_error "Invalid IPSEC ($ipsec)" if $ipsec =~ /^(?:in|out)\b/;
	} else {
	    if ( $ipsec =~ s/^(?:(in|out)\b)// ) {
		$dir = $1;
	    } else {
		fatal_error q(IPSEC rules in the $asection section require that the value begin with 'in' or 'out');
	    }
	}

	$rule .= do_ipsec( $dir, $ipsec );
    }

    if ( ! $chainref ) {
	if ( reserved_chain_name( $chain ) ) {
	    fatal_error "May not use chain $chain in the $sectionname section" if $asection && $chain ne $defaultchain;
	    $chainref = ensure_accounting_chain $chain, 0 , $restriction;
	} elsif ( $asection ) {
	    fatal_error "Unknown accounting chain ($chain)";
	} else {
	    $chainref = ensure_accounting_chain $chain, 0 , $restriction;
	}

	unless ( $asection ) {
	    $dir = ipsec_chain_name( $chain );

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
	}
    } else {
	fatal_error "$chain is not an accounting chain" unless $chainref->{accounting};

	unless ( $asection ) {
	    if ( $ipsec ne '-' ) {
		$dir = $chainref->{ipsec};
		fatal_error "Adding an IPSEC rule into a non-IPSEC chain is not allowed" unless $dir;
		$rule .= do_ipsec( $dir , $ipsec );
	    } elsif ( $asection ) {
		$restriction |= $chainref->{restriction};
	    }
	}
    }

    set_optflags( $chainref, DONT_OPTIMIZE ) if $target eq 'RETURN';

    if ( $jumpchainref ) {
	if ( $asection ) {
	    #
	    # Check the jump-to chain to be sure that it doesn't contain rules that are incompatible with this section
	    #
	    my $jumprestricted = $jumpchainref->{restricted};
	    fatal_error "Chain $jumpchainref->{name} contains rules that are incompatible with the $sectionname section" if $jumprestricted && $restriction && $jumprestricted ne $restriction;
	    $restriction |= $jumpchainref->{restriction};
	}

	$accountingjumps{$jumpchainref->{name}}{$chain} = 1;
    }

    fatal_error "$chain is not an accounting chain" unless $chainref->{accounting};

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

	$nonEmpty |= process_accounting_rule while read_a_line( NORMAL_READ );

	clear_comment;

	if ( $nonEmpty ) {
	    my $tableref = $chain_table{$acctable};

	    if ( have_bridges || $asection ) {
		if ( $tableref->{accountin} ) {
		    insert_ijump( $tableref->{INPUT}, j => 'accountin', 0 );
		}

		if ( $tableref->{accounting} ) {
		    set_optflags( 'accounting' , DONT_OPTIMIZE );
		    for my $chain ( qw/INPUT FORWARD/ ) {
			insert_ijump( $tableref->{$chain}, j => 'accounting', 0 );
		    }
		}

		if ( $tableref->{accountfwd} ) {
		    insert_ijump( $tableref->{FORWARD}, j => 'accountfwd', 0 );
		}

		if ( $tableref->{accountout} ) {
		    insert_ijump( $tableref->{OUTPUT}, j => 'accountout', 0 );
		}

		if ( $tableref->{accountpre} ) {
		    insert_ijump( $tableref->{PREROUTING}, j => 'accountpre' , 0 );
		}

		if ( $tableref->{accountpost} ) {
		    insert_ijump( $tableref->{POSTROUTING}, j => 'accountpost', 0 );
		}
	    } elsif ( $tableref->{accounting} ) {
		set_optflags( 'accounting' , DONT_OPTIMIZE );
		for my $chain ( qw/INPUT FORWARD OUTPUT/ ) {
		    insert_ijump( $tableref->{$chain}, j => 'accounting', 0 );
		}
	    }

	    if ( $tableref->{accipsecin} ) {
		for my $chain ( qw/INPUT FORWARD/ ) {
		    insert_ijump( $tableref->{$chain}, j => 'accipsecin', 0 );
		}
	    }

	    if ( $tableref->{accipsecout} ) {
		for my $chain ( qw/FORWARD OUTPUT/ ) {
		    insert_ijump( $tableref->{$chain}, j => 'accipsecout', 0 );
		}
	    }

	    unless ( $asection ) {
		for ( accounting_chainrefs ) {
		    warning_message "Accounting chain $_->{name} has no references" unless keys %{$_->{references}};
		}
	    }

	    if ( my $chainswithjumps = keys %accountingjumps ) {
		my $progress = 1;

		while ( $chainswithjumps && $progress ) {
		    $progress = 0;
		    for my $chain1 (  keys %accountingjumps ) {
			if ( keys %{$accountingjumps{$chain1}} ) {
			    for my $chain2 ( keys %{$accountingjumps{$chain1}} ) {
				delete $accountingjumps{$chain1}{$chain2}, $progress = 1 unless $accountingjumps{$chain2};
			    }
			} else {
			    delete $accountingjumps{$chain1};
			    $chainswithjumps--;
			    $progress = 1;
			}
		    }
		}

		if ( $chainswithjumps ) {
		    my @chainswithjumps = keys %accountingjumps;
		    fatal_error "Jump loop involving the following chains: @chainswithjumps";
		}
	    }
	}
    }
}

1;
