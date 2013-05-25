#
# Shorewall 4.5 -- /usr/share/shorewall/Shorewall/Misc.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010,2011,2012,2013 - Tom Eastep (teastep@shorewall.net)
#
#       Complete documentation is available at http://shorewall.net
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of Version 2 of the GNU General Public License
#       as published by the Free Software Foundation.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty ofs
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#   This module contains those routines that don't seem to fit well elsewhere. It
#   was carved from the Rules module in 4.4.16.
#
package Shorewall::Misc;
require Exporter;

use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::Rules;
use Shorewall::Proc;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( process_tos
		  setup_ecn
		  add_common_rules
		  setup_mac_lists
		  process_routestopped
		  process_stoppedrules
		  compile_stop_firewall
		  generate_matrix
		  );
our @EXPORT_OK = qw( initialize );
our $VERSION = 'MODULEVERSION';

our $family;

#
# Rather than initializing globals in an INIT block or during declaration,
# we initialize them in a function. This is done for two reasons:
#
#   1. Proper initialization depends on the address family which isn't
#      known until the compiler has started.
#
#   2. The compiler can run multiple times in the same process so it has to be
#      able to re-initialize its dependent modules' state.
#
sub initialize( $ ) {
    $family = shift;
}

sub process_tos() {
    my $chain    = have_capability( 'MANGLE_FORWARD' ) ? 'fortos'  : 'pretos';
    my $stdchain = have_capability( 'MANGLE_FORWARD' ) ? 'FORWARD' : 'PREROUTING';

   if ( my $fn = open_file 'tos' ) {
	my $first_entry = 1;

	my ( $pretosref, $outtosref );

	first_entry( sub { progress_message2 "$doing $fn...";
			   warning_message "Use of the tos file is deprecated in favor of the TOS target in tcrules";
			   $pretosref = ensure_chain 'mangle' , $chain;
			   $outtosref = ensure_chain 'mangle' , 'outtos';
		       }
		   );

	while ( read_a_line( NORMAL_READ ) ) {

	    my ($src, $dst, $proto, $ports, $sports , $tos, $mark ) = split_line 'tos file entry', { source => 0, dest => 1, proto => 2, dport => 3, sport => 4, tos => 5, mark => 6 } ;

	    $first_entry = 0;

	    $tos = decode_tos( $tos , 1 );

	    my $chainref;

	    my $restriction = NO_RESTRICT;

	    my ( $srczone , $source , $remainder );

	    if ( $family == F_IPV4 ) {
		( $srczone , $source , $remainder ) = split( /:/, $src, 3 );
		fatal_error 'Invalid SOURCE' if defined $remainder;
	    } elsif ( $src =~ /^(.+?):<(.*)>\s*$/ || $src =~ /^(.+?):\[(.*)\]\s*$/ ) {
		$srczone = $1;
		$source  = $2;
	    } else {
		$srczone = $src;
	    }

	    if ( $srczone eq firewall_zone ) {
		$chainref    = $outtosref;
		$src         = $source || '-';
		$restriction = OUTPUT_RESTRICT;
	    } else {
		$chainref = $pretosref;
		$src =~ s/^all:?//;
	    }

	    $dst =~ s/^all:?//;

	    expand_rule
		$chainref ,
		$restriction ,
		'',
		do_proto( $proto, $ports, $sports ) . do_test( $mark , $globals{TC_MASK} ) ,
		$src ,
		$dst ,
		'' ,
		'TOS' . $tos ,
		'' ,
		'TOS' ,
		'';
	}

	unless ( $first_entry ) {
	    add_ijump( $mangle_table->{$stdchain}, j => $chain )   if $pretosref->{referenced};
	    add_ijump( $mangle_table->{OUTPUT},    j => 'outtos' ) if $outtosref->{referenced};
	}
    }
}

#
# Setup ECN disabling rules
#
sub setup_ecn()
{
    my %interfaces;
    my @hosts;

    if ( my $fn = open_file 'ecn' ) {

	first_entry( sub { progress_message2 "$doing $fn...";
			   require_capability 'MANGLE_ENABLED', 'Entries in the ecn file', '';
			   warning_message 'ECN will not be applied to forwarded packets' unless have_capability 'MANGLE_FORWARD';
		       } );

	while ( read_a_line( NORMAL_READ ) ) {

	    my ($interface, $hosts ) = split_line1 'ecn file entry', { interface => 0, host => 1, hosts => 1 }, {}, 2;

	    fatal_error 'INTERFACE must be specified' if $interface eq '-';
	    fatal_error "Unknown interface ($interface)" unless known_interface $interface;

	    $interfaces{$interface} = 1;

	    $hosts = ALLIP if $hosts eq '-';

	    for my $host( split_list $hosts, 'address' ) {
		validate_host( $host , 1 );
		push @hosts, [ $interface, $host ];
	    }
	}

	if ( @hosts ) {
	    my @interfaces = ( keys %interfaces );

	    progress_message "$doing ECN control on @interfaces...";

	    for my $interface ( @interfaces ) {
		my $chainref = ensure_chain 'mangle', ecn_chain( $interface );

		add_ijump $mangle_table->{POSTROUTING} , j => $chainref, p => 'tcp', imatch_dest_dev( $interface ) if have_capability 'MANGLE_FORWARD';
		add_ijump $mangle_table->{OUTPUT},       j => $chainref, p => 'tcp', imatch_dest_dev( $interface );
	    }

	    for my $host ( @hosts ) {
		add_ijump( $mangle_table->{ecn_chain $host->[0]}, j => 'ECN', targetopts => '--ecn-tcp-remove', p => 'tcp',  imatch_dest_net( $host->[1] ) );
	    }
	}
    }
}

sub add_rule_pair( $$$$ ) {
    my ($chainref , $predicate , $target , $level ) = @_;

    log_rule( $level, $chainref, "\U$target", $predicate )  if supplied $level;
    add_jump( $chainref , $target, 0, $predicate );
}

sub setup_blacklist() {

    my $zones  = find_zones_by_option 'blacklist', 'in';
    my $zones1 = find_zones_by_option 'blacklist', 'out';
    my $chainref;
    my $chainref1;
    my ( $level, $disposition ) = @config{'BLACKLIST_LOG_LEVEL', 'BLACKLIST_DISPOSITION' };
    my $audit       = $disposition =~ /^A_/;
    my $target      = $disposition eq 'REJECT' ? 'reject' : $disposition;
    my $orig_target = $target;

  BLACKLIST:
    {
	if ( my $fn = open_file 'blacklist' ) {
	    #
	    # We go ahead and generate the blacklist chains and jump to them, even if they turn out to be empty. That is necessary
	    # for 'refresh' to work properly.
	    #
	    if ( @$zones || @$zones1 ) {
		$chainref  = set_optflags( new_standard_chain( 'blacklst' ), DONT_OPTIMIZE | DONT_DELETE ) if @$zones;
		$chainref1 = set_optflags( new_standard_chain( 'blackout' ), DONT_OPTIMIZE | DONT_DELETE ) if @$zones1;

		if ( supplied $level ) {
		    $target = ensure_blacklog_chain ( $target, $disposition, $level, $audit );
		} elsif ( $audit ) {
		    require_capability 'AUDIT_TARGET', "BLACKLIST_DISPOSITION=$disposition", 's';
		    $target = verify_audit( $disposition );
		}
	    }

	    my $first_entry = 1;

	    first_entry "$doing $fn...";

	    while ( read_a_line ( NORMAL_READ ) ) {

		if ( $first_entry ) {
		    unless  ( @$zones || @$zones1 ) {
			warning_message qq(The entries in $fn have been ignored because there are no 'blacklist' zones);
			close_file;
			last BLACKLIST;
		    }

		    $first_entry = 0;
		}

		my ( $networks, $protocol, $ports, $options ) = split_line 'blacklist file', { networks => 0, proto => 1, port => 2, options => 3 };

		if ( $options eq '-' ) {
		    $options = 'src';
		} elsif ( $options eq 'audit' ) {
		    $options = 'audit,src';
		}

		my ( $to, $from, $whitelist, $auditone ) = ( 0, 0, 0, 0 );

		my @options = split_list $options, 'option';

		for ( @options ) {
		    $whitelist++ if $_ eq 'whitelist';
		    $auditone++  if $_ eq 'audit';
		}

		warning_message "Duplicate 'whitelist' option ignored" if $whitelist > 1;

		my $tgt = $whitelist ? 'RETURN' : $target;

		if ( $auditone ) {
		    fatal_error "'audit' not allowed in whitelist entries" if $whitelist;

		    if ( $audit ) {
			warning_message "Superfluous 'audit' option ignored";
		    } else {
			warning_message "Duplicate 'audit' option ignored" if $auditone > 1;



			$tgt = verify_audit( 'A_' . $target, $orig_target, $target );
		    }
		}

		for ( @options ) {
		    if ( $_ =~ /^(?:src|from)$/ ) {
			if ( $from++ ) {
			    warning_message "Duplicate 'src' ignored";
			} else {
			    if ( @$zones ) {
				expand_rule(
					    $chainref ,
					    NO_RESTRICT ,
					    '' ,
					    do_proto( $protocol , $ports, '' ) ,
					    $networks,
					    '',
					    '' ,
					    $tgt ,
					    '' ,
					    $tgt ,
					    '' );
			    } else {
				warning_message '"src" entry ignored because there are no "blacklist in" zones';
			    }
			}
		    } elsif ( $_ =~ /^(?:dst|to)$/ ) {
			if ( $to++ ) {
			    warning_message "Duplicate 'dst' ignored";
			} else {
			    if ( @$zones1 ) {
				expand_rule(
					    $chainref1 ,
					    NO_RESTRICT ,
					    '' ,
					    do_proto( $protocol , $ports, '' ) ,
					    '',
					    $networks,
					    '' ,
					    $tgt ,
					    '' ,
					    $tgt ,
					    '' );
			    } else {
				warning_message '"dst" entry ignored because there are no "blacklist out" zones';
			    }
			}
		    } else {
			fatal_error "Invalid blacklist option($_)" unless $_ eq 'whitelist' || $_ eq 'audit';
		    }
		}

		progress_message "  \"$currentline\" added to blacklist";
	    }

	    warning_message q(There are interfaces or zones with the 'blacklist' option but the 'blacklist' file is empty) if $first_entry && @$zones;
	} elsif ( @$zones || @$zones1 ) {
	    warning_message q(There are interfaces or zones with the 'blacklist' option, but the 'blacklist' file is either missing or has zero size);
	}
    }
}

#
# Remove instances of 'blacklist' from the passed file.
#
sub remove_blacklist( $ ) {
    my $file = shift;

    my $fn = find_file $file;

    return 1 unless -f $file;

    my $oldfile = open_file $fn;
    my $newfile;
    my $changed;

    open $newfile, '>', "$fn.new" or fatal_error "Unable to open $fn.new for output: $!";

    while ( read_a_line( EMBEDDED_ENABLED | EXPAND_VARIABLES ) ) {
	my ( $rule, $comment ) = split '#', $currentline, 2;

	if ( $rule =~ /blacklist/ ) {
	    $changed = 1;

	    if ( $comment ) {
		$comment =~ s/^/          / while $rule =~ s/blacklist,//;
		$rule =~ s/blacklist/         /g;
		$currentline = join( '#', $rule, $comment );
	    } else {
		$currentline =~ s/blacklist/         /g;
	    }
	}

	print $newfile "$currentline\n";
    }

    close $newfile;

    if ( $changed ) {
	rename $fn, "$fn.bak" or fatal_error "Unable to rename $fn to $fn.bak: $!";
	rename "$fn.new", $fn or fatal_error "Unable to rename $fn.new to $fn: $!";
	progress_message2 "\u$file file $fn saved in $fn.bak"
    }
}

#
# Convert a pre-4.4.25 blacklist to a 4.4.25 blacklist
#
sub convert_blacklist() {
    my $zones  = find_zones_by_option 'blacklist', 'in';
    my $zones1 = find_zones_by_option 'blacklist', 'out';
    my ( $level, $disposition ) = @config{'BLACKLIST_LOG_LEVEL', 'BLACKLIST_DISPOSITION' };
    my $audit       = $disposition =~ /^A_/;
    my $target      = $disposition eq 'REJECT' ? 'reject' : $disposition;
    my $orig_target = $target;
    my @rules;

    if ( @$zones || @$zones1 ) {
	if ( supplied $level ) {
	    $target = 'blacklog';
	} elsif ( $audit ) {
	    $target = verify_audit( $disposition );
	}

	my $fn = open_file 'blacklist';

	first_entry "Converting $fn...";

	while ( read_a_line( NORMAL_READ ) ) {
	    my ( $networks, $protocol, $ports, $options ) = split_line 'blacklist file', { networks => 0, proto => 1, port => 2, options => 3 };

	    if ( $options eq '-' ) {
		$options = 'src';
	    } elsif ( $options eq 'audit' ) {
		$options = 'audit,src';
	    }

	    my ( $to, $from, $whitelist, $auditone ) = ( 0, 0, 0, 0 );

	    my @options = split_list $options, 'option';

	    for ( @options ) {
		$whitelist++ if $_ eq 'whitelist';
		$auditone++  if $_ eq 'audit';
	    }

	    warning_message "Duplicate 'whitelist' option ignored" if $whitelist > 1;

	    my $tgt = $whitelist ? 'WHITELIST' : $target;

	    if ( $auditone ) {
		fatal_error "'audit' not allowed in whitelist entries" if $whitelist;

		if ( $audit ) {
		    warning_message "Superfluous 'audit' option ignored";
		} else {
		    warning_message "Duplicate 'audit' option ignored" if $auditone > 1;
		}

		$tgt = verify_audit( 'A_' . $target, $orig_target, $target );
	    }

	    for ( @options ) {
		if ( $_ =~ /^(?:src|from)$/ ) {
		    if ( $from++ ) {
			warning_message "Duplicate 'src' ignored";
		    } else {
			if ( @$zones ) {
			    push @rules, [ 'src', $tgt, $networks, $protocol, $ports ];
			} else {
			    warning_message '"src" entry ignored because there are no "blacklist in" zones';
			}
		    }
		} elsif ( $_ =~ /^(?:dst|to)$/ ) {
		    if ( $to++ ) {
			warning_message "Duplicate 'dst' ignored";
		    } else {
			if ( @$zones1 ) {
			    push @rules, [ 'dst', $tgt, $networks, $protocol, $ports ];
			} else {
			    warning_message '"dst" entry ignored because there are no "blacklist out" zones';
			}
		    }
		} else {
		    fatal_error "Invalid blacklist option($_)" unless $_ eq 'whitelist' || $_ eq 'audit';
		}
	    }
	}

	if ( @rules ) {
	    my $fn1 = find_file( 'blrules' );
	    my $blrules;
	    my $date = localtime;

	    if ( -f $fn1 ) {
		open $blrules, '>>', $fn1 or fatal_error "Unable to open $fn1: $!";
	    } else {
		open $blrules, '>',  $fn1 or fatal_error "Unable to open $fn1: $!";
		print $blrules <<'EOF';
#
# Shorewall version 4.5 - Blacklist Rules File
#
# For information about entries in this file, type "man shorewall-blrules"
#
# Please see http://shorewall.net/blacklisting_support.htm for additional
# information.
#
###################################################################################################################################################################################################
#ACTION		SOURCE		        DEST		        PROTO	DEST	SOURCE		ORIGINAL	RATE		USER/	MARK	CONNLIMIT	TIME         HEADERS         SWITCH
#							                PORT	PORT(S)		DEST		LIMIT		GROUP
EOF
	    }

	    print( $blrules
		   "#\n" ,
		   "# Rules generated from blacklist file $fn by Shorewall $globals{VERSION} - $date\n" ,
		   "#\n" );

	    for ( @rules ) {
		my ( $srcdst, $tgt, $networks, $protocols, $ports ) = @$_;

		$tgt .= "\t\t";

		my $list = $srcdst eq 'src' ? $zones : $zones1;

		for my $zone ( @$list ) {
		    my $rule = $tgt;

		    if ( $srcdst eq 'src' ) {
			if ( $networks ne '-' ) {
			    $rule .= "$zone:$networks\tall\t\t";
			} else {
			    $rule .= "$zone\t\t\tall\t\t";
			}
		    } else {
			if ( $networks ne '-' ) {
			    $rule .= "all\t\t\t$zone:$networks\t";
			} else {
			    $rule .= "all\t\t\t$zone\t\t\t";
			}
		    }

		    $rule .= "\t$protocols" if $protocols ne '-';
		    $rule .= "\t$ports"     if $ports     ne '-';

		    print $blrules "$rule\n";
		}
	    }

	    close $blrules;
	} else {
	    warning_message q(There are interfaces or zones with the 'blacklist' option but the 'blacklist' file is empty or does not exist) unless @rules;
	}

	if ( -f $fn ) {
	    rename $fn, "$fn.bak";
	    progress_message2 "Blacklist file $fn saved in $fn.bak";
	}

	for my $file ( qw(zones interfaces hosts) ) {
	    remove_blacklist $file;
	}

	progress_message2 "Blacklist successfully converted";

	return 1;
    } else {
	my $fn = find_file 'blacklist';
	if ( -f $fn ) {
	    rename $fn, "$fn.bak" or fatal_error "Unable to rename $fn to $fn.bak: $!";
	    warning_message "No zones have the blacklist option - the blacklist file was saved in $fn.bak";
	}

	return 0;
    }
}

sub process_routestopped() {

    if ( my $fn = open_file 'routestopped' ) {
	my ( @allhosts, %source, %dest , %notrack, @rule );

	my $seq = 0;

	first_entry "$doing $fn...";

	while ( read_a_line ( NORMAL_READ ) ) {

	    my ($interface, $hosts, $options , $proto, $ports, $sports ) =
		split_line 'routestopped file', { interface => 0, hosts => 1, options => 2, proto => 3, dport => 4, sport => 5 };

	    my $interfaceref;

	    fatal_error 'INTERFACE must be specified' if $interface eq '-';
	    fatal_error "Unknown interface ($interface)" unless $interfaceref = known_interface $interface;
	    $hosts = ALLIP unless $hosts && $hosts ne '-';

	    my $routeback = 0;

	    my @hosts;

	    $seq++;

	    my $rule = do_proto( $proto, $ports, $sports, 0 );

	    for my $host ( split /,/, $hosts ) {
		fatal_error "Ipsets not allowed with SAVE_IPSETS=Yes" if $host =~ /^!?\+/ && $config{SAVE_IPSETS};
		validate_host $host, 1;
		push @hosts, "$interface|$host|$seq";
		push @rule, $rule;
	    }


	    unless ( $options eq '-' ) {
		for my $option (split /,/, $options ) {
		    if ( $option eq 'routeback' ) {
			if ( $routeback ) {
			    warning_message "Duplicate 'routeback' option ignored";
			} else {
			    $routeback = 1;
			}
		    } elsif ( $option eq 'source' ) {
			for my $host ( split /,/, $hosts ) {
			    $source{"$interface|$host|$seq"} = 1;
			}
		    } elsif ( $option eq 'dest' ) {
			for my $host ( split /,/, $hosts ) {
			    $dest{"$interface|$host|$seq"} = 1;
			}
		    } elsif ( $option eq 'notrack' ) {
			for my $host ( split /,/, $hosts ) {
			    $notrack{"$interface|$host|$seq"} = 1;
			}
		    } else {
			warning_message "Unknown routestopped option ( $option ) ignored" unless $option eq 'critical';
			warning_message "The 'critical' option is no longer supported (or needed)";
		    }
		}
	    }

	    if ( $routeback || $interfaceref->{options}{routeback} ) {
		my $chainref = $filter_table->{FORWARD};

		for my $host ( split /,/, $hosts ) {
		    add_ijump( $chainref ,
			       j => 'ACCEPT',
			       imatch_source_dev( $interface ) ,
			       imatch_dest_dev( $interface ) ,
			       imatch_source_net( $host ) ,
			       imatch_dest_net( $host ) );
		    clearrule;
		}
	    }

	    push @allhosts, @hosts;
	}

	for my $host ( @allhosts ) {
	    my ( $interface, $h, $seq ) = split /\|/, $host;
	    my $source  = match_source_net $h;
	    my $dest    = match_dest_net $h;
	    my $sourcei = match_source_dev $interface;
	    my $desti   = match_dest_dev $interface;
	    my $rule    = shift @rule;

	    add_rule $filter_table->{INPUT},  "$sourcei $source $rule -j ACCEPT", 1;
	    add_rule $filter_table->{OUTPUT}, "$desti $dest $rule -j ACCEPT", 1 unless $config{ADMINISABSENTMINDED};

	    my $matched = 0;

	    if ( $source{$host} ) {
		add_rule $filter_table->{FORWARD}, "$sourcei $source $rule -j ACCEPT", 1;
		$matched = 1;
	    }

	    if ( $dest{$host} ) {
		add_rule $filter_table->{FORWARD}, "$desti $dest $rule -j ACCEPT", 1;
		$matched = 1;
	    }

	    if ( $notrack{$host} ) {
		add_rule $raw_table->{PREROUTING}, "$sourcei $source $rule -j NOTRACK", 1;
		add_rule $raw_table->{OUTPUT},     "$desti $dest $rule -j NOTRACK", 1;
	    }

	    unless ( $matched ) {
		for my $host1 ( @allhosts ) {
		    unless ( $host eq $host1 ) {
			my ( $interface1, $h1 , $seq1 ) = split /\|/, $host1;
			my $dest1 = match_dest_net $h1;
			my $desti1 = match_dest_dev $interface1;
			add_rule $filter_table->{FORWARD}, "$sourcei $desti1 $source $dest1 $rule -j ACCEPT", 1;
			clearrule;
		    }
		}
	    }
	}
    }
}

#
# Process the stoppedrules file. Returns true if the file was non-empty.
#
sub process_stoppedrules() {
    my $fw = firewall_zone;
    my $result;

    if ( my $fn = open_file 'stoppedrules' , 1, 1 ) {
	first_entry "$doing $fn...";

	while ( read_a_line( NORMAL_READ ) ) {

	    $result = 1;

	    my ( $target, $source, $dest, $protos, $ports, $sports ) = 
		split_line1 'stoppedrules file', { target => 0, source => 1, dest => 2, proto => 3, dport => 4, sport => 5 };

	    fatal_error( "Invalid TARGET ($target)" ) unless $target =~ /^(?:ACCEPT|NOTRACK)$/;

	    my $tableref;

	    my $chainref;
	    my $restriction = NO_RESTRICT;

	    if ( $target eq 'NOTRACK' ) {
		$tableref = $raw_table;
		require_capability 'RAW_TABLE', 'NOTRACK', 's';
		$chainref = $raw_table->{PREROUTING};
		$restriction = PREROUTE_RESTRICT | DESTIFACE_DISALLOW;
	    } else {
		$tableref = $filter_table;
	    }

	    if ( $source eq $fw ) {
		$chainref = ( $target eq 'NOTRACK' ? $raw_table : $filter_table)->{OUTPUT};
		$source = '';
		$restriction = OUTPUT_RESTRICT;
	    } elsif ( $source =~ s/^($fw):// ) {
		$chainref = ( $target eq 'NOTRACK' ? $raw_table : $filter_table)->{OUTPUT};
		$restriction = OUTPUT_RESTRICT;
	    }

	    if ( $dest eq $fw ) {
		fatal_error "\$FW may not be specified as the destination of a NOTRACK rule" if $target eq 'NOTRACK';
		$chainref = $filter_table->{INPUT};
		$dest = '';
		$restriction = INPUT_RESTRICT;
	    } elsif ( $dest =~ s/^($fw):// ) {
		fatal_error "\$FW may not be specified as the destination of a NOTRACK rule" if $target eq 'NOTRACK';
		$chainref = $filter_table->{INPUT};
		$restriction = INPUT_RESTRICT;
	    }

	    $chainref = $tableref->{FORWARD} unless $chainref;

	    my $disposition = $target;

	    $target = 'CT --notrack' if $target eq 'NOTRACK' and have_capability( 'CT_TARGET' );

	    unless ( $restriction == OUTPUT_RESTRICT
		     && $target eq 'ACCEPT'
		     && $config{ADMINISABSENTMINDED} ) {
		for my $proto ( split_list $protos, 'Protocol' ) {
		    expand_rule( $chainref ,
				 $restriction ,
				 '' ,
				 do_proto( $proto, $ports, $sports ) ,
				 $source ,
				 $dest ,
				 '' ,
				 $target,
				 '',
				 $disposition,
				 do_proto( $proto, '-', '-' ) );
		}
	    } else {
		warning_message "Redundant OUTPUT rule ignored because ADMINISABSENTMINDED=Yes";
	    }
	}
    }

    $result;
}

sub setup_mss();

sub add_common_rules ( $ ) {
    my $upgrade = shift;
    my $interface;
    my $chainref;
    my $target;
    my $target1;
    my $rule;
    my $list;
    my $chain;
    my $dynamicref;

    my @state     = state_imatch( $globals{BLACKLIST_STATES} );
    my $faststate = $config{RELATED_DISPOSITION} eq 'ACCEPT' && $config{RELATED_LOG_LEVEL} eq '' ? 'ESTABLISHED,RELATED' : 'ESTABLISHED';
    my $level     = $config{BLACKLIST_LOG_LEVEL};
    my $rejectref = $filter_table->{reject};

    if ( $config{DYNAMIC_BLACKLIST} ) {
	add_rule_pair( set_optflags( new_standard_chain( 'logdrop' )  , DONT_OPTIMIZE | DONT_DELETE ), '' , 'DROP'   , $level );
	add_rule_pair( set_optflags( new_standard_chain( 'logreject' ), DONT_OPTIMIZE | DONT_DELETE ), '' , 'reject' , $level );
	$dynamicref =  set_optflags( new_standard_chain( 'dynamic' ) ,  DONT_OPTIMIZE );
	add_commands( $dynamicref, '[ -f ${VARDIR}/.dynamic ] && cat ${VARDIR}/.dynamic >&3' );
    }

    setup_mss;

    if ( $config{FASTACCEPT} ) {
	add_ijump( $filter_table->{OUTPUT} , j => 'ACCEPT', state_imatch $faststate )
    }

    my $policy   = $config{SFILTER_DISPOSITION};
    $level       = $config{SFILTER_LOG_LEVEL};
    my $audit    = $policy =~ s/^A_//;
    my @ipsec    = have_ipsec ? ( policy => '--pol none --dir in' ) : ();

    if ( $level || $audit ) {
	#
	# Create a chain to log and/or audit and apply the policy
	#
	$chainref = new_standard_chain 'sfilter';

	log_rule $level , $chainref , $policy , '' if $level ne '';

	add_ijump( $chainref, j => 'AUDIT', targetopts => '--type ' . lc $policy ) if $audit;

	add_ijump $chainref, g => $policy eq 'REJECT' ? 'reject' : $policy;

	$target = 'sfilter';
    } else {
	$target = $policy eq 'REJECT' ? 'reject' : $policy;
    }

    if ( @ipsec ) {
	#
	# sfilter1 will be used in the FORWARD chain where we allow traffic entering the interface
	# to leave the interface encrypted. We need a separate chain because '--dir out' cannot be
	# used in the input chain
	#
	$chainref = new_standard_chain 'sfilter1';

	add_ijump ( $chainref, j => 'RETURN', policy => '--pol ipsec --dir out' );
	log_rule $level , $chainref , $policy , '' if $level ne '';

	add_ijump( $chainref, j => 'AUDIT', targetopts => '--type ' . lc $policy ) if $audit;

	add_ijump $chainref, g => $policy eq 'REJECT' ? 'reject' : $policy;

	$target1 = 'sfilter1';
    } else {
	#
	# No IPSEC -- use the same target in both INPUT and FORWARD
	#
	$target1 = $target;
    }

    for $interface ( all_real_interfaces ) {
	ensure_chain( 'filter', $_ ) for first_chains( $interface ), output_chain( $interface ), option_chains( $interface ), output_option_chain( $interface );

	my $interfaceref = find_interface $interface;

	unless ( $interfaceref->{options}{ignore} & NO_SFILTER || $interfaceref->{options}{rpfilter} || $interfaceref->{physical} eq 'lo' ) {

	    my @filters = @{$interfaceref->{filter}};

	    $chainref = $filter_table->{forward_option_chain $interface};

	    if ( @filters ) {
		add_ijump( $chainref , @ipsec ? 'j' : 'g' => $target1, imatch_source_net( $_ ), @ipsec ), $chainref->{filtered}++ for @filters;
	    } elsif ( $interfaceref->{bridge} eq $interface ) {
		add_ijump( $chainref , @ipsec ? 'j' : 'g' => $target1, imatch_dest_dev( $interface ), @ipsec ), $chainref->{filtered}++
		    unless( $config{ROUTE_FILTER} eq 'on' ||
			    $interfaceref->{options}{routeback} ||
			    $interfaceref->{options}{routefilter} ||
			    $interfaceref->{physical} eq '+' );
	    }


	    if ( @filters ) {
		$chainref = $filter_table->{input_option_chain $interface};
		add_ijump( $chainref , g => $target, imatch_source_net( $_ ), @ipsec ), $chainref->{filtered}++ for @filters;
	    }

	    for ( option_chains( $interface ) ) {
		add_ijump( $filter_table->{$_}, j => $dynamicref, @state ) if $dynamicref;
		add_ijump( $filter_table->{$_}, j => 'ACCEPT', state_imatch $faststate ) if $config{FASTACCEPT};
	    }
	}
    }

    #
    # Delete 'sfilter' chains unless there are referenced to them
    #
    for ( qw/sfilter sfilter1/ ) {
	if ( $chainref = $filter_table->{$_} ) {
	    $chainref->{referenced} = 0 unless keys %{$chainref->{references}};
	}
    }

    $list = find_interfaces_by_option('rpfilter');

    if ( @$list ) {
	$policy   = $config{RPFILTER_DISPOSITION};
	$level    = $config{RPFILTER_LOG_LEVEL};
	$audit    = $policy =~ s/^A_//;
	
	if ( $level || $audit ) {
	    #
	    # Create a chain to log and/or audit and apply the policy
	    #
	    $chainref = ensure_mangle_chain 'rplog';

	    log_rule $level , $chainref , $policy , '' if $level ne '';

	    add_ijump( $chainref, j => 'AUDIT', targetopts => '--type ' . lc $policy ) if $audit;

	    add_ijump $chainref, g => $policy eq 'REJECT' ? 'reject' : $policy;

	    $target = 'rplog';
	} else {
	    $target = $policy eq 'REJECT' ? 'reject' : $policy;
	}

	add_ijump( ensure_mangle_chain( 'rpfilter' ),
		   j        => $target,
		   rpfilter => '--validmark --invert',
		   state_imatch 'NEW,RELATED,INVALID',
		   @ipsec
		 );
    }
	    
    run_user_exit1 'initdone';

    if ( $upgrade ) {
	exit 0 unless convert_blacklist;
    } else {
	setup_blacklist;
    }

    $list = find_hosts_by_option 'nosmurfs';

    if ( @$list ) {
	progress_message2 'Adding Anti-smurf Rules';

	$chainref = new_standard_chain 'smurfs';

	my $smurfdest = $config{SMURF_DISPOSITION};

	if ( supplied $config{SMURF_LOG_LEVEL} ) {
	    my $smurfref = new_chain( 'filter', 'smurflog' );

	    log_rule_limit( $config{SMURF_LOG_LEVEL},
			    $smurfref,
			    'smurfs' ,
			    'DROP',
			    $globals{LOGLIMIT},
			    '',
			    'add',
			    '' );
	    add_ijump( $smurfref, j => 'AUDIT', targetopts => '--type drop' ) if $smurfdest eq 'A_DROP';
	    add_ijump( $smurfref, j => 'DROP' );

	    $smurfdest = 'smurflog';
	} else {
	    verify_audit( $smurfdest ) if $smurfdest eq 'A_DROP';
	}

	if ( have_capability( 'ADDRTYPE' ) ) {
	    if ( $family == F_IPV4 ) {
		add_ijump $chainref , j => 'RETURN', s => '0.0.0.0';         ;
	    } else {
		add_ijump $chainref , j => 'RETURN', s => '::';
	    }

	    add_ijump( $chainref, g => $smurfdest, addrtype => '--src-type BROADCAST' ) ;
	} else {
	    if ( $family == F_IPV4 ) {
		add_commands $chainref, 'for address in $ALL_BCASTS; do';
	    } else {
		add_commands $chainref, 'for address in $ALL_ACASTS; do';
	    }

	    incr_cmd_level $chainref;
	    add_ijump( $chainref, g => $smurfdest, s => '$address' );
	    decr_cmd_level $chainref;
	    add_commands $chainref, 'done';
	}

	if ( $family == F_IPV4 ) {
	    add_ijump( $chainref, g => $smurfdest, s => '224.0.0.0/4' );
	} else {
	    add_ijump( $chainref, g => $smurfdest, s => IPv6_MULTICAST );
	}

	my @state = have_capability( 'RAW_TABLE' ) ? state_imatch 'NEW,INVALID,UNTRACKED' : state_imatch 'NEW,INVALID';

	for my $hostref  ( @$list ) {
	    $interface     = $hostref->[0];
	    my $ipsec      = $hostref->[1];
	    my @policy     = have_ipsec ? ( policy => "--pol $ipsec --dir in" ) : ();
	    my $target     = source_exclusion( $hostref->[3], $chainref );

	    for $chain ( option_chains $interface ) {
		add_ijump( $filter_table->{$chain} , j => $target, @state, imatch_source_net( $hostref->[2] ), @policy );
	    }
	}
    }

    if ( have_capability( 'ADDRTYPE' ) ) {
	add_ijump $rejectref , j => 'DROP' , addrtype => '--src-type BROADCAST';
    } else {
	if ( $family == F_IPV4 ) {
	    add_commands $rejectref, 'for address in $ALL_BCASTS; do';
	} else {
	    add_commands $rejectref, 'for address in $ALL_ACASTS; do';
	}

	incr_cmd_level $rejectref;
	add_ijump $rejectref, j => 'DROP', d => '$address';
	decr_cmd_level $rejectref;
	add_commands $rejectref, 'done';
    }

    if ( $family == F_IPV4 ) {
	add_ijump $rejectref , j => 'DROP', s => '224.0.0.0/4';
    } else {
	add_ijump $rejectref , j => 'DROP', s => IPv6_MULTICAST;
    }

    add_ijump $rejectref , j => 'DROP', p => 2;
    add_ijump $rejectref , j => 'REJECT', targetopts => '--reject-with tcp-reset', p => 6;

    if ( have_capability( 'ENHANCED_REJECT' ) ) {
	add_ijump $rejectref , j => 'REJECT', p => 17;

	if ( $family == F_IPV4 ) {
	    add_ijump $rejectref, j => 'REJECT --reject-with icmp-host-unreachable', p => 1;
	    add_ijump $rejectref, j => 'REJECT --reject-with icmp-host-prohibited';
	} else {
	    add_ijump $rejectref, j => 'REJECT --reject-with icmp6-addr-unreachable', p => 58;
	    add_ijump $rejectref, j => 'REJECT --reject-with icmp6-adm-prohibited';
	}
    } else {
	add_ijump $rejectref , j => 'REJECT';
    }

    $list = find_interfaces_by_option 'dhcp';

    if ( @$list ) {
	progress_message2 'Adding rules for DHCP';

	my $ports = $family == F_IPV4 ? '67:68' : '546:547';

	for $interface ( @$list ) {
	    set_rule_option( add_ijump( $filter_table->{$_} , j => 'ACCEPT', p => "udp --dport $ports" ) ,
			     'dhcp',
			     1 ) for input_option_chain( $interface ), output_option_chain( $interface );

	    add_ijump( $filter_table->{forward_option_chain $interface} ,
		       j => 'ACCEPT',
		       p =>  "udp --dport $ports" ,
		       imatch_dest_dev( $interface ) )
		if get_interface_option( $interface, 'bridge' );

	    unless ( $family == F_IPV6 || get_interface_option( $interface, 'allip' ) ) {
		add_ijump( $filter_table->{input_chain( $interface ) } ,
			   j => 'ACCEPT' ,
			   p => "udp --dport $ports" ,
			   s => NILIPv4 . '/' . VLSMv4 );
	    }
	}
    }

    $list = find_hosts_by_option 'tcpflags';

    if ( @$list ) {
	my $level = $config{TCP_FLAGS_LOG_LEVEL};
	my $disposition = $config{TCP_FLAGS_DISPOSITION};
	my $audit = $disposition =~ /^A_/;

	progress_message2 "$doing TCP Flags filtering...";

	$chainref = new_standard_chain 'tcpflags';

	if ( $level  ) {
	    my $logflagsref = new_standard_chain 'logflags';

	    my $savelogparms = $globals{LOGPARMS};

	    $globals{LOGPARMS} = "$globals{LOGPARMS}--log-ip-options ";

	    log_rule $level , $logflagsref , $config{TCP_FLAGS_DISPOSITION}, '';

	    $globals{LOGPARMS} = $savelogparms;

	    if ( $audit ) {
		$disposition =~ s/^A_//;
		add_ijump( $logflagsref, j => 'AUDIT', targetopts => '--type ' . lc $disposition );
	    }

	    if ( $disposition eq 'REJECT' ) {
		add_ijump $logflagsref , j => 'REJECT', targetopts => '--reject-with tcp-reset', p => 6;
	    } else {
		add_ijump $logflagsref , j => $disposition;
	    }

	    $disposition = 'logflags';
	} elsif ( $audit ) {
	    require_capability( 'AUDIT_TARGET', "TCP_FLAGS_DISPOSITION=$disposition", 's' );
	    verify_audit( $disposition );
	}

	add_ijump $chainref , g => $disposition, p => 'tcp --tcp-flags ALL FIN,URG,PSH';
	add_ijump $chainref , g => $disposition, p => 'tcp --tcp-flags ALL NONE';
	add_ijump $chainref , g => $disposition, p => 'tcp --tcp-flags SYN,RST SYN,RST';
	add_ijump $chainref , g => $disposition, p => 'tcp --tcp-flags SYN,FIN SYN,FIN';
	add_ijump $chainref , g => $disposition, p => 'tcp --syn --sport 0';

	for my $hostref  ( @$list ) {
	    my $interface  = $hostref->[0];
	    my $target     = source_exclusion( $hostref->[3], $chainref );
	    my @policy     = have_ipsec ? ( policy => "--pol $hostref->[1] --dir in" ) : ();

	    for $chain ( option_chains $interface ) {
		add_ijump( $filter_table->{$chain} , j => $target, p => 'tcp', imatch_source_net( $hostref->[2] ), @policy );
	    }
	}
    }

    if ( $family == F_IPV4 ) {
	my $announced = 0;

	$list = find_interfaces_by_option 'upnp';

	if ( @$list ) {
	    progress_message2 "$doing UPnP";

	    $chainref = set_optflags( new_nat_chain( 'UPnP' ), DONT_OPTIMIZE );

	    add_commands( $chainref, '[ -s /${VARDIR}/.UPnP ] && cat ${VARDIR}/.UPnP >&3' );

	    $announced = 1;

	    for $interface ( @$list ) {
		add_ijump $nat_table->{PREROUTING} , j => 'UPnP', imatch_source_dev ( $interface );
	    }
	}

	$list = find_interfaces_by_option 'upnpclient';

	if ( @$list ) {
	    progress_message2 "$doing UPnP" unless $announced;

	    for $interface ( @$list ) {
		my $chainref = $filter_table->{input_option_chain $interface};
		my $base     = uc var_base get_physical $interface;
		my $optional = interface_is_optional( $interface );
		my $variable = get_interface_gateway( $interface, ! $optional );

		if ( $optional ) {
		    add_commands( $chainref,
				  qq(if [ -n "SW_\$${base}_IS_USABLE" -a -n "$variable" ]; then) );
		    incr_cmd_level( $chainref );
		    add_ijump( $chainref, j => 'ACCEPT', imatch_source_dev( $interface ), s => $variable, p => 'udp' );
		    decr_cmd_level( $chainref );
		    add_commands( $chainref, 'fi' );
		} else {
		    add_ijump( $chainref, j => 'ACCEPT', imatch_source_dev( $interface ), s => $variable, p => 'udp' );
		}
	    }
	}
    }

    setup_syn_flood_chains;

}

my %maclist_targets = ( ACCEPT => { target => 'RETURN' , mangle => 1 } ,
			REJECT => { target => 'reject' , mangle => 0 } ,
			DROP   => { target => 'DROP' ,   mangle => 1 } );

sub setup_mac_lists( $ ) {

    my $phase = $_[0];

    my %maclist_interfaces;

    my $table = $config{MACLIST_TABLE};

    my $maclist_hosts = find_hosts_by_option 'maclist';

    my $target      = $globals{MACLIST_TARGET};
    my $level       = $config{MACLIST_LOG_LEVEL};
    my $disposition = $config{MACLIST_DISPOSITION};
    my $audit       = ( $disposition =~ s/^A_// );
    my $ttl         = $config{MACLIST_TTL};

    progress_message2 "$doing MAC Filtration -- Phase $phase...";

    for my $hostref ( @$maclist_hosts ) {
	$maclist_interfaces{ $hostref->[0] } = 1;
    }

    my @maclist_interfaces = ( sort keys %maclist_interfaces );

    if ( $phase == 1 ) {

	for my $interface ( @maclist_interfaces ) {
	    my $chainref = new_chain $table , mac_chain $interface;

	    if ( $family == F_IPV4 ) {
		add_ijump $chainref , j => 'RETURN', s => '0.0.0.0', d => '255.255.255.255', p => 'udp --dport 67:68'
		    if $table eq 'mangle'  && get_interface_option( $interface, 'dhcp');
	    } else {
		#
		# Accept any packet with a link-level source or destination address
		#
		add_ijump $chainref , j => 'RETURN', s => 'ff80::/10';
		add_ijump $chainref , j => 'RETURN', d => 'ff80::/10';
		#
		# Accept Multicast
		#
		add_ijump $chainref , j => 'RETURN', d => IPv6_MULTICAST;
	    }

	    if ( $ttl ) {
		my $chain1ref = new_chain $table, macrecent_target $interface;

		my $chain = $chainref->{name};

		add_ijump $chainref,  j => 'RETURN', recent => "--rcheck --seconds $ttl --name $chain";
		add_ijump  $chainref, j => $chain1ref;
		add_ijump $chainref,  j => 'RETURN', recent => "--update --name $chain";
		add_irule $chainref,  recent => "--set --name $chain";
	    }
	}

	if ( my $fn = open_file 'maclist', 1, 1 ) {

	    first_entry "$doing $fn...";

	    while ( read_a_line( NORMAL_READ ) ) {

		my ( $original_disposition, $interface, $mac, $addresses  ) = split_line1 'maclist file', { disposition => 0, interface => 1, mac => 2, addresses => 3 };

		my ( $disposition, $level, $remainder) = split( /:/, $original_disposition, 3 );

		fatal_error "Invalid DISPOSITION ($original_disposition)" if defined $remainder || ! $disposition;

		my $targetref = $maclist_targets{$disposition};

		fatal_error "Invalid DISPOSITION ($original_disposition)"              if ! $targetref || ( ( $table eq 'mangle' ) && ! $targetref->{mangle} );
		fatal_error "Unknown Interface ($interface)"                           unless known_interface( $interface );
		fatal_error "No hosts on $interface have the maclist option specified" unless $maclist_interfaces{$interface};

		my $chainref = $chain_table{$table}{( $ttl ? macrecent_target $interface : mac_chain $interface )};

		$mac       = '' unless $mac && ( $mac ne '-' );
		$addresses = '' unless defined $addresses && ( $addresses ne '-' );

		fatal_error "You must specify a MAC address or an IP address" unless $mac || $addresses;

		$mac = do_mac $mac if $mac;

		if ( $addresses ) {
		    for my $address ( split ',', $addresses ) {
			my $source = match_source_net $address;
			log_rule_limit $level, $chainref , mac_chain( $interface) , $disposition, '', '', 'add' , "${mac}${source}"
			    if supplied $level;

			add_ijump( $chainref , j => 'AUDIT', targetopts => '--type ' . lc $disposition ) if $audit && $disposition ne 'ACCEPT';
			add_jump( $chainref , $targetref->{target}, 0, "${mac}${source}" );
		    }
		} else {
		    log_rule_limit $level, $chainref , mac_chain( $interface) , $disposition, '', '', 'add' , $mac
			if supplied $level;

		    add_ijump( $chainref , j => 'AUDIT', targetopts => '--type ' . lc $disposition ) if $audit && $disposition ne 'ACCEPT';
		    add_jump ( $chainref , $targetref->{target}, 0, "$mac" );
		}

		progress_message "      Maclist entry \"$currentline\" $done";
	    }
	}
	#
	# Generate jumps from the input and forward chains
	#
	for my $hostref ( @$maclist_hosts ) {
	    my $interface  = $hostref->[0];
	    my $ipsec      = $hostref->[1];
	    my @policy     = have_ipsec ? ( policy => "--pol $ipsec --dir in" ) : ();
	    my @source     = imatch_source_net $hostref->[2];

	    my @state = have_capability( 'RAW_TABLE' ) ? state_imatch 'NEW,UNTRACKED' : state_imatch 'NEW';

	    if ( $table eq 'filter' ) {
		my $chainref = source_exclusion( $hostref->[3], $filter_table->{mac_chain $interface} );

		for my $chain ( option_chains $interface ) {
		    add_ijump $filter_table->{$chain} , j => $chainref, @source, @state, @policy;
		}
	    } else {
		my $chainref = source_exclusion( $hostref->[3], $mangle_table->{mac_chain $interface} );
		add_ijump $mangle_table->{PREROUTING}, j => $chainref, imatch_source_dev( $interface ), @source, @state, @policy;
	    }
	}
    } else {
	#
	# Phase II
	#
	ensure_audit_chain( $target, $disposition, undef, $table ) if $audit;

	for my $interface ( @maclist_interfaces ) {
	    my $chainref = $chain_table{$table}{( $ttl ? macrecent_target $interface : mac_chain $interface )};
	    my $chain    = $chainref->{name};

	    if ( $family == F_IPV4 ) {
		if ( $level ne '' || $disposition ne 'ACCEPT' ) {
		    my $variable = get_interface_addresses source_port_to_bridge( $interface );

		    if ( have_capability( 'ADDRTYPE' ) ) {
			add_commands( $chainref, "for address in $variable; do" );
			incr_cmd_level( $chainref );
			add_ijump( $chainref, j => 'RETURN', s => '$address', addrtype => '--dst-type BROADCAST' );
			add_ijump( $chainref, j => 'RETURN', s => '$address', d => '224.0.0.0/4' );
			decr_cmd_level( $chainref );
			add_commands( $chainref, 'done' );
		    } else {
			my $bridge    = source_port_to_bridge( $interface );
			my $bridgeref = find_interface( $bridge );

			add_commands( $chainref,
				      "for address in $variable; do" );
			incr_cmd_level( $chainref );

			if ( $bridgeref->{broadcasts} ) {
			    for my $address ( @{$bridgeref->{broadcasts}}, '255.255.255.255' ) {
				add_ijump( $chainref, j => 'RETURN', s => '$address', d => $address );
			    }
			} else {
			    my $variable1 = get_interface_bcasts $bridge;

			    add_commands( $chainref,
					  "    for address1 in $variable1; do" );
			    incr_cmd_level( $chainref );
			    add_ijump( $chainref, j => 'RETURN', s => '$address', d => '$address1' );
			    decr_cmd_level( $chainref );
			    add_commands( $chainref, 'done' );
			}

			add_ijump( $chainref, j => 'RETURN', s => '$address', d => '224.0.0.0/4' );
			decr_cmd_level( $chainref );
			add_commands( $chainref, 'done' );
		    }
		}
	    }

	    run_user_exit2( 'maclog', $chainref );

	    log_rule_limit $level, $chainref , $chain , $disposition, '', '', 'add', '' if $level ne '';
	    add_ijump $chainref, j => $target;
	}
    }
}

#
# Helper functions for generate_matrix()
#-----------------------------------------
#
# Return the target for rules from $zone to $zone1.
#
sub rules_target( $$ ) {
    my ( $zone, $zone1 ) = @_;
    my $chain = rules_chain( ${zone}, ${zone1} );
    my $chainref = $filter_table->{$chain};

    return $chain   if $chainref && $chainref->{referenced};
    return 'ACCEPT' if $zone eq $zone1;

    assert( $chainref );

    if ( $chainref->{policy} ne 'CONTINUE' ) {
	my $policyref = $filter_table->{$chainref->{policychain}};
	assert( $policyref );
	return $policyref->{name} if $policyref ne $chainref;
	return $chainref->{policy} eq 'REJECT' ? 'reject' : $chainref->{policy};
    }

    ''; # CONTINUE policy
}

#
# Generate rules for one destination zone
#
sub generate_dest_rules( $$$;@ ) {
    my ( $chainref, $chain, $z2, @matches ) = @_;

    my $z2ref            = find_zone( $z2 );
    my $type2            = $z2ref->{type};

    if ( $type2 & VSERVER ) {
	for my $hostref ( @{$z2ref->{hosts}{ip}{'%vserver%'}} ) {
	    my $exclusion = dest_exclusion( $hostref->{exclusions}, $chain);

	    for my $net ( @{$hostref->{hosts}} ) {
		add_ijump( $chainref,
			   j => $exclusion ,
			   imatch_dest_net ( $net ),
			   @matches );
	    }
	}
    } else {
	add_ijump( $chainref, j => $chain, @matches );
    }
}

#
# Generate rules for one vserver source zone
#
sub generate_source_rules( $$$;@ ) {
    my ( $outchainref, $z1, $z2, @matches ) = @_;
    my $chain = rules_target ( $z1, $z2 );

    if ( $chain && $chain ne 'NONE' ) {
	#
	# Not a CONTINUE policy with no rules
	#
	for my $hostref ( @{defined_zone( $z1 )->{hosts}{ip}{'%vserver%'}} ) {
	    my @ipsec_match = match_ipsec_in $z1 , $hostref;
	    my $exclusion   = source_exclusion( $hostref->{exclusions}, $chain);

	    for my $net ( @{$hostref->{hosts}} ) {
		generate_dest_rules( $outchainref,
				     $exclusion,
				     $z2,
				     imatch_source_net( $net ),
				     @matches ,
				     @ipsec_match
				   );
	    }
	}
    }
}

#
# Loopback traffic -- this is where we assemble the intra-firewall chains
#
sub handle_loopback_traffic() {
    my @zones   = ( vserver_zones, firewall_zone );
    my $natout  = $nat_table->{OUTPUT};
    my $rawout  = $raw_table->{OUTPUT};
    my $rulenum = 0;
    my $local   = local_zone;

    my $outchainref;
    my @rule;

    if ( @zones > 1 ) {
	#
	# We have a vserver zone -- route output through a separate chain
	#
	$outchainref = new_standard_chain 'loopback';
	add_ijump $filter_table->{OUTPUT}, j => $outchainref, o => 'lo';
    } else {
	#
	# Only the firewall -- just use the OUTPUT chain
	#
	$outchainref = $filter_table->{OUTPUT};
	@rule = ( o => 'lo');
    }

    for my $z1 ( @zones ) {
	my $z1ref            = find_zone( $z1 );
	my $type1            = $z1ref->{type};
	my $natref           = $nat_table->{dnat_chain $z1};
	my $notrackref       = $raw_table->{notrack_chain( $z1 )};
	#
	# Add jumps in the 'output' chain to the rules chains
	#
	if ( $type1 == FIREWALL ) {
	    for my $z2 ( @zones ) {
		next if $local && $z1 eq $z2;

		my $chain = rules_target( $z1, $z2 );

		generate_dest_rules( $outchainref, $chain, $z2, @rule ) if $chain;
	    }
	    #
	    # Handle conntrack 
	    #
	    if ( $notrackref ) {
		add_ijump $rawout, j => $notrackref if $notrackref->{referenced};
	    }
	} else {
	    for my $z2 ( @zones ) {
		generate_source_rules( $outchainref, $z1, $z2, @rule );
	    }
	    #
	    # Handle conntrack rules
	    #
	    if ( $notrackref->{referenced} ) {
		for my $hostref ( @{defined_zone( $z1 )->{hosts}{ip}{'%vserver%'}} ) {
		    my $exclusion   = source_exclusion( $hostref->{exclusions}, $notrackref);
		    my @ipsec_match = match_ipsec_in $z1 , $hostref;

		    for my $net ( @{$hostref->{hosts}} ) {
			insert_ijump( $rawout,
				      j => $exclusion ,
				      $rawout->{insert}++,
				      imatch_source_net $net,
				      @ipsec_match );
		    }
		}
	    }
	}

	if ( $natref && $natref->{referenced} ) {
	    #
	    # There are DNAT rules with this zone as the source --  add jumps from the nat OUTPUT chain
	    #
	    my $source_hosts_ref = defined_zone( $z1 )->{hosts};

	    for my $typeref ( values %{$source_hosts_ref} ) {
		for my $hostref ( @{$typeref->{'%vserver%'}} ) {
		    my $exclusion   = source_exclusion( $hostref->{exclusions}, $natref);

		    for my $net ( @{$hostref->{hosts}} ) {
			insert_ijump( $natout,
				      j => $exclusion,
				      $rulenum++,
				      imatch_source_net( $net , 0, ) );
		    }
		}
	    }
	}
    }
}

#
# Add jumps from the builtin chains to the interface-chains that are used by this configuration
#
sub add_interface_jumps {
    our %input_jump_added;
    our %output_jump_added;
    our %forward_jump_added;
    my @interfaces = grep $_ ne '%vserver%', @_;
    my $dummy;
    my $lo_jump_added = local_zone && ! get_interface_option( 'lo', 'destonly' );
    #
    # Add Nat jumps
    #
    for my $interface ( @_ ) {
	addnatjump 'POSTROUTING' , snat_chain( $interface ), imatch_dest_dev( $interface );
    }

    for my $interface ( @interfaces  ) {
	addnatjump 'PREROUTING'  , input_chain( $interface )  , imatch_source_dev( $interface );
	addnatjump 'POSTROUTING' , output_chain( $interface ) , imatch_dest_dev( $interface );
	addnatjump 'POSTROUTING' , masq_chain( $interface ) , imatch_dest_dev( $interface );

	if ( have_capability 'RAWPOST_TABLE' ) {
	    insert_ijump ( $rawpost_table->{POSTROUTING}, j => postrouting_chain( $interface ), 0, imatch_dest_dev( $interface) )   if $rawpost_table->{postrouting_chain $interface};
	    insert_ijump ( $raw_table->{PREROUTING},      j => prerouting_chain( $interface ),  0, imatch_source_dev( $interface) ) if $raw_table->{prerouting_chain $interface};
	    insert_ijump ( $raw_table->{OUTPUT},          j => output_chain( $interface ),      0, imatch_dest_dev( $interface) )   if $raw_table->{output_chain $interface};
	}

	add_ijump( $mangle_table->{PREROUTING}, j => 'rpfilter' , imatch_source_dev( $interface ) ) if interface_has_option( $interface, 'rpfilter', $dummy );
    }
    #
    # Add the jumps to the interface chains from filter FORWARD, INPUT, OUTPUT
    #
    for my $interface ( @interfaces ) {
	my $forwardref   = $filter_table->{forward_chain $interface};
	my $inputref     = $filter_table->{input_chain $interface};
	my $outputref    = $filter_table->{output_chain $interface};
	my $interfaceref = find_interface($interface);

	add_ijump $filter_table->{INPUT} , j => 'ACCEPT', i => 'lo' if $interfaceref->{physical} eq '+' && ! $lo_jump_added++;

	if ( $interfaceref->{options}{port} ) {
	    my $bridge = $interfaceref->{bridge};

	    add_ijump ( $filter_table->{forward_chain $bridge},
			j => 'ACCEPT',
			imatch_source_dev( $interface, 1),
			imatch_dest_dev( $interface, 1)
		     ) unless $interfaceref->{nets};

	    add_ijump( $filter_table->{forward_chain $bridge} ,
		       j => $forwardref ,
		       imatch_source_dev( $interface, 1 )
		     ) unless $forward_jump_added{$interface} || ! use_forward_chain $interface, $forwardref;

	    add_ijump( $filter_table->{input_chain $bridge },
		       j => $inputref ,
		       imatch_source_dev( $interface, 1 )
		    ) unless $input_jump_added{$interface}   || ! use_input_chain $interface, $inputref;

	    unless ( $output_jump_added{$interface} || ! use_output_chain $interface, $outputref ) {
		add_ijump( $filter_table->{output_chain $bridge} ,
			   j => $outputref ,
			   imatch_dest_dev( $interface, 1 ) )
		    unless get_interface_option( $interface, 'port' );
	    }
	} else {
	    add_ijump ( $filter_table->{FORWARD}, j => 'ACCEPT', imatch_source_dev( $interface) , imatch_dest_dev( $interface) ) unless $interfaceref->{nets} || ! $interfaceref->{options}{bridge};

	    add_ijump( $filter_table->{FORWARD} , j => $forwardref , imatch_source_dev( $interface ) ) if use_forward_chain( $interface, $forwardref ) && ! $forward_jump_added{$interface}++;
	    add_ijump( $filter_table->{INPUT}   , j => $inputref ,   imatch_source_dev( $interface ) ) if use_input_chain( $interface, $inputref )     && ! $input_jump_added{$interface}++;

	    if ( use_output_chain $interface, $outputref ) {
		add_ijump $filter_table->{OUTPUT} , j => $outputref , imatch_dest_dev( $interface ) unless get_interface_option( $interface, 'port' ) || $output_jump_added{$interface}++;
	    }
	}
    }

    add_ijump $filter_table->{INPUT} , j => 'ACCEPT', i => 'lo' unless $lo_jump_added++;

    handle_loopback_traffic;
}

#
# Do the initial matrix processing for a complex zone
#
sub handle_complex_zone( $$ ) {
    my ( $zone, $zoneref ) = @_;

    our %input_jump_added;
    our %output_jump_added;
    our %forward_jump_added;
    our %ipsec_jump_added;
    #
    # Complex zone or we have more than two off-firewall zones -- Shorewall::Rules::classic_blacklist created a zone forwarding chain
    #
    my $frwd_ref = $filter_table->{zone_forward_chain( $zone )};

    assert( $frwd_ref, $zone );
    #
    # Add Zone mark if any
    #
    add_ijump( $frwd_ref , j => 'MARK --set-mark ' . in_hex( $zoneref->{mark} ) . '/' . in_hex( $globals{ZONE_MASK} ) ) if $zoneref->{mark};

    if ( have_ipsec ) {
	#
	# In general, policy match can only match an 'in' or an 'out' policy (but not both), so we place the
	# '--pol ipsec --dir in' rules at the front of the (interface) forwarding chains. Otherwise, decrypted packets
	# can match '--pol none --dir out' rules and send the packets down the wrong rules chain.
	#
	my $type       = $zoneref->{type};
	my $source_ref = ( $zoneref->{hosts}{ipsec} ) || {};

	for my $interface ( sort { interface_number( $a ) <=> interface_number( $b ) } keys %$source_ref ) {
	    my $sourcechainref = $filter_table->{forward_chain $interface};
	    my @interfacematch;
	    my $interfaceref = find_interface $interface;

	    next if $interfaceref->{options}{destonly};

	    if ( use_forward_chain( $interface, $sourcechainref ) ) {
		#
		# Use the interface forward chain
		#
		if ( $interfaceref->{ports} && $interfaceref->{options}{bridge} ) {
		    #
		    # This is a bridge with ports
		    #
		    @interfacematch = imatch_source_dev $interface;
		    #
		    # Copy the rules from the interface forward chain to the zone forward chain unless they have already been copied
		    #
		    copy_rules( $sourcechainref, $frwd_ref, 1 ) unless $ipsec_jump_added{$zone}++;
		    #
		    # Jump directly from FORWARD to the zone forward chain
		    #
		    $sourcechainref = $filter_table->{FORWARD};
		} elsif ( $interfaceref->{options}{port} ) {
		    #
		    # The forwarding chain for a bridge with ports is always used -- use physdev match for this interface
		    #
		    add_ijump( $filter_table->{ forward_chain $interfaceref->{bridge} } ,
			       j => $sourcechainref ,
			       imatch_source_dev( $interface , 1 ) )
			unless $forward_jump_added{$interface}++;
		} else {
		    #
		    # Add jump from FORWARD to the intrface forward chain
		    #
		    add_ijump $filter_table->{FORWARD} , j => $sourcechainref, imatch_source_dev( $interface ) unless $forward_jump_added{$interface}++;
		}
	    } else {
		if ( $interfaceref->{options}{port} ) {
		    #
		    # The forwarding chain for a bridge with ports is always used -- use physdev match
		    #
		    $sourcechainref = $filter_table->{ forward_chain $interfaceref->{bridge} };
		    @interfacematch = imatch_source_dev $interface, 1;
		} else {
		    $sourcechainref = $filter_table->{FORWARD};
		    @interfacematch = imatch_source_dev $interface;
		}
		#
		# copy any rules from the interface forward chain to the zone forward chain
		#
		move_rules( $filter_table->{forward_chain $interface} , $frwd_ref );
	    }

	    my $arrayref = $source_ref->{$interface};
	    #
	    # Now add the jumps from the source chain (interface forward or FORWARD) to the zone forward chain
	    #
	    for my $hostref ( @{$arrayref} ) {
		my @ipsec_match = match_ipsec_in $zone , $hostref;
		for my $net ( @{$hostref->{hosts}} ) {
		    add_ijump(
			      $sourcechainref,
			      @{$zoneref->{parents}} ? 'j' : 'g' => source_exclusion( $hostref->{exclusions}, $frwd_ref ),
			      @interfacematch ,
			      imatch_source_net( $net ),
			      @ipsec_match
			     );
		}
	    }
	}
    }
}
 
#
# The passed zone is a sub-zone. We need to determine if
#
#   a) A parent zone defines DNAT/REDIRECT or notrack rules; and
#   b) The current zone has a CONTINUE policy to some other zone.
#
# If a) but not b), then we must avoid sending packets from this
# zone through the DNAT/REDIRECT or notrack chain for the parent.
# 
sub handle_nested_zone( $$ ) {
    my ( $zone, $zoneref ) = @_;
    #
    # Function returns this 3-tuple
    #
    my ( $nested, $parenthasnat, $parenthasnotrack ) = ( 1, 0, 0 );
    
    for my $parent ( @{$zoneref->{parents}} ) {
	my $ref1 = $nat_table->{dnat_chain $parent} || {};
	my $ref2 = $raw_table->{notrack_chain $parent} || {};
	$parenthasnat     = 1 if $ref1->{referenced};
	$parenthasnotrack = 1 if $ref2->{referenced};
	last if $parenthasnat && $parenthasnotrack;
    }

    if ( $parenthasnat || $parenthasnotrack ) {
	for my $zone1 ( all_zones ) {
	    if ( $filter_table->{rules_chain( ${zone}, ${zone1} )}->{policy} eq 'CONTINUE' ) {
		#
		# This zone has a continue policy to another zone. We must
		# send packets from this zone through the parent's DNAT/REDIRECT/NOTRACK chain.
		#
		$nested = 0;
		last;
	    }
	}
    } else {
	#
	# No parent has DNAT or notrack so there is nothing to worry about. Don't bother to generate needless RETURN rules in the 'dnat' or 'notrack' chain.
	#
	$nested = 0;
    }

    ( $nested, $parenthasnat, $parenthasnotrack );
}

#
# Add output jump to the passed zone:interface:hostref:net
#
sub add_output_jumps( $$$$$$$ ) {
    my ( $zone, $interface, $hostref, $net, $exclusions, $isport, $bridge, ) = @_;

    our @vservers;
    our %output_jump_added;

    my $chain1            = rules_target firewall_zone , $zone;
    my $chain1ref         = $filter_table->{$chain1};
    my $nextchain         = dest_exclusion( $exclusions, $chain1 );
    my $outputref;
    my $interfacechainref = $filter_table->{output_chain $interface};
    my @interfacematch;
    my $use_output        = 0;
    my @dest              = imatch_dest_net $net;
    my @ipsec_out_match   = match_ipsec_out $zone , $hostref;

    if ( @vservers || use_output_chain( $interface, $interfacechainref ) || ( @{$interfacechainref->{rules}} && ! $chain1ref ) ) {
	#
	# - There are vserver zones (so OUTPUT will have multiple source; or
	# - We must use the interface output chain; or
	# - There are rules in the interface chain and none in the rules chain
	#
	#   In any of these cases use the inteface output chain
	#
	$outputref = $interfacechainref;

	if ( $isport ) {
	    #
	    # It is a bridge port zone -- use the bridges output chain and match the physdev
	    #
	    add_ijump( $filter_table->{ output_chain $bridge },
		       j => $outputref ,
		       imatch_dest_dev( $interface, 1 ) )
		unless $output_jump_added{$interface}++;
	} else {
	    #
	    # Not a bridge -- match the input interface
	    #
	    add_ijump $filter_table->{OUTPUT}, j => $outputref, imatch_dest_dev( $interface ) unless $output_jump_added{$interface}++;
	}

	$use_output = 1;

	unless ( lc $net eq IPv6_LINKLOCAL ) {
	    #
	    # Generate output rules for the vservers
	    #
	    for my $vzone ( @vservers ) {
		generate_source_rules ( $outputref, $vzone, $zone, @dest );
	    }
	}
    } elsif ( $isport ) {
	#
	# It is a bridge port zone -- use the bridges output chain and match the physdev
	#
	$outputref = $filter_table->{ output_chain $bridge };
	@interfacematch = imatch_dest_dev $interface, 1;
    } else {
	#
	# Just put the jump in the OUTPUT chain
	#
	$outputref = $filter_table->{OUTPUT};
	@interfacematch = imatch_dest_dev $interface;
    }
    #
    #  Add the jump
    # 
    add_ijump $outputref , j => $nextchain, @interfacematch, @dest, @ipsec_out_match;
    #
    #  Add jump for broadcast
    #
    add_ijump( $outputref , j => $nextchain, @interfacematch, d => '255.255.255.255' , @ipsec_out_match )
	if $family == F_IPV4 && $hostref->{options}{broadcast};
    #
    # Move the rules from the interface output chain if we didn't use it
    #
    move_rules( $interfacechainref , $chain1ref ) unless $use_output;
}

#
# Add prerouting jumps from the passed zone:interface:hostref:net
#
sub add_prerouting_jumps( $$$$$$$$ ) {
    my ( $zone, $interface, $hostref, $net, $exclusions, $nested, $parenthasnat, $parenthasnotrack ) = @_;

    my $dnatref         = $nat_table->{dnat_chain( $zone )};
    my $preroutingref   = $nat_table->{PREROUTING};
    my $rawref          = $raw_table->{PREROUTING};
    my $notrackref      = ensure_chain 'raw' , notrack_chain( $zone );
    my @ipsec_in_match  = match_ipsec_in  $zone , $hostref;

    my @source = imatch_source_net $net;

    if ( $dnatref->{referenced} ) {
	#
	# There are DNAT/REDIRECT rules with this zone as the source.
	# Add a jump from this source network to this zone's DNAT/REDIRECT chain
	#
	add_ijump( $preroutingref,
		   j => source_exclusion( $exclusions, $dnatref),
		   imatch_source_dev( $interface),
		   @source,
		   @ipsec_in_match );

	check_optimization( $dnatref ) if @source;
    }

    if ( $notrackref->{referenced} ) {
	#
	# There are notrack rules with this zone as the source.
	# Add a jump from this source network to this zone's notrack chain
	#
	insert_ijump $rawref, j => source_exclusion( $exclusions, $notrackref), $rawref->{insert}++, imatch_source_dev( $interface), @source, @ipsec_in_match;
    }
    #
    # If this zone has parents with DNAT/REDIRECT or notrack rules and there are no CONTINUE polcies with this zone as the source
    # then add a RETURN jump for this source network.
    #
    if ( $nested ) {
	if ( $parenthasnat ) {
	    add_ijump $preroutingref, j => 'RETURN',                      imatch_source_dev( $interface), @source, @ipsec_in_match;
	}
	if ( $parenthasnotrack ) {
	    my $rawref = $raw_table->{PREROUTING};
	    insert_ijump $rawref,     j => 'RETURN', $rawref->{insert}++, imatch_source_dev( $interface), @source, @ipsec_in_match;
	}
    }
}

#
# Add input jump from the passed zone:interface:hostref:net
#
sub add_input_jumps( $$$$$$$$ ) {
    my ( $zone, $interface, $hostref, $net, $exclusions, $frwd_ref, $isport, $bridge ) = @_;

    our @vservers;
    our %input_jump_added;

    my $chain2            = rules_target $zone, firewall_zone;
    my $chain2ref         = $filter_table->{$chain2};
    my $inputchainref;
    my $interfacechainref = $filter_table->{input_chain $interface};
    my @interfacematch;
    my $use_input;
    my @source            = imatch_source_net $net;
    my @ipsec_in_match    = match_ipsec_in  $zone , $hostref;

    if ( @vservers || use_input_chain( $interface, $interfacechainref ) || ! $chain2 || ( @{$interfacechainref->{rules}} && ! $chain2ref ) ) {
	#
	# - There are vserver zones (so INPUT will have multiple destinations; or
	# - We must use the interface input chain; or
	# - The zone->firewall policy is CONTINUE; or
	# - There are rules in the interface chain and none in the rules chain
	#
	#   In any of these cases use the inteface input chain
	#
	$inputchainref = $interfacechainref;

	if ( $isport ) {
	    #
	    # It is a bridge port zone -- use the bridges input chain and match the physdev
	    #
	    add_ijump( $filter_table->{ input_chain $bridge },
		       j => $inputchainref ,
		       imatch_source_dev($interface, 1) )
		unless $input_jump_added{$interface}++;
	} else {
	    #
	    # Not a bridge -- match the input interface
	    #
	    add_ijump $filter_table->{INPUT}, j => $inputchainref, imatch_source_dev($interface) unless $input_jump_added{$interface}++;
	}

	$use_input = 1;

	unless ( lc $net eq IPv6_LINKLOCAL ) {
	    #
	    # Generate input rules for the vservers
	    #
	    for my $vzone ( @vservers ) {
		my $target = rules_target( $zone, $vzone );
		generate_dest_rules( $inputchainref, $target, $vzone, @source, @ipsec_in_match ) if $target;
	    }
	}
    } elsif ( $isport ) {
	#
	# It is a bridge port zone -- use the bridges input chain and match the physdev
	#
	$inputchainref = $filter_table->{ input_chain $bridge };
	@interfacematch = imatch_source_dev $interface, 1;
    } else {
	#
	# Just put the jump in the INPUT chain
	#
	$inputchainref = $filter_table->{INPUT};
	@interfacematch = imatch_source_dev $interface;
    }

    if ( $chain2 ) {
	#
	# Add the jump from the input chain to the rules chain
	#
	add_ijump $inputchainref, j => source_exclusion( $exclusions, $chain2 ), @interfacematch, @source, @ipsec_in_match;
	move_rules( $interfacechainref , $chain2ref ) unless $use_input;
    }
}

#
# This function is called when there is forwarding and this net isn't IPSEC protected. It adds the jump for this net to the zone forwarding chain.
#
sub add_forward_jump( $$$$$$$$ ) {
    my ( $zone, $interface, $hostref, $net, $exclusions, $frwd_ref, $isport, $bridge ) = @_;

    our %forward_jump_added;

    my @source            = imatch_source_net $net;
    my @ipsec_in_match    = match_ipsec_in  $zone , $hostref;

    my $ref = source_exclusion( $exclusions, $frwd_ref );
    my $forwardref = $filter_table->{forward_chain $interface};

    if ( use_forward_chain $interface, $forwardref ) {
	#
	# We must use the interface forwarding chain -- add the jump from the interface forward chain to the zone forward chain.
	#
	add_ijump $forwardref , j => $ref, @source, @ipsec_in_match;

	if ( $isport ) {
	    #
	    # It is a bridge port zone -- use the bridges input chain and match the physdev
	    #
	    add_ijump( $filter_table->{ forward_chain $bridge } ,
		       j => $forwardref ,
		       imatch_source_dev( $interface , 1 ) )
		unless $forward_jump_added{$interface}++;
	} else {
	    #
	    # Not a bridge -- match the input interface
	    #
	    add_ijump $filter_table->{FORWARD} , j => $forwardref, imatch_source_dev( $interface ) unless $forward_jump_added{$interface}++;
	}
    } else {
	if ( $isport ) {
	    #
	    # It is a bridge port zone -- use the bridges input chain and match the physdev
	    #
	    add_ijump( $filter_table->{ forward_chain $bridge } ,
		       j => $ref ,
		       imatch_source_dev( $interface, 1 ) ,
		       @source,
		       @ipsec_in_match );
	} else {
	    #
	    # Not a bridge -- match the input interface
	    #
	    add_ijump $filter_table->{FORWARD} , j => $ref, imatch_source_dev( $interface ) , @source, @ipsec_in_match;
	}

	move_rules ( $forwardref , $frwd_ref );
    }
}

#
# Generate the list of destination zones from the passed source zone when optimization level 1 is selected
#
# - Drop zones where the policy to that zone is 'NONE'
# - Drop this zone if it has only one interface without 'routeback'
# - Drop BPORT zones that are not on the same bridge
# - Eliminate duplicate zones that have the same '2all' (-all) rules chain.
#
sub optimize1_zones( $$@ ) {
    my $zone    = shift;
    my $zoneref = shift;
    my $last_chain = '';
    my @dest_zones;
    my @temp_zones;

    for my $zone1 ( @_ )  {
	my $zone1ref = find_zone( $zone1 );
	my $policy = $filter_table->{rules_chain( ${zone}, ${zone1} )}->{policy};
	
	next if $policy eq 'NONE';

	my $chain = rules_target $zone, $zone1;

	next unless $chain;

	if ( $zone eq $zone1 ) {
	    next if ( scalar ( keys( %{ $zoneref->{interfaces}} ) ) < 2 ) && ! $zoneref->{options}{in_out}{routeback};
	}

	if ( $zone1ref->{type} & BPORT ) {
	    next unless $zoneref->{bridge} eq $zone1ref->{bridge};
	}

	if ( $chain =~ /(2all|-all)$/ ) {
	    if ( $chain ne $last_chain ) {
		$last_chain = $chain;
		push @dest_zones, @temp_zones;
		@temp_zones = ( $zone1 );
	    } elsif ( $policy eq 'ACCEPT' ) {
		push @temp_zones , $zone1;
	    } else {
		$last_chain = $chain;
		@temp_zones = ( $zone1 );
	    }
	} else {
	    push @dest_zones, @temp_zones, $zone1;
	    @temp_zones = ();
	    $last_chain = '';
	}
    }

    if ( $last_chain && @temp_zones == 1 ) {
	push @dest_zones, @temp_zones;
	$last_chain = '';
    }

    ( $last_chain, @dest_zones );
}

# Generate the rules matrix.
#
# Stealing a comment from the Burroughs B6700 MCP Operating System source, "generate_matrix makes a sow's ear out of a silk purse".
#
# The biggest disadvantage of the zone-policy-rule model used by Shorewall is that it doesn't scale well as the number of zones increases (Order N**2 where N = number of zones).
# A major goal of the rewrite of the compiler in Perl was to restrict those scaling effects to this function and the rules that it generates.
#
# The function traverses the full "source-zone by destination-zone" matrix and generates the rules necessary to direct traffic through the right set of filter-table, raw-table and
# nat-table rules.
#
sub generate_matrix() {
    my @interfaces = ( all_interfaces );
    #
    # Should this be the real PREROUTING chain?
    #
    my @zones     = off_firewall_zones;
    our @vservers = vserver_zones;

    my $interface_jumps_added = 0;

    our %input_jump_added   = ();
    our %output_jump_added  = ();
    our %forward_jump_added = ();
    our %ipsec_jump_added   = ();

    progress_message2 'Generating Rule Matrix...';
    progress_message  '  Handling complex zones...';
    #
    # Special processing for configurations with more than 2 off-firewall zones or with other special considerations like IPSEC.
    # Don't be tempted to move this logic into the zone loop below -- it won't work.
    #
    for my $zone ( @zones ) {
	my $zoneref = find_zone( $zone );
	if ( @zones > 2 || $zoneref->{complex} ) {
	    handle_complex_zone( $zone, $zoneref );
	} else {
	    new_standard_chain zone_forward_chain( $zone ) if @zones > 1;
	}
    }
    #
    # Main source-zone matrix-generation loop
    #
    progress_message '  Entering main matrix-generation loop...';

    for my $zone ( @zones ) {
	my $zoneref          = find_zone( $zone );
	my $source_hosts_ref = $zoneref->{hosts};
	my $frwd_ref         = $filter_table->{zone_forward_chain $zone};
	my $nested           = @{$zoneref->{parents}};
	my $parenthasnat     = 0;
	my $parenthasnotrack = 0;
	#
	# Create the zone's dnat chain
	#
	ensure_chain 'nat', dnat_chain( $zone );

	( $nested, $parenthasnat, $parenthasnotrack) = handle_nested_zone( $zone, $zoneref ) if $nested;
	#
	# Take care of PREROUTING, INPUT and OUTPUT jumps
	#
	for my $typeref ( values %$source_hosts_ref ) {
	    for my $interface ( sort { interface_number( $a ) <=> interface_number( $b ) } keys %$typeref ) {
		if ( get_physical( $interface ) eq '+' ) {
		    #
		    # Insert the interface-specific jumps before this one which is not interface-specific
		    #
		    add_interface_jumps(@interfaces) unless $interface_jumps_added++;
		}

		my $interfaceref  = find_interface $interface;
		my $isport        = $interfaceref->{options}{port};
		my $bridge        = $interfaceref->{bridge};

		for my $hostref ( @{$typeref->{$interface}} ) {
		    my $exclusions = $hostref->{exclusions};

		    for my $net ( @{$hostref->{hosts}} ) {
			#
			# OUTPUT
			#
			if ( rules_target( firewall_zone, $zone ) && ! ( zone_type( $zone) & BPORT ) ) {
			    #
			    # Policy from the firewall to this zone is not 'CONTINUE' and this isn't a bport zone
			    #
			    add_output_jumps( $zone, $interface, $hostref, $net, $exclusions, $isport, $bridge );
			}

			clearrule;

			unless( $hostref->{options}{destonly} ) {
			    #
			    # PREROUTING
			    #
			    add_prerouting_jumps( $zone, $interface, $hostref, $net, $exclusions, $nested, $parenthasnat, $parenthasnotrack );
			    #
			    # INPUT
			    #
			    add_input_jumps( $zone, $interface, $hostref, $net, $exclusions, $frwd_ref, $isport, $bridge );
			    #
			    # FORWARDING Jump for non-IPSEC host group
			    #
			    add_forward_jump( $zone, $interface, $hostref, $net, $exclusions, $frwd_ref, $isport, $bridge ) if $frwd_ref && $hostref->{ipsec} ne 'ipsec' && $zoneref->{type} ne LOCAL;
			}
		    } # Subnet Loop
		} # Hostref Loop
	    } # Interface Loop
	} #Type Loop

	next if $zoneref->{type} == LOCAL;

	if ( $frwd_ref ) {
	    #
	    #                                            F O R W A R D I N G
	    #
	    my @dest_zones;
	    my $last_chain = '';

	    if ( $config{OPTIMIZE} & 1 ) {
		( $last_chain , @dest_zones ) = optimize1_zones($zone, $zoneref, @zones );
	    } else {
		@dest_zones =  @zones ;
	    }
	    #
	    # We now loop through the destination zones creating jumps to the rules chain for each source/dest combination.
	    # @dest_zones is the list of destination zones that we need to handle from this source zone
	    #
	    for my $zone1 ( @dest_zones ) {
		my $zone1ref = find_zone( $zone1 );

		next if $filter_table->{rules_chain( ${zone}, ${zone1} )}->{policy}  eq 'NONE';

		next if $zone1ref->{type} == LOCAL;

		my $chain = rules_target $zone, $zone1;

		next unless $chain; # CONTINUE policy with no rules

		my $num_ifaces = 0;

		if ( $zone eq $zone1 ) {
		    next if ( $num_ifaces = scalar( keys ( %{$zoneref->{interfaces}} ) ) ) < 2 && ! $zoneref->{options}{in_out}{routeback};
		}

		if ( $zone1ref->{type} & BPORT ) {
		    next unless $zoneref->{bridge} eq $zone1ref->{bridge};
		}

		my $chainref = $filter_table->{$chain}; #Will be null if $chain is a Netfilter Built-in target like ACCEPT
		
		for my $typeref ( values %{$zone1ref->{hosts}} ) {
		    for my $interface ( sort { interface_number( $a ) <=> interface_number( $b ) } keys %$typeref ) {
			for my $hostref ( @{$typeref->{$interface}} ) {
			    next if $hostref->{options}{sourceonly};
			    if ( $zone ne $zone1 || $num_ifaces > 1 || $hostref->{options}{routeback} ) {
				my @ipsec_out_match = match_ipsec_out $zone1 , $hostref;
				my $dest_exclusion = dest_exclusion( $hostref->{exclusions}, $chain);
				for my $net ( @{$hostref->{hosts}} ) {
				    add_ijump $frwd_ref, j => $dest_exclusion, imatch_dest_dev( $interface) , imatch_dest_net($net), @ipsec_out_match;
				}
			    }
			}
		    }
		}
	    }
	    #
	    #                                      E N D   F O R W A R D I N G
	    #
	    # Now add an unconditional jump to the last unique policy-only chain determined above, if any
	    #
	    add_ijump $frwd_ref , g => $last_chain if $frwd_ref && $last_chain;
	} # Forwarding required
    } # Source Zone Loop

    progress_message '  Finishing matrix...';
    #
    # Make sure that the 1:1 NAT jumps are last in PREROUTING
    #
    addnatjump 'PREROUTING'  , 'nat_in';
    addnatjump 'POSTROUTING' , 'nat_out';

    add_interface_jumps @interfaces unless $interface_jumps_added;

    my %builtins = ( mangle => [ qw/PREROUTING INPUT FORWARD POSTROUTING/ ] ,
		     nat=>     [ qw/PREROUTING OUTPUT POSTROUTING/ ] ,
		     filter=>  [ qw/INPUT FORWARD OUTPUT/ ] );

    unless ( $config{COMPLETE} ) {
	complete_standard_chain $filter_table->{INPUT}   , 'all' , firewall_zone , 'DROP';
	complete_standard_chain $filter_table->{OUTPUT}  , firewall_zone , 'all', 'REJECT';
	complete_standard_chain $filter_table->{FORWARD} , 'all' , 'all', 'REJECT';
    }

    if ( $config{LOGALLNEW} ) {
	for my $table ( qw/mangle nat filter/ ) {
	    for my $chain ( @{$builtins{$table}} ) {
		log_rule_limit
		    $config{LOGALLNEW} ,
		    $chain_table{$table}{$chain} ,
		    $table ,
		    $chain ,
		    '' ,
		    '' ,
		    'insert' ,
		    "$globals{STATEMATCH} NEW ";
	    }
	}
    }
}

sub setup_mss( ) {
    my $clampmss = $config{CLAMPMSS};
    my $option;
    my @match;
    my $chainref = $filter_table->{FORWARD};

    if ( $clampmss ) {
	if ( "\L$clampmss" eq 'yes' ) {
	    $option = '--clamp-mss-to-pmtu';
	} else {
	    @match  = ( tcpmss => "--mss $clampmss:" ) if have_capability( 'TCPMSS_MATCH' );
	    $option = "--set-mss $clampmss";
	}

	push @match, ( policy => '--pol none --dir out' ) if have_ipsec;
    }

    my $interfaces = find_interfaces_by_option( 'mss' );

    if ( @$interfaces ) {
	#
	# Since we will need multiple rules, we create a separate chain
	#
	$chainref = new_chain 'filter', 'settcpmss';
	#
	# Send all forwarded SYN packets to the 'settcpmss' chain
	#
	add_ijump $filter_table->{FORWARD} , j => $chainref, p => 'tcp --tcp-flags SYN,RST SYN';

	my @in_match  = ();
	my @out_match = ();

	if ( have_ipsec ) {
	    @in_match  = ( policy => '--pol none --dir in' );
	    @out_match = ( policy => '--pol none --dir out' );
	}

	for ( @$interfaces ) {
	    my $mss      = get_interface_option( $_, 'mss' );
	    my @mssmatch = have_capability( 'TCPMSS_MATCH' ) ? ( tcpmss => "--mss $mss:" ) : ();
	    my @source   = imatch_source_dev $_;
	    my @dest     = imatch_dest_dev $_;
	    add_ijump $chainref, j => 'TCPMSS', targetopts => "--set-mss $mss", @dest,   p => 'tcp --tcp-flags SYN,RST SYN', @mssmatch, @out_match;
	    add_ijump $chainref, j => 'RETURN', @dest if $clampmss;
	    add_ijump $chainref, j => 'TCPMSS', targetopts => "--set-mss $mss", @source, p => 'tcp --tcp-flags SYN,RST SYN', @mssmatch, @in_match;
	    add_ijump $chainref, j => 'RETURN', @source if $clampmss;
	}
    }

    add_ijump $chainref , j => 'TCPMSS', targetopts => $option, p => 'tcp --tcp-flags SYN,RST SYN', @match if $clampmss;
}

#
# Compile the stop_firewall() function
#
sub compile_stop_firewall( $$$ ) {
    my ( $test, $export, $have_arptables ) = @_;

    my $input   = $filter_table->{INPUT};
    my $output  = $filter_table->{OUTPUT};
    my $forward = $filter_table->{FORWARD};

    emit <<'EOF';
#
# Stop/restore the firewall after an error or because of a 'stop' or 'clear' command
#
stop_firewall() {
    local hack
EOF

    $output->{policy} = 'ACCEPT' if $config{ADMINISABSENTMINDED};

    if ( $family == F_IPV4 ) {
	emit <<'EOF';
    deletechain() {
        qt $IPTABLES -L $1 -n && qt $IPTABLES -F $1 && qt $IPTABLES -X $1
    }

    case $COMMAND in
        stop|clear|restore)
            if chain_exists dynamic; then
                ${IPTABLES}-save -t filter | grep '^-A dynamic' > ${VARDIR}/.dynamic
            fi
            ;;
        *)
            set +x
EOF
    } else {
	emit <<'EOF';
    deletechain() {
        qt $IPTABLES -L $1 -n && qt $IPTABLES -F $1 && qt $IPTABLES -X $1
    }

    case $COMMAND in
        stop|clear|restore)
            if chain_exists dynamic; then
                ${IP6TABLES}-save -t filter | grep '^-A dynamic' > ${VARDIR}/.dynamic
            fi
            ;;
        *)
            set +x
EOF
    }

    emit <<'EOF';
            case $COMMAND in
	        start)
	            logger -p kern.err "ERROR:$g_product start failed"
	            ;;
	        restart)
	            logger -p kern.err "ERROR:$g_product restart failed"
	            ;;
	        refresh)
	            logger -p kern.err "ERROR:$g_product refresh failed"
	            ;;
                enable)
                    logger -p kern.err "ERROR:$g_product 'enable $g_interface' failed"
                    ;;
            esac

            if [ "$RESTOREFILE" = NONE ]; then
                COMMAND=clear
                clear_firewall
                echo "$g_product Cleared"

	        kill $$
	        exit 2
            else
	        g_restorepath=${VARDIR}/$RESTOREFILE

	        if [ -x $g_restorepath ]; then
		    echo Restoring ${g_product:=Shorewall}...

                    g_recovering=Yes

		    if run_it $g_restorepath restore; then
		        echo "$g_product restored from $g_restorepath"
		        set_state "Restored from $g_restorepath"
		    else
		        set_state "Unknown"
		    fi

	            kill $$
	            exit 2
	        fi
            fi
	    ;;
    esac

    if [ -n "$g_stopping" ]; then
        kill $$
        exit 1
    fi

    set_state "Stopping"

    g_stopping="Yes"

    deletechain shorewall

    run_stop_exit

    #
    # Enable automatic helper association on kernel 3.5.0 and later
    #
    if [ $COMMAND = clear -a -f /proc/sys/net/netfilter/nf_conntrack_helper ]; then
        echo 1 > /proc/sys/net/netfilter/nf_conntrack_helper
    fi

EOF

    if ( have_capability( 'NAT_ENABLED' ) ) {
	emit<<'EOF';
    if [ -f ${VARDIR}/nat ]; then
        while read external interface; do
      	    del_ip_addr $external $interface
	done < ${VARDIR}/nat

	rm -f ${VARDIR}/nat
    fi
EOF
    }

    if ( $family == F_IPV4 ) {
	emit <<'EOF';
    if [ -f ${VARDIR}/proxyarp ]; then
	while read address interface external haveroute; do
	    qtnoin $IP -4 neigh del proxy $address dev $external
	    [ -z "${haveroute}${g_noroutes}" ] && qtnoin $IP -4 route del $address/32 dev $interface
	    f=/proc/sys/net/ipv4/conf/$interface/proxy_arp
	    [ -f $f ] && echo 0 > $f
	done < ${VARDIR}/proxyarp

        rm -f ${VARDIR}/proxyarp
    fi

EOF
    } else {
	emit <<'EOF';
    if [ -f ${VARDIR}/proxyndp ]; then
	while read address interface external haveroute; do
	    qtnoin $IP -6 neigh del proxy $address dev $external
	    [ -z "${haveroute}${g_noroutes}" ] && qtnoin $IP -6 route del $address/128 dev $interface
	    f=/proc/sys/net/ipv4/conf/$interface/proxy_ndp
	    [ -f $f ] && echo 0 > $f
	done < ${VARDIR}/proxyndp

        rm -f ${VARDIR}/proxyndp
    fi

EOF
    }

    push_indent;

    emit 'delete_tc1' if $config{CLEAR_TC};

    emit( 'undo_routing',
	  "restore_default_route $config{USE_DEFAULT_RT}"
	  );

    my @chains = $config{ADMINISABSENTMINDED} ? qw/INPUT FORWARD/ : qw/INPUT OUTPUT FORWARD/;

    add_ijump $filter_table ->{$_}, j => 'ACCEPT', state_imatch 'ESTABLISHED,RELATED' for @chains;

    if ( $family == F_IPV6 ) {
	add_ijump $input, j => 'ACCEPT', s => IPv6_LINKLOCAL;
	add_ijump $input, j => 'ACCEPT', d => IPv6_LINKLOCAL;
	add_ijump $input, j => 'ACCEPT', d => IPv6_MULTICAST;

	unless ( $config{ADMINISABSENTMINDED} ) {
	    add_ijump $output, j => 'ACCEPT', d => IPv6_LINKLOCAL;
	    add_ijump $output, j => 'ACCEPT', d => IPv6_MULTICAST;
	}
    }

    process_routestopped unless process_stoppedrules;

    add_ijump $input,  j => 'ACCEPT', i => 'lo';
    add_ijump $output, j => 'ACCEPT', o => 'lo' unless $config{ADMINISABSENTMINDED};

    my $interfaces = find_interfaces_by_option 'dhcp';

    if ( @$interfaces ) {
	my $ports = $family == F_IPV4 ? '67:68' : '546:547';

	for my $interface ( @$interfaces ) {
	    add_ijump $input,  j => 'ACCEPT', p => "udp --dport $ports", imatch_source_dev( $interface );
	    add_ijump $output, j => 'ACCEPT', p => "udp --dport $ports", imatch_dest_dev( $interface ) unless $config{ADMINISABSENTMINDED};
	    #
	    # This might be a bridge
	    #
	    add_ijump $forward, j => 'ACCEPT', p => "udp --dport $ports", imatch_source_dev( $interface ), imatch_dest_dev( $interface );
	}
    }

    emit '';

    create_stop_load $test;

    if ( $family == F_IPV4 ) {
	emit( '$ARPTABLES -F',
	      '' ) if $have_arptables; 
	if ( $config{IP_FORWARDING} eq 'on' ) {
	    emit( 'echo 1 > /proc/sys/net/ipv4/ip_forward',
		  'progress_message2 IPv4 Forwarding Enabled' );
	} elsif ( $config{IP_FORWARDING} eq 'off' ) {
	    emit( 'echo 0 > /proc/sys/net/ipv4/ip_forward',
		  'progress_message2 IPv4 Forwarding Disabled!'
		);
	}
    } else {
	for my $interface ( all_bridges ) {
	    emit "do_iptables -A FORWARD -p 58 " . match_source_dev( $interface ) . match_dest_dev( $interface ) . "-j ACCEPT";
	}

	if ( $config{IP_FORWARDING} eq 'on' ) {
	    emit( 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding',
		  'progress_message2 IPv6 Forwarding Enabled' );
	} elsif ( $config{IP_FORWARDING} eq 'off' ) {
	    emit( 'echo 0 > /proc/sys/net/ipv6/conf/all/forwarding',
		  'progress_message2 IPv6 Forwarding Disabled!'
		);
	}
    }

    pop_indent;

    emit '
    run_stopped_exit';

    my @ipsets = all_ipsets;

    if ( @ipsets || ( $config{SAVE_IPSETS} && have_ipset_rules ) ) {
	emit <<'EOF';

    case $IPSET in
        */*)
            if [ ! -x "$IPSET" ]; then
                error_message "ERROR: IPSET=$IPSET does not exist or is not executable - ipsets are not saved"
                IPSET=
            fi
	    ;;
	*)
	    IPSET="$(mywhich $IPSET)"
	    [ -n "$IPSET" ] || error_message "ERROR: The ipset utility cannot be located - ipsets are not saved"
	    ;;
    esac

    if [ -n "$IPSET" ]; then
        if [ -f /etc/debian_version ] && [ $(cat /etc/debian_version) = 5.0.3 ]; then
            #
            # The 'grep -v' is a hack for a bug in ipset's nethash implementation when xtables-addons is applied to Lenny
            #
            hack='| grep -v /31'
        else
            hack=
        fi

        if eval $IPSET -S $hack > ${VARDIR}/ipsets.tmp; then
            #
            # Don't save an 'empty' file
            #
            grep -qE '^(-N|create )' ${VARDIR}/ipsets.tmp && mv -f ${VARDIR}/ipsets.tmp ${VARDIR}/ipsets.save
        fi
    fi
EOF
    }

    emit '

    set_state "Stopped"
    logger -p kern.info "$g_product Stopped"

    case $COMMAND in
    stop|clear)
	;;
    *)
	#
	# The firewall is being stopped when we were trying to do something
	# else. Kill the shell in case we\'re running in a subshell
	#
	kill $$
	;;
    esac
}
';

}

1;
