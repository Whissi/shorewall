#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Raw.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2009,2010,2011,2012,2013 - Tom Eastep (teastep@shorewall.net)
#
#       Complete documentation is available at http://shorewall.net
#
#       This program is part of Shorewall.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by the
#       Free Software Foundation, either version 2 of the license or, at your
#       option, any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, see <http://www.gnu.org/licenses/>.
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

our %valid_ctevent = ( new        => 1,
		       related    => 1,
		       destroy    => 1,
		       reply      => 1,
		       assured    => 1,
		       protoinfo  => 1,
		       helper     => 1,
		       mark       => 1,
		       natseqinfo => 1,
		       secmark    => 1 );

our $family;

sub initialize($) {
    $family = shift;
}

#
# Notrack
#
sub process_conntrack_rule( $$$$$$$$$$ ) {

    my ($chainref, $zoneref, $action, $source, $dest, $proto, $ports, $sports, $user, $switch ) = @_;

    require_capability 'RAW_TABLE', 'conntrack rules', '';

    $proto  = ''    if $proto  eq 'any';
    $ports  = ''    if $ports  eq 'any' || $ports  eq 'all';
    $sports = ''    if $sports eq 'any' || $sports eq 'all';

    my $zone;
    my $restriction = PREROUTE_RESTRICT;

    if ( $chainref ) {
	$restriction = OUTPUT_RESTRICT if $chainref->{name} eq 'OUTPUT';
    } else {
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
	$restriction = OUTPUT_RESTRICT if $zoneref->{type}  & (FIREWALL | VSERVER );
	fatal_error 'USER/GROUP is not allowed unless the SOURCE zone is $FW or a Vserver zone' if $user ne '-' && $restriction != OUTPUT_RESTRICT;
    }

    my $disposition = $action;
    my $exception_rule = '';
    my $rule = do_proto( $proto, $ports, $sports ) . do_user ( $user ) . do_condition( $switch , $chainref->{name} );
    my $level = '';

    if ( $action =~ /^(?:NFLOG|ULOG)/ ) {
	$action = join( ":" , 'LOG', $action );
    }

    if ( $action eq 'NOTRACK' ) {
	#
	# A patch that deimplements the NOTRACK target has been posted on the
	# Netfilter development list
	#
	if ( have_capability 'CT_TARGET' ) {
	    $action = 'CT --notrack';
	    $disposition = 'notrack';
	}
    } elsif ( $action =~ /^(DROP|LOG)(:(.+))?$/ ) {
	if ( $2 ) {
	    validate_level( $level = $3 );
	    $action      = $1;
	    $disposition = $1;
	}
    } elsif ( $action =~ /^IP(6)?TABLES\((.+)\)(:(.*))?$/ ) {
	if ( $family == F_IPV4 ) {
	    fatal_error 'Invalid conntrack ACTION (IP6TABLES)' if $1;
	} else {
	    fatal_error "Invalid conntrack ACTION (IPTABLES)" unless $1;
	}

	my ( $tgt, $options ) = split( ' ', $2 );
	my $target_type = $builtin_target{$tgt};
	fatal_error "Unknown target ($tgt)" unless $target_type;
	fatal_error "The $tgt TARGET is not allowed in the raw table" unless $target_type & RAW_TABLE;
	$disposition = $tgt;
	$action      = $2;
	validate_level( $level = $4 ) if supplied $4;
    } else {
	(  $disposition, my ( $option, $args ), $level ) = split ':', $action, 4;

	fatal_error "Invalid conntrack ACTION ( $action )" if $disposition ne 'CT';

	validate_level( $level ) if supplied $level;

	require_capability 'CT_TARGET', 'CT entries in the conntrack file', '';

	if ( $option eq 'notrack' ) {
	    fatal_error "Invalid conntrack ACTION ( $action )" if supplied $args;
	    $action = 'CT --notrack';
	    $disposition = 'notrack';
	} else {
	    fatal_error "Invalid or missing CT option and arguments" unless supplied $option && supplied $args;

	    if ( $option eq 'helper' ) {
		my $modifiers = '';

		$disposition = 'helper';

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
	    } elsif ( $option eq 'ctevents' ) {
		$disposition = 'helper';

		for ( split_list( $args, 'ctevents' ) ) {
		    fatal_error "Invalid 'ctevents' event ($_)" unless $valid_ctevent{$_};
		}

		$action = "CT --ctevents $args";
	    } elsif ( $option eq 'expevents' ) {
		fatal_error "Invalid expevent argument ($args)" unless $args eq 'new';
		$action = 'CT --expevents new';
	    } else {
		fatal_error "Invalid CT option ($option)";
	    }
	}
    }

    expand_rule( $chainref ,
		 $restriction ,
		 '',
		 $rule,
		 $source ,
		 $dest ,
		 '' ,
		 $action ,
		 $level || '' ,
		 $disposition ,
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
				$user,
				'-',
			      );
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
			 '',
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
			 '' ,
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

    fatal_error q(FORMAT must be '1', '2' or '3') unless $format =~ /^[123]$/;
    format_warning;

    $file_format = $format;
}

sub setup_conntrack($) {
    my $convert = shift;
    my $fn;

    for my $name ( qw/notrack conntrack/ ) {

	$fn = open_file( $name, 3 , 1 );

	if ( $fn ) {

	    my $action;

	    my $empty = 1;

	    first_entry( "$doing $fn..." );

	    while ( read_a_line( NORMAL_READ ) ) {
		my ( $source, $dest, $protos, $ports, $sports, $user, $switch );

		if ( $file_format == 1 ) {
		    ( $source, $dest, $protos, $ports, $sports, $user, $switch ) =
			split_line1( 'Conntrack File',
				     { source => 0, dest => 1, proto => 2, dport => 3, sport => 4, user => 5, switch => 6 } );
		    $action = 'NOTRACK';
		} else {
		    ( $action, $source, $dest, $protos, $ports, $sports, $user, $switch ) = split_line1 'Conntrack File', { action => 0, source => 1, dest => 2, proto => 3, dport => 4, sport => 5, user => 6, switch => 7 };
		}

		$empty = 0;

		for my $proto ( split_list $protos, 'Protocol' ) {
		    if ( $file_format < 3 ) {
			if ( $source =~ /^all(-)?(:(.+))?$/ ) {
			    fatal_error 'USER/GROUP is not allowed unless the SOURCE zone is $FW or a Vserver zone' if $user ne '-';
			    for my $zone ( $1 ? off_firewall_zones : all_zones ) {
				process_conntrack_rule( undef ,
							undef,
							$action,
							$zone . ( $2 || ''),
							$dest,
							$proto,
							$ports,
							$sports,
							$user ,
							$switch );
			    }
			} else {
			    process_conntrack_rule( undef, undef, $action, $source, $dest, $proto, $ports, $sports, $user, $switch );
			}
		    } elsif ( $action =~ s/:O$// ) {
			process_conntrack_rule( $raw_table->{OUTPUT}, undef, $action, $source, $dest, $proto, $ports, $sports, $user, $switch );
		    } elsif ( $action =~ s/:OP$// || $action =~ s/:PO// ) {
			process_conntrack_rule( $raw_table->{PREROUTING}, undef, $action, $source, $dest, $proto, $ports, $sports, $user, $switch );
			process_conntrack_rule( $raw_table->{OUTPUT},     undef, $action, $source, $dest, $proto, $ports, $sports, $user, $switch );
		    } else {
			$action =~ s/:P$//;
			process_conntrack_rule( $raw_table->{PREROUTING}, undef, $action, $source, $dest, $proto, $ports, $sports, $user, $switch );
		    }
		}
	    }

	    if ( $name eq 'notrack') {
		if ( $empty ) {
		    if ( unlink( $fn ) ) {
			warning_message "Empty notrack file ($fn) removed";
		    } else {
			warning_message "Unable to remove empty notrack file ($fn): $!";
		    }
		    $convert = undef;
		}
	    }
	} elsif ( $name eq 'notrack' ) {
	    $convert = undef;

	    if ( -f ( my $fn1 = find_file( $name ) ) ) {
		if ( unlink( $fn1 ) ) {
		    warning_message "Empty notrack file ($fn1) removed";
		} else {
		    warning_message "Unable to remove empty notrack file ($fn1): $!";
		}
	    }
	}
    }

    if ( $convert ) {
	my $conntrack;
	my $empty  = 1;
	my $date = localtime;

	if ( $fn ) {
	    open $conntrack, '>>', $fn or fatal_error "Unable to open $fn for notrack conversion: $!";
	} else {
	    open $conntrack, '>', $fn = find_file 'conntrack' or fatal_error "Unable to open $fn for notrack conversion: $!";

	    print $conntrack <<'EOF';
#
# Shorewall version 5 - conntrack File
#
# For information about entries in this file, type "man shorewall-conntrack"
#
##############################################################################################################
EOF
	    print $conntrack '?' . "FORMAT 3\n";
	    
	    print $conntrack <<'EOF';
#ACTION                 SOURCE          DESTINATION     PROTO   DEST            SOURCE  USER/           SWITCH
#                                                               PORT(S)         PORT(S) GROUP
EOF
	}

	print( $conntrack
	       "#\n" ,
	       "# Rules generated from notrack file $fn by Shorewall $globals{VERSION} - $date\n" ,
	       "#\n" );

	$fn = open_file( 'notrack' , 3, 1 ) || fatal_error "Unable to open the notrack file for conversion: $!";

	while ( read_a_line( PLAIN_READ ) ) {
	    #
	    # Don't copy the header comments from the old notrack file
	    #
	    next if $empty && ( $currentline =~ /^\s*#/ || $currentline =~ /^\s*$/ );

	    if ( $empty ) {
		#
		# First non-commentary line
		#
		$empty = undef;

		print $conntrack '?' . "FORMAT 1\n" unless $currentline =~ /^\s*\??FORMAT/i;
	    }

	    print $conntrack "$currentline\n";
	}

	rename $fn, "$fn.bak" or fatal_error "Unable to rename $fn to $fn.bak: $!";
	progress_message2 "notrack file $fn saved in $fn.bak"
    }
}

1;
