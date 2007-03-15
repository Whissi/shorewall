#
# Shorewall 3.9 -- /usr/share/shorewall/Shorewall/Tc.pm
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
#
package Shorewall::Tc;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Chains;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( process_tcrules setup_traffic_shaping );
our @EXPORT_OK = qw( process_tc_rule );
our @VERSION = 1.00;

my %tcs = ( t => { chain  => 'tcpost',
		   connmark => 0,
		   fw       => 1
		   } ,
	    ct => { chain  => 'tcpost' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 1 			
		    } ,
	    c  => { target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 1 
		    } ,
	    p  => { chain    => 'tcpre' ,
		    connmark => 0 ,
		    fw       => 0
		    } ,
	    cp => { chain    => 'tcpre' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0
		    } ,
	    f =>  { chain    => 'tcfor' ,
		    connmark => 0 ,
		    fw       => 0
		    } ,
	    cf => { chain    => 'tcfor' ,
		    fw       => 0 ,
		    connmark => 1 ,
		    } ,
	    t  => { chain    => 'tcpost' ,
		    connmark => 0 ,
		    fw       => 0
		    } ,
	    ct => { chain    => 'tcpost' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0
		    } ,
	    c  => { target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0
		    }
	    );

use constant { NOMARK    => 0 ,
	       SMALLMARK => 1 ,
	       HIGHMARK  => 2 
	       };
	       
my @tccmd = ( { pattern   => 'SAVE' ,
		target    => 'CONNMARK --save-mark --mask' ,
		mark      => SMALLMARK ,
		mask      => '0xFF'
		} ,
	      { pattern   => 'RESTORE' ,
		target => 'CONNMARK --restore-mark --mask' ,
		mark      => SMALLMARK ,
		mask      => '0xFF'
		} ,
	      { pattern   => 'CONTINUE',
		target    => 'RETURN' ,
		mark      => NOMARK ,
		mask      => '' 
		} ,
	      { pattern   => '\|.*' ,
		target    => 'MARK --or-mark' ,
		mark      => HIGHMARK ,
		mask      => '' } ,
	      { pattern   => '&.*' ,
		target    => 'MARK --and-mark ' ,
		mark      => HIGHMARK ,
		mask      => '' 
		}
	      );

sub process_tc_rule( $$$$$$$$$$ ) {
    my ( $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $extra ) = @_;

    my $original_mark = $mark;

    ( $mark, my $designator ) = split /:/, $mark;

    my $chain  = $env{MARKING_CHAIN};
    my $target = 'MARK --set-mark';
    my $tcsref;
    my $connmark = 0;
    my $classid  = 0;

    if ( $source ) {
	if ( $source eq $firewall_zone ) {
	    $chain = 'tcout';
	    $source = '';
	} else {
	    $chain = 'tcout' if $source =~ s/^($firewall_zone)://;
	}
    }

    if ( $designator ) {
	$tcsref = $tcs{$designator};
	
	if ( $tcsref ) {
	    if ( $chain eq 'tcout' ) {
		fatal_error "Invalid chain designator for source $firewall_zone; rule \"$line\"" unless $tcsref->{fw};
	    }

	    $chain    = $tcsref->{chain}  if $tcsref->{chain};
	    $target   = $tcsref->{target} if $tcsref->{target};
	    $mark     = "$mark/0xFF"      if $connmark = $tcsref->{connmark};
	    
	} else {
	    fatal_error "Invalid MARK ($original_mark) in rule \"$line\"" unless $mark =~ /^([0-9]+|0x[0-9a-f]+)$/ and $designator =~ /^([0-9]+|0x[0-9a-f]+)$/;
	    $chain   = 'tcpost';
	    $classid = 1;
	    $mark    = $original_mark;
	    $target  = 'CLASSIFY --set-class';
	}
    }

    my $mask = 0xffff;

    my ($cmd, $rest) = split '/', $mark;

    unless ( $classid )
	{
	  MARK:
	    {
	  PATTERN:
		for my $tccmd ( @tccmd ) {
		    if ( $cmd =~ /^($tccmd->{pattern})$/ ) {
			fatal_error "$mark not valid with :C[FP]" if $connmark;
			
			$target      = "$tccmd->{target} ";
			my $marktype = $tccmd->{mark};
			
			$mark   =~ s/^[!&]//;
			
			if ( $rest ) {
			    fatal_error "Invalid MARK ($original_mark)" if $marktype == NOMARK;

			    $mark = $rest if $tccmd->{mask};

			    if ( $marktype == SMALLMARK ) {
				verify_small_mark $mark;
			    } else {
				validate_mark $mark;
			    }
			} elsif ( $tccmd->{mask} ) {
			    $mark = $tccmd->{mask};
			}
			
			last MARK;
		    }
		}
	    }
	    
	    validate_mark $mark;

	    fatal_error 'Marks < 256 may not be set in the PREROUTING chain when HIGH_ROUTE_MARKS=Yes' 
		if $cmd || $chain eq 'tcpre' || numeric_value( $cmd ) <= 0xFF || $config{HIGH_ROUTE_MARKS};
	}

    expand_rule 
	ensure_chain( 'mangle' , $chain ) ,
	do_proto( $proto, $ports, $sports) . do_test( $testval, $mask ) ,
	$source ,
	$dest ,
	'' ,
	"-j $target $mark" ,
	'' ,
	'' ,
	'';
    
    progress_message "   TC Rule \"$line\" $done";
    
}
	
#
# Process the tcrules file
#
sub process_tcrules() {
    
    open TC, "$ENV{TMP_DIR}/tcrules" or fatal_error "Unable to open stripped tcrules file: $!";

    while ( $line = <TC> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $extra ) = split /\s+/, $line;

	if ( $mark eq 'COMMENT' ) {
	    if ( $capabilities{COMMENTS} ) {
		( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		$comment =~ s/\s*$//;
	    } else {
		warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
	    }
	} else {
	    fatal_error "Invalid tcrule: \"$line\"" if $extra;
	    process_tc_rule $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos
	}
	
    }

    close TC;

    $comment = '';
}

sub setup_traffic_shaping() {
    1;
}

1;
