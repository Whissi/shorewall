#
# Shorewall-perl 4.4 -- /usr/share/shorewall-perl/Shorewall/Tc.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009 - Tom Eastep (teastep@shorewall.net)
#
#     Traffic Control is from tc4shorewall Version 0.5
#     (c) 2005 Arne Bernin <arne@ucbering.de>
#     Modified by Tom Eastep for integration into the Shorewall distribution
#     published under GPL Version 2#
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
#   This module deals with Traffic Shaping and the tcrules file.
#
package Shorewall::Tc;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::Providers;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_tc );
our @EXPORT_OK = qw( process_tc_rule initialize );
our $VERSION = '4.3_7';

our %tcs = ( T => { chain  => 'tcpost',
		    connmark => 0,
		    fw       => 1
		  } ,
	    CT => { chain  => 'tcpost' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 1
		    } ,
	    C  => { target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 1
		    } ,
	    P  => { chain    => 'tcpre' ,
		    connmark => 0 ,
		    fw       => 0
		    } ,
	    CP => { chain    => 'tcpre' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0
		    } ,
	    F =>  { chain    => 'tcfor' ,
		    connmark => 0 ,
		    fw       => 0
		    } ,
	    CF => { chain    => 'tcfor' ,
		    connmark => 1 ,
		    fw       => 0 ,
		    } ,
	    );

use constant { NOMARK    => 0 ,
	       SMALLMARK => 1 ,
	       HIGHMARK  => 2
	       };

our @tccmd = ( { match     => sub ( $ ) { $_[0] eq 'SAVE' } ,
		 target    => 'CONNMARK --save-mark --mask' ,
		 mark      => SMALLMARK ,
		 mask      => '0xFF' ,
		 connmark  => 1
	       } ,
	      { match     => sub ( $ ) { $_[0] eq 'RESTORE' },
		target    => 'CONNMARK --restore-mark --mask' ,
		mark      => SMALLMARK ,
		mask      => '0xFF' ,
		connmark  => 1
		} ,
	      { match     => sub ( $ ) { $_[0] eq 'CONTINUE' },
		target    => 'RETURN' ,
		mark      => NOMARK ,
		mask      => '' ,
		connmark  => 0
		} ,
	      { match     => sub ( $ ) { $_[0] eq 'SAME' },
		target    => 'sticky' ,
		mark      => NOMARK ,
		mask      => '' ,
		connmark  => 0
		} ,
	      { match     => sub ( $ ) { $_[0] =~ '\|.*'} ,
		target    => 'MARK --or-mark' ,
		mark      => HIGHMARK ,
		mask      => '' } ,
	      { match     => sub ( $ ) { $_[0] =~ '&.*' },
		target    => 'MARK --and-mark ' ,
		mark      => HIGHMARK ,
		mask      => '' ,
		connmark  => 0
		}
	      );

our %flow_keys = ( 'src'            => 1,
		   'dst'            => 1,
		   'proto'          => 1,
		   'proto-src'      => 1,
		   'proto-dst'      => 1,
		   'iif'            => 1,
		   'priority'       => 1,
		   'mark'           => 1,
		   'nfct'           => 1,
		   'nfct-src'       => 1,
		   'nfct-dst'       => 1,
		   'nfct-proto-src' => 1,
		   'nfct-proto-dst' => 1,
		   'rt-classid'     => 1,
		   'sk-uid'         => 1,
		   'sk-gid'         => 1,
		   'vlan-tag'       => 1 );

our %classids;

our @deferred_rules;

#
# Perl version of Arn Bernin's 'tc4shorewall'.
#
# TCDevices Table
#
# %tcdevices { <interface> -> {in_bandwidth  => <value> ,
#                              out_bandwidth => <value> ,
#                              number        => <number>,
#                              classify      => 0|1
#                              tablenumber   => <next u32 table to be allocated for this device>
#                              default       => <default class mark value>
#                              redirected    => [ <dev1>, <dev2>, ... ]
#                                               }
#
our @tcdevices;
our %tcdevices;
our @devnums;
our $devnum;
our $sticky;


#
# TCClasses Table
#
# %tcclasses { device    => <device> ,
#              mark      => <mark> ,
#              number    => <number> ,
#              rate      => <rate> ,
#              ceiling   => <ceiling> ,
#              priority  => <priority> ,
#              options   => { tos  => [ <value1> , <value2> , ... ];
#                             tcp_ack => 1 ,
#                             ...
#

our @tcclasses;
our %tcclasses;

our %restrictions = ( tcpre      => PREROUTE_RESTRICT ,
		      tcpost     => POSTROUTE_RESTRICT ,
		      tcfor      => NO_RESTRICT ,
		      tcout      => OUTPUT_RESTRICT );

our $family;

#
# Initialize globals -- we take this novel approach to globals initialization to allow
#                       the compiler to run multiple times in the same process. The
#                       initialize() function does globals initialization for this
#                       module and is called from an INIT block below. The function is
#                       also called by Shorewall::Compiler::compiler at the beginning of
#                       the second and subsequent calls to that function.
#

sub initialize( $ ) {
    $family   = shift;
    %classids = ();
    @deferred_rules = ();
    @tcdevices = ();
    %tcdevices = ();
    @tcclasses = ();
    %tcclasses = ();
    @devnums   = ();
    $devnum = 0;
    $sticky = 0;
}

INIT {
    initialize( F_IPV4 );
}

sub process_tc_rule( $$$$$$$$$$$$ ) {
    my ( $originalmark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $connbytes , $helper ) = @_;

    my ( $mark, $designator, $remainder ) = split( /:/, $originalmark, 3 );

    fatal_error "Invalid MARK ($originalmark)" if defined $remainder || ! defined $mark || $mark eq '';

    my $chain  = $globals{MARKING_CHAIN};
    my $target = 'MARK --set-mark';
    my $tcsref;
    my $connmark = 0;
    my $classid  = 0;
    my $device   = '';
    my $fw       = firewall_zone;
    my $list;

    if ( $source ) {
	if ( $source eq $fw ) {
	    $chain = 'tcout';
	    $source = '';
	} else {
	    $chain = 'tcout' if $source =~ s/^($fw)://;
	}
    }

    if ( $designator ) {
	$tcsref = $tcs{$designator};

	if ( $tcsref ) {
	    if ( $chain eq 'tcout' ) {
		fatal_error "Invalid chain designator for source $fw" unless $tcsref->{fw};
	    }

	    $chain    = $tcsref->{chain}  if $tcsref->{chain};
	    $target   = $tcsref->{target} if $tcsref->{target};
	    $mark     = "$mark/0xFF"      if $connmark = $tcsref->{connmark};

	    require_capability ('CONNMARK' , "CONNMARK Rules", '' ) if $connmark;

	} else {
	    fatal_error "Invalid MARK ($originalmark)"   unless $mark =~ /^([0-9]+|0x[0-9a-f]+)$/ and $designator =~ /^([0-9]+|0x[0-9a-f]+)$/;

	    if ( $config{TC_ENABLED} eq 'Internal' ) {
		fatal_error "Unknown Class ($originalmark)}" unless ( $device = $classids{$originalmark} );
	    }

	    $chain   = 'tcpost';
	    $classid = 1;
	    $mark    = $originalmark;
	    $target  = 'CLASSIFY --set-class';
	}
    }

    my $mask = 0xffff;

    my ($cmd, $rest) = split( '/', $mark, 2 );

    $list = '';

    unless ( $classid ) {
      MARK:
	{
	    for my $tccmd ( @tccmd ) {
		if ( $tccmd->{match}($cmd) ) {
		    fatal_error "$mark not valid with :C[FPT]" if $connmark;

		    require_capability ('CONNMARK' , "SAVE/RESTORE Rules", '' ) if $tccmd->{connmark};

		    $target      = "$tccmd->{target} ";
		    my $marktype = $tccmd->{mark};

		    if ( $marktype == NOMARK ) {
			$mark = ''
		    } else {
			$mark =~ s/^[|&]//;
		    }

		    if ( $target eq 'sticky ' ) {
			if ( $chain eq 'tcout' ) {
			    $target = 'sticko';
			} else {
			    fatal_error "SAME rules are only allowed in the PREROUTING and OUTPUT chains" if $chain ne 'tcpre';
			}

			$sticky++;
		    }

		    if ( $rest ) {
			fatal_error "Invalid MARK ($originalmark)" if $marktype == NOMARK;

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

	    validate_mark $mark;

	    if ( $config{HIGH_ROUTE_MARKS} ) {
		my $val = numeric_value( $cmd );
		fatal_error "Invalid MARK/CLASSIFY ($cmd)" unless defined $val;
		my $limit = $config{WIDE_TC_MARKS} ? 65535 : 255;
		fatal_error "Marks <= $limit may not be set in the PREROUTING or OUTPUT chains when HIGH_ROUTE_MARKS=Yes"
		    if $cmd && ( $chain eq 'tcpre' || $chain eq 'tcout' ) && $val <= $limit;
	    }
	}
    }

    if ( ( my $result = expand_rule( ensure_chain( 'mangle' , $chain ) ,
				     $restrictions{$chain} ,
				     do_proto( $proto, $ports, $sports) . 
				     do_user( $user ) . 
				     do_test( $testval, $mask ) . 
				     do_length( $length ) . 
				     do_tos( $tos ) . 
				     do_connbytes( $connbytes ) . 
				     do_helper( $helper ),
				     $source ,
				     $dest ,
				     '' ,
				     "-j $target $mark" ,
				     '' ,
				     '' ,
				     '' ) )
	  && $device ) {
	#
	# expand_rule() returns destination device if any
	#
	fatal_error "Class Id $originalmark is not associated with device $result" if $device ne $result;
    }

    progress_message "  TC Rule \"$currentline\" $done";

}

sub rate_to_kbit( $ ) {
    my $rate = $_[0];

    return 0           if $rate eq '-';
    return $1          if $rate =~ /^(\d+)kbit$/i;
    return $1 * 1000   if $rate =~ /^(\d+)mbit$/i;
    return $1 * 8000   if $rate =~ /^(\d+)mbps$/i;
    return $1 * 8      if $rate =~ /^(\d+)kbps$/i;
    return int($1/125) if $rate =~ /^(\d+)(bps)?$/;
    fatal_error "Invalid Rate ($rate)";
}

sub calculate_r2q( $ ) {
    my $rate = rate_to_kbit $_[0];
    my $r2q= $rate / 200 ;
    $r2q <= 5 ? 5 : $r2q;
}

sub calculate_quantum( $$ ) {
    my ( $rate, $r2q ) = @_;
    $rate = rate_to_kbit $rate;
    int( ( $rate * 125 ) / $r2q );
}

sub process_flow($) {
    my $flow = shift;

    $flow =~ s/^\(// if $flow =~ s/\)$//;

    my @flow = split /,/, $flow;

    for ( @flow ) {
	fatal_error "Invalid flow key ($_)" unless $flow_keys{$_};
    }

    $flow;
}

sub validate_tc_device( $$$$$ ) {
    my ( $device, $inband, $outband , $options , $redirected ) = @_;

    my $devnumber;

    if ( $device =~ /:/ ) {
	( my $number, $device, my $rest )  = split /:/, $device, 3;

	fatal_error "Invalid NUMBER:INTERFACE ($device:$number:$rest)" if defined $rest;

	if ( defined $number ) {
	    $devnumber = hex_value( $number );
	    fatal_error "Invalid interface NUMBER ($number)" unless defined $devnumber && $devnumber;
	    fatal_error "Duplicate interface number ($number)" if defined $devnums[ $devnumber ];
	    $devnum = $devnumber if $devnumber > $devnum;
	} else {
	    fatal_error "Missing interface NUMBER";
	}
    } else {
	$devnumber = ++$devnum;
    }

    $devnums[ $devnumber ] = $device;

    fatal_error "Duplicate INTERFACE ($device)"    if $tcdevices{$device};
    fatal_error "Invalid INTERFACE name ($device)" if $device =~ /[:+]/;

    my ( $classify, $pfifo, $flow)  = (0, 0, '' );

    if ( $options ne '-' ) {
	for my $option ( split_list1 $options, 'option' ) {
	    if ( $option eq 'classify' ) {
		$classify = 1;
	    } elsif ( $option =~ /^flow=(.*)$/ ) {
		fatal_error "The 'flow' option is not allowed with 'pfifo'" if $pfifo;
		$flow = process_flow $1;
	    } elsif ( $option eq 'pfifo' ) {
		fatal_error "The 'pfifo'' option is not allowed with 'flow='" if $flow;
		$pfifo = 1;
	    } else {
		fatal_error "Unknown device option ($option)";
	    }
	}
    }

    my @redirected = ();

    @redirected = split_list( $redirected , 'device' ) if defined $redirected && $redirected ne '-';

    if ( @redirected ) {
	fatal_error "IFB devices may not have IN-BANDWIDTH" if $inband ne '-' && $inband;
	$classify = 1;
    }	

    for my $rdevice ( @redirected ) {
	fatal_error "Invalid device name ($rdevice)" if $rdevice =~ /[:+]/;
	my $rdevref = $tcdevices{$rdevice};
	fatal_error "REDIRECTED device ($rdevice) has not been defined in this file" unless $rdevref;
	fatal_error "IN-BANDWIDTH must be zero for REDIRECTED devices" if $rdevref->{in_bandwidth} ne '0kbit';
    }

    $tcdevices{$device} = { in_bandwidth  => rate_to_kbit( $inband ) . 'kbit' ,
			    out_bandwidth => rate_to_kbit( $outband ) . 'kbit' ,
			    number        => $devnumber,
			    classify      => $classify ,
			    flow          => $flow ,
			    pfifo         => $pfifo ,
			    tablenumber   => 1 ,
			    redirected    => \@redirected ,
			  } ,

    push @tcdevices, $device;

    progress_message "  Tcdevice \"$currentline\" $done.";
}

sub convert_rate( $$$ ) {
    my ($full, $rate, $column) = @_;

    if ( $rate =~ /\bfull\b/ ) {
	$rate =~ s/\bfull\b/$full/g;
	fatal_error "Invalid $column ($_[1])" if $rate =~ m{[^0-9*/+()-]};
	no warnings;
	$rate = eval "int( $rate )";
	use warnings;
	fatal_error "Invalid $column ($_[1])" unless defined $rate;
    } else {
	$rate = rate_to_kbit $rate
    }

    fatal_error "$column may not be zero" unless $rate;
    fatal_error "$column ($_[1]) exceeds OUT-BANDWIDTH" if $rate > $full;

    $rate;
}

sub dev_by_number( $ ) {
    my $dev = $_[0];
    my $devnum = uc $dev;
    my $devref;

    if ( $devnum =~ /^\d+$/ ) {
	$dev = $devnums[ $devnum ];
	fatal_error "Undefined INTERFACE number ($_[0])" unless defined $dev;
	$devref = $tcdevices{$dev};
	assert( $devref );
    } else {
	$devref = $tcdevices{$dev};
	fatal_error "Unknown INTERFACE ($dev)" unless $devref;
    }

    ( $dev , $devref );

}

sub validate_tc_class( $$$$$$ ) {
    my ( $devclass, $mark, $rate, $ceil, $prio, $options ) = @_;

    my %tosoptions = ( 'tos-minimize-delay'       => 'tos=0x10/0x10' ,
		       'tos-maximize-throughput'  => 'tos=0x08/0x08' ,
		       'tos-maximize-reliability' => 'tos=0x04/0x04' ,
		       'tos-minimize-cost'        => 'tos=0x02/0x02' ,
		       'tos-normal-service'       => 'tos=0x00/0x1e' );

    my $classnumber = 0;
    my $devref;
    my $device = $devclass;
    my $occurs = 1;

    if ( $devclass =~ /:/ ) {
	( $device, my ($number, $rest ) )  = split /:/, $device, 3;
	fatal_error "Invalid INTERFACE:CLASS ($devclass)" if defined $rest;

	( $device , $classnumber ) = ( hex_value $device, hex_value $number );

	( $device , $devref) = dev_by_number( $device );

	if ( defined $number ) {
	    if ( $devref->{classify} ) {
		fatal_error "Invalid interface/class number ($devclass)" unless defined $classnumber && $classnumber;
		fatal_error "Duplicate interface/class number ($devclass)" if defined $devnums[ $classnumber ];
	    } else {
		warning_message "Class NUMBER ignored -- INTERFACE $device does not have the 'classify' option";
	    }
	} else {
	    fatal_error "Missing interface NUMBER";
	}
    } else {
	($device, $devref ) = dev_by_number( $device );
	fatal_error "Missing class NUMBER" if $devref->{classify};
    }

    my $full  = rate_to_kbit $devref->{out_bandwidth};

    $tcclasses{$device} = {} unless $tcclasses{$device};
    my $tcref = $tcclasses{$device};

    my $markval = 0;

    if ( $mark ne '-' ) {
	if ( $devref->{classify} ) {
	    warning_message "INTERFACE $device has the 'classify' option - MARK value ($mark) ignored";
	} else {
	    fatal_error "Invalid Mark ($mark)" unless $mark =~ /^([0-9]+|0x[0-9a-fA-F]+)$/ && numeric_value( $mark ) <= 0xff;

	    $markval = numeric_value( $mark );
	    fatal_error "Invalid MARK ($markval)" unless defined $markval;
	    $classnumber = $config{WIDE_TC_MARKS} ? 0x4000 | $markval : $devnum . $markval;
	    fatal_error "Duplicate MARK ($mark)" if $tcref->{$classnumber};
	}
    } else {
	fatal_error "Missing MARK" unless $devref->{classify};
	fatal_error "Duplicate Class NUMBER ($classnumber)" if $tcref->{$classnumber};
    }

    $tcref->{$classnumber} = { tos      => [] ,
			       rate     => convert_rate( $full, $rate, 'RATE' ) ,
			       ceiling  => convert_rate( $full, $ceil, 'CEIL' ) ,
			       priority => $prio eq '-' ? 1 : $prio ,
			       mark     => $markval ,
			       flow     => '' ,
			       pfifo    => 0,
			       occurs   => 1,
			       src      => 0,
			     };

    $tcref = $tcref->{$classnumber};

    fatal_error "RATE ($tcref->{rate}) exceeds CEIL ($tcref->{ceiling})" if $tcref->{rate} > $tcref->{ceiling};

    unless ( $options eq '-' ) {
	for my $option ( split_list1 "\L$options", 'option' ) {
	    my $optval = $tosoptions{$option};

	    $option = $optval if $optval;

	    if ( $option eq 'default' ) {
		fatal_error "Only one default class may be specified for device $device" if $devref->{default};
		fatal_error q(The 'default' option is not valid with 'occurs') if $tcref->{occurs} > 1;
		$devref->{default} = $classnumber;
	    } elsif ( $option eq 'tcp-ack' ) {
		fatal_error q(The 'tcp-ack' option is not valid with 'occurs') if $tcref->{occurs} > 1;
		$tcref->{tcp_ack} = 1;
	    } elsif ( $option =~ /^tos=0x[0-9a-f]{2}$/ ) {
		fatal_error q(The 'tos' option is not valid with 'occurs') if $tcref->{occurs} > 1;
		( undef, $option ) = split /=/, $option;
		push @{$tcref->{tos}}, "$option/0xff";
	    } elsif ( $option =~ /^tos=0x[0-9a-f]{2}\/0x[0-9a-f]{2}$/ ) {
		fatal_error q(The 'tos' option is not valid with 'occurs') if $tcref->{occurs} > 1;
		( undef, $option ) = split /=/, $option;
		push @{$tcref->{tos}}, $option;
	    } elsif ( $option =~ /^flow=(.*)$/ ) {
		fatal_error q(The 'flow' option is not allowed with 'pfifo') if $tcref->{pfifo};
		$tcref->{flow} = process_flow $1;
	    } elsif ( $option eq 'pfifo' ) {
		fatal_error q(The 'pfifo'' option is not allowed with 'flow=') if $tcref->{flow};
		$tcref->{pfifo} = 1;
	    } elsif ( $option =~ /^occurs=((\d+)([ds]?))$/ ) {
		my $val = $2;
		$occurs = numeric_value($val);
		$tcref->{src} = 1 if $3 eq 's';

		fatal_error q(The 'occurs' option is only valid for IPv4)        if $family == F_IPV6;
		fatal_error "Invalid 'occurs' ($val)"                            unless defined $occurs && $occurs > 1 && $occurs <= 256;
		fatal_error "Invalid 'occurs' ($val)"                            if $occurs > ( $config{WIDE_TC_MARKS} ? 8191 : 255 );
		fatal_error q(Duplicate 'occurs')                                if $tcref->{occurs} > 1;
		fatal_error q(The 'occurs' option is only valid with 'classify') unless $devref->{classify};
		fatal_error q(The 'occurs' option is not valid with 'default')   if $devref->{default} == $classnumber;
		fatal_error q(The 'occurs' option is not valid with 'tos')       if @{$tcref->{tos}};

		$tcref->{occurs} = $occurs;
	    } else {
		fatal_error "Unknown option ($option)";
	    }
	}
    }

    $tcref->{flow}  = $devref->{flow}  unless $tcref->{flow};
    $tcref->{pfifo} = $devref->{pfifo} unless $tcref->{flow} || $tcref->{pfifo};

    push @tcclasses, "$device:$classnumber";

    while ( --$occurs ) {
	fatal_error "Duplicate class number ($classnumber)" if $tcclasses{$device}{++$classnumber};

	$tcclasses{$device}{$classnumber} =  { tos      => [] ,
					       rate     => $tcref->{rate} ,
					       ceiling  => $tcref->{ceiling} ,
					       priority => $tcref->{priority} ,
					       mark     => 0 ,
					       flow     => $tcref->{flow} ,
					       pfifo    => $tcref->{pfifo},
					       occurs   => 0,
					     };
	push @tcclasses, "$device:$classnumber";
    };

    progress_message "  Tcclass \"$currentline\" $done.";
}

#
# Process a record from the tcfilters file
#
sub process_tc_filter( $$$$$$ ) {
    my ($devclass , $source, $dest , $proto, $portlist , $sportlist ) = @_;

    my ($device, $class, $rest ) = split /:/, $devclass, 3;

    fatal_error "Invalid INTERFACE:CLASS ($devclass)" if defined $rest || ! ($device && $class );

    ( $device , my $devref ) = dev_by_number( $device );

    my $devnum = $devref->{number};

    my $tcref = $tcclasses{$device};

    fatal_error "No Classes were defined for INTERFACE $device" unless $tcref;

    my $classnum = hex_value $class;

    fatal_error "Invalid CLASS ($class)" unless defined $classnum;

    $tcref = $tcref->{$classnum};

    fatal_error "Unknown CLASS ($devclass)" unless $tcref && $tcref->{occurs};

    my $occurs = $tcref->{occurs};

    my $rule = "filter add dev $device protocol ip parent $devnum:0 prio 10 u32";

    if ( $source ne '-' ) {
	my ( $net , $mask ) = decompose_net( $source );
	$rule .= "\\\n   match ip src $net/$mask";
    }

    if ( $dest ne '-' ) {
	my ( $net , $mask ) = decompose_net( $dest );
	$rule .= "\\\n   match ip dst $net/$mask";
    }

    my $protonumber = 0;

    unless ( $proto eq '-' ) {
	$protonumber = resolve_proto $proto;
	fatal_error "Unknown PROTO ($proto)" unless defined $protonumber;
	fatal_error "PROTO not permitted in this rule" unless $occurs == 1;
	$rule .= "\\\n   match ip protocol $protonumber 0xff" if $protonumber;
    }

    if ( $portlist eq '-' && $sportlist eq '-' ) {
	if ( $occurs == 1 ) {
	    emit( "\nrun_tc $rule\\" ,
		  "   flowid $devref->{number}:$class" ,
		  '' );
	} else {
	    my $offset = $tcref->{src} ? 12 : 16;
	    my $tnum   = $devref->{tablenumber}++;
	    my $bucket;

	    emit( "\nrun_tc filter add dev $device parent $devnum:0 protocol ip prio 10 handle $tnum: u32 divisor $occurs" );

	    for ( my $i = 0; $i < $occurs; $i++ ) {
		$class  = in_hexp $classnum++;
		$bucket = in_hexp $i;
		emit( "run_tc filter add dev $device protocol ip parent $devnum:0 prio 10 u32 ht $tnum:$bucket match u32 0x00000000 0x000000 at 12 flowid $devref->{number}:$class" );
	    }

	    emit( "\nrun_tc $rule\\",
		  "   link $tnum: hashkey mask ff at $offset\\" );
	}
    } else {
	fatal_error "Ports may not be specified without a PROTO" unless $protonumber;
	our $lastrule;
	our $lasttnum;
	#
	# In order to be able to access the protocol header, we must create another hash table and link to it.
	#
	# Create the Table.
	#
	my $tnum;

	if ( $lastrule eq $rule ) {
	    #
	    # The source, dest and protocol are the same as the last rule that specified a port
	    # Use the same table
	    #
	    $tnum = $lasttnum
	} else {
	    $tnum     = in_hex3 $devref->{tablenumber}++;
	    $lasttnum = $tnum;
	    $lastrule = $rule;

	    emit( "\nrun_tc filter add dev $device parent $devnum:0 protocol ip prio 10 handle $tnum: u32 divisor 1" );
	}
	#
	# And link to it using the current contents of $rule
	#
	emit( "\nrun_tc $rule\\" ,
	      "   link $tnum:0 offset at 0 mask 0x0F00 shift 6 plus 0 eat" );
	#
	# The rule to match the port(s) will be inserted into the new table
	#
	$rule     = "filter add dev $device protocol ip parent $devnum:0 prio 10 u32 ht $tnum:0";

	if ( $portlist eq '-' ) {
	    fatal_error "Only TCP, UDP and SCTP may specify SOURCE PORT" 
		unless $protonumber == TCP || $protonumber == UDP || $protonumber == SCTP;

	    for my $sportrange ( split_list $sportlist , 'port list' ) {
		my @sportlist = expand_port_range $protonumber , $sportrange;

		while ( @sportlist ) {
		    my ( $sport, $smask ) = ( shift @sportlist, shift @sportlist );
		    my $rule1;

		    if ( $protonumber == TCP ) {
			$rule1 = join( ' ', 'match tcp src', hex_value( $sport ), "0x$smask" );
		    } elsif ( $protonumber == UDP ) {
			$rule1 = join( ' ', 'match udp src', hex_value( $sport ), "0x$smask" );
		    } else {
			$rule1 = "match u32 0x${sport}0000 0x${smask}0000 at nexthdr+0\\" ,
		    }

		    emit( "\nrun_tc $rule\\" ,
			  "   $rule1\\" ,
			  "   flowid $devref->{number}:$class" );
		}
	    }
	} else {
	    fatal_error "Only TCP, UDP, SCTP and ICMP may specify DEST PORT" 
		unless $protonumber == TCP || $protonumber == UDP || $protonumber == SCTP || $protonumber == ICMP;

	    for my $portrange ( split_list $portlist, 'port list' ) {
		if ( $protonumber == ICMP ) {
		    fatal_error "SOURCE PORT(S) are not allowed with ICMP" if $sportlist ne '-';

		    my ( $icmptype , $icmpcode ) = split '//', validate_icmp( $portrange );

		    my $rule1 = "   match icmp type $icmptype 0xff";
		    $rule1   .= "\\\n   match icmp code $icmpcode 0xff" if defined $icmpcode;
		    emit( "\nrun_tc ${rule}\\" ,
			  "$rule1\\" ,
			  "   flowid $devref->{number}:$class" );
		} else {
		    my @portlist = expand_port_range $protonumber , $portrange;

		    while ( @portlist ) {
			my ( $port, $mask ) = ( shift @portlist, shift @portlist );

			my $rule1;
			
			if ( $protonumber == TCP ) {
			    $rule1 = join( ' ', 'match tcp dst', hex_value( $port ), "0x$mask" );
			} elsif ( $protonumber == UDP ) {
			    $rule1 = join( ' ', 'match udp dst', hex_value( $port ), "0x$mask" );
			} else {
			    $rule1 = "match u32 0x0000${port} 0x0000${mask} at nexthdr+0";
			}

			if ( $sportlist eq '-' ) {
			    emit( "\nrun_tc ${rule}\\" ,
				  "   $rule1\\" ,
				  "   flowid $devref->{number}:$class" );
			} else {
			    for my $sportrange ( split_list $sportlist , 'port list' ) {
				my @sportlist = expand_port_range $protonumber , $sportrange;

				while ( @sportlist ) {
				    my ( $sport, $smask ) = ( shift @sportlist, shift @sportlist );

				    my $rule2;

				    if ( $protonumber == TCP ) {
					$rule2 = join( ' ', 'match tcp src', hex_value( $sport ), "0x$smask" );
				    } elsif ( $protonumber == UDP ) {
					$rule2 = join( ' ', 'match udp src', hex_value( $sport ), "0x$smask" );
				    } else {
					$rule2 = "match u32 0x${sport}0000 0x${smask}0000 at nexthdr+0\\" ,
				    }

				    emit( "\nrun_tc ${rule}\\",
					  "   $rule1\\" ,
					  "   $rule2\\" ,
					  "   flowid $devref->{number}:$class" );
				}
			    }
			}   
		    }
		}    
	    }
	}
    }

    emit '';

    progress_message "  TC Filter \"$currentline\" $done";

    $currentline =~ s/\s+/ /g;

    save_progress_message_short qq("   TC Filter \"$currentline\" defined.");

    emit '';

}   

sub setup_traffic_shaping() {
    our $lastrule = '';

    save_progress_message "Setting up Traffic Control...";

    my $fn = open_file 'tcdevices';

    if ( $fn ) {
	first_entry "$doing $fn...";

	while ( read_a_line ) {

	    my ( $device, $inband, $outband, $options , $redirected ) = split_line 3, 5, 'tcdevices';

	    fatal_error "Invalid tcdevices entry" if $outband eq '-';
	    validate_tc_device( $device, $inband, $outband , $options , $redirected );
	}
    }

    $devnum = $devnum > 10 ? 10 : 1;

    $fn = open_file 'tcclasses';

    if ( $fn ) {
	first_entry "$doing $fn...";

	while ( read_a_line ) {

	    my ( $device, $mark, $rate, $ceil, $prio, $options ) = split_line 4, 6, 'tcclasses file';

	    validate_tc_class( $device, $mark, $rate, $ceil, $prio, $options );
	}
    }

    for my $device ( @tcdevices ) {
	my $dev     = chain_base( $device );
	my $devref  = $tcdevices{$device};
	my $defmark = in_hexp ( $devref->{default} || 0 );
	my $devnum  = $devref->{number};

	emit "if interface_is_up $device; then";

	push_indent;

	emit ( "${dev}_exists=Yes",
	       "qt \$TC qdisc del dev $device root",
	       "qt \$TC qdisc del dev $device ingress",
	       "run_tc qdisc add dev $device root handle $devnum: htb default $defmark",
	       "${dev}_mtu=\$(get_device_mtu $device)",
	       "${dev}_mtu1=\$(get_device_mtu1 $device)",
	       "run_tc class add dev $device parent $devnum: classid $devnum:1 htb rate $devref->{out_bandwidth} \$${dev}_mtu1"
	       );

	my $inband = rate_to_kbit $devref->{in_bandwidth};

	if ( $inband ) {
	    emit ( "run_tc qdisc add dev $device handle ffff: ingress",
		   "run_tc filter add dev $device parent ffff: protocol ip prio 10 u32 match ip src 0.0.0.0/0 police rate ${inband}kbit burst 10k drop flowid :1"
		   );
	}

	for my $rdev ( @{$devref->{redirected}} ) {
	    emit ( "run_tc qdisc add dev $rdev handle ffff: ingress" );
	    emit( "run_tc filter add dev $rdev parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev $device > /dev/null" );
	}

	save_progress_message_short "   TC Device $device defined.";

	pop_indent;
	emit 'else';
	push_indent;

	emit qq(error_message "WARNING: Device $device is not in the UP state -- traffic-shaping configuration skipped");
	emit "${dev}_exists=";
	pop_indent;
	emit "fi\n";
    }

    my $lastdevice = '';

    for my $class ( @tcclasses ) {
	my ( $device, $classnum ) = split /:/, $class;
	my $devref   = $tcdevices{$device};
	my $tcref    = $tcclasses{$device}{$classnum};
	my $mark     = $tcref->{mark};
	my $devicenumber  = $devref->{number};
	my $classid  = join( ':', in_hexp $devicenumber, in_hexp $classnum);
	my $rate     = "$tcref->{rate}kbit";
	my $quantum  = calculate_quantum $rate, calculate_r2q( $devref->{out_bandwidth} );
	my $dev      = chain_base $device;
	my $priority = $tcref->{priority} << 8;

	$classids{$classid}=$device;

	$classnum = in_hexp $classnum;

	$classid = join( ':', in_hexp $devicenumber, $classnum );

	if ( $lastdevice ne $device ) {
	    if ( $lastdevice ) {
		pop_indent;
		emit "fi\n";
	    }

	    emit qq(if [ -n "\$${dev}_exists" ]; then);
	    push_indent;
	    $lastdevice = $device;
	}

	emit ( "[ \$${dev}_mtu -gt $quantum ] && quantum=\$${dev}_mtu || quantum=$quantum",
	       "run_tc class add dev $device parent $devref->{number}:1 classid $classid htb rate $rate ceil $tcref->{ceiling}kbit prio $tcref->{priority} \$${dev}_mtu1 quantum \$quantum" );

	emit( "run_tc qdisc add dev $device parent $classid handle ${classnum}: sfq quantum \$quantum limit 127 perturb 10" ) unless $tcref->{pfifo};
	#
	# add filters
	#
	emit "run_tc filter add dev $device protocol ip parent $devicenumber:0 prio " . ( $priority | 20 ) . " handle $mark fw classid $classid" unless $devref->{classify};
	emit "run_tc filter add dev $device protocol ip prio 1 parent $classnum: protocol ip handle $classnum flow hash keys $tcref->{flow} divisor 1024" if $tcref->{flow};
	#
	#options
	#
	emit "run_tc filter add dev $device parent $devref->{number}:0 protocol ip prio " . ( $priority | 10 ) ." u32 match ip protocol 6 0xff match u8 0x05 0x0f at 0 match u16 0x0000 0xffc0 at 2 match u8 0x10 0xff at 33 flowid $classid" if $tcref->{tcp_ack};

	for my $tospair ( @{$tcref->{tos}} ) {
	    my ( $tos, $mask ) = split q(/), $tospair;
	    emit "run_tc filter add dev $device parent $devicenumber:0 protocol ip prio " . ( $priority | 10 ) . " u32 match ip tos $tos $mask flowid $classid";
	}

	save_progress_message_short qq("   TC Class $class defined.");
	emit '';
    }

    if ( $lastdevice ) {
	pop_indent;
	emit "fi\n";
    }

    if ( $family == F_IPV4 ) {
	$fn = open_file 'tcfilters';

	if ( $fn ) {
	    first_entry( sub { progress_message2 "$doing $fn..."; save_progress_message "Adding TC Filters"; } );

	    while ( read_a_line ) {

		my ( $devclass, $source, $dest, $proto, $port, $sport ) = split_line 2, 6, 'tcfilters file';

		process_tc_filter( $devclass, $source, $dest, $proto, $port, $sport );
	    }
	}
    }
}

#
# Process the tcrules file and setup traffic shaping
#
sub setup_tc() {

    if ( $capabilities{MANGLE_ENABLED} && $config{MANGLE_ENABLED} ) {
	ensure_mangle_chain 'tcpre';
	ensure_mangle_chain 'tcout';

	if ( $capabilities{MANGLE_FORWARD} ) {
	    ensure_mangle_chain 'tcfor';
	    ensure_mangle_chain 'tcpost';
	}

	my $mark_part = '';

	if ( @routemarked_interfaces && ! $config{TC_EXPERT} ) {
	    $mark_part = $config{HIGH_ROUTE_MARKS} ? $config{WIDE_TC_MARKS} ? '-m mark --mark 0/0xFF0000' : '-m mark --mark 0/0xFF00' : '-m mark --mark 0/0xFF';

	    for my $interface ( @routemarked_interfaces ) {
		add_rule $mangle_table->{PREROUTING} , "-i $interface -j tcpre";
	    }
	}

	add_rule $mangle_table->{PREROUTING} , "$mark_part -j tcpre";
	add_rule $mangle_table->{OUTPUT} ,     "$mark_part -j tcout";

	if ( $capabilities{MANGLE_FORWARD} ) {
	    add_rule $mangle_table->{FORWARD} ,     '-j tcfor';
	    add_rule $mangle_table->{POSTROUTING} , '-j tcpost';
	}

	if ( $config{HIGH_ROUTE_MARKS} ) {
	    for my $chain qw(INPUT FORWARD POSTROUTING) {
		insert_rule1 $mangle_table->{$chain}, 0, $config{WIDE_TC_MARKS} ? '-j MARK --and-mark 0x3FFF' : '-j MARK --and-mark 0xFF';
	    }
	}
    }

    if ( $globals{TC_SCRIPT} ) {
	save_progress_message 'Setting up Traffic Control...';
	append_file $globals{TC_SCRIPT};
    } elsif ( $config{TC_ENABLED} eq 'Internal' ) {
	setup_traffic_shaping;
    }

    if ( $config{TC_ENABLED} ) {
	if ( my $fn = open_file 'tcrules' ) {

	    first_entry( sub { progress_message2 "$doing $fn..."; require_capability 'MANGLE_ENABLED' , 'a non-empty tcrules file' , 's'; } );

	    while ( read_a_line ) {

		my ( $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper ) = split_line1 2, 12, 'tcrules file';

		if ( $mark eq 'COMMENT' ) {
		    process_comment;
		} else {
		    process_tc_rule $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos, $connbytes, $helper;
		}

	    }

	    clear_comment;
	}
    }

    for ( @deferred_rules ) {
	add_rule ensure_chain( 'mangle' , 'tcpost' ), $_;
    }

    handle_stickiness( $sticky );
}

1;
