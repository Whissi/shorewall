#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Tc.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010,2011 - Tom Eastep (teastep@shorewall.net)
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
our @EXPORT = qw( process_tc setup_tc );
our @EXPORT_OK = qw( process_tc_rule initialize );
our $VERSION = 'MODULEVERSION';

my  %tcs = ( T => { chain  => 'tcpost',
		    connmark => 0,
		    fw       => 1,
		    fwi      => 0,
		  } ,
	    CT => { chain  => 'tcpost' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 1 ,
		    fwi      => 0,
		    } ,
	    C  => { target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 1 ,
		    fwi      => 1 ,
		    } ,
	    P  => { chain    => 'tcpre' ,
		    connmark => 0 ,
		    fw       => 0 ,
		    fwi      => 0 ,
		    } ,
	    CP => { chain    => 'tcpre' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0 ,
		    fwi      => 0 ,
		    } ,
	    F =>  { chain    => 'tcfor' ,
		    connmark => 0 ,
		    fw       => 0 ,
		    fwi      => 0 ,
		    } ,
	    CF => { chain    => 'tcfor' ,
		    connmark => 1 ,
		    fw       => 0 ,
		    fwi      => 0 ,
		    } ,
	    );

use constant { NOMARK    => 0 ,
	       SMALLMARK => 1 ,
	       HIGHMARK  => 2
	       };

my  %flow_keys = ( 'src'            => 1,
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

my %designator = ( F => 'tcfor' ,
		   T => 'tcpost' );

my  %tosoptions = ( 'tos-minimize-delay'       => '0x10/0x10' ,
		    'tos-maximize-throughput'  => '0x08/0x08' ,
		    'tos-maximize-reliability' => '0x04/0x04' ,
		    'tos-minimize-cost'        => '0x02/0x02' ,
		    'tos-normal-service'       => '0x00/0x1e' );
my  %classids;

#
# Perl version of Arn Bernin's 'tc4shorewall'.
#
# TCDevices Table
#
# %tcdevices { <interface> => {in_bandwidth  => <value> ,
#                              out_bandwidth => <value> ,
#                              number        => <number>,
#                              classify      => 0|1
#                              tablenumber   => <next u32 table to be allocated for this device>
#                              default       => <default class mark value>
#                              redirected    => [ <dev1>, <dev2>, ... ]
#                              nextclass     => <number>
#                              occurs        => Has one or more occurring classes
#                              qdisc         => htb|hfsc
#                              guarantee     => <total RATE of classes seen so far>
#                              name          => <interface>
#                                               }
#
my  @tcdevices;
my  %tcdevices;
my  @devnums;
my  $devnum;
my  $sticky;
my  $ipp2p;

#
# TCClasses Table
#
# %tcclasses { device    => <device> { number => { mark      => <mark> ,
#                                                  rate      => <rate> ,
#                                                  umax      => <umax> ,
#                                                  dmax      => <dmax> ,
#                                                  ceiling   => <ceiling> ,
#                                                  priority  => <priority> ,
#                                                  occurs    => <number> # 0 means that this is a class generated by another class with occurs > 1
#                                                  parent    => <class number>
#                                                  leaf      => 0|1
#                                                  guarantee => <sum of rates of sub-classes>
#                                                  options   => { tos  => [ <value1> , <value2> , ... ];
#                                                  tcp_ack   => 1 ,
#                                                  filters   => [ filter list ]
#                                                }
#                                     }
#             }
my  @tcclasses;
my  %tcclasses;

my  %restrictions = ( tcpre      => PREROUTE_RESTRICT ,
		      tcpost     => POSTROUTE_RESTRICT ,
		      tcfor      => NO_RESTRICT ,
		      tcin       => INPUT_RESTRICT ,
		      tcout      => OUTPUT_RESTRICT );

my $family;

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
    $family   = shift;
    %classids = ();
    @tcdevices = ();
    %tcdevices = ();
    @tcclasses = ();
    %tcclasses = ();
    @devnums   = ();
    $devnum = 0;
    $sticky = 0;
    $ipp2p  = 0;
}

sub process_tc_rule( ) {
    my ( $originalmark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $connbytes, $helper, $headers ) = 
	split_line1 'tcrules file', { mark => 0, source => 1, dest => 2, proto => 3, dport => 4, sport => 5, user => 6, test => 7, length => 8, tos => 9, connbytes => 10, helper => 11, headers => 12 };

    our @tccmd;

    fatal_error 'MARK must be specified' if $originalmark eq '-';

    if ( $originalmark eq 'COMMENT' ) {
	process_comment;
	return;
    }

    my ( $mark, $designator, $remainder ) = split( /:/, $originalmark, 3 );

    fatal_error "Invalid MARK ($originalmark)" unless supplied $mark;

    my $chain    = $globals{MARKING_CHAIN};
    my $classid  = 0;

    if ( $remainder ) { 
	if ( $originalmark =~ /^\w+\(?.*\)$/ ) {
	    $mark = $originalmark; # Most likely, an IPv6 address is included in the parameter list
	} else {
	    fatal_error "Invalid MARK ($originalmark)" 
		unless ( $mark =~ /^([0-9a-fA-F]+)$/ &&
			 $designator =~ /^([0-9a-fA-F]+)$/ && 
			 ( $chain = $designator{$remainder} ) );
	    $mark    = join( ':', $mark, $designator );
	    $classid = 1;
	}
    }

    my $target = 'MARK --set-mark';
    my $tcsref;
    my $connmark = 0;
    my $device   = '';
    my $fw       = firewall_zone;
    my $list;

    if ( $source ) {
	if ( $source eq $fw ) {
	    if ( $classid ) {
		fatal_error ":F is not allowed when the SOURCE is the firewall" if $chain eq 'tcfor';
	    } else {
		$chain = 'tcout';
	    }
	    $source = '';
	} elsif ( $source =~ s/^($fw):// ) {
	    fatal_error ":F is not allowed when the SOURCE is the firewall" if $chain eq 'tcfor';
	    $chain = 'tcout';
	}
    }

    if ( $dest ) {
	if ( $dest eq $fw ) {
	    fatal_error 'A CLASSIFY rule may not have $FW as the DEST' if $classid;
	    $chain = 'tcin';
	    $dest  = '';
	} elsif ( $dest =~ s/^($fw):// ) {
	    fatal_error 'A CLASSIFY rule may not have $FW as the DEST' if $classid;
	    $chain = 'tcin';
	}
    }

    if ( $designator ) {
	$tcsref = $tcs{$designator};

	if ( $tcsref ) {
	    if ( $chain eq 'tcout' ) {
		fatal_error "Invalid chain designator for source $fw" unless $tcsref->{fw};
	    } elsif ( $chain eq 'tcin' ) {
		fatal_error "Invalid chain designator for dest $fw" unless $tcsref->{fwi};
	    }

	    $chain    = $tcsref->{chain}                       if $tcsref->{chain};
	    $target   = $tcsref->{target}                      if $tcsref->{target};
	    $mark     = "$mark/" . in_hex( $globals{TC_MASK} ) if $connmark = $tcsref->{connmark};

	    require_capability ('CONNMARK' , "CONNMARK Rules", '' ) if $connmark;

	} else {
	    unless ( $classid ) {
		fatal_error "Invalid MARK ($originalmark)" unless $mark =~ /^([0-9a-fA-F]+)$/ and $designator =~ /^([0-9a-fA-F]+)$/;
		fatal_error 'A CLASSIFY rule may not have $FW as the DEST' if $chain eq 'tcin';
		$chain = 'tcpost';
		$mark  = $originalmark;
	    }

	    if ( $config{TC_ENABLED} eq 'Internal' || $config{TC_ENABLED} eq 'Shared' ) {
		$originalmark = join( ':', normalize_hex( $mark ), normalize_hex( $designator ) );
		fatal_error "Unknown Class ($mark)}" unless ( $device = $classids{$mark} );
		fatal_error "IFB Classes may not be specified in tcrules" if @{$tcdevices{$device}{redirected}};

		unless ( $tcclasses{$device}{hex_value $designator}{leaf} ) {
		    warning_message "Non-leaf Class ($originalmark) - tcrule ignored";
		    return;
		}

		if ( $dest eq '-' ) {
		    $dest = $device;
		} else {
		    $dest = join( ':', $device, $dest ) unless $dest =~ /^[[:alpha:]]/;
		}
	    }

	    $classid = 1;
	    $target  = 'CLASSIFY --set-class';
	}
    }

    my ($cmd, $rest) = split( '/', $mark, 2 );

    $list = '';

    my $restriction = 0;

    unless ( $classid ) {
      MARK:
	{
	    for my $tccmd ( @tccmd ) {
		if ( $tccmd->{match}($cmd) ) {
		    fatal_error "$mark not valid with :C[FPT]" if $connmark;

		    require_capability ('CONNMARK' , "SAVE/RESTORE Rules", '' ) if $tccmd->{connmark};

		    $target      = $tccmd->{target};
		    my $marktype = $tccmd->{mark};

		    if ( $marktype == NOMARK ) {
			$mark = ''
		    } else {
			$mark =~ s/^[|&]//;
		    }

		    if ( $target eq 'sticky' ) {
			if ( $chain eq 'tcout' ) {
			    $target = 'sticko';
			} else {
			    fatal_error "SAME rules are only allowed in the PREROUTING and OUTPUT chains" if $chain ne 'tcpre';
			}

			$restriction = DESTIFACE_DISALLOW;

			ensure_mangle_chain($target);

			$sticky++;
		    } elsif ( $target eq 'IPMARK' ) {
			my ( $srcdst, $mask1, $mask2, $shift ) = ('src', 255, 0, 0 );

			require_capability 'IPMARK_TARGET', 'IPMARK', 's';

			if ( $cmd =~ /^IPMARK\((.+?)\)$/ ) {
			    my $params = $1;
			    my $val;

			    my ( $sd, $m1, $m2, $s , $bad ) = split ',', $params;

			    fatal_error "Invalid IPMARK parameters ($params)" if $bad;
			    fatal_error "Invalid IPMARK parameter ($sd)" unless ( $sd eq 'src' || $sd eq 'dst' );
			    $srcdst = $sd;

			    if ( supplied $m1 ) {
				$val = numeric_value ($m1);
				fatal_error "Invalid Mask ($m1)" unless defined $val && $val && $val <= 0xffffffff;
				$mask1 = in_hex ( $val & 0xffffffff );
			    }

			    if ( supplied $m2 ) {
				$val = numeric_value ($m2);
				fatal_error "Invalid Mask ($m2)" unless defined $val && $val <= 0xffffffff;
				$mask2 = in_hex ( $val & 0xffffffff );
			    }

			    if ( defined $s ) {
				$val = numeric_value ($s);
				fatal_error "Invalid Shift Bits ($s)" unless defined $val && $val >= 0 && $val < 128;
				$shift = $s;
			    }
			} else {
			    fatal_error "Invalid MARK/CLASSIFY ($cmd)" unless $cmd eq 'IPMARK';
			}

			$target = "IPMARK --addr $srcdst --and-mask $mask1 --or-mask $mask2 --shift $shift";
		    } elsif ( $target eq 'TPROXY' ) {
			require_capability( 'TPROXY_TARGET', 'Use of TPROXY', 's');

			fatal_error "Invalid TPROXY specification( $cmd/$rest )" if $rest;

			$chain = 'tcpre';

			$cmd =~ /TPROXY\((.+?)\)$/;

			my $params = $1;

			fatal_error "Invalid TPROXY specification( $cmd )" unless defined $params;

			( $mark, my $port, my $ip, my $bad ) = split ',', $params;

			fatal_error "Invalid TPROXY specification( $cmd )" if defined $bad;

			if ( $port ) {
			    $port = validate_port( 'tcp', $port );
			} else {
			    $port = 0;
			}

			$target .= " --on-port $port";

			if ( supplied $ip ) {
			    if ( $family == F_IPV6 ) {
				$ip = $1 if $ip =~ /^\[(.+)\]$/ || $ip =~ /^<(.+)>$/;
			    }

			    validate_address $ip, 1;
			    $target .= " --on-ip $ip";
			}

			$target .= ' --tproxy-mark';
		    } elsif ( $target eq 'TTL' ) {
			fatal_error "TTL is not supported in IPv6 - use HL instead" if $family == F_IPV6;
			fatal_error "Invalid TTL specification( $cmd/$rest )" if $rest;
			fatal_error "Chain designator $designator not allowed with TTL" if $designator && ! ( $designator eq 'F' );

			$chain = 'tcfor';

			$cmd =~ /^TTL\(([-+]?\d+)\)$/;

			my $param =  $1;

			fatal_error "Invalid TTL specification( $cmd )" unless $param && ( $param = abs $param ) < 256;

			if ( $1 =~ /^\+/ ) {
			    $target .= " --ttl-inc $param";
			} elsif ( $1 =~ /\-/ ) {
			    $target .= " --ttl-dec $param";
			} else {
			    $target .= " --ttl-set $param";
			}
		    } elsif ( $target eq 'HL' ) {
			fatal_error "HL is not supported in IPv4 - use TTL instead" if $family == F_IPV4;
			fatal_error "Invalid HL specification( $cmd/$rest )" if $rest;
			fatal_error "Chain designator $designator not allowed with HL" if $designator && ! ( $designator eq 'F' );

			$chain = 'tcfor';

			$cmd =~ /^HL\(([-+]?\d+)\)$/;

			my $param =  $1;

			fatal_error "Invalid HL specification( $cmd )" unless $param && ( $param = abs $param ) < 256;

			if ( $1 =~ /^\+/ ) {
			    $target .= " --hl-inc $param";
			} elsif ( $1 =~ /\-/ ) {
			    $target .= " --hl-dec $param";
			} else {
			    $target .= " --hl-set $param";
			}
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

	    if ( $config{PROVIDER_OFFSET} ) {
		my $val = numeric_value( $cmd );
		fatal_error "Invalid MARK/CLASSIFY ($cmd)" unless defined $val;
		my $limit = $globals{TC_MASK};
		unless ( have_capability 'FWMARK_RT_MASK' ) {
		    fatal_error "Marks <= $limit may not be set in the PREROUTING or OUTPUT chains when HIGH_ROUTE_MARKS=Yes"
			if $cmd && ( $chain eq 'tcpre' || $chain eq 'tcout' ) && $val <= $limit;
		}
	    }
	}
    }

    fatal_error "USER/GROUP only allowed in the OUTPUT chain" unless ( $user eq '-' || ( $chain eq 'tcout' || $chain eq 'tcpost' ) ); 

    if ( ( my $result = expand_rule( ensure_chain( 'mangle' , $chain ) ,
				     $restrictions{$chain} | $restriction,
				     do_proto( $proto, $ports, $sports) .
				     do_user( $user ) .
				     do_test( $testval, $globals{TC_MASK} ) .
				     do_length( $length ) .
				     do_tos( $tos ) .
				     do_connbytes( $connbytes ) .
				     do_helper( $helper ) .
				     do_headers( $headers ) ,
				     $source ,
				     $dest ,
				     '' ,
				     $mark ? "$target $mark" : $target,
				     '' ,
				     $target ,
				     '' ) )
	  && $device ) {
	#
	# expand_rule() returns destination device if any
	#
	fatal_error "Class Id $originalmark is not associated with device $result" if $device ne $result &&( $config{TC_ENABLED} eq 'Internal' || $config{TC_ENABLED} eq 'Shared' );
    }

    progress_message "  TC Rule \"$currentline\" $done";

}

sub rate_to_kbit( $ ) {
    my $rate = $_[0];

    return 0           if $rate eq '-';
    return $1          if $rate =~ /^((\d+)(\.\d+)?)kbit$/i;
    return $1 * 1000   if $rate =~ /^((\d+)(\.\d+)?)mbit$/i;
    return $1 * 8000   if $rate =~ /^((\d+)(\.\d+)?)mbps$/i;
    return $1 * 8      if $rate =~ /^((\d+)(\.\d+)?)kbps$/i;
    return ($1/125)    if $rate =~ /^((\d+)(\.\d+)?)(bps)?$/;
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

#
# The next two function implement handling of the IN-BANDWIDTH column in both tcdevices and tcinterfaces
#
sub process_in_bandwidth( $ ) {
    my $in_rate     = shift;
    
    return 0 if $in_rate eq '-';

    my $in_burst    = '10kb';
    my $in_avrate   = 0;
    my $in_band     = $in_rate;
    my $burst;
    my $in_interval = '250ms';
    my $in_decay    = '4sec';

    if ( $in_rate =~ s/^~// ) {
	require_capability 'BASIC_FILTER', 'An estimated policing filter', 's';

	if ( $in_rate =~ /:/ ) {
	    ( $in_rate, $in_interval, $in_decay ) = split /:/, $in_rate, 3;
	    fatal_error "Invalid IN-BANDWIDTH ($in_band)" unless supplied( $in_interval ) && supplied( $in_decay );
	    fatal_error "Invalid Interval ($in_interval)" unless $in_interval =~ /^(?:(?:250|500)ms|(?:1|2|4|8)sec)$/;
	    fatal_error "Invalid Decay ($in_decay)"       unless $in_decay    =~ /^(?:500ms|(?:1|2|4|8|16|32|64)sec)$/;
	    
	    if ( $in_decay =~ /ms/ ) {
		fatal_error "Decay must be at least twice the interval" unless $in_interval eq '250ms';
	    } else {
		unless ( $in_interval =~ /ms/ ) {
		    my ( $interval, $decay ) = ( $in_interval, $in_decay );
		    $interval =~ s/sec//;
		    $decay    =~ s/sec//;

		    fatal_error "Decay must be at least twice the interval" unless $decay > $interval;
		} 
	    }
	}
	    
	$in_avrate = rate_to_kbit( $in_rate );
	$in_rate = 0; 
    } else {
	if ( $in_band =~ /:/ ) {
	    ( $in_band, $burst ) = split /:/, $in_rate, 2;
	    fatal_error "Invalid burst ($burst)" unless $burst  =~ /^\d+(k|kb|m|mb|mbit|kbit|b)?$/;
	    $in_burst = $burst;
	}

	$in_rate = rate_to_kbit( $in_band );
	
    }

    [ $in_rate, $in_burst, $in_avrate, $in_interval, $in_decay ];
}

sub handle_in_bandwidth( $$ ) {
    my ($physical, $arrayref ) = @_;

    return 1 unless $arrayref;

    my ($in_rate, $in_burst, $in_avrate, $in_interval, $in_decay ) = @$arrayref;

    emit ( "run_tc qdisc add dev $physical handle ffff: ingress" );
    
    if ( have_capability 'BASIC_FILTER' ) {
	if ( $in_rate ) {
	    emit( "run_tc filter add dev $physical parent ffff: protocol all prio 10 basic \\",
		  "    police mpu 64 rate ${in_rate}kbit burst $in_burst action drop\n" );
	} else {
	    emit( "run_tc filter add dev $physical parent ffff: protocol all prio 10 \\",
		  "    estimator $in_interval $in_decay basic \\",
		  "    police avrate ${in_avrate}kbit action drop\n" );
	}
    } else {
	emit( "run_tc filter add dev $physical parent ffff: protocol all prio 10 \\" ,
	      "    u32 match ip src "  . ALLIPv4 . ' \\' ,
	      "    police rate ${in_rate}kbit burst $in_burst drop flowid :1",
	      '',
	      "run_tc filter add dev $physical parent ffff: protocol all prio 10 \\" ,
	      "    u32 match ip6 src " . ALLIPv6 . ' \\' ,
	      "    police rate ${in_rate}kbit burst $in_burst drop flowid :1\n" );
    }
}
	
sub process_flow($) {
    my $flow = shift;

    my @flow = split /,/, $flow;

    for ( @flow ) {
	fatal_error "Invalid flow key ($_)" unless $flow_keys{$_};
    }

    $flow;
}

sub process_simple_device() {
    my ( $device , $type , $in_rate , $out_part ) = split_line 'tcinterfaces', { interface => 0, type => 1, in_bandwidth => 2, out_bandwidth => 3 };

    fatal_error 'INTERFACE must be specified'      if $device eq '-';
    fatal_error "Duplicate INTERFACE ($device)"    if $tcdevices{$device};
    fatal_error "Invalid INTERFACE name ($device)" if $device =~ /[:+]/;

    my $number = in_hexp( $tcdevices{$device} = ++$devnum );

    fatal_error "Unknown interface( $device )" unless known_interface $device;

    my $physical = physical_name $device;
    my $dev      = chain_base( $physical );

    push @tcdevices, $device;

    if ( $type ne '-' ) {
	if ( lc $type eq 'external' ) {
	    $type = 'nfct-src';
	} elsif ( lc $type eq 'internal' ) {
	    $type = 'dst';
	} else {
	    fatal_error "Invalid TYPE ($type)";
	}
    }

    $in_rate = process_in_bandwidth( $in_rate );


    emit( '',
	  '#',
	  "# Setup Simple Traffic Shaping for $physical",
	  '#',
	  "setup_${dev}_tc() {"
	);

    push_indent;

    emit "if interface_is_up $physical; then";

    push_indent;

    emit ( "qt \$TC qdisc del dev $physical root",
	   "qt \$TC qdisc del dev $physical ingress\n"
	 );

    handle_in_bandwidth( $physical, $in_rate );

    if ( $out_part ne '-' ) {
	my ( $out_bandwidth, $burst, $latency, $peak, $minburst ) = split ':', $out_part;

	fatal_error "Invalid Out-BANDWIDTH ($out_part)" if ( defined $minburst && $minburst =~ /:/ ) || $out_bandwidth eq '';

	$out_bandwidth = rate_to_kbit( $out_bandwidth );

	my $command = "run_tc qdisc add dev $physical root handle $number: tbf rate ${out_bandwidth}kbit";

	if ( supplied $burst ) {
	    fatal_error "Invalid burst ($burst)" unless $burst =~ /^\d+(?:\.\d+)?(k|kb|m|mb|mbit|kbit|b)?$/;
	    $command .= " burst $burst";
	} else {
	    $command .= ' burst 10kb';
	}

	if ( supplied $latency ) {
	    fatal_error "Invalid latency ($latency)" unless $latency =~ /^\d+(?:\.\d+)?(s|sec|secs|ms|msec|msecs|us|usec|usecs)?$/;
	    $command .= " latency $latency";
	} else {
	    $command .= ' latency 200ms';
	}

	$command .= ' mpu 64'; #Assume Ethernet

	if ( supplied $peak ) {
	    fatal_error "Invalid peak ($peak)" unless $peak =~ /^\d+(?:\.\d+)?(k|kb|m|mb|mbit|kbit|b)?$/;
	    $command .= " peakrate $peak";
	}

	if ( supplied $minburst ) {
	    fatal_error "Invalid minburst ($minburst)" unless $minburst =~ /^\d+(?:\.\d+)?(k|kb|m|mb|mbit|kbit|b)?$/;
	    $command .= " minburst $minburst";
	}

	emit $command;

	my $id = $number; $number = in_hexp( $devnum | 0x100 );

	emit "run_tc qdisc add dev $physical parent $id: handle $number: prio bands 3 priomap $config{TC_PRIOMAP}";
    } else {
	emit "run_tc qdisc add dev $physical root handle $number: prio bands 3 priomap $config{TC_PRIOMAP}";
    }

    for ( my $i = 1; $i <= 3; $i++ ) {
	emit "run_tc qdisc add dev $physical parent $number:$i handle ${number}${i}: sfq quantum 1875 limit 127 perturb 10";
	emit "run_tc filter add dev $physical protocol all prio 2 parent $number: handle $i fw classid $number:$i";
	emit "run_tc filter add dev $physical protocol all prio 1 parent ${number}$i: handle ${number}${i} flow hash keys $type divisor 1024" if $type ne '-' && have_capability 'FLOW_FILTER';
	emit '';
    }
    
    emit( "run_tc filter add dev $physical parent $number:0 protocol all prio 1 u32" .
	  "\\\n    match ip protocol 6 0xff" .
	  "\\\n    match u8 0x05 0x0f at 0" .
	  "\\\n    match u16 0x0000 0xffc0 at 2" .
	  "\\\n    match u8 0x10 0xff at 33 flowid $number:1\n" );

    emit( "run_tc filter add dev $physical parent $number:0 protocol all prio 1 u32" .
	  "\\\n    match ip6 protocol 6 0xff" .
	  "\\\n    match u8 0x05 0x0f at 0" .
	  "\\\n    match u16 0x0000 0xffc0 at 2" .
	  "\\\n    match u8 0x10 0xff at 33 flowid $number:1\n" );

    save_progress_message_short qq("   TC Device $physical defined.");

    pop_indent;
    emit 'else';
    push_indent;

    emit qq(error_message "WARNING: Device $physical is not in the UP state -- traffic-shaping configuration skipped");
    pop_indent;
    emit 'fi';
    pop_indent;
    emit "}\n";

    progress_message "  Simple tcdevice \"$currentline\" $done.";
}

sub validate_tc_device( ) {
    my ( $device, $inband, $outband , $options , $redirected ) = split_line 'tcdevices', { interface => 0, in_bandwidth => 1, out_bandwidth => 2, options => 3, redirect => 4 };

    fatal_error 'INTERFACE must be specified' if $device eq '-';
    fatal_error "Invalid tcdevices entry"     if $outband eq '-';

    my $devnumber;

    if ( $device =~ /:/ ) {
	( my $number, $device, my $rest )  = split /:/, $device, 3;

	fatal_error "Invalid NUMBER:INTERFACE ($device:$number:$rest)" if defined $rest;

	if ( defined $number ) {
	    $number = normalize_hex( $number );
	    $devnumber = hex_value( $number );
	    fatal_error "Invalid device NUMBER ($number)" unless defined $devnumber && $devnumber && $devnumber < 256;
	    fatal_error "Duplicate interface number ($number)" if defined $devnums[ $devnumber ];
	} else {
	    fatal_error "Missing interface NUMBER";
	}
    } else {
	1 while $devnums[++$devnum];

	if ( ( $devnumber = $devnum ) > 255 ) {
	    fatal_error "Attempting to assign a device number > 255";
	}
    }

    $devnums[ $devnumber ] = $device;

    fatal_error "Duplicate INTERFACE ($device)"    if $tcdevices{$device};
    fatal_error "Invalid INTERFACE name ($device)" if $device =~ /[:+]/;

    my ( $classify, $pfifo, $flow, $qdisc )  = (0, 0, '', 'htb' );

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
	    } elsif ( $option eq 'hfsc' ) {
		$qdisc = 'hfsc';
	    } elsif ( $option eq 'htb' ) {
		$qdisc = 'htb';
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

	for my $rdevice ( @redirected ) {
	    fatal_error "Invalid device name ($rdevice)" if $rdevice =~ /[:+]/;
	    my $rdevref = $tcdevices{$rdevice};
	    fatal_error "REDIRECTED device ($rdevice) has not been defined in this file" unless $rdevref;
	    fatal_error "IN-BANDWIDTH must be zero for REDIRECTED devices" if $rdevref->{in_bandwidth} != 0;
	}
    }

    $inband = process_in_bandwidth( $inband );

    $tcdevices{$device} = { in_bandwidth  => $inband,
			    out_bandwidth => rate_to_kbit( $outband ) . 'kbit',
			    number        => $devnumber,
			    classify      => $classify,
			    flow          => $flow,
			    pfifo         => $pfifo,
			    tablenumber   => 1 ,
			    redirected    => \@redirected,
			    default       => 0,
			    nextclass     => 2,
			    qdisc         => $qdisc,
			    guarantee     => 0,
			    name          => $device,
			    physical      => physical_name $device,
			    filters       => []
			  } ,

    push @tcdevices, $device;

    $tcclasses{$device} = {};

    progress_message "  Tcdevice \"$currentline\" $done.";
}

sub convert_rate( $$$$ ) {
    my ($full, $rate, $column, $max) = @_;

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
    fatal_error "$column ($_[1]) exceeds $max (${full}kbit)" if $rate > $full;

    $rate;
}

sub convert_delay( $ ) {
    my $delay = shift;

    return 0 unless $delay;
    return $1 if $delay =~ /^(\d+)(ms)?$/;
    fatal_error "Invalid Delay ($delay)";
}

sub convert_size( $ ) {
    my $size = shift;
    return '' unless $size;
    return $1 if $size =~ /^(\d+)b?$/;
    fatal_error "Invalid Size ($size)";
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

sub validate_tc_class( ) {
    my ( $devclass, $mark, $rate, $ceil, $prio, $options ) =
	split_line 'tcclasses file', { interface => 0, mark => 1, rate => 2, ceil => 3, prio => 4, options => 5 };
    my $classnumber = 0;
    my $devref;
    my $device = $devclass;
    my $occurs = 1;
    my $parentclass = 1;
    my $parentref;

    fatal_error 'INTERFACE must be specified' if $devclass eq '-';
    fatal_error 'CEIL must be specified'      if $ceil eq '-';

    if ( $devclass =~ /:/ ) {
	( $device, my ($number, $subnumber, $rest ) )  = split /:/, $device, 4;
	fatal_error "Invalid INTERFACE:CLASS ($devclass)" if defined $rest;

	if ( $device =~ /^[\da-fA-F]+$/ && ! $tcdevices{$device} ) {
	    ( $number , $classnumber ) = ( hex_value $device, hex_value $number );
	    ( $device , $devref) = dev_by_number( $number );
	} else {
	    $classnumber = hex_value $number;
	    ($device, $devref ) = dev_by_number( $device);
	    $number = $devref->{number};
	}

	if ( defined $number ) {
	    if ( defined $subnumber ) {
		fatal_error "Invalid interface/class number ($devclass)" unless defined $classnumber && $classnumber;
		$parentclass = $classnumber;
		$classnumber = hex_value $subnumber;
	    }

	    fatal_error "Invalid interface/class number ($devclass)" unless defined $classnumber && $classnumber && $classnumber < 0x8000;
	    fatal_error "Reserved class number (1)" if $classnumber == 1;
	    fatal_error "Duplicate interface:class number ($number:$classnumber}" if $tcclasses{$device}{$classnumber};
	} else {
	    fatal_error "Missing interface NUMBER";
	}
    } else {
	($device, $devref ) = dev_by_number( $device );
	fatal_error "Missing class NUMBER" if $devref->{classify};
    }

    my $full    = rate_to_kbit $devref->{out_bandwidth};
    my $ratemax = $full;
    my $ceilmax = $full;
    my $ratename = 'OUT-BANDWIDTH';
    my $ceilname = 'OUT-BANDWIDTH';

    my $tcref = $tcclasses{$device};

    my $markval = 0;

    if ( $mark ne '-' ) {
	if ( $devref->{classify} ) {
	    warning_message "INTERFACE $device has the 'classify' option - MARK value ($mark) ignored";
	} else {
	    fatal_error "MARK may not be specified when TC_BITS=0" unless $config{TC_BITS};

	    $markval = numeric_value( $mark );
	    fatal_error "Invalid MARK ($markval)" unless defined $markval;

	    fatal_error "Invalid Mark ($mark)" unless $markval <= $globals{TC_MAX};

	    if ( $classnumber ) {
		fatal_error "Duplicate Class NUMBER ($classnumber)" if $tcref->{$classnumber};
	    } else {
		$classnumber = $config{TC_BITS} >= 14 ? $devref->{nextclass}++ : hex_value( $devnum . $markval );
		fatal_error "Duplicate MARK ($mark)" if $tcref->{$classnumber};
	    }
	}
    } else {
	fatal_error "Duplicate Class NUMBER ($classnumber)" if $tcref->{$classnumber};
    }

    if ( $parentclass != 1 ) {
	#
	# Nested Class
	#
	$parentref = $tcref->{$parentclass};
	my $parentnum = in_hexp $parentclass;
	fatal_error "Unknown Parent class ($parentnum)" unless $parentref && $parentref->{occurs} == 1;
	fatal_error "The class ($parentnum) specifies UMAX and/or DMAX; it cannot serve as a parent" if $parentref->{dmax};
	fatal_error "The class ($parentnum) specifies flow; it cannot serve as a parent"             if $parentref->{flow};
	fatal_error "The default class ($parentnum) may not have sub-classes"                        if $devref->{default} == $parentclass;
	$parentref->{leaf} = 0;
	$ratemax  = $parentref->{rate};
	$ratename = q(the parent class's RATE);
	$ceilmax = $parentref->{ceiling};
	$ceilname = q(the parent class's CEIL);
    }

    my ( $umax, $dmax ) = ( '', '' );

    if ( $devref->{qdisc} eq 'hfsc' ) {
	( my $trate , $dmax, $umax , my $rest ) = split ':', $rate , 4;

	fatal_error "Invalid RATE ($rate)" if defined $rest;

	$rate = convert_rate ( $ratemax, $trate, 'RATE', $ratename );
	$dmax = convert_delay( $dmax );
	$umax = convert_size( $umax );
	fatal_error "DMAX must be specified when UMAX is specified" if $umax && ! $dmax;
	$parentclass ||= 1;
    } else {
	$rate = convert_rate ( $ratemax, $rate, 'RATE' , $ratename );
    }

    if ( $parentref ) {
	warning_message "Total RATE of sub classes ($parentref->{guarantee}kbits) exceeds RATE of parent class ($parentref->{rate}kbits)" if ( $parentref->{guarantee} += $rate ) > $parentref->{rate};
    } else {
	warning_message "Total RATE of classes ($devref->{guarantee}kbits) exceeds OUT-BANDWIDTH (${full}kbits)" if ( $devref->{guarantee} += $rate ) > $full;
    }

    fatal_error "Invalid PRIO ($prio)" unless defined numeric_value $prio;

    $tcref->{$classnumber} = { tos       => [] ,
			       rate      => $rate ,
			       umax      => $umax ,
			       dmax      => $dmax ,
			       ceiling   => convert_rate( $ceilmax, $ceil, 'CEIL' , $ceilname ) ,
			       priority  => $prio eq '-' ? 1 : $prio ,
			       mark      => $markval ,
			       flow      => '' ,
			       pfifo     => 0,
			       occurs    => 1,
			       parent    => $parentclass,
			       leaf      => 1,
			       guarantee => 0,
			       limit     => 127,
			     };

    $tcref = $tcref->{$classnumber};

    fatal_error "RATE ($tcref->{rate}) exceeds CEIL ($tcref->{ceiling})" if $tcref->{rate} > $tcref->{ceiling};

    unless ( $options eq '-' ) {
	for my $option ( split_list1 "\L$options", 'option' ) {
	    my $optval = $tosoptions{$option};

	    $option = "tos=$optval" if $optval;

	    if ( $option eq 'default' ) {
		fatal_error "Only one default class may be specified for device $device" if $devref->{default};
		fatal_error "The $option option is not valid with 'occurs" if $tcref->{occurs} > 1;
		$devref->{default} = $classnumber;
	    } elsif ( $option eq 'tcp-ack' ) {
		fatal_error "The $option option is not valid with 'occurs" if $tcref->{occurs} > 1;
		$tcref->{tcp_ack} = 1;
	    } elsif ( $option =~ /^tos=0x[0-9a-f]{2}$/ ) {
		fatal_error "The $option option is not valid with 'occurs" if $tcref->{occurs} > 1;
		( undef, $option ) = split /=/, $option;
		push @{$tcref->{tos}}, "$option/0xff";
	    } elsif ( $option =~ /^tos=0x[0-9a-f]{2}\/0x[0-9a-f]{2}$/ ) {
		fatal_error "The $option option is not valid with 'occurs" if $tcref->{occurs} > 1;
		( undef, $option ) = split /=/, $option;
		push @{$tcref->{tos}}, $option;
	    } elsif ( $option =~ /^flow=(.*)$/ ) {
		fatal_error "The 'flow' option is not allowed with 'pfifo'" if $tcref->{pfifo};
		$tcref->{flow} = process_flow $1;
	    } elsif ( $option eq 'pfifo' ) {
		fatal_error "The 'pfifo'' option is not allowed with 'flow='" if $tcref->{flow};
		$tcref->{pfifo} = 1;
	    } elsif ( $option =~ /^occurs=(\d+)$/ ) {
		my $val = $1;
		$occurs = numeric_value($val);

		fatal_error q(The 'occurs' option is only valid for IPv4)           if $family == F_IPV6;
		fatal_error q(The 'occurs' option may not be used with 'classify')  if $devref->{classify};
		fatal_error "Invalid 'occurs' ($val)"                               unless defined $occurs && $occurs > 1 && $occurs <= 256;
		fatal_error "Invalid 'occurs' ($val)"                               if $occurs > $globals{TC_MAX};
		fatal_error q(Duplicate 'occurs')                                   if $tcref->{occurs} > 1;
		fatal_error q(The 'occurs' option is not valid with 'default')      if $devref->{default} == $classnumber;
		fatal_error q(The 'occurs' option is not valid with 'tos')          if @{$tcref->{tos}};
		warning_message "MARK ($mark) is ignored on an occurring class"     if $mark ne '-';

		$tcref->{occurs} = $occurs;
		$devref->{occurs} = 1;
	    } elsif ( $option =~ /^limit=(\d+)$/ ) {
		warning_message "limit ignored with pfifo queuing" if $tcref->{pfifo};
		fatal_error "Invalid limit ($1)" if $1 < 3 || $1 > 128;
		$tcref->{limit} = $1;
	    } else {
		fatal_error "Unknown option ($option)";
	    }
	}
    }

    unless ( $devref->{classify} || $occurs > 1 ) {
	fatal_error "Missing MARK" if $mark eq '-';
	warning_message "Class NUMBER ignored -- INTERFACE $device does not have the 'classify' option"	if $devclass =~ /:/;
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
					       parent   => $parentclass,
					       limit    => $tcref->{limit},
					     };
	push @tcclasses, "$device:$classnumber";
    };

    progress_message "  Tcclass \"$currentline\" $done.";
}

my %validlengths = ( 32 => '0xffe0', 64 => '0xffc0', 128 => '0xff80', 256 => '0xff00', 512 => '0xfe00', 1024 => '0xfc00', 2048 => '0xf800', 4096 => '0xf000', 8192 => '0xe000' );

#
# Process a record from the tcfilters file
#
sub process_tc_filter() {

    my ( $devclass, $source, $dest , $proto, $portlist , $sportlist, $tos, $length ) = split_line 'tcfilters file', { class => 0, source => 1, dest => 2, proto => 3, dport => 4, sport => 5, tos => 6, length => 7 };

    fatal_error 'CLASS must be specified' if $devclass eq '-';

    my ($device, $class, $rest ) = split /:/, $devclass, 3;

    our $lastdevice;

    fatal_error "Invalid INTERFACE:CLASS ($devclass)" if defined $rest || ! ($device && $class );

    my ( $ip, $ip32, $prio , $lo ) = $family == F_IPV4 ? ('ip', 'ip', 10, 2 ) : ('ipv6', 'ip6', 11 , 4 );

    my $devref;

    if ( $device =~ /^[\da-fA-F]+$/ && ! $tcdevices{$device} ) {
	( $device, $devref ) = dev_by_number( hex_value( $device ) );
    } else {
	( $device , $devref ) = dev_by_number( $device );
    }

    my $devnum = in_hexp $devref->{number};

    my $tcref = $tcclasses{$device};

    my $filtersref = $devref->{filters};

    fatal_error "No Classes were defined for INTERFACE $device" unless $tcref;

    my $classnum = hex_value $class;

    fatal_error "Invalid CLASS ($class)" unless defined $classnum;

    $tcref = $tcref->{$classnum};

    fatal_error "Unknown CLASS ($devclass)"                  unless $tcref && $tcref->{occurs};
    fatal_error "Filters may not specify an occurring CLASS" if $tcref->{occurs} > 1;

    unless ( $tcref->{leaf} ) {
	warning_message "Filter specifying a non-leaf CLASS ($devnum:$class) ignored";
	return;
    }

    my $have_rule = 0;

    my $rule = "filter add dev $devref->{physical} protocol $ip parent $devnum:0 prio $prio u32";

    if ( $source ne '-' ) {
	my ( $net , $mask ) = decompose_net( $source );
	$rule .= "\\\n   match $ip32 src $net/$mask";
	$have_rule = 1;
    }

    if ( $dest ne '-' ) {
	my ( $net , $mask ) = decompose_net( $dest );
	$rule .= "\\\n   match $ip32 dst $net/$mask";
	$have_rule = 1;
    }

    if ( $tos ne '-' ) {
	my $tosval = $tosoptions{$tos};
	my $mask;

	$tosval = $tos unless $tosval;

	if ( $tosval =~ /^0x[0-9a-f]{2}$/ ) {
	    $mask = '0xff';
	} elsif ( $tosval =~ /^(0x[0-9a-f]{2})\/(0x[0-9a-f]{2})$/ ) {
	    $tosval = $1;
	    $mask   = $2;
	} else {
	    fatal_error "Invalid TOS ($tos)";
	}

	$rule .= "\\\n  match $ip32 tos $tosval $mask";
	$have_rule = 1;
    }

    if ( $length ne '-' ) {
	my $len = numeric_value( $length ) || 0;
	my $mask = $validlengths{$len};
	fatal_error "Invalid LENGTH ($length)" unless $mask;
	$rule .="\\\n   match u16 0x0000 $mask at $lo";
	$have_rule = 1;
    }

    my $protonumber = 0;

    unless ( $proto eq '-' ) {
	$protonumber = resolve_proto $proto;
	fatal_error "Unknown PROTO ($proto)" unless defined $protonumber;
	if ( $protonumber ) {
	    $rule .= "\\\n   match $ip32 protocol $protonumber 0xff";
	    $have_rule = 1;
	}
    }

    if ( $portlist eq '-' && $sportlist eq '-' ) {
	if ( $have_rule ) {
	    push @$filtersref , ( "\nrun_tc $rule\\" ,
				  "   flowid $devnum:$class" ,
				  '' );
	} else {
	    warning_message "Degenerate tcfilter ignored";
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

	    push @$filtersref, ( "\nrun_tc filter add dev $devref->{physical} parent $devnum:0 protocol $ip prio $prio handle $tnum: u32 divisor 1" );
	}
	#
	# And link to it using the current contents of $rule
	#
	if ( $family == F_IPV4 ) {
	    push @$filtersref, ( "\nrun_tc $rule\\" ,
				 "   link $tnum:0 offset at 0 mask 0x0F00 shift 6 plus 0 eat" );
	} else {
	    push @$filtersref, ( "\nrun_tc $rule\\" ,
				 "   link $tnum:0 offset plus 40 eat" );
	}    
	#
	# The rule to match the port(s) will be inserted into the new table
	#
	$rule     = "filter add dev $devref->{physical} protocol $ip parent $devnum:0 prio $prio u32 ht $tnum:0";

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
			$rule1 = "match u32 0x${sport}0000 0x${smask}0000 at nexthdr+0" ,
		    }

		    push @$filtersref, ( "\nrun_tc $rule\\" ,
					 "   $rule1\\" ,
					 "   flowid $devnum:$class" );
		}
	    }
	} else {
	    fatal_error "Only TCP, UDP, SCTP and ICMP may specify DEST PORT"
		unless $protonumber == TCP || $protonumber == UDP || $protonumber == SCTP || $protonumber == ICMP;

	    for my $portrange ( split_list $portlist, 'port list' ) {
		if ( $protonumber == ICMP ) {
		    fatal_error "ICMP not allowed with IPv6" unless $family == F_IPV4;
		    fatal_error "SOURCE PORT(S) are not allowed with ICMP" if $sportlist ne '-';

		    my ( $icmptype , $icmpcode ) = split '/', validate_icmp( $portrange );

		    my $rule1 = "   match icmp type $icmptype 0xff";
		    $rule1   .= "\\\n   match icmp code $icmpcode 0xff" if defined $icmpcode;
		    push @$filtersref, ( "\nrun_tc ${rule}\\" ,
					 "$rule1\\" ,
					 "   flowid $devnum:$class" );
		} elsif ( $protonumber == IPv6_ICMP ) {
		    fatal_error "IPv6 ICMP not allowed with IPv4" unless $family == F_IPV4;
		    fatal_error "SOURCE PORT(S) are not allowed with IPv6 ICMP" if $sportlist ne '-';

		    my ( $icmptype , $icmpcode ) = split '/', validate_icmp6( $portrange );

		    my $rule1 = "   match icmp6 type $icmptype 0xff";
		    $rule1   .= "\\\n   match icmp6 code $icmpcode 0xff" if defined $icmpcode;
		    push @$filtersref, ( "\nrun_tc ${rule}\\" ,
					 "$rule1\\" ,
					 "   flowid $devnum:$class" );
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
			    push @$filtersref, ( "\nrun_tc ${rule}\\" ,
						 "   $rule1\\" ,
						 "   flowid $devnum:$class" );
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
					$rule2 = "match u32 0x${sport}0000 0x${smask}0000 at nexthdr+0" ,
				    }

				    push @$filtersref, ( "\nrun_tc ${rule}\\",
							 "   $rule1\\" ,
							 "   $rule2\\" ,
							 "   flowid $devnum:$class" );
				}
			    }
			}
		    }
		}
	    }
	}
    }

    emit '';

    if ( $family == F_IPV4 ) {

	progress_message "  IPv4 TC Filter \"$currentline\" $done";

	$currentline =~ s/\s+/ /g;
    } else {
	progress_message "  IPv6 TC Filter \"$currentline\" $done";

	$currentline =~ s/\s+/ /g;
    }

    emit '';

}

#
# Process the tcfilter file storing the compiled filters in the %tcdevices table
#
sub process_tcfilters() {

    my $fn = open_file 'tcfilters';

    if ( $fn ) {
	my @family = ( $family );
	
	first_entry( "$doing $fn..." );
	
	while ( read_a_line ) {
	    if ( $currentline =~ /^\s*IPV4\s*$/ ) {
		Shorewall::IPAddrs::initialize( $family = F_IPV4 ) unless $family == F_IPV4;
	    } elsif ( $currentline =~ /^\s*IPV6\s*$/ ) {
		Shorewall::IPAddrs::initialize( $family = F_IPV6 ) unless $family == F_IPV6;
	    } elsif ( $currentline =~ /^\s*ALL\s*$/ ) {
		$family = 0;
	    } elsif ( $family ) {
		process_tc_filter;
	    } else {
		push @family, $family;

		for ( F_IPV4, F_IPV6 ) {
		    Shorewall::IPAddrs::initialize( $family = $_ );
		    process_tc_filter;
		}

		Shorewall::IPAddrs::initialize( $family = pop @family );
	    }
	}

	Shorewall::IPAddrs::initialize( $family = pop @family );
    }
}

#
# Process a tcpri record
#
sub process_tc_priority() {
    my ( $band, $proto, $ports , $address, $interface, $helper ) = split_line1 'tcpri', { band => 0, proto => 1, port => 2, address => 3, interface => 4, helper => 5 };

    fatal_error 'BAND must be specified' if $band eq '-';

    if ( $band eq 'COMMENT' ) {
	process_comment;
	return;
    }

    fatal_error "Invalid tcpri entry" if ( $proto     eq '-' &&
					   $ports     eq '-' &&
					   $address   eq '-' &&
					   $interface eq '-' &&
					   $helper    eq '-' );


    my $val = numeric_value $band;

    fatal_error "Invalid PRIORITY ($band)" unless $val && $val <= 3;

    my $rule = do_helper( $helper ) . "-j MARK --set-mark $band";

    $rule .= join('', '/', in_hex( $globals{TC_MASK} ) ) if have_capability( 'EXMARK' );

    if ( $interface ne '-' ) {
	fatal_error "Invalid combination of columns" unless $address eq '-' && $proto eq '-' && $ports eq '-';

	my $forwardref = $mangle_table->{tcfor};

	add_rule( $forwardref ,
		  join( '', match_source_dev( $interface) , $rule ) ,
		  1 );
    } else {
	my $postref = $mangle_table->{tcpost};

	if ( $address ne '-' ) {
	    fatal_error "Invalid combination of columns" unless $proto eq '-' && $ports eq '-';
	    add_rule( $postref ,
		      join( '', match_source_net( $address) , $rule ) ,
		      1 );
	} else {
	    add_rule( $postref ,
		      join( '', do_proto( $proto, $ports, '-' , 0 ) , $rule ) ,
		      1 );

	    if ( $ports ne '-' ) {
		my $protocol = resolve_proto $proto;

		if ( $proto =~ /^ipp2p/ ) {
		    fatal_error "ipp2p may not be used when there are tracked providers and PROVIDER_OFFSET=0" if @routemarked_interfaces && $config{PROVIDER_OFFSET} == 0;
		    $ipp2p = 1;
		}

		add_rule( $postref ,
			  join( '' , do_proto( $proto, '-', $ports, 0 ) , $rule ) ,
			  1 )
		    unless $proto =~ /^ipp2p/ || $protocol == ICMP || $protocol == IPv6_ICMP;
	    }
	}
    }
}

#
# Process tcinterfaces
#
sub process_tcinterfaces() {

    my $fn = open_file 'tcinterfaces';

    if ( $fn ) {
	first_entry "$doing $fn...";
	process_simple_device while read_a_line;
    }
}

#
# Process tcpri
#
sub process_tcpri() {
    my $fn  = find_file 'tcinterfaces';
    my $fn1 = open_file 'tcpri';

    if ( $fn1 ) {
	first_entry
	    sub {
		progress_message2 "$doing $fn1...";
		warning_message "There are entries in $fn1 but $fn was empty" unless @tcdevices || $family == F_IPV6;
	    };

	process_tc_priority while read_a_line;

	clear_comment;

	if ( $ipp2p ) {
	    insert_irule( $mangle_table->{tcpost} ,
			  j => 'CONNMARK --restore-mark --ctmask ' . in_hex( $globals{TC_MASK} ) ,
			  0 ,
			  mark => '--mark 0/'   . in_hex( $globals{TC_MASK} )
			);

	    add_ijump( $mangle_table->{tcpost} ,
		       j    => 'CONNMARK --save-mark --ctmask '    . in_hex( $globals{TC_MASK} ),
		       mark => '! --mark 0/' . in_hex( $globals{TC_MASK} ) 
		     );
	}
    }
}

#
# Process the compilex traffic shaping files storing the configuration in %tcdevices and %tcclasses
#
sub process_traffic_shaping() {

    our $lastrule = '';

    my $fn = open_file 'tcdevices';

    if ( $fn ) {
	first_entry "$doing $fn...";

	validate_tc_device while read_a_line;
    }

    $devnum = $devnum > 10 ? 10 : 1;

    $fn = open_file 'tcclasses';

    if ( $fn ) {
	first_entry "$doing $fn...";

	validate_tc_class while read_a_line;
    }

    process_tcfilters;

    my $sfq = 0;
    my $sfqinhex;

    for my $devname ( @tcdevices ) {
	my $devref  = $tcdevices{$devname};
	my $defmark = in_hexp ( $devref->{default} || 0 );
	my $devnum  = in_hexp $devref->{number};
	my $r2q     = int calculate_r2q $devref->{out_bandwidth};

	fatal_error "No default class defined for device $devname" unless $devref->{default};

	my $device = physical_name $devname;

	unless ( $config{TC_ENABLED} eq 'Shared' ) {

	    my $dev = chain_base( $device );

	    emit( '',
		  '#',
		  "# Configure Traffic Shaping for $device",
		  '#',
		  "setup_${dev}_tc() {" );

	    push_indent;

	    emit "if interface_is_up $device; then";

	    push_indent;

	    emit ( "qt \$TC qdisc del dev $device root",
		   "qt \$TC qdisc del dev $device ingress",
		   "${dev}_mtu=\$(get_device_mtu $device)",
		   "${dev}_mtu1=\$(get_device_mtu1 $device)"
		 );

	    if ( $devref->{qdisc} eq 'htb' ) {
		emit ( "run_tc qdisc add dev $device root handle $devnum: htb default $defmark r2q $r2q" ,
		       "run_tc class add dev $device parent $devnum: classid $devnum:1 htb rate $devref->{out_bandwidth} \$${dev}_mtu1" );
	    } else {
		emit ( "run_tc qdisc add dev $device root handle $devnum: hfsc default $defmark" ,
		       "run_tc class add dev $device parent $devnum: classid $devnum:1 hfsc sc rate $devref->{out_bandwidth} ul rate $devref->{out_bandwidth}" );
	    }

	    if ( $devref->{occurs} ) {
		#
		# The following command may succeed yet generate an error message and non-zero exit status :-(. We thus run it silently
		# and check the result. Note that since this is the first filter added after the root qdisc was added, the 'ls | grep' test
		# is fairly robust
		#
		my $command = "\$TC filter add dev $device parent $devnum:0 prio 65535 protocol all fw";

		emit( qq(if ! qt $command ; then) ,
		      qq(    if ! \$TC filter list dev $device | grep -q 65535; then) ,
		      qq(        error_message "ERROR: Command '$command' failed"),
		      qq(        stop_firewall),
		      qq(        exit 1),
		      qq(    fi),
		      qq(fi) );
	    }

	    handle_in_bandwidth( $device, $devref->{in_bandwidth} );

	    for my $rdev ( @{$devref->{redirected}} ) {
		emit ( "run_tc qdisc add dev $rdev handle ffff: ingress" );
		emit( "run_tc filter add dev $rdev parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev $device > /dev/null" );
	    }

	    for my $class ( @tcclasses ) {
		#
		# The class number in the tcclasses array is expressed in decimal.
		#
		my ( $d, $decimalclassnum ) = split /:/, $class;

		next unless $d eq $devname;
		#
		# For inclusion in 'tc' commands, we also need the hex representation
		#
		my $classnum = in_hexp $decimalclassnum;
		#
		# The decimal value of the class number is also used as the key for the hash at $tcclasses{$device}
		#
		my $tcref    = $tcclasses{$devname}{$decimalclassnum};
		my $mark     = $tcref->{mark};
		my $devicenumber  = in_hexp $devref->{number};
		my $classid  = join( ':', $devicenumber, $classnum);
		my $rate     = "$tcref->{rate}kbit";
		my $quantum  = calculate_quantum $rate, calculate_r2q( $devref->{out_bandwidth} );

		$classids{$classid}=$device;

		my $priority = $tcref->{priority} << 8;
		my $parent   = in_hexp $tcref->{parent};
		
		emit ( "[ \$${dev}_mtu -gt $quantum ] && quantum=\$${dev}_mtu || quantum=$quantum" );

		if ( $devref->{qdisc} eq 'htb' ) {
		    emit ( "run_tc class add dev $device parent $devicenumber:$parent classid $classid htb rate $rate ceil $tcref->{ceiling}kbit prio $tcref->{priority} \$${dev}_mtu1 quantum \$quantum" );
		} else {
		    my $dmax = $tcref->{dmax};

		    if ( $dmax ) {
			my $umax = $tcref->{umax} ? "$tcref->{umax}b" : "\${${dev}_mtu}b";
			emit ( "run_tc class add dev $device parent $devicenumber:$parent classid $classid hfsc sc umax $umax dmax ${dmax}ms rate $rate ul rate $tcref->{ceiling}kbit" );
		    } else {
			emit ( "run_tc class add dev $device parent $devicenumber:$parent classid $classid hfsc sc rate $rate ul rate $tcref->{ceiling}kbit" );
		    }
		}

		if ( $tcref->{leaf} && ! $tcref->{pfifo} ) {
		    1 while $devnums[++$sfq];

		    $sfqinhex = in_hexp( $sfq);
		    if ( $devref->{qdisc} eq 'htb' ) {
			emit( "run_tc qdisc add dev $device parent $classid handle $sfqinhex: sfq quantum \$quantum limit $tcref->{limit} perturb 10" );
		    } else {
			emit( "run_tc qdisc add dev $device parent $classid handle $sfqinhex: sfq limit $tcref->{limit} perturb 10" );
		    }
		}
		#
		# add filters
		#
		unless ( $devref->{classify} ) {
		    emit "run_tc filter add dev $device protocol all parent $devicenumber:0 prio " . ( $priority | 20 ) . " handle $mark fw classid $classid" if $tcref->{occurs} == 1;
		}

		emit "run_tc filter add dev $device protocol all prio 1 parent $sfqinhex: handle $classnum flow hash keys $tcref->{flow} divisor 1024" if $tcref->{flow};
		#
		# options
		#
		emit( "run_tc filter add dev $device parent $devicenumber:0 protocol ip prio " . ( $priority | 10 ) . ' u32' .
		      "\\\n    match ip protocol 6 0xff" .
		      "\\\n    match u8 0x05 0x0f at 0" .
		      "\\\n    match u16 0x0000 0xffc0 at 2" .
		      "\\\n    match u8 0x10 0xff at 33 flowid $classid" ) if $tcref->{tcp_ack};

		for my $tospair ( @{$tcref->{tos}} ) {
		    my ( $tos, $mask ) = split q(/), $tospair;
		    emit "run_tc filter add dev $device parent $devicenumber:0 protocol ip prio " . ( $priority | 10 ) . " u32 match ip tos $tos $mask flowid $classid";
		}
		
		save_progress_message_short qq("   TC Class $classid defined.");
		emit '';

	    }

	    emit '';

	    emit "$_" for @{$devref->{filters}};
	
	    save_progress_message_short qq("   TC Device $device defined.");

	    pop_indent;
	    emit 'else';
	    push_indent;

	    emit qq(error_message "WARNING: Device $device is not in the UP state -- traffic-shaping configuration skipped");
	    pop_indent;
	    emit "fi\n";

	    pop_indent;
	    emit "}\n";
	} else {
	    for my $class ( @tcclasses ) {
		#
		# The class number in the tcclasses array is expressed in decimal.
		#
		my ( $d, $decimalclassnum ) = split /:/, $class;

		next unless $d eq $devname;
		#
		# For inclusion in 'tc' commands, we also need the hex representation
		#
		my $classnum = in_hexp $decimalclassnum;
		#
		# The decimal value of the class number is also used as the key for the hash at $tcclasses{$device}
		#
		my $devicenumber  = in_hexp $devref->{number};
		my $classid  = join( ':', $devicenumber, $classnum);

		$classids{$classid}=$device;
	    }
	}
    }
}

#
# Validate the TC configuration storing basic information in %tcdevices and %tcdevices
#
sub process_tc() {
    if ( $config{TC_ENABLED} eq 'Internal' || $config{TC_ENABLED} eq 'Shared' ) {
	process_traffic_shaping;
    } elsif ( $config{TC_ENABLED} eq 'Simple' ) {
	process_tcinterfaces;
    }
    #
    # The Providers module needs to know which devices are tc-enabled so that
    # it can call the appropriate 'setup_x_tc" function when the device is
    # enabled.

    my %empty;
    
    $config{TC_ENABLED} eq 'Shared' ? \%empty : \%tcdevices;
}

#
# Call the setup_${dev}_tc functions
#
sub setup_traffic_shaping() {
    save_progress_message q("Setting up Traffic Control...");

    for my $device ( @tcdevices ) {
	my $interfaceref = known_interface( $device );
	my $dev          = chain_base( $interfaceref ? $interfaceref->{physical} : $device );

	emit "setup_${dev}_tc";
    }
}

#
# Process a record in the secmarks file
#
sub process_secmark_rule() {
    my ( $secmark, $chainin, $source, $dest, $proto, $dport, $sport, $user, $mark ) =
	split_line1( 'Secmarks file' , { secmark => 0, chain => 1, source => 2, dest => 3, proto => 4, dport => 5, sport => 6, user => 7, mark => 8 } );

    fatal_error 'SECMARK must be specified' if $secmark eq '-';

    if ( $secmark eq 'COMMENT' ) {
	process_comment;
	return;
    }

    my %chns = ( T => 'tcpost'  ,
		 P => 'tcpre'   ,
		 F => 'tcfor'   ,
		 I => 'tcin'    ,
		 O => 'tcout'   , );

    my %state = ( N =>  'NEW' ,
		  I => 'INVALID',
		  NI => 'NEW,INVALID',
		  E =>  'ESTABLISHED' ,
		  ER => 'ESTABLISHED,RELATED',
		);

    my ( $chain , $state, $rest) = split ':', $chainin , 3;

    fatal_error "Invalid CHAIN:STATE ($chainin)" if $rest || ! $chain;

    my $chain1= $chns{$chain};

    fatal_error "Invalid or missing CHAIN ( $chain )" unless $chain1;
    fatal_error "USER/GROUP may only be used in the OUTPUT chain" if $user ne '-' && $chain1 ne 'tcout';

    if ( ( $state ||= '' ) ne '' ) {
	my $state1;
	fatal_error "Invalid STATE ( $state )" unless $state1 = $state{$state};
	$state = "$globals{STATEMATCH} $state1 ";
    }

    my $target = $secmark eq 'SAVE'    ? 'CONNSECMARK --save' :
	         $secmark eq 'RESTORE' ? 'CONNSECMARK --restore' :
		 "SECMARK --selctx $secmark";

    my $disposition = $target;

    $disposition =~ s/ .*//;

    expand_rule( ensure_mangle_chain( $chain1 ) ,
		 $restrictions{$chain1} ,
		 $state .
		 do_proto( $proto, $dport, $sport ) .
		 do_user( $user ) .
		 do_test( $mark, $globals{TC_MASK} ) ,
		 $source ,
		 $dest ,
		 '' ,
		 $target ,
		 '' ,
		 $disposition,
		 '' );

    progress_message "Secmarks rule \"$currentline\" $done";

}

#
# Process the tcrules file and setup traffic shaping
#
sub setup_tc() {

    if ( $config{MANGLE_ENABLED} ) {
	ensure_mangle_chain 'tcpre';
	ensure_mangle_chain 'tcout';

	if ( have_capability( 'MANGLE_FORWARD' ) ) {
	    ensure_mangle_chain 'tcfor';
	    ensure_mangle_chain 'tcpost';
	    ensure_mangle_chain 'tcin';
	}

	my @mark_part;

	if ( @routemarked_interfaces && ! $config{TC_EXPERT} ) {
	    @mark_part = ( mark => '--mark 0/' . in_hex( $globals{PROVIDER_MASK} ) );

	    unless ( $config{TRACK_PROVIDERS} ) {
		#
		# This is overloading TRACK_PROVIDERS a bit but sending tracked packets through PREROUTING is a PITA for users
		#
		for my $interface ( @routemarked_interfaces ) {
		    add_ijump $mangle_table->{PREROUTING} , j => 'tcpre', imatch_source_dev( $interface );
		}
	    }
	}

	add_ijump $mangle_table->{PREROUTING} , j => 'tcpre', @mark_part;
	add_ijump $mangle_table->{OUTPUT} ,     j => 'tcout', @mark_part;

	if ( have_capability( 'MANGLE_FORWARD' ) ) {
	    my $mask = have_capability 'EXMARK' ? have_capability 'FWMARK_RT_MASK' ? '/' . in_hex $globals{PROVIDER_MASK} : '' : '';

	    add_ijump $mangle_table->{FORWARD},      j => "MARK --set-mark 0${mask}" if $config{FORWARD_CLEAR_MARK};
	    add_ijump $mangle_table->{FORWARD} ,     j => 'tcfor';
	    add_ijump $mangle_table->{POSTROUTING} , j => 'tcpost';
	    add_ijump $mangle_table->{INPUT} ,       j => 'tcin';
	}
    }

    if ( $globals{TC_SCRIPT} ) {
	save_progress_message q('Setting up Traffic Control...');
	append_file $globals{TC_SCRIPT};
    } else {
	process_tcpri if $config{TC_ENABLED} eq 'Simple';
	setup_traffic_shaping unless $config{TC_ENABLED} eq 'Shared';
    }

    if ( $config{TC_ENABLED} ) {
	our  @tccmd = ( { match     => sub ( $ ) { $_[0] eq 'SAVE' } ,
			  target    => 'CONNMARK --save-mark --mask' ,
			  mark      => SMALLMARK ,
			  mask      => in_hex( $globals{TC_MASK} ) ,
			  connmark  => 1
			} ,
			{ match     => sub ( $ ) { $_[0] eq 'RESTORE' },
			  target    => 'CONNMARK --restore-mark --mask' ,
			  mark      => SMALLMARK ,
			  mask      => in_hex( $globals{TC_MASK} ) ,
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
			{ match     => sub ( $ ) { $_[0] =~ /^IPMARK/ },
			  target    => 'IPMARK' ,
			  mark      => NOMARK,
			  mask      => '',
			  connmark  => 0
			} ,
			{ match     => sub ( $ ) { $_[0] =~ '\|.*'} ,
			  target    => 'MARK --or-mark' ,
			  mark      => HIGHMARK ,
			  mask      => '' } ,
			{ match     => sub ( $ ) { $_[0] =~ '&.*' },
			  target    => 'MARK --and-mark' ,
			  mark      => HIGHMARK ,
			  mask      => '' ,
			  connmark  => 0
			} ,
			{ match     => sub ( $ ) { $_[0] =~ /^TPROXY/ },
			  target    => 'TPROXY',
			  mark      => HIGHMARK,
			  mask      => '',
			  connmark  => '' },
			{ match     => sub( $ ) { $_[0] =~ /^TTL/ },
			  target    => 'TTL',
			  mark      => NOMARK,
			  mask      => '',
			  connmark  => 0
			},
			{ match     => sub( $ ) { $_[0] =~ /^HL/ },
			  target    => 'HL',
			  mark      => NOMARK,
			  mask      => '',
			  connmark  => 0
			} 
		      );

	if ( my $fn = open_file 'tcrules' ) {

	    first_entry "$doing $fn...";

	    process_tc_rule while read_a_line;

	    clear_comment;
	}
    }

    if ( $config{MANGLE_ENABLED} ) {
	if ( my $fn = open_file 'secmarks' ) {

	    first_entry "$doing $fn...";

	    process_secmark_rule while read_a_line;

	    clear_comment;
	}

	handle_stickiness( $sticky );
    }
}

1;
