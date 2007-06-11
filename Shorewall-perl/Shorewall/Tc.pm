#
# Shorewall-perl 4.0 -- /usr/share/shorewall-perl/Shorewall/Tc.pm
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2007 - Tom Eastep (teastep@shorewall.net)
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
#       Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#
#   This module deals with Traffic Shaping and the tcrules file.
#
package Shorewall::Tc;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Chains;
use Shorewall::Interfaces;
use Shorewall::Providers;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_tc );
our @EXPORT_OK = qw( process_tc_rule );
our @VERSION = 1.00;

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
		    fw       => 0 ,
		    connmark => 1 ,
		    } ,
	    T  => { chain    => 'tcpost' ,
		    connmark => 0 ,
		    fw       => 0
		    } ,
	    CT => { chain    => 'tcpost' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0
		    } ,
	    C  => { target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0
		    }
	    );

use constant { NOMARK    => 0 ,
	       SMALLMARK => 1 ,
	       HIGHMARK  => 2
	       };

our @tccmd = ( { match     => sub ( $ ) { $_[0] eq 'SAVE' } ,
		 target    => 'CONNMARK --save-mark --mask' ,
		 mark      => SMALLMARK ,
		 mask      => '0xFF'
	       } ,
	      { match     => sub ( $ ) { $_[0] eq 'RESTORE' },
		target    => 'CONNMARK --restore-mark --mask' ,
		mark      => SMALLMARK ,
		mask      => '0xFF'
		} ,
	      { match     => sub ( $ ) { $_[0] eq 'CONTINUE' },
		target    => 'RETURN' ,
		mark      => NOMARK ,
		mask      => ''
		} ,
	      { match     => sub ( $ ) { $_[0] =~ '\|.*'} ,
		target    => 'MARK --or-mark' ,
		mark      => HIGHMARK ,
		mask      => '' } ,
	      { match     => sub ( $ ) { $_[0] =~ '&.*' },
		target    => 'MARK --and-mark ' ,
		mark      => HIGHMARK ,
		mask      => ''
		}
	      );

sub process_tc_rule( $$$$$$$$$$ ) {
    my ( $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos ) = @_;

    my $original_mark = $mark;

    ( $mark, my ( $designator, $remainder ) ) = split( /:/, $mark, 3 );

    fatal_error "Invalid MARK" if defined $remainder;

    my $chain  = $globals{MARKING_CHAIN};
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
		fatal_error "Invalid chain designator for source $firewall_zone" unless $tcsref->{fw};
	    }

	    $chain    = $tcsref->{chain}  if $tcsref->{chain};
	    $target   = $tcsref->{target} if $tcsref->{target};
	    $mark     = "$mark/0xFF"      if $connmark = $tcsref->{connmark};

	} else {
	    fatal_error "Invalid MARK ($original_mark)" unless $mark =~ /^([0-9]+|0x[0-9a-f]+)$/ and $designator =~ /^([0-9]+|0x[0-9a-f]+)$/;
	    $chain   = 'tcpost';
	    $classid = 1;
	    $mark    = $original_mark;
	    $target  = 'CLASSIFY --set-class';
	}
    }

    my $mask = 0xffff;

    my ($cmd, $rest) = split( '/', $mark, 2 );

    unless ( $classid ) {
      MARK:
	{
	    for my $tccmd ( @tccmd ) {
		if ( $tccmd->{match}($cmd) ) {
		    fatal_error "$mark not valid with :C[FPT]" if $connmark;
		    
		    $target      = "$tccmd->{target} ";
		    my $marktype = $tccmd->{mark};

		    if ( $marktype == NOMARK ) {
			$mark = ''
		    } else {
			$mark =~ s/^[|&]//;
		    }

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

	    validate_mark $mark;

	    fatal_error 'Marks < 256 may not be set in the PREROUTING chain when HIGH_ROUTE_MARKS=Yes'
		if $cmd && $chain eq 'tcpre' && numeric_value( $cmd ) <= 0xFF && $config{HIGH_ROUTE_MARKS};

	    $target =~ s/set-mark/or-mark/ if numeric_value( $cmd ) > 0xFF && ( $chain eq 'tcpre' || $chain eq 'tcout' );
	}
    }

    expand_rule
	ensure_chain( 'mangle' , $chain ) ,
	NO_RESTRICT ,
	do_proto( $proto, $ports, $sports) . do_test( $testval, $mask ) . do_tos( $tos ) ,
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
# Perl version of Arn Bernin's 'tc4shorewall'.
#
# TCDevices Table
#
# %tcdevices { <interface> -> {in_bandwidth => <value> ,
#                              out_bandwidth => <value>
#                              number => <ordinal>
#                              default => <default class mark value> }
#
my @tcdevices;
my %tcdevices;

#
# TCClasses Table
#
# %tcclasses { device    => <device> ,
#              mark      => <mark> ,
#              rate      => <rate> ,
#              ceiling   => <ceiling> ,
#              priority  => <priority> ,
#              options   => { tos  => [ <value1> , <value2> , ... ];
#                             tcp_ack => 1 ,
#                             ...
#

my @tcclasses;
my %tcclasses;

my $prefix = '1';

sub rate_to_kbit( $ ) {
    my $rate = $_[0];

    return $1          if $rate =~ /^(\d+)kbit$/i;
    return $1 * 1000   if $rate =~ /^(\d+)mbit$/i;
    return $1 * 8000   if $rate =~ /^(\d+)mbps$/i;
    return $1 * 8      if $rate =~ /^(\d+)kbps$/i;
    return $rate / 125 if $rate =~ /^\d+$/;
    fatal_error "Invalid Rate ( $rate )";
}

sub calculate_r2q( $ ) {
    my $rate = rate_to_kbit $_[0];
    my $r2q= $rate / 200 ;
    $r2q <= 5 ? 5 : $r2q;
}

sub calculate_quantum( $$ ) {
    my ( $rate, $r2q ) = @_;
    $rate = rate_to_kbit $rate;
    eval "int( ( $rate * 125 ) / $r2q )";
}

sub validate_tc_device( $$$ ) {
    my ( $device, $inband, $outband ) = @_;

    fatal_error "Duplicate device ( $device )"    if $tcdevices{$device};
    fatal_error "Invalid device name ( $device )" if $device =~ /[:+]/;

    rate_to_kbit $inband;
    rate_to_kbit $outband;

    $tcdevices{$device} = {};
    $tcdevices{$device}{in_bandwidth}  = $inband;
    $tcdevices{$device}{out_bandwidth} = $outband;

    push @tcdevices, $device;
}

sub convert_rate( $$ ) {
    my ($full, $rate) = @_;

    if ( $rate =~ /\bfull\b/ ) {
	$rate =~ s/\bfull\b/$full/g;
	$rate = eval "int( $rate )";
    } else {
	$rate = rate_to_kbit $rate
    }
	
    "${rate}kbit";
}

sub validate_tc_class( $$$$$$ ) {
    my ( $device, $mark, $rate, $ceil, $prio, $options ) = @_;

    my %tosoptions = ( 'tos-minimize-delay'       => 'tos=0x10/0x10' ,
		       'tos-maximize-throughput'  => 'tos=0x08/0x08' ,
		       'tos-maximize-reliability' => 'tos=0x04/0x04' ,
		       'tos-minimize-cost'        => 'tos=0x02/0x02' ,
		       'tos-normal-service'       => 'tos=0x00/0x1e' );

    my $devref = $tcdevices{$device};
    fatal_error "Unknown Device ( $device )" unless $devref;
    my $full  = rate_to_kbit $devref->{out_bandwidth};

    $tcclasses{$device} = {} unless $tcclasses{$device};
    my $tcref = $tcclasses{$device};

    fatal_error "Invalid Mark ( $mark )" unless $mark =~ /^([0-9]+|0x[0-9a-f]+)$/ && numeric_value( $mark ) < 0xff;

    my $markval = numeric_value( $mark );
    fatal_error "Duplicate Mark ( $mark )" if $tcref->{$markval};

    $tcref->{$markval} = {};
    $tcref             = $tcref->{$markval};
    $tcref->{tos}      = [];
    $tcref->{rate}     = convert_rate $full, $rate;
    $tcref->{ceiling}  = convert_rate $full, $ceil;
    $tcref->{priority} = $prio eq '-' ? 1 : $prio;

    unless ( $options eq '-' ) {
	for my $option ( split /,/, "\L$options" ) {
	    my $optval = $tosoptions{$option};

	    $option = $optval if $optval;

	    if ( $option eq 'default' ) {
		fatal_error "Only one default class may be specified for device $device" if $devref->{default};
		$devref->{default} = $markval;
	    } elsif ( $option eq 'tcp-ack' ) {
		$tcref->{tcp_ack} = 1;
	    } elsif ( $option =~ /^tos=0x[0-9a-f]{2}$/ ) {
		( undef, $option ) = split /=/, $option;
		push @{$tcref->{tos}}, "$option/0xff";
	    } elsif ( $option =~ /^tos=0x[0-9a-f]{2}\/0x[0-9a-f]{2}$/ ) {
		( undef, $option ) = split /=/, $option;
		push @{$tcref->{tos}}, $option;
	    } else {
		fatal_error "Unknown option ( $option )";
	    }
	}
    }

    push @tcclasses, "$device:$markval";
}

sub setup_traffic_shaping() {
    save_progress_message "Setting up Traffic Control...";

    my $fn = open_file 'tcdevices';

    if ( $fn ) {
	my $first_entry = 1;

	while ( read_a_line ) {

	    if ( $first_entry ) {
		progress_message2 "$doing $fn...";
		$first_entry = 0;
	    }

	    my ( $device, $inband, $outband ) = split_line 3, 3, 'tcdevices';

	    fatal_error "Invalid tcdevices entry" if $outband eq '-';
	    validate_tc_device( $device, $inband, $outband );
	}
    }

    $fn = open_file 'tcclasses';

    if ( $fn ) {
	my $first_entry = 1;

	while ( read_a_line ) {

	    if ( $first_entry ) {
		progress_message2 "$doing $fn...";
		$first_entry = 0;
	    }

	    my ( $device, $mark, $rate, $ceil, $prio, $options ) = split_line 4, 6, 'tcclasses file';

	    validate_tc_class( $device, $mark, $rate, $ceil, $prio, $options );
	}
    }

    my $devnum = 1;

    $prefix = '10' if @tcdevices > 10;

    for my $device ( @tcdevices ) {
	my $dev     = chain_base( $device );
	my $devref  = $tcdevices{$device};
	my $defmark = $devref->{default} || 0;

	$defmark = "${prefix}${defmark}" if $defmark;

	emit "if interface_is_usable $device; then";

	push_indent;

	emitj( "${dev}_exists=Yes",
	       "qt tc qdisc del dev $device root",
	       "qt tc qdisc del dev $device ingress",
	       "run_tc qdisc add dev $device root handle $devnum: htb default $defmark",
	       "${dev}_mtu=\$(get_device_mtu $device)",
	       "${dev}_mtu1=\$(get_device_mtu1 $device)",
	       "run_tc class add dev $device parent $devnum: classid $devnum:1 htb rate $devref->{out_bandwidth} \$${dev}_mtu1"
	       );

	my $inband = rate_to_kbit $devref->{in_bandwidth};

	if ( $inband ) {
	    emitj( "run_tc qdisc add dev $device handle ffff: ingress",
		   "run_tc filter add dev $device parent ffff: protocol ip prio 50 u32 match ip src 0.0.0.0/0 police rate ${inband}kbit burst 10k drop flowid :1"
		   );
	}

	$devref->{number} = $devnum++;

	save_progress_message_short "   TC Device $device defined.";

	pop_indent;
	emit 'else';
	push_indent;

	emit qq(error_message "WARNING: Device $device not up and configured -- traffic-shaping configuration skipped");
	emit "${dev}_exists=";
	pop_indent;
	emit "fi\n";
    }

    my $lastdevice = '';

    for my $class ( @tcclasses ) {
	my ( $device, $mark ) = split /:/, $class;
	my $devref  = $tcdevices{$device};
	my $tcref   = $tcclasses{$device}{$mark};
	my $devnum  = $devref->{number};
	my $classid = "$devnum:${prefix}${mark}";
	my $rate    = $tcref->{rate};
	my $quantum = calculate_quantum $rate, calculate_r2q( $devref->{out_bandwidth} );
	my $dev     = chain_base $device;

	if ( $lastdevice ne $device ) {
	    if ( $lastdevice ) {
		pop_indent;
		emit "fi\n";
	    }

	    emit qq(if [ -n "\$${dev}_exists" ]; then);
	    push_indent;
	    $lastdevice = $device;
	}

	emitj( "[ \$${dev}_mtu -gt $quantum ] && quantum=\$${dev}_mtu || quantum=$quantum",
	       "run_tc class add dev $device parent $devref->{number}:1 classid $classid htb rate $rate ceil $tcref->{ceiling} prio $tcref->{priority} \$${dev}_mtu1 quantum \$quantum",
	       "run_tc qdisc add dev $device parent $classid handle ${prefix}${mark}: sfq perturb 10"
	       );
	#
	# add filters
	#
	if ( "$capabilities{CLASSIFY_TARGET}" && known_interface $device ) {
	    add_rule ensure_chain( 'mangle' , 'tcpost' ), " -o $device -m mark --mark $mark/0xFF -j CLASSIFY --set-class $classid";
	} else {
	    emit "run_tc filter add dev $device protocol ip parent $devnum:0 prio 1 handle $mark fw classid $classid";
	}
	#
	#options
	#
	emit "run_tc filter add dev $device parent $devref->{number}:0 protocol ip prio 10 u32 match ip protocol 6 0xff match u8 0x05 0x0f at 0 match u16 0x0000 0xffc0 at 2 match u8 0x10 0xff at 33 flowid $classid" if $tcref->{tcp_ack};

	for my $tospair ( @{$tcref->{tos}} ) {
	    my ( $tos, $mask ) = split q(/), $tospair;
	    emit "run_tc filter add dev $device parent $devnum:0 protocol ip prio 10 u32 match ip tos $tos $mask flowid $classid";
	}

	save_progress_message_short qq("   TC Class $class defined.");
	emit '';
    }

    if ( $lastdevice ) {
	pop_indent;
	emit "fi\n";
    }
}

#
# Process the tcrules file and setup traffic shaping
#
sub setup_tc() {

    my $first_entry = 1;

    if ( $capabilities{MANGLE_ENABLED} ) {
	ensure_mangle_chain 'tcpre';
	ensure_mangle_chain 'tcout';

	if ( $capabilities{MANGLE_FORWARD} ) {
	    ensure_mangle_chain 'tcfor';
	    ensure_mangle_chain 'tcpost';
	}
    }

    if ( my $fn = open_file 'tcrules' ) {

	while ( read_a_line ) {

	    if ( $first_entry ) {
		progress_message2 "$doing $fn...";
		require_capability( 'MANGLE_ENABLED' , 'a non-empty tcrules file' , 's' );
		$first_entry = 0;
	    }

	    my ( $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos ) = split_line1 2, 10, 'tcrules file';

	    if ( $mark eq 'COMMENT' ) {
		process_comment;
	    } else {
		process_tc_rule $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos
	    }

	}

	$comment = '';
    }

    if ( $capabilities{MANGLE_ENABLED} ) {

	my $mark_part = '';

	if ( @routemarked_interfaces && ! $config{TC_EXPERT} ) {
	    $mark_part = $config{HIGH_ROUTE_MARKS} ? '-m mark --mark 0/0xFF00' : '-m mark --mark 0/0xFF';

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
		insert_rule $mangle_table->{$chain}, 1, '-j MARK --and-mark 0xFF';
	    }
	}
    }

    if ( $globals{TC_SCRIPT} ) {
	save_progress_message 'Setting up Traffic Control...';
	append_file $globals{TC_SCRIPT};
    } elsif ( $config{TC_ENABLED} eq 'Internal' ) {
	setup_traffic_shaping;
    }
}

1;
