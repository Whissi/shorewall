#
# Shorewall-perl 4.1 -- /usr/share/shorewall-perl/Shorewall/IPAddrs.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
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
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#   This module provides interfaces for dealing with IPv4 addresses, protocol names, and
#   port names. It also exports functions for validating protocol- and port- (service) 
#   related constructs.
#
package Shorewall::IPAddrs;
require Exporter;
use Shorewall::Config qw( :DEFAULT split_list require_capability in_hex8);

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( ALLIPv4
		  TCP
		  UDP
		  ICMP
		  SCTP

		  validate_address
		  validate_net
		  decompose_net
		  validate_host
		  validate_range
		  ip_range_explicit
		  expand_port_range
		  allipv4
		  rfc1918_neworks
		  resolve_proto
		  proto_name
		  validate_port
		  validate_portpair
		  validate_port_list
		  validate_icmp
		 );
our @EXPORT_OK = qw( );
our $VERSION = 4.1.5;

#
# Some IPv4 useful stuff
#
our @allipv4 = ( '0.0.0.0/0' );

use constant { ALLIPv4 => '0.0.0.0/0' , ICMP => 1, TCP => 6, UDP => 17 , SCTP => 132 };

our @rfc1918_networks = ( "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" );

sub vlsm_to_mask( $ ) {
    my $vlsm = $_[0];

    in_hex8 ( ( 0xFFFFFFFF << ( 32 - $vlsm ) ) && 0xFFFFFFFF );
}

sub valid_address( $ ) {
    my $address = $_[0];

    my @address = split /\./, $address;
    return 0 unless @address == 4;
    for my $a ( @address ) {
	return 0 unless $a =~ /^\d+$/ && $a < 256;
    }

    1;
}

sub validate_address( $$ ) {
    my ( $addr, $allow_name ) =  @_;

    my @addrs = ( $addr );
    
    unless ( valid_address $addr ) {
	fatal_error "Invalid IP Address ($addr)" unless $allow_name;
	fatal_error "Unknown Host ($addr)" unless (@addrs = gethostbyname $addr);

	if ( defined wantarray ) {
	    shift @addrs for (1..4);
	    for ( @addrs ) {
		my (@a) = unpack('C4',$_);
		$_ = join('.', @a );
	    }
	}
    }

    defined wantarray ? wantarray ? @addrs : $addrs[0] : undef;
}

sub decodeaddr( $ ) {
    my $address = $_[0];

    my @address = split /\./, $address;

    my $result = shift @address;

    for my $a ( @address ) {
	$result = ( $result << 8 ) | $a;
    }

    $result;
}

sub encodeaddr( $ ) {
    my $addr = $_[0];
    my $result = $addr & 0xff;

    for my $i ( 1..3 ) {
	my $a = ($addr = $addr >> 8) & 0xff;
	$result = "$a.$result";
    }

    $result;
}

sub validate_net( $$ ) {
    my ($net, $vlsm, $rest) = split( '/', $_[0], 3 );
    my $allow_name = $_[1];

    fatal_error "Missing address" if $net eq '';
    fatal_error "An ipset name ($net) is not allowed in this context" if substr( $net, 0, 1 ) eq '+';

    if ( defined $vlsm ) {
        fatal_error "Invalid VLSM ($vlsm)"            unless $vlsm =~ /^\d+$/ && $vlsm <= 32;
	fatal_error "Invalid Network address ($_[0])" if defined $rest;
	fatal_error "Invalid IP address ($net)"       unless valid_address $net;
    } else {
	fatal_error "Invalid Network address ($_[0])" if $_[0] =~ '/' || ! defined $net;
	validate_address $net, $_[1];
	$vlsm = 32;
    }

    if ( defined wantarray ) {
	fatal_error "Internal Error in validate_net()" if $allow_name;
	if ( wantarray ) {
	    ( decodeaddr( $net ) , $vlsm );
	} else {
	    "$net/$vlsm";
	}	    
    }
}

sub validate_range( $$ ) {
    my ( $low, $high ) = @_;

    validate_address $low, 0;
    validate_address $high, 0;

    my $first = decodeaddr $low;
    my $last  = decodeaddr $high;

    fatal_error "Invalid IP Range ($low-$high)" unless $first <= $last;
}

sub ip_range_explicit( $ ) {
    my $range = $_[0];
    my @result;

    my ( $low, $high ) = split /-/, $range;

    validate_address $low, 0;

    push @result, $low;

    if ( defined $high ) {
	validate_address $high, 0;

	my $first = decodeaddr $low;
	my $last  = decodeaddr $high;
	my $diff  = $last - $first;

	fatal_error "Invalid IP Range ($range)" unless $diff >= 0 && $diff <= 256;

	while ( ++$first <= $last ) {
	    push @result, encodeaddr( $first );
	}
    }

    @result;
}

sub decompose_net( $ ) {
    my $net = $_[0];

    return ( qw/0x00000000 0x00000000/ ) if $net eq '-';

    ( $net, my $vlsm ) = validate_net( $net , 0 );

    ( in_hex8( $net ) , vlsm_to_mask( $vlsm ) );
    
}

sub validate_host( $$ ) {
    my ( $host, $allow_name )  = $_[0];

    if ( $host =~ /^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) {
	validate_range $1, $2;
    } else {
	validate_net( $host, $allow_name );
    }
}

sub allipv4() {
    @allipv4;
}

sub rfc1918_networks() {
    @rfc1918_networks
}
 
#
# Protocol/port validation
#

our %nametoproto = ( all => 0, ALL => 0, icmp => 1, ICMP => 1, tcp => 6, TCP => 6, udp => 17, UDP => 17  );
our @prototoname = ( 'all', 'icmp', '', '', '', '', 'tcp', '', '', '', '', '', '', '', '', '', '', 'udp' );

#
# Returns the protocol number if the passed argument is a valid protocol number or name. Returns undef otherwise
#
sub resolve_proto( $ ) {
    my $proto = $_[0];
    my $number;

    $proto =~ /^(\d+)$/ ? $proto <= 65535 ? $proto : undef : defined( $number = $nametoproto{$proto} ) ? $number : scalar getprotobyname $proto;
}

sub proto_name( $ ) {
    my $proto = $_[0];

    $proto =~ /^(\d+)$/ ? $prototoname[ $proto ] || scalar getprotobynumber $proto : $proto
}

sub validate_port( $$ ) {
    my ($proto, $port) = @_;

    my $value;

    if ( $port =~ /^(\d+)$/ ) {
	return $port if $port <= 65535;
    } else {
	$proto = getprotobynumber $proto if $proto =~ /^(\d+)$/;
	$value = getservbyname( $port, $proto );
    }

    fatal_error "Invalid/Unknown $proto port/service ($port)" unless defined $value;

    $value;
}

sub validate_portpair( $$ ) {
    my ($proto, $portpair) = @_;

    fatal_error "Invalid port range ($portpair)" if $portpair =~ tr/:/:/ > 1;

    $portpair = "0$portpair"       if substr( $portpair,  0, 1 ) eq ':';
    $portpair = "${portpair}65535" if substr( $portpair, -1, 1 ) eq ':';

    my @ports = split /:/, $portpair, 2;

    $_ = validate_port( $proto, $_) for ( @ports );

    if ( @ports == 2 ) {
	fatal_error "Invalid port range ($portpair)" unless $ports[0] < $ports[1];
    }

    join ':', @ports;

}

sub validate_port_list( $$ ) {
    my $result = '';
    my ( $proto, $list ) = @_;
    my @list   = split_list( $list, 'port' );

    if ( @list > 1 && $list =~ /:/ ) {
	require_capability( 'XMULTIPORT' , 'Port ranges in a port list', '' );
    }

    $proto = proto_name $proto;

    for ( @list ) {
	my $value = validate_portpair( $proto , $_ );
	$result = $result ? join ',', $result, $value : $value;
    }

    $result;
}

my %icmp_types = ( any                          => 'any',
		   'echo-reply'                 => 0,
		   'destination-unreachable'    => 3,
		   'network-unreachable'        => '3/0',
		   'host-unreachable'           => '3/1',
		   'protocol-unreachable'       => '3/2',
		   'port-unreachable'           => '3/3',
		   'fragmentation-needed'       => '3/4',
		   'source-route-failed'        => '3/5',
		   'network-unknown'            => '3/6',
		   'host-unknown'               => '3/7',
		   'network-prohibited'         => '3/9',
		   'host-prohibited'            => '3/10',
		   'TOS-network-unreachable'    => '3/11',
		   'TOS-host-unreachable'       => '3/12',
		   'communication-prohibited'   => '3/13',
		   'host-precedence-violation'  => '3/14',
		   'precedence-cutoff'          => '3/15',
		   'source-quench'              => 4,
		   'redirect'                   => 5,
		   'network-redirect'           => '5/0',
		   'host-redirect'              => '5/1',
		   'TOS-network-redirect'       => '5/2',
		   'TOS-host-redirect'          => '5/3',
		   'echo-request'               => '8',
		   'router-advertisement'       => 9,
		   'router-solicitation'        => 10,
		   'time-exceeded'              => 11,
		   'ttl-zero-during-transit'    => '11/0',
		   'ttl-zero-during-reassembly' => '11/1',
		   'parameter-problem'          => 12,
		   'ip-header-bad'              => '12/0',
		   'required-option-missing'    => '12/1',
		   'timestamp-request'          => 13,
		   'timestamp-reply'            => 14,
		   'address-mask-request'       => 17,
		   'address-mask-reply'         => 18 );

sub validate_icmp( $ ) {
    my $type = $_[0];

    my $value = $icmp_types{$type};

    return $value if defined $value;

    if ( $type =~ /^(\d+)(\/(\d+))?$/ ) {
	return $type if $1 < 256 && ( ! $2 || $3 < 256 );
    }

    fatal_error "Invalid ICMP Type ($type)"
}

#
# Expands a port range into a minimal list of ( port, mask ) pairs.
# Each port and mask are expressed as 4 hex nibbles without a leading '0x'.
#
# Example:
#
#       DB<3> @foo = Shorewall::IPAddrs::expand_port_range( 6, '110:' ); print "@foo\n"
#       006e fffe 0070 fff0 0080 ff80 0100 ff00 0200 fe00 0400 fc00 0800 f800 1000 f000 2000 e000 4000 c000 8000 8000
#
sub expand_port_range( $$ ) {
    my ( $proto, $range ) = @_;

    if ( $range =~ /^(.*):(.*)$/ ) {
	my ( $first, $last ) = ( $1, $2);
	my @result;

	fatal_error "Invalid port range ($range)" unless $first ne '' or $last ne '';
	#
	# Supply missing first/last port number
	#
	$first = 0     if $first eq '';
	$last  = 65535 if $last eq '';
	#
	# Validate the ports
	#
	( $first , $last ) = ( validate_port( $proto, $first ) , validate_port( $proto, $last ) );

	$last++; #Increment last address for limit testing.
	#
	# Break the range into groups:
	#
	#      - If the first port in the remaining range is odd, then the next group is ( <first>, ffff ).
	#      - Otherwise, find the largest power of two P that divides the first address such that 
	#        the remaining range has less than or equal to P ports. The next group is
	#        ( <first> , ~( P-1 ) ).
	#
	while ( ( my $ports = ( $last - $first ) ) > 0 ) {
	    my $mask = 0xffff;         #Mask for current ports in group.
	    my $y    = 2;              #Next power of two to test
	    my $z    = 1;              #Number of ports in current group (Previous value of $y).
	    
	    while ( ( ! ( $first % $y ) ) && ( $y <= $ports ) ) {
		$mask <<= 1;
		$z  = $y;
		$y <<= 1;
	    }
	    #
	    #
	    push @result, sprintf( '%04x', $first ) , sprintf( '%04x' , $mask & 0xffff );
	    $first += $z;
	}
	
	fatal_error "Invalid port range ($range)" unless @result; # first port > last port

	@result;

    } else {
	( sprintf( '%04x' , validate_port( $proto, $range ) ) , 'ffff' );
    } 
}   

1;
