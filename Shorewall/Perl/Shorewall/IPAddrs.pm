#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/IPAddrs.pm
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
#   This module provides interfaces for dealing with IPv4 addresses, protocol names, and
#   port names. It also exports functions for validating protocol- and port- (service)
#   related constructs.
#
package Shorewall::IPAddrs;
require Exporter;
use Shorewall::Config qw( :DEFAULT split_list require_capability in_hex8 numeric_value F_IPV4 F_IPV6 );
use Socket;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( ALLIPv4
                  ALLIPv6
		  NILIPv4
		  NILIPv6
	          IPv4_MULTICAST
	          IPv6_MULTICAST
	          IPv6_LINKLOCAL
	          IPv6_SITELOCAL
	          IPv6_LOOPBACK
	          IPv6_LINK_ALLNODES
	          IPv6_LINK_ALLRTRS
	          IPv6_SITE_ALLNODES
	          IPv6_SITE_ALLRTRS
		  ALLIP
		  NILIP
		  ALL
		  TCP
		  UDP
		  UDPLITE
		  ICMP
		  DCCP
		  IPv6_ICMP
		  SCTP

		  validate_address
		  validate_net
		  decompose_net
		  compare_nets
		  validate_host
		  validate_range
		  ip_range_explicit
		  expand_port_range
		  allipv4
		  allipv6
		  allip
		  nilipv4
		  nilipv6
		  nilip
		  rfc1918_networks
		  resolve_proto
		  proto_name
		  validate_port
		  validate_portpair
		  validate_port_list
		  validate_icmp
		  validate_icmp6
		 );
our @EXPORT_OK = qw( );
our $VERSION = '4.4_17';

#
# Some IPv4/6 useful stuff
#
our @allipv4 = ( '0.0.0.0/0' );
our @allipv6 = ( '::/0' );
our $allip;
our @allip;
our @nilipv4 = ( '0.0.0.0' );
our @nilipv6 = ( '::' );
our $nilip;
our @nilip;
our $valid_address;
our $validate_address;
our $validate_net;
our $validate_range;
our $validate_host;
our $family;

use constant { ALLIPv4             => '0.0.0.0/0' ,
	       ALLIPv6             => '::/0' ,
	       NILIPv4             => '0.0.0.0' ,
	       NILIPv6             => '::' ,
	       IPv4_MULTICAST      => '224.0.0.0/4' ,
	       IPv6_MULTICAST      => 'ff00::/8' ,
	       IPv6_LINKLOCAL      => 'fe80::/10' ,
	       IPv6_SITELOCAL      => 'feC0::/10' ,
	       IPv6_LOOPBACK       => '::1' ,
	       IPv6_LINK_ALLNODES  => 'ff01::1' ,
	       IPv6_LINK_ALLRTRS   => 'ff01::2' ,
	       IPv6_SITE_ALLNODES  => 'ff02::1' ,
	       IPv6_SITE_ALLRTRS   => 'ff02::2' ,
	       ICMP                => 1,
	       TCP                 => 6,
	       UDP                 => 17,
	       DCCP                => 33,
	       IPv6_ICMP           => 58,
	       SCTP                => 132,
	       UDPLITE             => 136 };

our @rfc1918_networks = ( "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" );

#
# Note: initialize() is declared at the bottom of the file
#
sub vlsm_to_mask( $ ) {
    my $vlsm = $_[0];

    in_hex8 ( ( 0xFFFFFFFF << ( 32 - $vlsm ) ) & 0xFFFFFFFF );
}

sub valid_4address( $ ) {
    my $address = $_[0];

    my @address = split /\./, $address;
    return 0 unless @address == 4;
    for ( @address ) {
	return 0 unless /^\d+$/ && $_ < 256;
    }

    1;
}

sub validate_4address( $$ ) {
    my ( $addr, $allow_name ) =  @_;

    my @addrs = ( $addr );

    unless ( valid_4address $addr ) {
	fatal_error "Invalid IP Address ($addr)" unless $allow_name;
	fatal_error "Unknown Host ($addr)" unless  @addrs = gethostbyname( $addr );

	if ( defined wantarray ) {
	    shift @addrs for (1..4);
	    for ( @addrs ) {
		$_ = ( inet_ntoa( $_ ) );
	    }
	}
    }

    defined wantarray ? wantarray ? @addrs : $addrs[0] : undef;
}

sub decodeaddr( $ ) {
    my $address = $_[0];

    my @address = split /\./, $address;

    my $result = shift @address;

    for ( @address ) {
	$result = ( $result << 8 ) | $_;
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

sub validate_4net( $$ ) {
    my ($net, $vlsm, $rest) = split( '/', $_[0], 3 );
    my $allow_name = $_[1];

    $net = '' unless defined $net;

    fatal_error "Missing address" if $net eq '';

    if ( $net =~ /\+(\[?)/ ) {
	if ( $1 ) {
	    fatal_error "An ipset list ($net) is not allowed in this context";
	} elsif ( $net =~ /^\+[a-zA-Z][-\w]*$/ ) {
	    fatal_error "An ipset name ($net) is not allowed in this context";
	} else {
	    fatal_error "Invalid ipset name ($net)";
	}
    }

    if ( defined $vlsm ) {
        fatal_error "Invalid VLSM ($vlsm)"            unless $vlsm =~ /^\d+$/ && $vlsm <= 32;
	fatal_error "Invalid Network address ($_[0])" if defined $rest;
	fatal_error "Invalid IP address ($net)"       unless valid_4address $net;
    } else {
	fatal_error "Invalid Network address ($_[0])" if $_[0] =~ '/' || ! defined $net;
	validate_4address $net, $_[1];
	$vlsm = 32;
    }

    if ( defined wantarray ) {
	assert ( ! $allow_name );
	if ( wantarray ) {
	    ( decodeaddr( $net ) , $vlsm );
	} else {
	    "$net/$vlsm";
	}
    }
}

sub validate_4range( $$ ) {
    my ( $low, $high ) = @_;

    validate_4address $low, 0;
    validate_4address $high, 0;

    my $first = decodeaddr $low;
    my $last  = decodeaddr $high;

    fatal_error "Invalid IP Range ($low-$high)" unless $first <= $last;
}

sub validate_4host( $$ ) {
    my ( $host, $allow_name )  = $_[0];

    if ( $host =~ /^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) {
	validate_4range $1, $2;
    } else {
	validate_4net( $host, $allow_name );
    }
}

sub ip_range_explicit( $ ) {
    my $range = $_[0];
    my @result;

    my ( $low, $high ) = split /-/, $range;

    validate_4address $low, 0;

    push @result, $low;

    if ( defined $high ) {
	validate_4address $high, 0;

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

    ( $net, my $vlsm ) = validate_net( $net , 0 );
    ( ( $family == F_IPV4 ? encodeaddr( $net) : normalize_6addr( $net ) )  , $vlsm );

}

sub compare_nets( $$ ) {
    my ( @net1, @net2 );

    @net1 = decompose_net( $_[0] );
    @net2 = decompose_net( $_[1] );
    
    $net1[0] eq $net2[0] && $net1[1] == $net2[1];
}			    

sub allipv4() {
    @allipv4;
}

sub allipv6() {
    @allipv6;
}

sub nilipv4() {
    @nilipv4;
}

sub nilipv6() {
    @nilipv6;
}

sub rfc1918_networks() {
    @rfc1918_networks
}

#
# Protocol/port validation
#

our %nametoproto = ( all => 0, ALL => 0, icmp => 1, ICMP => 1, tcp => 6, TCP => 6, udp => 17, UDP => 17 );
our @prototoname = ( 'all', 'icmp', '', '', '', '', 'tcp', '', '', '', '', '', '', '', '', '', '', 'udp' );

#
# Returns the protocol number if the passed argument is a valid protocol number or name. Returns undef otherwise
#
sub resolve_proto( $ ) {
    my $proto = $_[0];
    my $number;

    if ( $proto =~ /^\d+$/ || $proto =~ /^0x/ ) {
	$number = numeric_value ( $proto );
	defined $number && $number <= 65535 ? $number : undef;
    } else {
	#
	# Allow 'icmp' as a synonym for 'ipv6-icmp' in IPv6 compilations
	#
	$proto= 'ipv6-icmp' if $proto eq 'icmp' && $family == F_IPV6;

	defined( $number = $nametoproto{$proto} ) ? $number : scalar getprotobyname $proto;
    }
}

sub proto_name( $ ) {
    my $proto = $_[0];

    $proto =~ /^(\d+)$/ ? $prototoname[ $proto ] || scalar getprotobynumber $proto : $proto
}

sub validate_port( $$ ) {
    my ($proto, $port) = @_;

    my $value;

    if ( $port =~ /^(\d+)$/ || $port =~ /^0x/ ) {
	$port = numeric_value $port;
	return $port if defined $port && $port && $port <= 65535;
    } else {
	$proto = proto_name $proto if $proto =~ /^(\d+)$/;
	$value = getservbyname( $port, $proto );
    }

    return $value if defined $value;

    fatal_error "The separator for a port range is ':', not '-' ($port)" if $port =~ /^\d+-\d+$/;

    fatal_error "Invalid/Unknown $proto port/service ($_[1])" unless defined $value;
}

sub validate_portpair( $$ ) {
    my ($proto, $portpair) = @_;

    fatal_error "Invalid port range ($portpair)" if $portpair =~ tr/:/:/ > 1;

    $portpair = "0$portpair"       if substr( $portpair,  0, 1 ) eq ':';
    $portpair = "${portpair}65535" if substr( $portpair, -1, 1 ) eq ':';

    my @ports = split /:/, $portpair, 2;

    $_ = validate_port( $proto, $_) for ( grep $_, @ports );

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
	( $first , $last ) = ( validate_port( $proto, $first || 1 ) , validate_port( $proto, $last ) );

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

sub valid_6address( $ ) {
    my $address = $_[0];

    my @address = split /:/, $address;
    my $max;

    if ( $address[-1] && $address[-1] =~ /^\d+\.\d+\.\d+\.\d+$/ ) {
	return 0 unless valid_4address pop @address;
	$max = 6;
	$address = join ':', @address;
	return 1 if @address eq ':';
    } else {
	$max = 8;
    }

    return 0 if @address > $max;
    return 0 unless ( @address == $max ) || $address =~ /::/;
    return 0 if $address =~ /:::/ || $address =~ /::.*::/;

    unless ( $address =~ /^::/ ) {
	return 0 if $address =~ /^:/;
    }

    unless ( $address =~ /::$/  ) {
	return 0 if $address =~ /:$/;
    }

    for my $a ( @address ) {
	return 0 unless $a eq '' || ( $a =~ /^[a-fA-f\d]+$/ && length $a < 5 );
    }

    1;
}

sub validate_6address( $$ ) {
    my ( $addr, $allow_name ) =  @_;

    my @addrs = ( $addr );

    unless ( valid_6address $addr ) {
	fatal_error "Invalid IPv6 Address ($addr)" unless $allow_name;
	require Socket6;
	fatal_error "Unknown Host ($addr)" unless (@addrs = Socket6::gethostbyname2( $addr, Socket6::AF_INET6()));

	if ( defined wantarray ) {
	    shift @addrs for (1..4);
	    for ( @addrs ) {
		$_ = Socket6::inet_ntop( Socket6::AF_INET6(), $_ );
	    }
	}
    }

    defined wantarray ? wantarray ? @addrs : $addrs[0] : undef;
}

sub validate_6net( $$ ) {
    my ($net, $vlsm, $rest) = split( '/', $_[0], 3 );
    my $allow_name = $_[1];

    if ( $net =~ /\+(\[?)/ ) {
	if ( $1 ) {
	    fatal_error "An ipset list ($net) is not allowed in this context";
	} elsif ( $net =~ /^\+[a-zA-Z][-\w]*$/ ) {
	    fatal_error "An ipset name ($net) is not allowed in this context";
	} else {
	    fatal_error "Invalid ipset name ($net)";
	}
    }

    if ( defined $vlsm ) {
        fatal_error "Invalid VLSM ($vlsm)"              unless $vlsm =~ /^\d+$/ && $vlsm <= 128;
	fatal_error "Invalid Network address ($_[0])"   if defined $rest;
	fatal_error "Invalid IPv6 address ($net)"       unless valid_6address $net;
    } else {
	fatal_error "Invalid Network address ($_[0])" if $_[0] =~ '/' || ! defined $net;
	validate_6address $net, $allow_name;
    }

    if ( defined wantarray ) {
	assert ( ! $allow_name );
	if ( wantarray ) {
	    ( $net , $vlsm );
	} else {
	    "$net/$vlsm";
	}
    }
}

#
# Note: the input is assumed to be a valid IPv6 address
#
sub normalize_6addr( $ ) {
    my $addr = shift;

    if ( $addr eq '::' ) {
	'0:0:0:0:0:0:0:0';
    } else {
	#
	# Suppress leading zeros
	#
	$addr =~ s/^0+//;
	$addr =~ s/:0+/:/g;
	$addr =~ s/^:/0:/;
	$addr =~ s/:$/:0/;

	$addr =~ s/::/:0::/ while $addr =~ tr/:/:/ < 7;
	#
	# Note: "s/::/:0:/g" doesn't work here
	#
	1 while $addr =~ s/::/:0:/;

	$addr =~ s/^0+:/0:/;

	$addr;
    }
}

sub validate_6range( $$ ) {
    my ( $low, $high ) = @_;

    validate_6address $low, 0;
    validate_6address $high, 0;

    my @low  = split ":", normalize_6addr( $low );
    my @high = split ":", normalize_6addr( $high );


    while ( @low ) {
	my ( $l, $h) = ( shift @low, shift @high );
	next     if hex "0x$l" == hex "0x$h";
	return 1 if hex "0x$l"  < hex "0x$h";
	last;
    }

    fatal_error "Invalid IPv6 Range ($low-$high)";
}

sub validate_6host( $$ ) {
    my ( $host, $allow_name )  = @_;

    if ( $host =~ /^(.*:.*)-(.*:.*)$/ ) {
	validate_6range $1, $2;
    } else {
	validate_6net( $host, $allow_name );
    }
}

my %ipv6_icmp_types = ( any                          => 'any',
			'destination-unreachable'    => 1,
			'no-route'                   => '1/0',
			'communication-prohibited'   => '1/1',
			'address-unreachable'        => '1/2',
			'port-unreachable'           => '1/3',
			'packet-too-big'             =>  2,
			'time-exceeded'              =>  3,
			'ttl-exceeded'               =>  3,
			'ttl-zero-during-transit'    => '3/0',
			'ttl-zero-during-reassembly' => '3/1',
			'parameter-problem'          =>  4,
			'bad-header'                 => '4/0',
			'unknown-header-type'        => '4/1',
			'unknown-option'             => '4/2',
			'echo-request'               => 128,
			'echo-reply'                 => 129,
			'router-solicitation'        => 133,
			'router-advertisement'       => 134,
			'neighbour-solicitation'     => 135,
			'neighbour-advertisement'    => 136,
			redirect                     => 137 );


sub validate_icmp6( $ ) {
    my $type = $_[0];

    my $value = $ipv6_icmp_types{$type};

    return $value if defined $value;

    if ( $type =~ /^(\d+)(\/(\d+))?$/ ) {
	return $type if $1 < 256 && ( ! $2 || $3 < 256 );
    }

    fatal_error "Invalid IPv6 ICMP Type ($type)"
}

sub ALLIP() {
    $allip;
}

sub allip() {
    @allip;
}

sub NILIP() {
    $nilip;
}

sub nilip() {
    @nilip;
}

sub valid_address ( $ ) {
    $valid_address->(@_);
}

sub validate_address ( $$ ) {
    $validate_address->(@_);
}

sub validate_net ( $$ ) {
    $validate_net->(@_);
}

sub validate_range ($$ ) {
    $validate_range->(@_);
}

sub validate_host ($$ ) {
    $validate_host->(@_);
}

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

    if ( $family == F_IPV4 ) {
	$allip            = ALLIPv4;
	@allip            = @allipv4;
	$nilip            = NILIPv4;
	@nilip            = @nilipv4;
	$valid_address    = \&valid_4address;
	$validate_address = \&validate_4address;
	$validate_net     = \&validate_4net;
	$validate_range   = \&validate_4range;
	$validate_host    = \&validate_4host;
    } else {
	$allip            = ALLIPv6;
	@allip            = @allipv6;
	$nilip            = NILIPv6;
	@nilip            = @nilipv6;
	$valid_address    = \&valid_6address;
	$validate_address = \&validate_6address;
	$validate_net     = \&validate_6net;
	$validate_range   = \&validate_6range;
	$validate_host    = \&validate_6host;
    }
}

1;
