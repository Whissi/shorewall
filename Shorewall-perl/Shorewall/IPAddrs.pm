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
#   This module provides interfaces for dealing with IPv4 addresses.
#
package Shorewall::IPAddrs;
require Exporter;
use Shorewall::Config;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( ALLIPv4
		  TCP
		  UDP
		  ICMP

		  validate_address
		  validate_net
		  validate_host
		  validate_range
		  ip_range_explicit
		  allipv4
		  rfc1918_neworks
		 );
our @EXPORT_OK = qw( );
our $VERSION = 4.0.5;

#
# Some IPv4 useful stuff
#
our @allipv4 = ( '0.0.0.0/0' );

use constant { ALLIPv4 => '0.0.0.0/0' , ICMP => 1, TCP => 6, UDP => 17 };

our @rfc1918_networks = ( "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" );

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

sub validate_net( $$ ) {
    my ($net, $vlsm, $rest) = split( '/', $_[0], 3 );
    my $allow_name = $_[1];

    fatal_error "An ipset name ($net) is not allowed in this context" if substr( $net, 0, 1 ) eq '+';

    if ( defined $vlsm ) {
        fatal_error "Invalid VLSM ($vlsm)"            unless $vlsm =~ /^\d+$/ && $vlsm <= 32;
	fatal_error "Invalid Network address ($_[0])" if defined $rest;
	fatal_error "Invalid IP address ($net)"       unless valid_address $net;
    } else {
	fatal_error "Invalid Network address ($_[0])" if $_[0] =~ '/' || ! defined $net;
	validate_address $net, $_[1];
    }
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

sub validate_host( $ ) {
    my $host = $_[0];

    if ( $host =~ /^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/ ) {
	validate_range $1, $2;
    } else {
	validate_net( $host, 0 );
    }
}

sub allipv4() {
    @allipv4;
}

sub rfc1918_networks() {
    @rfc1918_networks
}
 
1;
