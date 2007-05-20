#
# Shorewall-perl 3.9 -- /usr/share/shorewall-perl/Shorewall/IPAddrs.pm
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
#   This module provides interfaces for dealing with IPv4 addresses. 
#   
package Shorewall::IPAddrs;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( ALLIPv4

		  validate_address
		  validate_net
		  validate_range
		  ip_range_explicit

		  @allipv4
		  @rfc1918_networks
		 );
our @EXPORT_OK = qw( );
our @VERSION = 1.00;

#
# Some IPv4 useful stuff
#
our @allipv4 = ( '0.0.0.0/0' );

use constant { ALLIPv4 => '0.0.0.0/0' };

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

sub validate_address( $ ) {
    my $addr = $_[0];

    unless ( valid_address $addr ) {
	fatal_error "Unknown Host ($addr)" unless defined gethostbyname $addr;
    }
}

sub validate_net( $ ) {
    my ($net, $vlsm, $rest) = split( '/', $_[0], 3 );

    if ( defined $vlsm ) {
        fatal_error "Invalid VLSM ($vlsm)"            unless $vlsm =~ /^\d+$/ && $vlsm <= 32;
	fatal_error "Invalid Network address ($_[0])" if defined $rest;
	fatal_error "Invalid IP address ($net)"       unless valid_address $net;
    } else {
	fatal_error "Invalid Network address ($_[0])" if $_[0] =~ '/' || ! defined $net;
	validate_address $net;
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

    fatal_error "Invalid IP address ( $low )" unless valid_address $low;
    fatal_error "Invalid IP address ( $high )" unless valid_address $high;

    my $first = decodeaddr $low;
    my $last  = decodeaddr $high;

    fatal_error "Invalid IP Range ( $low-$high )" unless $first <= $last;
}   

sub ip_range_explicit( $ ) {
    my $range = $_[0];
    my @result;

    my ( $low, $high ) = split /-/, $range;

    fatal_error "Invalid IP address ( $low )" unless valid_address $low;

    push @result, $low;

    if ( defined $high ) {
	fatal_error "Invalid IP address ( $high )" unless valid_address $high;

	my $first = decodeaddr $low;
	my $last  = decodeaddr $high;

	fatal_error "Invalid IP Range ( $range )" unless $first <= $last;

	while ( ++$first <= $last ) {
	    push @result, encodeaddr( $first );
	}
    }

    @result;
}

1;
