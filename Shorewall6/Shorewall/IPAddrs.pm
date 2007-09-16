#
# Shorewall-6 4.1 -- /usr/share/shorewall6/Shorewall6/IPAddrs.pm
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
our @EXPORT = qw( ALLIPv6

		  validate_address
		  validate_net
		  validate_host
		  validate_range
		  ip_range_explicit
		  allipv6
		 );
our @EXPORT_OK = qw( );
our $VERSION = '4.03';

#
# Some IPv6 useful stuff
#
our @allipv6 = ( '::/0' );

sub allipv6() {
    @allipv6
}

use constant { ALLIPv6 => '::/0' };

sub valid_address( $ ) {
    my $address = $_[0];

    my @address = split /:/, $address;

    return 0 if @address > 8;
    return 0 if @address < 8 && ! $address =~ /::/;
    return 0 if $address =~ /:::/ || $address =~ /::.*::/;
    
    if ( $address =~ /^:/ ) {
	unless ( $address eq '::' ) {
	    return 0 if $address =~ /:$/ || $address =~ /^:.*::/;
	}
    } elsif ( $address =~ /:$/ ) {
	return 0 if $address =~ /::.*:$/;
    }

    for my $a ( @address ) {
	return 0 unless $a eq '' || ( $a =~ /^[a-fA-f\d]+$/ && oct "0x$a" < 65536 );
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

    fatal_error "An ipset name ($net) is not allowed in this context" if substr( $net, 0, 1 ) eq '+';

    if ( defined $vlsm ) {
        fatal_error "Invalid VLSM ($vlsm)"              unless $vlsm =~ /^\d+$/ && $vlsm <= 64;
	fatal_error "Invalid Network address ($_[0])"   if defined $rest;
	fatal_error "Invalid IPv6 address ($net)"       unless valid_address $net;
    } else {
	fatal_error "Invalid Network address ($_[0])" if $_[0] =~ '/' || ! defined $net;
	validate_address $net;
    }
}

1;
