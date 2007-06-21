#! /usr/bin/perl -w
#
# Tool for building Shorewall::Ports.
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of Version 2 of the GNU General Public License
#	as published by the Free Software Foundation.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#
#  Usage:
#
#       buildports.pl [ <directory> ] > /usr/share/shorewall-perl/Shorewall/Ports.pm
#
#  Where:
#
#       <directory>   is the directory where the 'protocols' and 'services' files are
#                     located. If not specified, /etc is assumed.
#
use strict;
use lib '/usr/share/shorewall-perl';
use Shorewall::Common;
use Shorewall::Config;

our $offset = "\t\t  ";

our %service_hash;
  
sub print_it( $$ ) {
    my ( $name, $number ) = @_;
    my $tabs;
    my $length = length $name;

    if ( $name =~ /\W/ || $name =~ /^\d/ ) {
	$tabs = "\t" x int ( ( 27 - $length ) / 8 );
	print "${offset}'${name}'${tabs}=> $number,\n";
    } else {
	$tabs = "\t" x int ( ( 29 - $length ) / 8 );
	print "${offset}${name}${tabs}=> $number,\n";
    }
}

sub print_service( $$ ) {
    my ( $service, $number ) = @_;
    
    unless ( exists $service_hash{$service} ) {
	print_it( $service, $number );
	$service_hash{$service} = $number;
    }
}

set_shorewall_dir($ARGV[0] || '/etc');

ensure_config_path;

our $date = localtime;

print <<"EOF";
#
# Shorewall-perl 4.0 -- /usr/share/shorewall-perl/Shorewall/Ports.pm
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2007 - Tom Eastep (teastep\@shorewall.net)
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
# This module exports the %protocols and %services hashes built from 
# /etc/protocols and /etc/services respectively.
#
# Module generated using buildports.pl $globals{VERSION} - $date
#
EOF

print <<'EOF';
package Shorewall::Ports;

use strict;
use warnings;

our @ISA = qw(Exporter);
our @EXPORT = qw( %protocols %services );
our @EXPORT_OK = qw();
our $VERSION = '1.00';

our %protocols = (
EOF

open_file 'protocols' or fatal_error "Cannot open protocols: $!";

while ( read_a_line1 ) {
    my ( $proto1, $number, $proto2, $proto3 ) = split_line( 2, 4, '/etc/protocols entry');

    print_it( $proto1, $number );
    print_it( $proto2, $number ) unless $proto2 eq '-' || $proto3 ne '-';
}

print "\t\t );\n\n";

print "our %services  = (\n";

open_file 'services' or fatal_error "Cannot open services: $!";

while ( read_a_line1 ) {
    my ( $name1, $proto_number, @names ) = split_line( 2, 10, '/etc/services entry');

    my ( $number, $proto ) = split '/', $proto_number;

    next unless $proto eq 'tcp' || $proto eq 'udp';

    print_service( $name1 , $number );

    while ( defined ( $name1 = shift @names ) && $name1 ne '-' ) {
	print_service ($name1,  $number );
    }
}

print "\t\t );\n\n1;\n";
