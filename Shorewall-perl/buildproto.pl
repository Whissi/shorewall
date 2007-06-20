#! /usr/bin/perl -w
#
# Tool for building tables used to validate protocol and service names in Shorewall rules.
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
#       buildproto.pl [ <directory> ]
#
#  Where:
#
#       <directory>   is the directory where the 'protocols' and 'services' files are
#                     localed. If not specified, /etc is assumed.
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

    if ( $name =~ /[-.]/ ) {
	$tabs = $length < 4 ? "\t\t\t" : $length < 12 ? "\t\t" : "\t";
	print "${offset}'${name}'${tabs}=> $number,\n";
    } else {
	$tabs = $length < 6 ? "\t\t\t" : $length < 14 ? "\t\t" : "\t";
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
# Protocol and Services tables generated using buildproto.pl - $date
#
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

    print_service( $name1 , $number );

    while ( defined ( $name1 = shift @names ) && $name1 ne '-' ) {
	print_service ($name1,  $number );
    }
}

print "\t\t );\n";
