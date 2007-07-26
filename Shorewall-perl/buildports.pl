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
use Shorewall::Config qw( open_file
			  push_open
			  pop_open
			  read_a_line1
			  split_line
			  fatal_error
			  %globals
			  ensure_config_path
			  set_shorewall_dir
			  set_config_path );

our $offset = "\t\t  ";

our %service_hash;

sub print_it( $$ ) {
    my ( $name, $number ) = @_;
    my $tabs;
    my $length = length $name;

    if ( $name =~ /\W/ || $name =~ /^\d/ ) {
	my $repeat = int ( ( 27 - $length ) / 8 );
	$tabs = $repeat > 0 ? "\t" x $repeat : ' ';
	print "${offset}'${name}'${tabs}=> $number,\n";
    } else {
	my $repeat = int ( ( 29 - $length ) / 8 );
	$tabs = $repeat > 0 ? "\t" x $repeat : ' ';
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
#
#            E x e c u t i o n   B e g i n s   H e r e
#
set_config_path( '/etc' );

our $dir = $ARGV[0] || '/etc';

$dir =~ s|/+$|| unless $dir eq '/';
#
# Open the files before we do anything else
#
open_file "$dir/services" or fatal_error "$dir/services is empty";

push_open "$dir/protocols" or fatal_error "$dir/protocols is empty";

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

while ( read_a_line1 ) {
    my ( $proto1, $number, @aliases ) = split_line( 2, 10, '/etc/protocols entry');

    print_it( $proto1, $number );

    for my $alias ( @aliases ) {
	last if $alias eq '-';
	print_it( $alias, $number );
    }
}

pop_open;

print "\t\t );\n\n";

print "our %services  = (\n";

while ( read_a_line1 ) {
    my ( $name1, $proto_number, @names ) = split_line( 2, 10, '/etc/services entry');

    my ( $number, $proto ) = split '/', $proto_number;

    next unless $proto && ($proto eq 'tcp' || $proto eq 'udp');

    print_service( $name1 , $number );

    while ( defined ( $name1 = shift @names ) && $name1 ne '-' ) {
	print_service ($name1,  $number );
    }
}

print "\t\t );\n\n1;\n";
