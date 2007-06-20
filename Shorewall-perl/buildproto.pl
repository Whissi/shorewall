#! /usr/bin/perl -w

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

set_shorewall_dir($ARGV[0] ? $ARGV[0] : '.');

ensure_config_path;

our $date = localtime;

print <<"EOF";
#
# Protocol and Services tables generated using buildproto.pl - $date
#
EOF

print "our %protocols = (\n";

open_file 'protocols' or fatal_error "Cannot open protocols: $!";

while ( read_a_line1 ) {
    my ( $proto1, $number, $proto2, $proto3 ) = split_line( 2, 4, '/etc/protocols entry');

    print_it( $proto1, $number );
    print_it( $proto2, $number ) unless $proto2 eq '-' || $proto3 ne '-';
}

print "\t\t  );\n\n";

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

print "\t\t  );\n";
