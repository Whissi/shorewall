package Shorewall::Hosts;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Interfaces;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( validate_hosts_file );
our @EXPORT_OK = ();
our @VERSION = 1.00;

#
# Validates the hosts file. Generates entries in %zone{..}{hosts} 
#
sub validate_hosts_file()
{
    my %validoptions = (
			blacklist => 1,
			maclist => 1,
			norfc1918 => 1,
			nosmurfs => 1,
			routeback => 1,		
			routefilter => 1,
			tcpflags => 1,
			);

    open HOSTS, "$ENV{TMP_DIR}/hosts" or fatal_error "Unable to open stripped hosts file: $!";

    while ( $line = <HOSTS> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ($zone, $hosts, $options, $extra) = split /\s+/, $line;

	fatal_error "Invalid hosts file entry: $line" if $extra;

	my $zoneref = $zones{$zone};
	my $type    = $zoneref->{type};

	fatal_error "Unknown ZONE ($zone)" unless $type;
	fatal_error 'Firewall zone not allowed in ZONE column of hosts record' if $type eq 'firewall';

	my $interface;

	if ( $hosts =~ /^([\w.@%-]+):(.*)$/ ) {
	    $interface = $1;
	    $hosts = $2;
	    $zoneref->{options}{complex} = 1 if $hosts =~ /^\+/;
	    fatal_error "Unknown interface ($interface)" unless $interfaces{$interface}{root};
	} else {
	    fatal_error "Invalid HOSTS(S) column contents: $hosts";
	}

	my $optionsref;
	
	if ( $options && $options ne '-' ) {
	    my @options = split ',', $options;
	    my %options;

	    for my $option ( @options )
	    {
		if ( $option eq 'ipsec' ) {
		    $type = 'ipsec';
		    $zoneref->{options}{complex} = 1;
		} elsif ( $validoptions{$option}) {
		    $options{$option} = 1;
		} else {
		    fatal_error "Invalid option ($option)";
		}
	    }

	    $optionsref = \%options;
	}

	my @h = split ',', $hosts;

	add_group_to_zone( $zone, $type , $interface, \@h , $optionsref);

	progress_message "   Host \"$line\" validated";
    }

    close HOSTS;
}
