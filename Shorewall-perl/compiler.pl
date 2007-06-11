#! /usr/bin/perl -w
#
#     The Shoreline Firewall4 (Shorewall-perl) Packet Filtering Firewall Compiler - V3.9
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2007 - Tom Eastep (teastep@shorewall.net)
#
#	Complete documentation is available at http://shorewall.net
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
# See usage() function below for command line syntax.
#
use strict;
use lib '/usr/share/shorewall-perl';
use Shorewall::Common qw/ $verbose $timestamp /;
use Shorewall::Config qw/ fatal_error $shorewall_dir /;
use Shorewall::Compiler qw/ compiler $export /;
use Getopt::Long;

sub usage() {
    print STDERR "usage: compiler.pl [ --export ] [ --directory <directory> ] [ --verbose {0-2} ] [ --timestamp ] [ <filename> ]\n";
    exit 1;
}

Getopt::Long::Configure ('bundling');

my $result = GetOptions('export'      => \$export,
			'directory=s' => \$shorewall_dir,
			'verbose=i'   => \$verbose,
			'timestamp'   => \$timestamp );

usage unless $result;

if ( $shorewall_dir ne '' ) {
    fatal_error "$shorewall_dir is not an existing directory" unless -d $shorewall_dir;
}

usage unless @ARGV < 2;

compiler $ARGV[0];
