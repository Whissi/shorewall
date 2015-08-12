#! /usr/bin/perl -w
#
#     The Shoreline Firewall Packet Filtering Firewall Compiler - V4.4
#
#     (c) 2007,2008,2009,2010,2011,2014 - Tom Eastep (teastep@shorewall.net)
#
#	Complete documentation is available at http://shorewall.net
#
#       This program is part of Shorewall.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by the
#       Free Software Foundation, either version 2 of the license or, at your
#       option, any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, see <http://www.gnu.org/licenses/>.
#
# Usage:
#
#         compiler.pl [ <option> ... ] [ <filename> ]
#
#     Options:
#
#         --export                    # Compile for export
#         --verbosity=<number>        # Set VERBOSITY range -1 to 2
#         --directory=<directory>     # Directory where configuration resides (default is /etc/shorewall)
#         --timestamp                 # Timestamp all progress messages
#         --debug                     # Print stack trace on warnings and fatal error.
#         --refresh=<chainlist>       # Make the 'refresh' command refresh a comma-separated list of chains rather than 'blacklst'.
#         --log=<filename>            # Log file
#         --log_verbosity=<number>    # Log Verbosity range -1 to 2
#         --family=<number>           # IP family; 4 = IPv4 (default), 6 = IPv6
#         --preview                   # Preview the ruleset.
#         --shorewallrc=<path>        # Path to global shorewallrc file.
#         --shorewallrc1=<path>       # Path to export shorewallrc file.
#         --config_path=<path-list>   # Search path for config files
#         --inline                    # Update alternative column specifications
#         --tcrules                   # Create mangle from tcrules
#         --routestopped              # Create stoppedrules from routestopped
#         --notrack                   # Create conntrack from notrack
#
use strict;
use FindBin;
use lib "$FindBin::Bin";
use Shorewall::Compiler;
use Getopt::Long;

sub usage( $ ) {

    print STDERR << '_EOF_';

usage: compiler.pl [ <option> ... ] [ <filename> ]

  options are:
    [ --export ]
    [ --directory=<directory> ]
    [ --verbose={-1|0-2} ]
    [ --timestamp ]
    [ --debug ]
    [ --confess ]
    [ --refresh=<chainlist> ]
    [ --log=<filename> ]
    [ --log-verbose={-1|0-2} ]
    [ --test ]
    [ --preview ]
    [ --family={4|6} ]
    [ --annotate ]
    [ --update ]
    [ --convert ]
    [ --directives ]
    [ --shorewallrc=<pathname> ]
    [ --shorewallrc1=<pathname> ]
    [ --config_path=<path-list> ]
    [ --inline ]
    [ --tcrules ]
    [ --routestopped ]
    [ --notrack ]
_EOF_

exit shift @_;
}

#
#                                     E x e c u t i o n   B e g i n s   H e r e
#
my $export        = 0;
my $shorewall_dir = '';
my $verbose       = 0;
my $timestamp     = 0;
my $debug         = 0;
my $confess       = 0;
my $chains        = ':none:';
my $log           = '';
my $log_verbose   = 0;
my $help          = 0;
my $test          = 0;
my $family        = 4; # F_IPV4
my $preview       = 0;
my $annotate      = 0;
my $update        = 0;
my $convert       = 0;
my $directives    = 0;
my $config_path   = '';
my $shorewallrc   = '';
my $shorewallrc1  = '';
my $inline        = 0;
my $tcrules       = 0;
my $routestopped  = 0;
my $notrack       = 0;

Getopt::Long::Configure ('bundling');

my $result = GetOptions('h'               => \$help,
                        'help'            => \$help,
                        'export'          => \$export,
			'e'               => \$export,
			'directory=s'     => \$shorewall_dir,
			'd=s'             => \$shorewall_dir,
			'verbose=i'       => \$verbose,
			'v=i'             => \$verbose,
			'timestamp'       => \$timestamp,
			't'               => \$timestamp,
		        'debug'           => \$debug,
			'r=s'             => \$chains,
			'refresh=s'       => \$chains,
			'log=s'           => \$log,
			'l=s'             => \$log,
			'log_verbosity=i' => \$log_verbose,
			'test'            => \$test,
			'preview'         => \$preview,
			'f=i'             => \$family,
			'family=i'        => \$family,
			'c'               => \$confess,
			'confess'         => \$confess,
			'a'               => \$annotate,
			'annotate'        => \$annotate,
			'directives'      => \$directives,
			'D'               => \$directives,
			'u'               => \$update,
			'update'          => \$update,
			'convert'         => \$convert,
			'inline'          => \$inline,
			'tcrules'         => \$tcrules,
			'routestopped'    => \$routestopped,
			'notrack'         => \$notrack,
			'config_path=s'   => \$config_path,
			'shorewallrc=s'   => \$shorewallrc,
			'shorewallrc1=s'  => \$shorewallrc1,
		       );

usage(1) unless $result && @ARGV < 2;
usage(0) if $help;

compiler( script          => $ARGV[0] || '',
	  directory       => $shorewall_dir,
	  verbosity       => $verbose,
	  timestamp       => $timestamp,
	  debug           => $debug,
	  export          => $export,
	  chains          => $chains,
	  log             => $log,
	  log_verbosity   => $log_verbose,
	  test            => $test,
	  preview         => $preview,
	  family          => $family,
	  confess         => $confess,
	  update          => $update,
	  convert         => $convert,
	  annotate        => $annotate,
	  directives      => $directives,
	  config_path     => $config_path,
	  shorewallrc     => $shorewallrc,
	  shorewallrc1    => $shorewallrc1,
	  inline          => $inline,
	  tcrules         => $tcrules,
	);
