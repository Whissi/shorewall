#! /usr/bin/perl -w
#
#     Shorewall Packet Filtering Firewall RPM configuration program - V4.5
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2012 - Tom Eastep (teastep@shorewall.net)
#
#	Shorewall documentation is available at http://www.shorewall.net
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
#	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#       Usage: ./configure.pl <option>=<setting> ...
#
#
################################################################################################
use strict;

my %params;
my %options;

my %aliases = ( VENDOR => 'HOST',
		SHAREDSTATEDIR => 'VARDIR',
		DATADIR => 'SHAREDIR',
		SYSCONFDIR => 'CONFDIR' );

die "Usage: $0 <var>=<val> ..." unless @ARGV;

for ( @ARGV) {
    s/^--//;

    next unless defined $_ && $_ ne '';

    die "Invalid option specification ( $_ )" unless /^(\w+)=(.*)$/;

    my $pn = uc $1;
    my $pv = $2 || '';

    $pn = $aliases{$pn} if exists $aliases{$pn};

    $params{$pn} = $pv;
}

my $vendor = $params{HOST};
my $rcfile;
my $rcfilename;

if ( defined $vendor ) {
    $rcfilename = 'shorewallrc.' . $vendor;
} else {
    $rcfilename   = 'shorewallrc.default';
    $params{HOST} = 'linux';
}

open $rcfile, '<', $rcfilename or die "Unable to open $rcfilename for input: $!";

while ( <$rcfile> ) {
    next if /^\s*#/;
    s/\s*#.*//;
    next if /^\s*$/;
    chomp;
    die "Invalid entry ($_) in $rcfilename, line $." unless /\s*(\w+)=(.*)/;
    $options{$1} = $2;
}

close $rcfile;

while ( my ( $p, $v ) = each %params ) {
    $options{$p} = ${v};
}

my $outfile;

open $outfile, '>', 'shorewallrc' or die "Can't open 'shorewallrc' for output: $!";

for ( qw/ HOST
	  PREFIX
	  SHAREDIR
	  LIBEXECDIR
	  PERLLIBDIR
	  CONFDIR
	  SBINDIR
	  MANDIR 
	  INITDIR
	  INITSOURCE
	  INITFILE
	  AUXINITSOURCE
	  AUXINITFILE
	  SYSTEMD
	  SYSCONFFILE
	  SYSCONFDIR
	  ANNOTATED
	  VARDIR / ) {

    my $val = $options{$_} || '';

    print          "$_=$val\n";
    print $outfile "$_=$val\n";
}

close $outfile;

1;
