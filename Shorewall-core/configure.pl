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

#
# Build updates this
#
use constant {
    VERSION => '4.5.2.1'
};

my %params;
my %options;

my %aliases = ( VENDOR         => 'HOST',
		SHAREDSTATEDIR => 'VARLIB',
		DATADIR        => 'SHAREDIR' );

for ( @ARGV ) {
    die "ERROR: Invalid option specification ( $_ )" unless /^(?:--)?(\w+)=(.*)$/;

    my $pn = uc $1;
    my $pv = $2 || '';

    $pn = $aliases{$pn} if exists $aliases{$pn};

    $params{$pn} = $pv;
}

my $vendor = $params{HOST};
my $rcfile;
my $rcfilename;

unless ( defined $vendor ) {
    if ( -f '/etc/os-release' ) {
	my $id = `cat /etc/os-release | grep ^ID=`;

	chomp $id;

	$id =~ s/ID=//;
	
	if ( $id eq 'fedora' ) {
	    $vendor = 'redhat';
	} elsif ( $id eq 'opensuse' ) {
	    $vendor = 'suse';
	} elsif ( $id eq 'ubuntu' ) {
	    $vendor = 'debian';
	} else {
	    $vendor = $id;
	}
    }

    $params{HOST} = $vendor;
}

if ( defined $vendor ) {
    $rcfilename = $vendor eq 'linux' ? 'shorewallrc.default' : 'shorewallrc.' . $vendor;
    die qq("ERROR: $vendor" is not a recognized host type) unless -f $rcfilename;
} else {
    if ( -f '/etc/debian_version' ) {
	$vendor = 'debian';
	$rcfilename = 'shorewallrc.debian';
    } elsif ( -f '/etc/redhat-release' ){
	$vendor = 'redhat';
	$rcfilename = 'shorewallrc.redhat';
    } elsif ( -f '/etc/slackware-version' ) {
	$vendor = 'slackware';
	$rcfilename = 'shorewallrc.slackware';
    } elsif ( -f '/etc/SuSE-release' ) {
	$vendor = 'suse';
	$rcfilename = 'shorewallrc.suse';
    } elsif ( -f '/etc/arch-release' ) {
	$vendor = 'archlinux';
	$rcfilename = 'shorewallrc.archlinux';
    } elsif ( `uname` =~ '^Darwin' ) {
	$vendor = 'apple';
	$rcfilename = 'shorewallrc.apple';
    } elsif ( `uname` =~ '^Cygwin' ) {
	$vendor = 'cygwin';
	$rcfilename = 'shorewallrc.cygwin';
    } else {
	$vendor = 'linux';
	$rcfilename = 'shorewallrc.default';
    }

    $params{HOST} = $vendor;
}

my @localtime = localtime;
my @abbr = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );

if ( $vendor eq 'linux' ) {
    printf "INFO: Creating a generic Linux installation - %s %2d %04d %02d:%02d:%02d\n\n", $abbr[$localtime[4]], $localtime[3], 1900 + $localtime[5] , @localtime[2,1,0];;
} else {
    printf "INFO: Creating a %s-specific installation - %s %2d %04d %02d:%02d:%02d\n\n", $vendor, $abbr[$localtime[4]], $localtime[3], 1900 + $localtime[5] , @localtime[2,1,0];;
}

open $rcfile, '<', $rcfilename or die "Unable to open $rcfilename for input: $!";

while ( <$rcfile> ) {
    s/\s*#.*//;
    unless ( /^\s*$/ ) {
	chomp;
	die "ERROR: Invalid entry ($_) in $rcfilename, line $." unless /\s*(\w+)=(.*)/;
	$options{$1} = $2;
    }
}

close $rcfile;

while ( my ( $p, $v ) = each %params ) {
    $options{$p} = ${v};
}

my $outfile;

open $outfile, '>', 'shorewallrc' or die "Can't open 'shorewallrc' for output: $!";

printf $outfile "#\n# Created by Shorewall Core version %s configure.pl - %s %2d %04d %02d:%02d:%02d\n#\n", VERSION, $abbr[$localtime[4]], $localtime[3], 1900 + $localtime[5] , @localtime[2,1,0];

print  $outfile "# Input: @ARGV\n#\n" if @ARGV;

if ( $options{VARLIB} ) {
    unless ( $options{VARDIR} ) {
	$options{VARDIR} = '${VARLIB}/${PRODUCT}';
    }
} elsif ( $options{VARDIR} ) {
    $options{VARLIB} = $options{VARDIR};
    $options{VARDIR} = '${VARLIB}/${PRODUCT}';
}

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
          SERVICEFILE
	  SYSCONFFILE
	  SYSCONFDIR
	  SPARSE
	  ANNOTATED
	  VARLIB
	  VARDIR / ) {

    my $val = $options{$_} || '';

    print          "$_=$val\n";
    print $outfile "$_=$val\n";
}

close $outfile;

1;
