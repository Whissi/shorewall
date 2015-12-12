#! /usr/bin/perl -w
#
#     Shorewall Packet Filtering Firewall RPM configuration program - V4.5
#
#     (c) 2012, 2014 - Tom Eastep (teastep@shorewall.net)
#
#	Shorewall documentation is available at http://www.shorewall.net
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

use File::Basename;
chdir dirname($0);

my $vendor = $params{HOST};
my $rcfile;
my $rcfilename;

unless ( defined $vendor ) {
    if ( -f '/etc/os-release' ) {
	my $id = `cat /etc/os-release | grep ^ID=`;

	chomp $id;

	$id =~ s/ID=//;
	
	if ( $id eq 'fedora' || $id eq 'rhel' ) {
	    $vendor = 'redhat';
	} elsif ( $id eq 'opensuse' ) {
	    $vendor = 'suse';
	} elsif ( $id eq 'ubuntu' || $id eq 'debian' ) {
	    my $init = `ls -l /sbin/init`;
	    $vendor = $init =~ /systemd/ ? 'debian.systemd' : 'debian.sysvinit';
	} else {
	    $vendor = $id;
	}
    }

    $params{HOST} = $vendor;
    $params{HOST} =~ s/\..*//;
}

if ( defined $vendor ) {
    if ( $vendor eq 'debian' && -f '/etc/debian_version' ) {
	if ( -l '/sbin/init' ) {
	    if ( readlink('/sbin/init') =~ /systemd/ ) {
		$rcfilename = 'shorewallrc.debian.systemd';
	    } else {
		$rcfilename = 'shorewallrc.debian.sysvinit';
	    }
	} else {
	    $rcfilename = 'shorewallrc.debian.sysvinit';
	}
    } else {
	$rcfilename = $vendor eq 'linux' ? 'shorewallrc.default' : 'shorewallrc.' . $vendor;
    }

    unless ( -f $rcfilename ) {
	die qq("ERROR: $vendor" is not a recognized host type);
    } elsif ( $vendor eq 'default' ) {
	$params{HOST} = $vendor = 'linux';
    } elsif ( $vendor =~ /^debian\./ ) {
	$params{HOST} = $vendor = 'debian';
    }
} else {
    if ( -f '/etc/debian_version' ) {
	$vendor = 'debian';
	if ( -l '/sbin/init' ) {
	    if ( readlink '/sbin/init' =~ /systemd/ ) {
		$rcfilename = 'debian.systemd';
	    } else {
	$rcfilename = 'shorewallrc.debian.sysvinit';
	    }
	} else {
	    $rcfilename = 'shorewallrc.debian.sysvinit';
	}
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
    } elsif ( `uname` =~ /^Cygwin/i ) {
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
    printf "INFO: Creating a %s-specific installation - %s %2d %04d %02d:%02d:%02d\n\n", $params{HOST}, $abbr[$localtime[4]], $localtime[3], 1900 + $localtime[5] , @localtime[2,1,0];;
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

printf $outfile "#\n# Created by Shorewall Core version %s configure.pl - %s %2d %04d %02d:%02d:%02d\n", VERSION, $abbr[$localtime[4]], $localtime[3], 1900 + $localtime[5] , @localtime[2,1,0];
print $outfile "# rc file: $rcfilename\n#\n";

print  $outfile "# Input: @ARGV\n#\n" if @ARGV;

if ( $options{VARLIB} ) {
    unless ( $options{VARDIR} ) {
	$options{VARDIR} = '${VARLIB}/${PRODUCT}';
    }
} elsif ( $options{VARDIR} ) {
    $options{VARLIB} = $options{VARDIR};
    $options{VARDIR} = '${VARLIB}/${PRODUCT}';
}

$options{SERVICEDIR}=$options{SYSTEMD} unless $options{SERVICEDIR};

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
	  SERVICEDIR
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
