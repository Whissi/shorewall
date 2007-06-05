#
# Shorewall-perl 3.9 -- /usr/share/shorewall-perl/Shorewall/Config.pm
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2007 - Tom Eastep (teastep@shorewall.net)
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
#   This module is responsible for lower level configuration file handling.
#   It also exports functions for generating warning and error messages.
#   The get_configuration function parses the shorewall.conf, capabilities and 
#   modules files during compiler startup.
#
package Shorewall::Config;

use strict;
use warnings;
use Shorewall::Common;
use File::Basename;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		 warning_message
		 fatal_error
		 find_file
		 split_line
		 split_line1
		 split_line2
		 open_file
		 close_file
		 push_open
		 pop_open
		 read_a_line
		 validate_level
		 qt
		 get_configuration
		 require_capability
		 report_capabilities
		 propagateconfig
		 append_file
		 run_user_exit
		 run_user_exit1
		 run_user_exit2
		 generate_aux_config

		 %config
		 %globals
		 %capabilities
		 %protocols
		 %services );
our @EXPORT_OK = ();
our @VERSION = 1.00;

#
# Misc Globals
#
our %globals  =   ( SHAREDIR => '/usr/share/shorewall' ,
		    CONFDIR =>  '/etc/shorewall',
		    SHAREDIRPL => '/usr/share/shorewall-perl/',
		    ORIGINAL_POLICY_MATCH => '',
		    LOGPARMS => '',
		    TC_SCRIPT => '',
		    VERSION =>  '4.0.0-Beta3',
		  );

#
# From shorewall.conf file
#
our %config =
	      ( STARTUP_ENABLED => undef,
		VERBOSITY => undef,
		#
		# Logging
		#
		LOGFILE => undef,
		LOGFORMAT => undef,
		LOGTAGONLY => undef,
		LOGRATE => undef,
		LOGBURST => undef,
		LOGALLNEW => undef,
		BLACKLIST_LOGLEVEL => undef,
		MACLIST_LOG_LEVEL => undef,
		TCP_FLAGS_LOG_LEVEL => undef,
		RFC1918_LOG_LEVEL => undef,
		SMURF_LOG_LEVEL => undef,
		LOG_MARTIANS => undef,
		#
		# Location of Files
		#
		IPTABLES => undef,
		#
		#PATH is inherited
		#
		PATH => undef,
		SHOREWALL_SHELL => undef,
		SUBSYSLOCK => undef,
		MODULESDIR => undef,
		#
		#CONFIG_PATH is inherited
		#
		CONFIG_PATH => undef,
		RESTOREFILE => undef,
		IPSECFILE => undef,
		LOCKFILE => undef,
		#
		# Default Actions/Macros
		#
		DROP_DEFAULT => undef,
		REJECT_DEFAULT => undef,
		ACCEPT_DEFAULT => undef,
		QUEUE_DEFAULT => undef,
		#
		# RSH/RCP Commands
		#
		RSH_COMMAND => undef,
		RCP_COMMAND => undef,
		#
		# Firewall Options
		#
		BRIDGING => undef,
		IP_FORWARDING => undef,
		ADD_IP_ALIASES => undef,
		ADD_SNAT_ALIASES => undef,
		RETAIN_ALIASES => undef,
		TC_ENABLED => undef,
		TC_EXPERT => undef,
		CLEAR_TC => undef,
		MARK_IN_FORWARD_CHAIN => undef,
		CLAMPMSS => undef,
		ROUTE_FILTER => undef,
		DETECT_DNAT_IPADDRS => undef,
		MUTEX_TIMEOUT => undef,
		ADMINISABSENTMINDED => undef,
		BLACKLISTNEWONLY => undef,
		DELAYBLACKLISTLOAD => undef,
		MODULE_SUFFIX => undef,
		DISABLE_IPV6 => undef,
		DYNAMIC_ZONES => undef,
		PKTTYPE=> undef,
		RFC1918_STRICT => undef,
		MACLIST_TABLE => undef,
		MACLIST_TTL => undef,
		SAVE_IPSETS => undef,
		MAPOLDACTIONS => undef,
		FASTACCEPT => undef,
		IMPLICIT_CONTINUE => undef,
		HIGH_ROUTE_MARKS => undef,
		USE_ACTIONS=> undef,
		OPTIMIZE => undef,
		EXPORTPARAMS => undef,
		SHOREWALL_COMPILER => undef,
		#
		# Packet Disposition
		#
		MACLIST_DISPOSITION => undef,
		TCP_FLAGS_DISPOSITION => undef,
		BLACKLIST_DISPOSITION => undef,
		);
#
# Config options and global settings that are to be copied to object script
#
our @propagateconfig = qw/ DISABLE_IPV6 MODULESDIR MODULE_SUFFIX LOGFORMAT SUBSYSLOCK LOCKFILE /;
our @propagateenv    = qw/ LOGLIMIT LOGTAGONLY LOGRULENUMBERS /;

#
# From parsing the capabilities file
#
our %capabilities =
	     ( NAT_ENABLED => undef,
	       MANGLE_ENABLED => undef,
	       MULTIPORT => undef,
	       XMULTIPORT => undef,
	       CONNTRACK_MATCH => undef,
	       USEPKTTYPE => undef,
	       POLICY_MATCH => undef,
	       PHYSDEV_MATCH => undef,
	       LENGTH_MATCH => undef,
	       IPRANGE_MATCH => undef,
	       RECENT_MATCH => undef,
	       OWNER_MATCH => undef,
	       IPSET_MATCH => undef,
	       CONNMARK => undef,
	       XCONNMARK => undef,
	       CONNMARK_MATCH => undef,
	       XCONNMARK_MATCH => undef,
	       RAW_TABLE => undef,
	       IPP2P_MATCH => undef,
	       CLASSIFY_TARGET => undef,
	       ENHANCED_REJECT => undef,
	       KLUDGEFREE => undef,
	       MARK => undef,
	       XMARK => undef,
	       MANGLE_FORWARD => undef,
	       COMMENTS => undef,
	       ADDRTYPE => undef,
	       );
#
# /etc/protocols and /etc/services
#
our %protocols;
our %services;

#
# Capabilities
#
our %capdesc = ( NAT_ENABLED     => 'NAT',
		 MANGLE_ENABLED  => 'Packet Mangling',
		 MULTIPORT       => 'Multi-port Match' ,
		 XMULTIPORT      => 'Extended Multi-port Match',
		 CONNTRACK_MATCH => 'Connection Tracking Match',
		 USEPKTTYPE      => 'Packet Type Match',
		 POLICY_MATCH    => 'Policy Match',
		 PHYSDEV_MATCH   => 'Physdev Match',
		 LENGTH_MATCH    => 'Packet length Match',
		 IPRANGE_MATCH   => 'IP Range Match',
		 RECENT_MATCH    => 'Recent Match',
		 OWNER_MATCH     => 'Owner Match',
		 IPSET_MATCH     => 'Ipset Match',
		 CONNMARK        => 'CONNMARK Target',
		 XCONNMARK       => 'Extended CONNMARK Target',
		 CONNMARK_MATCH  => 'Connmark Match',
		 XCONNMARK_MATCH => 'Extended Connmark Match',
		 RAW_TABLE       => 'Raw Table',
		 IPP2P_MATCH     => 'IPP2P Match',
		 CLASSIFY_TARGET => 'CLASSIFY Target',
		 ENHANCED_REJECT => 'Extended Reject',
		 KLUDGEFREE      => 'Repeat match',
		 MARK            => 'MARK Target',
		 XMARK           => 'Extended Mark Target',
		 MANGLE_FORWARD  => 'Mangle FORWARD Chain',
		 COMMENTS        => 'Comments',
		 ADDRTYPE        => 'Address Type Match',
	       );
#
# Directories to search for configuration files
#
our @config_path;
#
# Stash away file references here when we encounter INCLUDE
#
our @includestack;
#
# Allow nested opens
#
our @openstack;

our $currentfile;             # File handle reference
our $currentfilename;         # File NAME
our $currentlinenumber = 0;   # Line number

#
# Issue a Warning Message
#
sub warning_message
{
    my $lineinfo = $currentfile ?  " : $currentfilename ( line $currentlinenumber )" : '';

    print STDERR "   WARNING: @_$lineinfo\n";
}

#
# Issue fatal error message and die
#
sub fatal_error	{
    my $lineinfo = $currentfile ?  " : $currentfilename ( line $currentlinenumber )" : '';

    print STDERR "   ERROR: @_$lineinfo\n";

    exit 1;
}

#
# Search the CONFIG_PATH for the passed file
#
sub find_file($)
{
    my $filename=$_[0];

    return $filename if substr( $filename, 0, 1 ) eq '/';

    my $directory;

    for $directory ( @config_path ) {
	my $file = "$directory$filename";
	return $file if -f $file;
    }

    "$globals{CONFDIR}/$filename";
}

#
# Pre-process a line from a configuration file.

#    ensure that it has an appropriate number of columns.
#    supply '-' in omitted trailing columns.
#
sub split_line( $$$ ) {
    my ( $mincolumns, $maxcolumns, $description ) = @_;

    fatal_error "Shorewall Configuration file entries may not contain single quotes, double quotes, single back quotes or backslashes" if $line =~ /["'`\\]/;

    my @line = split( /\s+/, $line, $maxcolumns + 1 );

    fatal_error "Invalid $description entry (too few columns)"  if @line < $mincolumns;
    fatal_error "Invalid $description entry (too many columns)" if @line > $maxcolumns;

    push @line, '-' while @line < $maxcolumns;

    @line;
}

#
# Version of 'split_line' that handles COMMENT lines
#
sub split_line1( $$$ ) {
    my ( $mincolumns, $maxcolumns, $description ) = @_;

    fatal_error "Shorewall Configuration file entries may not contain double quotes, single back quotes or backslashes" if $line =~ /["`\\]/;

    my @line = split( /\s+/, $line, $maxcolumns + 1);

    return @line if $line[0] eq 'COMMENT';

    fatal_error "Shorewall Configuration file entries may not contain single quotes" if $line =~ /'/;

    fatal_error "Invalid $description entry (too few columns)"  if @line < $mincolumns;
    fatal_error "Invalid $description entry (too many columns)" if @line > $maxcolumns;

    push @line, '-' while @line < $maxcolumns;

    @line;
}

#
# When splitting a line in the rules file, don't pad out the columns with '-' if the first column contains one of these
#

my %no_pad = ( COMMENT => 0,
	       SECTION => 2 );

#
# Version of 'split_line' used on rules file entries
#
sub split_line2( $$$ ) {
    my ( $mincolumns, $maxcolumns, $description ) = @_;

    fatal_error "Shorewall Configuration file entries may not contain double quotes, single back quotes or backslashes" if $line =~ /["`\\]/;

    my @line = split( /\s+/, $line, $maxcolumns + 1 );

    my $first   = $line[0];
    my $columns = $no_pad{$first};

    if ( defined $columns ) {
	fatal_error "Invalid $first entry" if $columns && @line != $columns;
	return @line 
    }

    fatal_error "Shorewall Configuration file entries may not contain single quotes" if $line =~ /'/;

    fatal_error "Invalid $description entry (too few columns)"  if @line < $mincolumns;
    fatal_error "Invalid $description entry (too many columns)" if @line > $maxcolumns;

    push @line, '-' while @line < $maxcolumns;

    @line;
}

#
# Open a file, setting $currentfile. Returns the file's absolute pathname if the file
# exists, is non-empty  and was successfully opened. Terminates with a fatal error
# if the file exists, is non-empty, but the open fails.
#
sub do_open_file( $ ) {
    my $fname = $_[0];
    open $currentfile, '<', $fname or fatal_error "Unable to open $fname: $!";
    $currentlinenumber = 0;
    $currentfilename   = $fname;
}

sub open_file( $ ) {
    my $fname = find_file $_[0];

    fatal_error 'Internal Error in open_file()' if defined $currentfile;

    do_open_file $fname if -f $fname && -s _;
}

#
# This function is normally called below in read_a_line() when EOF is reached. Clients of the
# module may also call the function to close the file before EOF
#

sub close_file() {
    if ( $currentfile ) {
	close $currentfile;

	my $arrayref = pop @includestack;

	if ( $arrayref ) {
	    ( $currentfile, $currentfilename, $currentlinenumber ) = @$arrayref;
	} else {
	    $currentfile = undef;
	}
    }
}

#
# The following two functions allow module clients to nest opens. This happens frequently
# in the Actions module.
#
sub push_open( $ ) {

    push @includestack, [ $currentfile, $currentfilename, $currentlinenumber ];
    my @a = @includestack;
    push @openstack, \@a;
    @includestack = ();
    $currentfile = undef;
    open_file( $_[0] );

}

sub pop_open() {
    @includestack = @{pop @openstack};

    my $arrayref = pop @includestack;

    if ( $arrayref ) {
	( $currentfile, $currentfilename, $currentlinenumber ) = @$arrayref;
    } else {
	$currentfile = undef;
    }
}

#
# Read a line from the current include stack.
#
#   - Ignore blank or comment-only lines.
#   - Remove trailing comments.
#   - Handle Line Continuation
#   - Expand shell variables from $ENV.
#   - Handle INCLUDE <filename>
#

sub read_a_line {
    while ( $currentfile ) {

	$line = '';

	while ( my $nextline = <$currentfile> ) {

	    $currentlinenumber++;

	    chomp $nextline;
	    #
	    # Continuation
	    #
	    if ( substr( ( $line .= $nextline ), -1, 1 ) eq '\\' ) {
		$line = substr( $line, 0, -1 );
		next;
	    }

	    $line =~ s/#.*$//;       # Remove Trailing Comments -- result might be a blank line
	    #
	    # Ignore ( concatenated ) Blank Lines
	    #
	    if ( $line =~ /^\s*$/ ) {
		$line = '';
		next;
	    }

	    $line =~ s/^\s+//;       # Remove Leading white space
	    $line =~ s/\s+$//;       # Remove Trailing white space

	    #
	    # Expand Shell Variables using %ENV 
	    #
	    $line = join( '', $1 , ( $ENV{$2} || '' ) , $3 ) while $line =~ /^(.*?)\${([a-zA-Z]\w*)}(.*)$/;
	    $line = join( '', $1 , ( $ENV{$2} || '' ) , $3 ) while $line =~ /^(.*?)\$([a-zA-Z]\w*)(.*)$/;

	    if ( $line =~ /^INCLUDE\s/ ) {

		my @line = split /\s+/, $line, 3;

		fatal_error "Invalid INCLUDE command: $line"    if @line != 2;
		fatal_error "INCLUDEs nested too deeply: $line" if @includestack >= 4;

		my $filename = find_file $line[1];

		fatal_error "INCLUDE file $filename not found" unless ( -f $filename );

		if ( -s _ ) {
		    push @includestack, [ $currentfile, $currentfilename, $currentlinenumber ];
		    $currentfile = undef;
		    do_open_file $filename;
		}

		$line = '';
	    } else {
		return 1;
	    }
	}

	close_file;
    }
}

#
# Provide the passed default value for the passed configuration variable
#
sub default ( $$ ) {
    my ( $var, $val ) = @_;

    $config{$var} = $val unless defined $config{$var} && $config{$var} ne '';
}

#
# Provide a default value for a yes/no configuration variable.
#
sub default_yes_no ( $$ ) {
    my ( $var, $val ) = @_;

    my $curval = "\L$config{$var}";

    if ( defined $curval && $curval ne '' ) {
	if (  $curval eq 'no' ) {
	    $config{$var} = '';
	} else {
	    fatal_error "Invalid value for $var ($val)" unless $curval eq 'yes';
	}
    } else {
	$config{$var} = $val;
    }
}

my %validlevels = ( debug   => 7,
		    info    => 6,
		    notice  => 5, 
		    warning => 4, 
		    warn    => 4, 
		    err     => 3,
		    error   => 3,
		    crit    => 2, 
		    alert   => 1, 
		    emerg   => 0, 
		    panic   => 0,
		    none    => '',
		    ULOG    => 'ULOG' );

#
# Validate a log level -- Drop the trailing '!' that some fools think is important.
#
sub validate_level( $ ) {
    my $level = $_[0];

    if ( defined $level && $level ne '' ) {
	$level =~ s/!$//;
	my $value = $validlevels{$level};
	return $value if defined $value;
	return $level if $level =~ /^[0-7]$/;
	fatal_error "Invalid log level ($level)";
    }

    '';
}

#
# Validate a log level and supply default
#
sub default_log_level( $$ ) {
    my ( $level, $default ) = @_;

    my $value = $config{$level};

    unless ( defined $value && $value ne '' ) {
	$config{$level} = $default;
    } else {
	$config{$level} = validate_level $value;
    }
}

#
# Check a tri-valued variable
#
sub check_trivalue( $$ ) {
    my ( $var, $default) = @_;
    my $val = "\L$config{$var}";

    if ( defined $val ) {
	if ( $val eq 'yes' || $val eq 'on' ) {
	    $config{$var} = 'on';
	} elsif ( $val eq 'no' || $val eq 'off' ) {
	    $config{$var} = 'off';
	} elsif ( $val eq 'keep' ) {
	    $config{$var} = '';
	} elsif ( $val eq '' ) {
	    $config{$var} = $default
	} else {
	    fatal_error "Invalid value ( $val ) for $var";
	}
    } else {
	$config{var} = $default
    }
}
    
#
# Produce a report of the detected capabilities
#
sub report_capabilities() {
    sub report_capability( $ ) {
	my $cap = $_[0];
	print "   $capdesc{$cap}: ";
	print $capabilities{$cap} ? "Available\n" : "Not Available\n";
    }

    print "Shorewall has detected the following capabilities:\n";

    for my $cap ( sort { $capdesc{$a} cmp $capdesc{$b} } keys %capabilities ) {
	report_capability $cap;
    }
}

#
# Search the current PATH for the passed executable
#
sub mywhich( $ ) {
    my $prog = $_[0];

    for my $dir ( split /:/, $ENV{PATH} ) {
	return "$dir/$prog" if -x "$dir/$prog";
    }

    '';
}

#
# Load the kernel modules defined in the 'modules' file.
#
sub load_kernel_modules( ) {
    my $moduleloader = mywhich 'modprobe' ? 'modprobe' : 'insmod';

    my $modulesdir = $config{MODULESDIR};

    unless ( $modulesdir ) {
	my $uname = `uname -r`;
	fatal_error "The command 'uname -r' failed" unless $? == 0;
	chomp $uname;
	$modulesdir = "/lib/modules/$uname/kernel/net/ipv4/netfilter:/lib/modules/$uname/kernel/net/netfilter";
    }

    my @moduledirectories = split /:/, $modulesdir;

    if ( @moduledirectories && open_file 'modules' ) {
	my %loadedmodules;

	progress_message "Loading Modules...";

	open LSMOD , '-|', 'lsmod' or fatal_error "Can't run lsmod";

	while ( $line = <LSMOD> ) {
	    my $module = ( split( /\s+/, $line, 2 ) )[0];
	    $loadedmodules{$module} = 1 unless $module eq 'Module'
	}

	close LSMOD;

	$config{MODULE_SUFFIX} = 'o gz ko o.gz ko.gz' unless $config{MODULES_SUFFIX};

	my @suffixes = split /\s+/ , $config{MODULE_SUFFIX};

	while ( read_a_line ) {
	    fatal_error "Invalid modules file entry" unless ( $line =~ /^loadmodule\s+([a-zA-Z]\w*)\s*(.*)$/ );
	    my ( $module, $arguments ) = ( $1, $2 );
	    unless ( $loadedmodules{ $module } ) {
		for my $directory ( @moduledirectories ) {
		    for my $suffix ( @suffixes ) {
			my $modulefile = "$directory/$module.$suffix";
			if ( -f $modulefile ) {
			    if ( $moduleloader eq 'insmod' ) {
				system ("insmod $modulefile $arguments" );
			    } else {
				system( "modprobe $module $arguments" );
			    }

			    $loadedmodules{ $module } = 1;
			}
		    }
		}
	    }
	}
    }
}

#
# Q[uie]t version of system(). Returns true for success
#
sub qt( $ ) {
    system( "@_ > /dev/null 2>&1" ) == 0;
}

#
# Determine which optional facilities are supported by iptables/netfilter
#
sub determine_capabilities() {

    my $iptables  = $config{IPTABLES};
    my $pid       = $$;
    my $sillyname = "fooX$pid";

    $capabilities{NAT_ENABLED}    = qt( "$iptables -t nat -L -n" );
    $capabilities{MANGLE_ENABLED} = qt( "$iptables -t mangle -L -n" );

    qt( "$iptables -N $sillyname" );

    $capabilities{CONNTRACK_MATCH} = qt( "$iptables -A $sillyname -m conntrack --ctorigdst 192.168.1.1 -j ACCEPT" );
    $capabilities{MULTIPORT}       = qt( "$iptables -A $sillyname -p tcp -m multiport --dports 21,22 -j ACCEPT" );
    $capabilities{XMULTIPORT}      = qt( "$iptables -A $sillyname -p tcp -m multiport --dports 21:22 -j ACCEPT" );
    $capabilities{POLICY_MATCH}    = qt( "$iptables -A $sillyname -m policy --pol ipsec --mode tunnel --dir in -j ACCEPT" );
    $capabilities{PHYSDEV_MATCH}   = qt( "$iptables -A $sillyname -m physdev --physdev-in eth0 -j ACCEPT" );

    if ( qt( "$iptables -A $sillyname -m iprange --src-range 192.168.1.5-192.168.1.124 -j ACCEPT" ) ) {
	$capabilities{IPRANGE_MATCH} = 1;
	unless ( $capabilities{KLUDGEFREE} ) {
	    $capabilities{KLUDGEFREE} = qt( "$iptables -A $sillyname -m iprange --src-range 192.168.1.5-192.168.1.124 -m iprange --dst-range 192.168.1.5-192.168.1.124 -j ACCEPT" );
	}
    }

    $capabilities{RECENT_MATCH} = qt( "$iptables -A $sillyname -m recent --update -j ACCEPT" );
    $capabilities{OWNER_MATCH}  = qt( "$iptables -A $sillyname -m owner --uid-owner 0 -j ACCEPT" );

    if ( qt( "$iptables -A $sillyname -m connmark --mark 2  -j ACCEPT" )) {
	$capabilities{CONNMARK_MATCH}  = 1;
	$capabilities{XCONNMARK_MATCH} = qt( "$iptables -A $sillyname -m connmark --mark 2/0xFF -j ACCEPT" );
    }

    $capabilities{IPP2P_MATCH}     = qt( "$iptables -A $sillyname -p tcp -m ipp2p --ipp2p -j ACCEPT" );
    $capabilities{LENGTH_MATCH}    = qt( "$iptables -A $sillyname -m length --length 10:20 -j ACCEPT" );
    $capabilities{ENHANCED_REJECT} = qt( "$iptables -A $sillyname -j REJECT --reject-with icmp-host-prohibited" );
    $capabilities{COMMENTS}        = qt( qq($iptables -A $sillyname -j ACCEPT -m comment --comment "This is a comment" ) );

    if  ( $capabilities{MANGLE_ENABLED} ) {
	qt( "$iptables -t mangle -N $sillyname" );

	if ( qt( "$iptables -t mangle -A $sillyname -j MARK --set-mark 1" ) ) {
	    $capabilities{MARK}  = 1;
	    $capabilities{XMARK} = qt( "$iptables -t mangle -A $sillyname -j MARK --and-mark 0xFF" );
	}

	if ( qt( "$iptables -t mangle -A $sillyname -j CONNMARK --save-mark" ) ) {
	    $capabilities{CONNMARK}  = 1;
	    $capabilities{XCONNMARK} = qt( "$iptables -t mangle -A $sillyname -j CONNMARK --save-mark --mask 0xFF" );
	}

	$capabilities{CLASSIFY_TARGET} = qt( "$iptables -t mangle -A $sillyname -j CLASSIFY --set-class 1:1" );
	qt( "$iptables -t mangle -F $sillyname" );
	qt( "$iptables -t mangle -X $sillyname" );

	$capabilities{MANGLE_FORWARD} = qt( "$iptables -t mangle -L FORWARD -n" );
    }

    $capabilities{RAW_TABLE} = qt( "$iptables -t raw -L -n" );

    if ( mywhich 'ipset' ) {
	qt( "ipset -X $sillyname" );

	if ( qt( "ipset -N $sillyname iphash" ) ) {
	    if ( qt( "$iptables -A $sillyname -m set --set $sillyname src -j ACCEPT" ) ) {
		qt( "$iptables -D $sillyname -m set --set $sillyname src -j ACCEPT" );
		$capabilities{IPSET_MATCH} = 1;
	    }

	    qt( "ipset -X $sillyname" );
	}
    }

    $capabilities{USEPKTTYPE} = qt( "$iptables -A $sillyname -m pkttype --pkt-type broadcast -j ACCEPT" );
    $capabilities{ADDRTYPE}   = qt( "$iptables -A $sillyname -m addrtype --src-type BROADCAST -j ACCEPT" );

    qt( "$iptables -F $sillyname" );
    qt( "$iptables -X $sillyname" );
}

#
# Require the passed capability
#
sub require_capability( $$$ ) {
    my ( $capability, $description, $singular ) = @_;

    fatal_error "$description require${singular} $capdesc{$capability} in your kernel and iptables"
      unless $capabilities{$capability};
}

#
# Set default config path
#
sub ensure_config_path() {

    my $f = "$globals{SHAREDIR}/configpath";

    $globals{CONFDIR} = '/usr/share/shorewall/configfiles/' if $> != 0;

    unless ( $config{CONFIG_PATH} ) {
	fatal_error "$f does not exist" unless -f $f;

	open_file $f;

	$ENV{CONFDIR} = $globals{CONFDIR};

	while ( read_a_line ) {
	    if ( $line =~ /^\s*([a-zA-Z]\w*)=(.*?)\s*$/ ) {
		my ($var, $val) = ($1, $2);
		$config{$var} = ( $val =~ /\"([^\"]*)\"$/ ? $1 : $val ) if exists $config{$var};
	    } else {
		fatal_error "Unrecognized entry";
	    }
	}

	fatal_error "CONFIG_PATH not found in $f" unless $config{CONFIG_PATH};
    }

    @config_path = split /:/, $config{CONFIG_PATH};

    for ( @config_path ) {
	$_ .= '/' unless m|//$|;
    }

    if ( my $sd = $ENV{SHOREWALL_DIR} ) {
	$sd .= '/' unless $sd =~ m|//$|;
	unshift @config_path, $sd if $sd ne $config_path[0];
    }
}

#
# - Read the shorewall.conf file
# - Read the capabilities file, if any
# - establish global hashes %config , %globals and %capabilities
#
sub get_configuration( $ ) {

    my $export = $_[0];

    ensure_config_path;

    my $file = find_file 'shorewall.conf';

    if ( -f $file ) {
	if ( -r _ ) {
	    open_file $file;

	    while ( read_a_line ) {
		if ( $line =~ /^\s*([a-zA-Z]\w*)=(.*?)\s*$/ ) {
		    my ($var, $val) = ($1, $2);
		    unless ( exists $config{$var} ) {
			warning_message "Unknown configuration option ($var) ignored";
			next;
		    }

		    $config{$var} = ( $val =~ /\"([^\"]*)\"$/ ? $1 : $val );
		} else {
		    fatal_error "Unrecognized entry";
		}
	    }
	} else {
	    fatal_error "Cannot read $file (Hint: Are you root?)";
	}
    } else {
	fatal_error "$file does not exist!";
    }

    ensure_config_path;

    default 'PATH' , '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin';

    default 'MODULE_PREFIX', 'o gz ko o.gz ko.gz';

    if ( ! $export && $> == 0 ) { # $> == $EUID
	unless ( $config{IPTABLES} ) {
	    $config{IPTABLES} = mywhich 'iptables';
	    fatal_error "Can't find iptables executable" unless $config{IPTABLES};
	} else {
	    fatal_error "\$IPTABLES=$config{IPTABLES} does not exist or is not executable" unless -x $config{IPTABLES};
	}

	load_kernel_modules;

	unless ( open_file 'capabilities' ) {
	    determine_capabilities;
	}
    } else {
	open_file 'capabilities' or fatal_error "The -e flag requires a capabilities file";
    }

    #
    # If we successfully called open_file above, then this loop will read the capabilities file.
    # Otherwise, the first call to read_a_line() below will return false
    #
    while ( read_a_line ) {
	if ( $line =~ /^([a-zA-Z]\w*)=(.*)$/ ) {
	    my ($var, $val) = ($1, $2);
	    unless ( exists $capabilities{$var} ) {
		warning_message "Unknown capability ($var) ignored";
		next;
	    }

	    $capabilities{$var} = $val =~ /^\"([^\"]*)\"$/ ? $1 : $val;
	} else {
	    fatal_error "Unrecognized capabilities entry";
	}
    }

    $globals{ORIGINAL_POLICY_MATCH} = $capabilities{POLICY_MATCH};

    if ( $config{LOGRATE} || $config{LOGBURST} ) {
	 $globals{LOGLIMIT}  = '-m limit ';
	 $globals{LOGLIMIT} .= "--limit $config{LOGRATE} "        if $config{LOGRATE};
	 $globals{LOGLIMIT} .= "--limit-burst $config{LOGBURST} " if $config{LOGBURST};
    } else {
	$globals{LOGLIMIT} = '';
    }

    check_trivalue ( 'IP_FORWARDING', 'on' );
    check_trivalue ( 'ROUTE_FILTER',  '' );
    check_trivalue ( 'LOG_MARTIANS',  '' );
 
    default_yes_no 'ADD_IP_ALIASES'             , 'Yes';
    default_yes_no 'ADD_SNAT_ALIASES'           , '';
    default_yes_no 'DETECT_DNAT_IPADDRS'        , '';
    default_yes_no 'DETECT_DNAT_IPADDRS'        , '';
    default_yes_no 'CLEAR_TC'                   , 'Yes';
    if ( defined $config{CLAMPMSS} ) {
	default_yes_no 'CLAMPMSS'                   , '' unless $config{CLAMPMSS} =~ /^\d+$/;
    } else {
	$config{CLAMPMSS} = '';
    }

    unless ( $config{ADD_IP_ALIASES} || $config{ADD_SNAT_ALIASES} ) {
	$config{RETAIN_ALIASES} = '';
    } else {
	default_yes_no 'RETAIN_ALIASES'             , '';
    }

    default_yes_no 'ADMINISABSENTMINDED'        , '';
    default_yes_no 'BLACKLISTNEWONLY'           , '';
    default_yes_no 'DISABLE_IPV6'               , '';
    default_yes_no 'DYNAMIC_ZONES'              , '';

    fatal_error "DYNAMIC_ZONES=Yes is incompatible with the -e option" if $config{DYNAMIC_ZONES} && $export;

    default_yes_no 'BRIDGING'                   , '';

    fatal_error 'BRIDGING=Yes is not supported by Shorewall-perl' . $globals{VERSION} if $config{BRIDGING};

    default_yes_no 'STARTUP_ENABLED'            , 'Yes';
    default_yes_no 'DELAYBLACKLISTLOAD'         , '';

    warning_message 'DELAYBLACKLISTLOAD=Yes is not supported by Shorewall-perl ' . $globals{VERSION} if $config{DELAYBLACKLISTLOAD};

    default_yes_no 'LOGTAGONLY'                 , '';
    default_yes_no 'RFC1918_STRICT'             , '';
    default_yes_no 'SAVE_IPSETS'                , '';

    warning_message 'SAVE_IPSETS=Yes is not supported by Shorewall-perl ' . $globals{VERSION} if $config{SAVE_IPSETS};

    default_yes_no 'MAPOLDACTIONS'              , '';

    warning_message 'MAPOLDACTIONS=Yes is not supported by Shorewall-perl ' . $globals{VERSION} if $config{MAPOLDACTIONS};

    default_yes_no 'FASTACCEPT'                 , '';

    fatal_error "BLACKLISTNEWONLY=No may not be specified with FASTACCEPT=Yes" if $config{FASTACCEPT} && ! $config{BLACKLISTNEWONLY};

    default_yes_no 'IMPLICIT_CONTINUE'          , '';
    default_yes_no 'HIGH_ROUTE_MARKS'           , '';
    default_yes_no 'TC_EXPERT'                  , '';
    default_yes_no 'USE_ACTIONS'                , 'Yes';

    warning_message 'USE_ACTIONS=No is not supported by Shorewall-perl ' . $globals{VERSION} unless $config{USE_ACTIONS};

    default_yes_no 'EXPORTPARAMS'               , '';
    default_yes_no 'MARK_IN_FORWARD_CHAIN'      , '';

    $capabilities{XCONNMARK} = '' unless $capabilities{XCONNMARK_MATCH} and $capabilities{XMARK};

    default 'BLACKLIST_DISPOSITION'             , 'DROP';

    default_log_level 'BLACKLIST_LOGLEVEL',  '';
    default_log_level 'MACLIST_LOG_LEVEL',   '';
    default_log_level 'TCP_FLAGS_LOG_LEVEL', '';
    default_log_level 'RFC1918_LOG_LEVEL',    6;
    default_log_level 'SMURF_LOG_LEVEL',     '';
    default_log_level 'LOGALLNEW',           '';

    my $val;

    $globals{MACLIST_TARGET} = 'reject';

    if ( $val = $config{MACLIST_DISPOSITION} ) {
	unless ( $val eq 'REJECT' ) {
	    if ( $val eq 'DROP' ) {
		$globals{MACLIST_TARGET} = 'DROP';
	    } elsif ( $val eq 'ACCEPT' ) {
		$globals{MACLIST_TARGET} = 'RETURN';
	    } else {
		fatal_error "Invalid value ( $config{MACLIST_DISPOSITION} ) for MACLIST_DISPOSITION"
		}
	}
    } else {
	$config{MACLIST_DISPOSITION} = 'REJECT';
    }

    if ( $val = $config{MACLIST_TABLE} ) {
	if ( $val eq 'mangle' ) {
	    fatal_error 'MACLIST_DISPOSITION=REJECT is not allowed with MACLIST_TABLE=mangle' if $config{MACLIST_DISPOSITION} eq 'REJECT';
	} else {
	    fatal_error "Invalid value ($val) for MACLIST_TABLE option" unless $val eq 'filter';
	}
    } else {
	default 'MACLIST_TABLE' , 'filter';
    }

    if ( $val = $config{TCP_FLAGS_DISPOSITION} ) {
	fatal_error "Invalid value ($config{TCP_FLAGS_DISPOSITION}) for TCP_FLAGS_DISPOSITION" unless $val =~ /^(REJECT|ACCEPT|DROP)$/;
    } else {
	$config{TCP_FLAGS_DISPOSITION} = 'DROP';
    }

    default 'TC_ENABLED' , 'Internal';

    $val = "\L$config{TC_ENABLED}";

    if ( $val eq 'yes' ) {
	$file = find_file 'tcstart';
	fatal_error "Unable to find tcstart file" unless -f $file;
	$globals{TC_SCRIPT} = $file;
    } elsif ( $val ne 'internal' ) {
	fatal_error "Invalid value ($config{TC_ENABLED}) for TC_ENABLED" unless $val eq 'no';
	$config{TC_ENABLED} = '';
    }

    default 'RESTOREFILE'           , 'restore';
    default 'DROP_DEFAULT'          , 'Drop';
    default 'REJECT_DEFAULT'        , 'Reject';
    default 'QUEUE_DEFAULT'         , 'none';
    default 'ACCEPT_DEFAULT'        , 'none';
    default 'OPTIMIZE'              , 0;
    default 'IPSECFILE'             , 'zones';

    fatal_error 'IPSECFILE=ipsec is not supported by Shorewall-perl ' . $globals{VERSION} unless $config{IPSECFILE} eq 'zones';

    for my $default qw/DROP_DEFAULT REJECT_DEFAULT QUEUE_DEFAULT ACCEPT_DEFAULT/ {
	$config{$default} = 'none' if "\L$config{$default}" eq 'none';
    }

    $val = $config{OPTIMIZE};

    fatal_error "Invalid OPTIMIZE value ($val)" unless ( $val eq '0' ) || ( $val eq '1' );

    fatal_error "Invalid IPSECFILE value ($config{IPSECFILE}" unless $config{IPSECFILE} eq 'zones';

    $globals{MARKING_CHAIN} = $config{MARK_IN_FORWARD_CHAIN} ? 'tcfor' : 'tcpre';

    if ( $val = $config{LOGFORMAT} ) {
	my $result;

	eval {
	    if ( $val =~ /%d/ ) {
		$globals{LOGRULENUMBERS} = 'Yes';
		$result = sprintf "$val", 'fooxx2barxx', 1, 'ACCEPT';
	    } else {
		$result = sprintf "$val", 'fooxx2barxx', 'ACCEPT';
	    }
	};

	fatal_error "Invalid LOGFORMAT ($val)" if $@;

	fatal_error "LOGFORMAT string is longer than 29 characters: \"$val\"" if length $result > 29;

	$globals{MAXZONENAMELENGTH} = int ( 5 + ( ( 29 - (length $result ) ) / 2) );
    } else {
	$config{LOGFORMAT}='Shorewall:%s:%s:';
	$globals{MAXZONENAMELENGTH} = 5;
    }

    if ( $config{LOCKFILE} ) {
	my ( $file, $dir, $suffix );

	eval {
	    ( $file, $dir, $suffix ) = fileparse( $config{LOCKFILE} );
	};

	die $@ if $@;

	fatal_error "LOCKFILE=$config{LOCKFILE}: Directory $dir does not exist" unless -d $dir;
    } else {
	$config{LOCKFILE} = '';
    }

    open_file '/etc/protocols' or fatal_error "Cannot open /etc/protocols: $!";

    while ( read_a_line ) {
	my ( $proto1, $number, $proto2, $proto3 ) = split_line( 2, 4, '/etc/protocols entry');

	$protocols{ $proto1 } = $number;
	$protocols{ $proto2 } = $number unless $proto2 eq '-' || $proto3 ne '-';
    }

    
    open_file '/etc/services' or fatal_error "Cannot open /etc/services: $!";

    while ( read_a_line ) {
	my ( $name1, $proto_number, @names ) = split_line( 2, 10, '/etc/services entry');

	my ( $number, $proto ) = split '/', $proto_number;

	$services{ $name1 } = $number;
	
	while ( defined ( $name1 = shift @names ) && $name1 ne '-' ) {
	    $services{ $name1 } = $number;
	}
    }
}

#
# The values of the options in @propagateconfig are copied to the object file in OPTION=<value> format.
#
sub propagateconfig() {
    for my $option ( @propagateconfig ) {
	my $value = $config{$option} || '';
	emit "$option=\"$value\"";
    }

    for my $option ( @propagateenv ) {
	my $value = $globals{$option} || '';
	emit "$option=\"$value\"";
    }
}

#
# Add a shell script file to the output script -- Return true if the
# file exists and is not in /usr/share/shorewall/.
#
sub append_file( $ ) {
    my $user_exit = find_file $_[0];
    my $result = 0;

    unless ( $user_exit =~ /$globals{SHAREDIR}/ ) {
	if ( -f $user_exit ) {
	    $result = 1;
	    save_progress_message "Processing $user_exit ...";
	    copy1 $user_exit;
	}
    }

    $result;
}

#
# Run a Perl extension script
#
sub run_user_exit( $ ) {
    my $chainref = $_[0];
    my $file = find_file $chainref->{name};

    if ( -f $file ) {
	progress_message "Processing $file...";

	unless (my $return = eval `cat $file` ) {
	    fatal_error "Couldn't parse $file: $@" if $@;
	    fatal_error "Couldn't do $file: $!"    unless defined $return;
	    fatal_error "Couldn't run $file";
	}
    }
}

sub run_user_exit1( $ ) {
    my $file = find_file $_[0];

    if ( -f $file ) {
	progress_message "Processing $file...";
	#
	# File may be empty -- in which case eval would fail
	#
	push_open $file;

	if ( read_a_line ) {
	    close_file;

	    unless (my $return = eval `cat $file` ) {
		fatal_error "Couldn't parse $file: $@" if $@;
		fatal_error "Couldn't do $file: $!"    unless defined $return;
		fatal_error "Couldn't run $file";
	    }
	}

	pop_open;
    }
}

sub run_user_exit2( $$ ) {
    my ($file, $chainref) = ( find_file $_[0], $_[1] );

    if ( -f $file ) {
	progress_message "Processing $file...";
	#
	# File may be empty -- in which case eval would fail
	#
	push_open $file;

	if ( read_a_line ) {
	    close_file;

	    unless (my $return = eval `cat $file` ) {
		fatal_error "Couldn't parse $file: $@" if $@;
		fatal_error "Couldn't do $file: $!"    unless defined $return;
		fatal_error "Couldn't run $file";
	    }
	}

	pop_open;
	
    }
}

#
# Generate the aux config file for Shorewall Lite
#
sub generate_aux_config() {
    sub conditionally_add_option( $ ) {
	my $option = $_[0];

	my $value = $config{$option};

	emit "[ -n \"\${$option:=$value}\" ]" if $value ne '';
    }

    sub conditionally_add_option1( $ ) {
	my $option = $_[0];

	my $value = $config{$option};

	emit "$option=\"$value\"" if $value;
    }

    create_temp_aux_config;

    emit join ( '', "#\n# Shorewall auxiliary configuration file created by Shorewall-perl version ", $globals{VERSION}, ' - ' , localtime , "\n#" );

    for my $option qw(VERBOSITY LOGFILE LOGFORMAT IPTABLES PATH SHOREWALL_SHELL SUBSYSLOCK LOCKFILE RESTOREFILE SAVE_IPSETS) {
	conditionally_add_option $option;
    }

    conditionally_add_option1 'TC_ENABLED';

    finalize_aux_config;

}

1;
