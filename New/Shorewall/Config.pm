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
#
package Shorewall::Config;

use strict;
use warnings;
use Shorewall::Common;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		 warning_message 
		 fatal_error
                 find_file
                 split_line
                 open_file
                 close_file
                 push_open
                 pop_open
                 read_a_line
                 get_configuration
                 require_capability
                 report_capabilities
                 propagateconfig
                 append_file
                 run_user_exit
                 generate_aux_config

                 %config
                 %globals
                 %capabilities );
our @EXPORT_OK = ();
our @VERSION = 1.00;

#
# Misc Globals
#
our %globals  =   ( SHAREDIR => '/usr/share/shorewall' ,
		    CONFDIR =>  '/etc/shorewall',
		    SHAREDIRPL => '/usr/share/shorewall-perl/',
		    LOGPARMS => '',
		    VERSION =>  '3.9.0-1',
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
		#PATH is inherited
		PATH => undef,
		SHOREWALL_SHELL => undef,
		SUBSYSLOCK => undef,
		MODULESDIR => undef,
		#CONFIG_PATH is inherited
		CONFIG_PATH => undef,
		RESTOREFILE => undef,
		IPSECFILE => undef,
		#
		# Default Actions/Macros
		#
		DROP_DEFAULT => undef,
		REJECT_DEFAULT => undef,
		ACCEPT_DEFAULT => undef,
		QUEUE_DEFAULT => undef,
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
		ORIGINAL_POLICY_MATCH => undef,
		);
#
# Config options and global settings that are to be copied to object
#
my @propagateconfig = qw/ CLEAR_TC DISABLE_IPV6 ADMINISABSENTMINDED IP_FORWARDING MODULESDIR MODULE_SUFFIX LOGFORMAT SUBSYSLOCK/;
my @propagateenv    = qw/ LOGLIMIT LOGTAGONLY LOGRULENUMBERS /;


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

my %capdesc = ( NAT_ENABLED     => 'NAT',
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

my @config_path;
#
# Stash away file references here when we encounter INCLUDE
#
my @openstack;

my $currentfile;
my $currentfilename;
my $currentlinenumber = 0;
my $tmp_dir;

INIT {
    $tmp_dir     = $ENV{TMP_DIR};
    @config_path = split /:/, $ENV{CONFIG_PATH};

}

#
# Issue a Warning Message
#
sub warning_message 
{
    my $lineinfo = $currentfile ?  " : $currentfilename ( line $currentlinenumber )" : '';

    print STDERR "   WARNING: @_$lineinfo\n";
}

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

    return $filename if $filename =~ '/.*';

    my $directory;

    for $directory ( @config_path ) {
	my $file = "$directory$filename";
	return $file if -f $file;
    }

    "$globals{CONFDIR}/$filename";
}

#
# When splitting a line, don't pad out the columns with '-' if the first column contains one of these
#

my %no_pad = ( COMMENT => 1,
	       SECTION => 1 );

#
# Pre-process a line from a configuration file.

#    chomp it.
#    compress out redundent white space.
#    ensure that it has an appropriate number of columns.
#    supply '-' in omitted trailing columns.
#
sub split_line( $$ ) {
    my ( $columns, $description ) = @_;

    my @line = split /\s+/, $line;

    return @line if $no_pad{$line[0]};

    fatal_error "Invalid $description entry (too many columns)" if @line > $columns;

    push @line, '-' while @line < $columns;

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
	
	my $arrayref = pop @openstack;

	if ( $arrayref ) {
	    ( $currentfile, $currentfilename, $currentlinenumber ) = @$arrayref;
	} else {
	    $currentfile = undef;
	}
    }
}

#
# Allow nested opens
#
my @pushstack;

sub push_open( $ ) {

    push @openstack, [ $currentfile, $currentfilename, $currentlinenumber ];
    my @a = @openstack;
    push @pushstack, \@a;
    @openstack = ();
    $currentfile = undef;
    open_file( $_[0] );

}

sub pop_open() {
    @openstack   = @{pop @pushstack};

    my $arrayref = pop @openstack;

    if ( $arrayref ) {
	( $currentfile, $currentfilename, $currentlinenumber ) = @$arrayref;
    } else {
	$currentfile = undef;
    }
}    

#
# Read a line from the current open stack.
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
	    if ( substr( $nextline, -1, 1 ) eq '\\' ) {
		$line .= substr( $nextline, 0, -1 );
		next;
	    }

	    $line .= $nextline;

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
	    # Expand Shell Variables using $ENV
	    #
	    $line = join( '', $1 , ( $ENV{$2} || '' ) , $3 ) while $line =~ /^(.*?)\${([a-zA-Z]\w*)}(.*)$/;
	    $line = join( '', $1 , ( $ENV{$2} || '' ) , $3 ) while $line =~ /^(.*?)\$([a-zA-Z]\w*)(.*)$/;
	    
	    if ( $line =~ /^INCLUDE\s/ ) {
		
		my @line = split /\s+/, $line;
	
		fatal_error "Missing file name after 'INCLUDE'" unless @line > 1;
		fatal_error "Invalid INCLUDE command: $line"    if @line > 2;
		fatal_error "INCLUDEs nested too deeply: $line" if @openstack >= 4;
		
		my $filename = find_file $line[1];
		
		fatal_error "INCLUDE file $filename not found" unless ( -f $filename );
		
		if ( -s _ ) {
		    push @openstack, [ $currentfile, $currentfilename, $currentlinenumber ];
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

sub default ( $$ ) {
    my ( $var, $val ) = @_;

    $config{$var} = $val unless defined $config{$var} && $config{$var} ne '';
}

sub default_yes_no ( $$ ) {
    my ( $var, $val ) = @_;

    my $curval = "\L$config{$var}";

    if ( $curval ) {
	if (  $curval eq 'no' ) {
	    $config{$var} = '';
	} else {
	    fatal_error "Invalid value for $var ($val)" unless $curval eq 'yes';
	}
    } else {
	$config{$var} = $val;
    }
}

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

sub require_capability( $$ ) {
    my ( $capability, $description ) = @_;

    fatal_error "$description requires $capdesc{$capability} in your kernel and iptables"
      unless $capabilities{$capability};
}

#
# - Read the shorewall.conf file
# - Read the capabilities file created by the compiler front-end
# - establish global hashes %config , %globals and %capabilities
#
sub get_configuration( $ ) {

    my $export = $_[0];

    for ( @config_path ) {
	$_ .= '/' unless m|//$|;
    }

    my $file = find_file 'shorewall.conf';

    if ( -f $file ) {
	if ( -r _ ) {
	    open_file $file;

	    while ( read_a_line ) {
		if ( $line =~ /^\s*([a-zA-Z]\w*)=(.*?)\s*$/ ) {
		    my ($var, $val) = ($1, $2);
		    unless ( exists $config{$var} ) {
			warning_message "Unknown configuration option \"$var\" ignored";
			next;
		    }

		    $config{$var} = ( $val =~ /\"([^\"]*)\"$/ ? $1 : $val );
		} else {
		    fatal_error "Unrecognized entry in $file: $line";
		}
	    }
	} else {
	    fatal_error "Cannot read $file (Hint: Are you root?)";
	}
    } else {
	fatal_error "$file does not exist!";
    }

    $file = "$tmp_dir/capabilities";

    if ( -f $file ) {
	if ( -r _ ) {
	    open CAPS , $file or fatal_error "Unable to open $file: $!";

	    while ( $line = <CAPS> ) {
		chomp $line;
		next if $line =~ /^\s*#/;
		next if $line =~ /^\s*$/;

		if ( $line =~ /^\s*([a-zA-Z]\w*)=(.*?)\s*$/ ) {
		    my ($var, $val) = ($1, $2);
		    unless ( exists $capabilities{$var} ) {
			warning_message "Unknown capability \"$var\" ignored";
			next;
		    }

		    $capabilities{$var} = $val =~ /^\"([^\"]*)\"$/ ? $1 : $val;
		} else {
		    fatal_error "Unrecognized entry";
		}
	    }

	    close CAPS;

	} else {
	    fatal_error "Cannot read $file (Hint: Are you root?)";
	}
    } else {
	fatal_error "$file does not exist!";
    }

    $globals{ORIGINAL_POLICY_MATCH} = $capabilities{POLICY_MATCH};

    default 'MODULE_PREFIX', 'o gz ko o.gz ko.gz';

    if ( $config{LOGRATE} || $config{LOGBURST} ) {
	$globals{LOGLIMIT} = '-m limit';
	$globals{LOGLIMIT} .= " --limit $config{LOGRATE}"        if $config{LOGRATE};
	$globals{LOGLIMIT} .= " --limit-burst $config{LOGBURST}" if $config{LOGBURST};
    } else {
	$globals{LOGLIMIT} = '';
    }

    if ( $config{IP_FORWARDING} ) {
	fatal_error "Invalid value ( $config{IP_FORWARDING} ) for IP_FORWARDING" 
	    unless $config{IP_FORWARDING} =~ /^(On|Off|Keep)$/i;
    } else {
	$config{IP_FORWARDING} = 'On';
    }

    default_yes_no 'ADD_IP_ALIASES'             , 'Yes';
    default_yes_no 'ADD_SNAT_ALIASES'           , '';
    default_yes_no 'ROUTE_FILTER'               , '';
    default_yes_no 'LOG_MARTIANS'               , '';
    default_yes_no 'DETECT_DNAT_IPADDRS'        , '';
    default_yes_no 'DETECT_DNAT_IPADDRS'        , '';
    default_yes_no 'CLEAR_TC'                   , 'Yes';
    default_yes_no 'CLAMPMSS'                   , '' unless $config{CLAMPMSS} =~ /^\d+$/;

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
    default_yes_no 'LOGTAGONLY'                 , '';
    default_yes_no 'RFC1918_STRICT'             , '';
    default_yes_no 'SAVE_IPSETS'                , '';

    warning_message 'SAVE_IPSETS=Yes is not supported by Shorewall-perl ' . $globals{VERSION} if $config{SAVE_IPSETS};

    default_yes_no 'MAPOLDACTIONS'              , '';

    warning_message 'MAPOLDACTIONS=Yes is not supported by Shorewall-perl ' . $globals{VERSION} if $config{MAPOLDACTIONS};

    default_yes_no 'FASTACCEPT'                 , '';
    default_yes_no 'IMPLICIT_CONTINUE'          , '';
    default_yes_no 'HIGH_ROUTE_MARKS'           , '';
    default_yes_no 'TC_EXPERT'                  , '';
    default_yes_no 'USE_ACTIONS'                , 'Yes';

    warning_message 'USE_ACTIONS=No is not supported by Shorewall-perl ' . $globals{VERSION} unless $config{USE_ACTIONS};

    default_yes_no 'EXPORTPARAMS'               , '';
    default_yes_no 'MARK_IN_FORWARD_CHAIN'      , '';

    $capabilities{XCONNMARK} = '' unless $capabilities{XCONNMARK_MATCH} and $capabilities{XMARK};

    default 'BLACKLIST_DISPOSITION'             , 'DROP';

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

    $globals{TC_SCRIPT} = '';

    if ( $val = "\L$config{TC_ENABLED}" ) {
	if ( $val eq 'yes' ) {
	    $file = find_file 'tcstart';
	    fatal_error "Unable to find tcstart file" unless -f $file;
	} elsif ( $val ne 'internal' ) {
	    fatal_error "Invalid value ($config{TC_ENABLED}) for TC_ENABLED" unless $val eq 'no';
	    $config{TC_ENABLED} = '';
	}
    }

    default 'RESTOREFILE'           , 'restore';
    default 'DROP_DEFAULT'          , 'Drop';
    default 'REJECT_DEFAULT'        , 'Reject';
    default 'QUEUE_DEFAULT'         , 'none';
    default 'ACCEPT_DEFAULT'        , 'none';
    default 'OPTIMIZE'              , 0;
    default 'IPSECFILE'             , 'ipsec';

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
	$globals{LOGFORMAT}='Shorewall:%s:%s:';
	$globals{MAXZONENAMELENGTH} = 5;
    }

}

sub propagateconfig() {
    for my $option ( @Shorewall::Config::propagateconfig ) {
	my $value = $config{$option} || '';
	emit "$option=\"$value\"";
    }

    for my $option ( @Shorewall::Config::propagateenv ) {
	my $value = $globals{$option} || '';
	emit "$option=\"$value\"";
    }
}

sub append_file( $ ) {
    my $user_exit = find_file $_[0];

    unless ( $user_exit =~ /$globals{SHAREDIR}/ ) {
	if ( -f $user_exit ) {
	    save_progress_message "Processing $user_exit ...";
	    copy1 $user_exit;
	}
    }
}

#
# Run a Perl extension script
#
sub run_user_exit( $ ) {
    my $chainref = $_[0];
    my $file = find_file $chainref->{name};

    if ( -f $file ) {
	progress_message "Processing $file...";

	unless (my $return = do $file) {
	    fatal_error "Couldn't parse $file: $@" if $@;
	    fatal_error "Couldn't do $file: $!"    unless defined $return;
	    fatal_error "Couldn't run $file"       unless $return;
	}
    }
}

sub generate_aux_config() {
    sub conditionally_add_option( $ ) {
	my $option = $_[0];

	my $value = $config{$option};

	emit "[ -n \"\${$option:=$value}\" ]" if $value;
    }

    sub conditionally_add_option1( $ ) {
	my $option = $_[0];

	my $value = $config{$option};

	emit "$option=\"$value\"" if $value;
    }

    create_temp_aux_config;

    emit join ( '', "#\n# Shorewall auxiliary configuration file created by Shorewall-perl version ", $globals{VERSION}, ' - ' , localtime , "\n#" );

    for my $option qw(VERBOSITY LOGFILE LOGFORMAT IPTABLES PATH SHOREWALL_SHELL SUBSYSLOCK RESTOREFILE SAVE_IPSETS) {
	conditionally_add_option $option;
    }

    conditionally_add_option1 'TC_ENABLED';

    finalize_aux_config;

}

END {
    if ( $tmp_dir ) {
	my $exitstatus = $?; #Changed by system()
	system "rm -rf $tmp_dir";
	$? = $exitstatus;
    }
}

1;
