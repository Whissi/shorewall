#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Config.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010 - Tom Eastep (teastep@shorewall.net)
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
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#   This module is responsible for lower level configuration file handling.
#   It also exports functions for generating warning and error messages.
#   The get_configuration function parses the shorewall.conf, capabilities and
#   modules files during compiler startup. The module also provides the basic
#   output file services such as creation of temporary 'script' files, writing
#   into those files (emitters) and finalizing those files (renaming
#   them to their final name and setting their mode appropriately).
#
package Shorewall::Config;

use strict;
use warnings;
use File::Basename;
use File::Temp qw/ tempfile tempdir /;
use Cwd qw(abs_path getcwd);
use autouse 'Carp' => qw(longmess confess);
use Scalar::Util 'reftype';

our @ISA = qw(Exporter);
#
# Imported variables should be treated as read-only by importers
#
our @EXPORT = qw(
		 warning_message
		 fatal_error
		 assert
		 progress_message
		 progress_message_nocompress
		 progress_message2
		 progress_message3
                );

our @EXPORT_OK = qw( $shorewall_dir initialize read_a_line1 set_config_path shorewall);

our %EXPORT_TAGS = ( internal => [ qw( create_temp_script
				       finalize_script
				       enable_script
				       disable_script
		                       numeric_value
		                       numeric_value1
		                       hex_value
		                       in_hex
		                       in_hex2
		                       in_hex3
		                       in_hex4
		                       in_hex8
		                       in_hexp
				       emit
				       emitstd
				       emit_unindented
				       save_progress_message
				       save_progress_message_short
				       set_timestamp
				       set_verbosity
				       set_log
				       close_log
				       set_command
				       push_indent
				       pop_indent
				       copy
				       copy1
				       copy2
				       create_temp_aux_config
				       finalize_aux_config
				       set_shorewall_dir
				       set_debug
				       find_file
				       split_list
				       split_list1
				       split_line
				       split_line1
				       first_entry
				       open_file
				       close_file
				       push_open
				       pop_open
				       push_params
				       pop_params
				       read_a_line
				       validate_level
				       which
				       qt
				       ensure_config_path
				       get_configuration
				       require_capability
				       have_capability
				       report_capabilities
				       propagateconfig
				       append_file
				       run_user_exit
				       run_user_exit1
				       run_user_exit2
				       generate_aux_config

				       $product
				       $Product
				       $toolname
				       $command
				       $doing
				       $done
				       $currentline
				       $debug
				       %config
				       %globals
				       %params

		                       F_IPV4
		                       F_IPV6

				       MIN_VERBOSITY
				       MAX_VERBOSITY
				     ) ] );

Exporter::export_ok_tags('internal');

our $VERSION = '4.4_16';

#
# describe the current command, it's present progressive, and it's completion.
#
our ($command, $doing, $done );
#
# VERBOSITY
#
our $verbosity;
#
# Logging
#
our ( $log, $log_verbosity );
#
# Timestamp each progress message, if true.
#
our $timestamp;
#
# Script (output) file handle
#
our $script;
#
# When 'true', writes to the script are enabled. Used to catch code emission between functions
#
our $script_enabled;
#
# True, if last line emitted is blank
#
our $lastlineblank;
#
# Tabs to indent the output
#
our $indent1;
#
# Characters to indent the output
#
our $indent2;
#
# Total indentation
#
our $indent;
#
# Script's Directory and File
#
our ( $dir, $file );
#
# Temporary output file's name
#
our $tempfile;
#
# Misc Globals
#
our %globals;
#
# From shorewall.conf file
#
our %config;
#
# Config options and global settings that are to be copied to output script
#
our @propagateconfig = qw/ DISABLE_IPV6 MODULESDIR MODULE_SUFFIX LOAD_HELPERS_ONLY SUBSYSLOCK LOG_VERBOSITY/;
#
# From parsing the capabilities file or detecting capabilities
#
our %capabilities;
#
# Capabilities
#
our %capdesc = ( NAT_ENABLED     => 'NAT',
		 MANGLE_ENABLED  => 'Packet Mangling',
		 MULTIPORT       => 'Multi-port Match' ,
		 XMULTIPORT      => 'Extended Multi-port Match',
		 CONNTRACK_MATCH => 'Connection Tracking Match',
		 OLD_CONNTRACK_MATCH =>
		                    'Old conntrack match syntax',
		 NEW_CONNTRACK_MATCH =>
		                    'Extended Connection Tracking Match',
		 USEPKTTYPE      => 'Packet Type Match',
		 POLICY_MATCH    => 'Policy Match',
		 PHYSDEV_MATCH   => 'Physdev Match',
		 PHYSDEV_BRIDGE  => 'Physdev-is-bridged support',
		 LENGTH_MATCH    => 'Packet length Match',
		 IPRANGE_MATCH   => 'IP Range Match',
		 RECENT_MATCH    => 'Recent Match',
		 OWNER_MATCH     => 'Owner Match',
		 IPSET_MATCH     => 'Ipset Match',
		 OLD_IPSET_MATCH => 'Old Ipset Match',
		 CONNMARK        => 'CONNMARK Target',
		 XCONNMARK       => 'Extended CONNMARK Target',
		 CONNMARK_MATCH  => 'Connmark Match',
		 XCONNMARK_MATCH => 'Extended Connmark Match',
		 RAW_TABLE       => 'Raw Table',
		 IPP2P_MATCH     => 'IPP2P Match',
		 OLD_IPP2P_MATCH => 'Old IPP2P Match Syntax',
		 CLASSIFY_TARGET => 'CLASSIFY Target',
		 ENHANCED_REJECT => 'Extended Reject',
		 KLUDGEFREE      => 'Repeat match',
		 MARK            => 'MARK Target',
		 XMARK           => 'Extended Mark Target',
		 EXMARK          => 'Extended Mark Target 2',
		 MANGLE_FORWARD  => 'Mangle FORWARD Chain',
		 COMMENTS        => 'Comments',
		 ADDRTYPE        => 'Address Type Match',
		 TCPMSS_MATCH    => 'TCPMSS Match',
		 HASHLIMIT_MATCH => 'Hashlimit Match',
		 NFQUEUE_TARGET  => 'NFQUEUE Target',
		 REALM_MATCH     => 'Realm Match',
		 HELPER_MATCH    => 'Helper Match',
		 CONNLIMIT_MATCH => 'Connlimit Match',
		 TIME_MATCH      => 'Time Match',
		 GOTO_TARGET     => 'Goto Support',
		 LOG_TARGET      => 'LOG Target',
		 LOGMARK_TARGET  => 'LOGMARK Target',
		 IPMARK_TARGET   => 'IPMARK Target',
		 PERSISTENT_SNAT => 'Persistent SNAT',
		 OLD_HL_MATCH    => 'Old Hash Limit Match',
		 TPROXY_TARGET   => 'TPROXY Target',
		 FLOW_FILTER     => 'Flow Classifier',
		 FWMARK_RT_MASK  => 'fwmark route mask',
		 MARK_ANYWHERE   => 'Mark in any table',
		 HEADER_MATCH    => 'Header Match',
		 CAPVERSION      => 'Capability Version',
		 KERNELVERSION   => 'Kernel Version',
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
#
# From the params file
#
our %params;
#
# Action parameters
#
our %actparms;

our $currentline;             # Current config file line image
our $currentfile;             # File handle reference
our $currentfilename;         # File NAME
our $currentlinenumber;       # Line number
our $perlscript;              # File Handle Reference to current temporary file being written by an in-line Perl script
our $perlscriptname;          # Name of that file.
our @tempfiles;               # Files that need unlinking at END
our $first_entry;             # Message to output or function to call on first non-blank line of a file

our $shorewall_dir;           # Shorewall Directory; if non-empty, search here first for files.

our $debug;                   # If true, use Carp to report errors with stack trace.

our $family;                  # Protocol family (4 or 6)
our $toolname;                # Name of the tool to use (iptables or iptables6)
our $toolNAME;                # Tool name in CAPS
our $product;                 # Name of product that will run the generated script
our $Product;                 # $product with initial cap.

our $sillyname;               # Name of temporary filter chains for testing capabilities
our $sillyname1;
our $iptables;                # Path to iptables/ip6tables
our $tc;                      # Path to tc
our $ip;                      # Path to ip

use constant { MIN_VERBOSITY => -1,
	       MAX_VERBOSITY => 2 ,
	       F_IPV4 => 4,
	       F_IPV6 => 6,
	   };

our %validlevels;             # Valid log levels.

#
# Rather than initializing globals in an INIT block or during declaration,
# we initialize them in a function. This is done for two reasons:
#
#   1. Proper initialization depends on the address family which isn't
#      known until the compiler has started.
#
#   2. The compiler can run multiple times in the same process so it has to be
#      able to re-initialize its dependent modules' state.
#
sub initialize( $ ) {
    $family = shift;

    if ( $family == F_IPV4 ) {
	( $product, $Product, $toolname, $toolNAME ) = qw( shorewall  Shorewall iptables  IPTABLES );
    } else {
	( $product, $Product, $toolname, $toolNAME ) = qw( shorewall6 Shorewall6 ip6tables IP6TABLES );
    }

    $verbosity = 0;            # Verbosity setting. -1 = silent, 0 = almost silent, 1 = major progress messages only, 2 = all progress messages (very noisy)
    $log = undef;              # File reference for log file
    $log_verbosity = -1;       # Verbosity of log.
    $timestamp = '';           # If true, we are to timestamp each progress message
    $script = 0;               # Script (output) file Handle Reference
    $script_enabled = 0;       # Writing to output file is disabled initially
    $lastlineblank = 0;        # Avoid extra blank lines in the output
    $indent1       = '';       # Current indentation tabs
    $indent2       = '';       # Current indentation spaces
    $indent        = '';       # Current total indentation
    ( $dir, $file ) = ('',''); # Script's Directory and Filename
    $tempfile = '';            # Temporary File Name
    $sillyname = '';           # Temporary ipchain

    #
    # Misc Globals
    #
    %globals  =   ( SHAREDIR => '/usr/share/shorewall' ,
		    SHAREDIRPL => '/usr/share/shorewall/' ,
		    CONFDIR =>  '/etc/shorewall',     # Run-time configuration directory
		    CONFIGDIR => '',                  # Compile-time configuration directory (location of $product.conf)
		    LOGPARMS => '',
		    TC_SCRIPT => '',
		    EXPORT => 0,
		    STATEMATCH => '-m state --state',
		    UNTRACKED => 0,
		    VERSION => "4.4.16-Beta7",
		    CAPVERSION => 40415 ,
		  );

    #
    # From shorewall.conf file
    #
    if ( $family == F_IPV4 ) {
	$globals{PRODUCT} = 'shorewall';

	%config =
	    ( STARTUP_ENABLED => undef,
	      VERBOSITY => undef,
	      #
	      # Logging
	      #
	      LOGFILE => undef,
	      LOGFORMAT => undef,
	      LOGTAGONLY => undef,
	      LOGLIMIT => undef,
	      LOGRATE => undef,
	      LOGBURST => undef,
	      LOGALLNEW => undef,
	      BLACKLIST_LOGLEVEL => undef,
	      RFC1918_LOG_LEVEL => undef,
	      MACLIST_LOG_LEVEL => undef,
	      TCP_FLAGS_LOG_LEVEL => undef,
	      SMURF_LOG_LEVEL => undef,
	      LOG_MARTIANS => undef,
	      LOG_VERBOSITY => undef,
	      STARTUP_LOG => undef,
	      #
	      # Location of Files
	      #
	      IPTABLES => undef,
	      IP => undef,
	      TC => undef,
	      IPSET => undef,
	      PERL => undef,
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
	      NFQUEUE_DEFAULT => undef,
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
	      TC_PRIOMAP => undef,
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
	      EXPAND_POLICIES => undef,
	      KEEP_RT_TABLES => undef,
	      DELETE_THEN_ADD => undef,
	      MULTICAST => undef,
	      DONT_LOAD => '',
	      AUTO_COMMENT => undef ,
	      MANGLE_ENABLED => undef ,
	      RFC1918_STRICT => undef ,
	      NULL_ROUTE_RFC1918 => undef ,
	      USE_DEFAULT_RT => undef ,
	      RESTORE_DEFAULT_ROUTE => undef ,
	      FAST_STOP => undef ,
	      AUTOMAKE => undef ,
	      WIDE_TC_MARKS => undef,
	      TRACK_PROVIDERS => undef,
	      ZONE2ZONE => undef,
	      ACCOUNTING => undef,
	      OPTIMIZE_ACCOUNTING => undef,
	      DYNAMIC_BLACKLIST => undef,
	      LOAD_HELPERS_ONLY => undef,
	      REQUIRE_INTERFACE => undef,
	      FORWARD_CLEAR_MARK => undef,
	      COMPLETE => undef,
	      #
	      # Packet Disposition
	      #
	      MACLIST_DISPOSITION => undef,
	      TCP_FLAGS_DISPOSITION => undef,
	      BLACKLIST_DISPOSITION => undef,
	      #
	      # Mark Geometry
	      #
	      TC_BITS => undef,
	      PROVIDER_BITS => undef,
	      PROVIDER_OFFSET => undef,
	      MASK_BITS => undef
	    );

	%validlevels = ( DEBUG   => 7,
			 INFO    => 6,
			 NOTICE  => 5,
			 WARNING => 4,
			 WARN    => 4,
			 ERR     => 3,
			 ERROR   => 3,
			 CRIT    => 2,
			 ALERT   => 1,
			 EMERG   => 0,
			 PANIC   => 0,
			 NONE    => '',
			 ULOG    => 'ULOG',
			 NFLOG   => 'NFLOG',
		         LOGMARK => 'LOGMARK' );
    } else {
	$globals{SHAREDIR} = '/usr/share/shorewall6';
	$globals{CONFDIR}  = '/etc/shorewall6';
	$globals{PRODUCT}  = 'shorewall6';

	%config =
	    ( STARTUP_ENABLED => undef,
	      VERBOSITY => undef,
	      #
	      # Logging
	      #
	      LOGFILE => undef,
	      LOGFORMAT => undef,
	      LOGTAGONLY => undef,
	      LOGLIMIT => undef,
	      LOGRATE => undef,
	      LOGBURST => undef,
	      LOGALLNEW => undef,
	      BLACKLIST_LOGLEVEL => undef,
	      TCP_FLAGS_LOG_LEVEL => undef,
	      SMURF_LOG_LEVEL => undef,
	      LOG_VERBOSITY => undef,
	      STARTUP_LOG => undef,
	      #
	      # Location of Files
	      #
	      IP6TABLES => undef,
	      IP => undef,
	      TC => undef,
	      IPSET => undef,
	      PERL => undef,
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
	      LOCKFILE => undef,
	      #
	      # Default Actions/Macros
	      #
	      DROP_DEFAULT => undef,
	      REJECT_DEFAULT => undef,
	      ACCEPT_DEFAULT => undef,
	      QUEUE_DEFAULT => undef,
	      NFQUEUE_DEFAULT => undef,
	      #
	      # RSH/RCP Commands
	      #
	      RSH_COMMAND => undef,
	      RCP_COMMAND => undef,
	      #
	      # Firewall Options
	      #
	      IP_FORWARDING => undef,
	      TC_ENABLED => undef,
	      TC_EXPERT => undef,
	      TC_PRIOMAP => undef,
	      CLEAR_TC => undef,
	      MARK_IN_FORWARD_CHAIN => undef,
	      CLAMPMSS => undef,
	      MUTEX_TIMEOUT => undef,
	      ADMINISABSENTMINDED => undef,
	      BLACKLISTNEWONLY => undef,
	      MODULE_SUFFIX => undef,
	      MAPOLDACTIONS => '',
	      FASTACCEPT => undef,
	      IMPLICIT_CONTINUE => undef,
	      HIGH_ROUTE_MARKS => undef,
	      OPTIMIZE => undef,
	      EXPORTPARAMS => undef,
	      EXPAND_POLICIES => undef,
	      KEEP_RT_TABLES => undef,
	      DELETE_THEN_ADD => undef,
	      MULTICAST => undef,
	      DONT_LOAD => '',
	      AUTO_COMMENT => undef,
	      MANGLE_ENABLED => undef ,
	      AUTOMAKE => undef ,
	      WIDE_TC_MARKS => undef,
	      TRACK_PROVIDERS => undef,
	      ZONE2ZONE => undef,
	      ACCOUNTING => undef,
	      OPTIMIZE_ACCOUNTING => undef,
	      DYNAMIC_BLACKLIST => undef,
	      LOAD_HELPERS_ONLY => undef,
	      REQUIRE_INTERFACE => undef,
	      FORWARD_CLEAR_MARK => undef,
	      COMPLETE => undef,
	      #
	      # Packet Disposition
	      #
	      TCP_FLAGS_DISPOSITION => undef,
	      BLACKLIST_DISPOSITION => undef,
	      #
	      # Mark Geometry
	      #
	      TC_BITS => undef,
	      PROVIDER_BITS => undef,
	      PROVIDER_OFFSET => undef,
	      MASK_BITS => undef
	    );

	%validlevels = ( DEBUG   => 7,
			 INFO    => 6,
			 NOTICE  => 5,
			 WARNING => 4,
			 WARN    => 4,
			 ERR     => 3,
			 ERROR   => 3,
			 CRIT    => 2,
			 ALERT   => 1,
			 EMERG   => 0,
			 PANIC   => 0,
			 NONE    => '',
			 NFLOG   => 'NFLOG',
		         LOGMARK => 'LOGMARK' );
    }
    #
    # From parsing the capabilities file or capabilities detection
    #
    %capabilities =
	     ( NAT_ENABLED => undef,
	       MANGLE_ENABLED => undef,
	       MULTIPORT => undef,
	       XMULTIPORT => undef,
	       CONNTRACK_MATCH => undef,
	       NEW_CONNTRACK_MATCH => undef,
	       OLD_CONNTRACK_MATCH => undef,
	       USEPKTTYPE => undef,
	       POLICY_MATCH => undef,
	       PHYSDEV_MATCH => undef,
	       PHYSDEV_BRIDGE => undef,
	       LENGTH_MATCH => undef,
	       IPRANGE_MATCH => undef,
	       RECENT_MATCH => undef,
	       OWNER_MATCH => undef,
	       IPSET_MATCH => undef,
	       OLD_IPSET_MATCH => undef,
	       CONNMARK => undef,
	       XCONNMARK => undef,
	       CONNMARK_MATCH => undef,
	       XCONNMARK_MATCH => undef,
	       RAW_TABLE => undef,
	       IPP2P_MATCH => undef,
	       OLD_IPP2P_MATCH => undef,
	       CLASSIFY_TARGET => undef,
	       ENHANCED_REJECT => undef,
	       KLUDGEFREE => undef,
	       MARK => undef,
	       XMARK => undef,
	       EXMARK => undef,
	       MANGLE_FORWARD => undef,
	       COMMENTS => undef,
	       ADDRTYPE => undef,
	       TCPMSS_MATCH => undef,
	       HASHLIMIT_MATCH => undef,
	       NFQUEUE_TARGET => undef,
	       REALM_MATCH => undef,
	       HELPER_MATCH => undef,
	       CONNLIMIT_MATCH => undef,
	       TIME_MATCH => undef,
	       GOTO_TARGET => undef,
	       LOGMARK_TARGET => undef,
	       IPMARK_TARGET => undef,
	       TPROXY_TARGET => undef,
	       LOG_TARGET => 1,         # Assume that we have it.
	       PERSISTENT_SNAT => undef,
	       OLD_HL_MATCH => undef,
	       FLOW_FILTER => undef,
	       FWMARK_RT_MASK => undef,
	       MARK_ANYWHERE => undef,
	       HEADER_MATCH => undef,
	       CAPVERSION => undef,
	       KERNELVERSION => undef,
	       );
    #
    # Directories to search for configuration files
    #
    @config_path = ();
    #
    # Stash away file references here when we encounter INCLUDE
    #
    @includestack = ();
    #
    # Allow nested opens
    #
    @openstack = ();

    $currentline = '';        # Line image
    $currentfile = undef;     # File handle reference
    $currentfilename = '';    # File NAME
    $currentlinenumber = 0;   # Line number
    $first_entry = 0;         # Message to output or function to call on first non-blank file entry

    $shorewall_dir = '';      #Shorewall Directory

    $debug = 0;

    %params = ( root        => '',
		system      => '',
		command     => '',
		files       => '',
		destination => '' );

    %actparms = ();
}

my @abbr = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );

#
# Issue a Warning Message
#
sub warning_message
{
    my $linenumber = $currentlinenumber || 1;
    my $currentlineinfo = $currentfile ?  " : $currentfilename (line $linenumber)" : '';
    our @localtime;

    $| = 1; #Reset output buffering (flush any partially filled buffers).

    if ( $log ) {
	@localtime = localtime;
	printf $log '%s %2d %02d:%02d:%02d ', $abbr[$localtime[4]], @localtime[3,2,1,0];
    }

    if ( $debug ) {
	print STDERR longmess( "   WARNING: @_$currentlineinfo" );
	print $log   longmess( "   WARNING: @_$currentlineinfo\n" ) if $log;
    } else {
	print STDERR "   WARNING: @_$currentlineinfo\n";
	print $log   "   WARNING: @_$currentlineinfo\n" if $log;
    }

    $| = 0; #Re-allow output buffering
}

sub cleanup() {
    #
    # Close files first in case we're running under Cygwin
    #
    close  $script, $script = undef         if $script;
    close  $perlscript, $perlscript = undef if $perlscript;
    close  $log, $log = undef               if $log;
    #
    # Unlink temporary files
    #
    unlink ( $tempfile ), $tempfile = undef             if $tempfile;
    unlink ( $perlscriptname ), $perlscriptname = undef if $perlscriptname;
    unlink ( @tempfiles ), @tempfiles = ()              if @tempfiles;
    #
    # Delete temporary chains
    #
    if ( $sillyname ) {
	#
	# We went through determine_capabilities()
	#
	qt1( "$iptables -F $sillyname" );
	qt1( "$iptables -X $sillyname" );
	qt1( "$iptables -F $sillyname1" );
	qt1( "$iptables -X $sillyname1" );
	qt1( "$iptables -t mangle -F $sillyname" );
	qt1( "$iptables -t mangle -X $sillyname" );
	$sillyname = '';
    }
}

#
# Issue fatal error message and die
#
sub fatal_error	{
    my $linenumber = $currentlinenumber || 1;
    my $currentlineinfo = $currentfile ?  " : $currentfilename (line $linenumber)" : '';

    $| = 1; #Reset output buffering (flush any partially filled buffers).

    if ( $log ) {
	our @localtime = localtime;
	printf $log '%s %2d %02d:%02d:%02d ', $abbr[$localtime[4]], @localtime[3,2,1,0];

	if ( $debug ) {
	    print $log longmess( "   ERROR: @_$currentlineinfo\n" );
	} else {
	    print $log "   ERROR: @_$currentlineinfo\n";
	}

	close $log;
	$log = undef;
    }

    cleanup;
    confess "   ERROR: @_$currentlineinfo" if $debug;
    die "   ERROR: @_$currentlineinfo\n";
}

sub fatal_error1	{
    $| = 1;

    if ( $log ) {
	our @localtime = localtime;
	printf $log '%s %2d %02d:%02d:%02d ', $abbr[$localtime[4]], @localtime[3,2,1,0];

	if ( $debug ) {
	    print $log longmess( "   ERROR: @_\n" );
	} else {
	    print $log "   ERROR: @_\n";
	}

	close $log;
	$log = undef;
    }

    cleanup;
    confess "   ERROR: @_" if $debug;
    die "   ERROR: @_\n";
}

#
# C/C++-like assertion checker
#
sub assert( $ ) {
    unless ( $_[0] ) {
	my @caller0 = caller 0; # Where assert() was called
	my @caller1 = caller 1; # Who called assert()

	fatal_error "Internal error in $caller1[3] at $caller0[1] line $caller0[2]";
    }
}

#
# Convert value to decimal number
#
sub numeric_value ( $ ) {
    my $mark = lc $_[0];
    my $negative = ( $mark =~ s/^-// );
    return undef unless $mark =~ /^(0x[a-f0-9]+|0[0-7]*|[1-9]\d*)$/;
    no warnings;
    $mark = ( $mark =~ /^0/ ? oct $mark : $mark );
    use warnings;
    $negative ? - $mark : $mark;
}

sub numeric_value1 ( $ ) {
    no warnings;
    my $val = numeric_value $_[0];
    fatal_error "Invalid Number ($_[0])" unless defined $val;
    $val;
    use warnings;
}

sub hex_value( $ ) {
    my $val = lc $_[0];
    return undef unless $val =~ /^[a-fA-F0-9]+$/;
    no warnings;
    oct '0x' . $val;
    use warnings;
}

#
# Return the argument expressed in Hex
#
sub in_hex( $ ) {
    sprintf '0x%x', $_[0];
}

sub in_hex2( $ ) {
    sprintf '0x%02x', $_[0];
}

sub in_hex3( $ ) {
    sprintf '0x%03x', $_[0];
}

sub in_hex4( $ ) {
    sprintf '0x%04x', $_[0];
}

sub in_hex8( $ ) {
    sprintf '0x%08x', $_[0];
}

sub in_hexp( $ ) {
    sprintf '%x', $_[0];
}

#
# Write the arguments to the script file (if any) with the current indentation.
#
# Replaces leading spaces with tabs as appropriate and suppresses consecutive blank lines.
#
sub emit {
    assert( $script_enabled );

    if ( $script || $debug ) {
	#
	# 'compile' as opposed to 'check'
	#
	for ( @_ ) {
	    unless ( /^\s*$/ ) {
		my $line = $_; # This copy is necessary because the actual arguments are almost always read-only.
		$line =~ s/^\n// if $lastlineblank;
		$line =~ s/^/$indent/gm if $indent;
		$line =~ s/        /\t/gm;
		print $script "$line\n" if $script;
		$lastlineblank = ( substr( $line, -1, 1 ) eq "\n" );

		if ( $debug ) {
		    $line =~ s/^\n//;
		    $line =~ s/\n/\nGS-----> /g;
		    print "GS-----> $line\n";
		}
	    } else {
		unless ( $lastlineblank ) {
		    print $script "\n"  if $script;
		    print "GS-----> \n" if $debug;
		}

		$lastlineblank = 1;
	    }
	}
    }
}

#
# Version of emit() that writes to standard out
#
sub emitstd {
    for ( @_ ) {
	unless ( /^\s*$/ ) {
	    my $line = $_; # This copy is necessary because the actual arguments are almost always read-only.
	    $line =~ s/^\n// if $lastlineblank;
	    $line =~ s/^/$indent/gm if $indent;
	    $line =~ s/        /\t/gm;
	    print "$line\n";
	    $lastlineblank = ( substr( $line, -1, 1 ) eq "\n" );
	} else {
	    print "\n" unless $lastlineblank;
	    $lastlineblank = 1;
	}
    }
}

#
# Write passed message to the script with newline but no indentation.
#
sub emit_unindented( $ ) {
    assert( $script_enabled );

    print $script "$_[0]\n" if $script;
}

#
# Write a progress_message2 command with surrounding blank lines to the output file.
#
sub save_progress_message( $ ) {
    emit "\nprogress_message2 @_\n" if $script;
}

#
# Write a progress_message command to the output file.
#
sub save_progress_message_short( $ ) {
    emit "progress_message $_[0]" if $script;
}

#
# Set $timestamp
#
sub set_timestamp( $ ) {
    $timestamp = shift;
}

#
# Set $verbosity
#
sub set_verbosity( $ ) {
    $verbosity = shift;
}

#
# Set $log and $log_verbosity
#
sub set_log ( $$ ) {
    my ( $l, $v ) = @_;

    if ( defined $v ) {
	my $value = numeric_value( $v );
	fatal_error "Invalid Log Verbosity ( $v )" unless defined($value) && ( $value >= -1 ) && ( $value <= 2);
	$log_verbosity = $value;
    }

    if ( $l && $log_verbosity >= 0 ) {
	unless ( open $log , '>>' , $l ) {
	    $log = undef;
	    fatal_error "Unable to open STARTUP_LOG ($l) for writing: $!";
	}
    } else {
	$log_verbosity = -1;
    }
}

sub close_log() {
    close $log, $log = undef if $log;
}

#
# Set $command, $doing and $done
#
sub set_command( $$$ ) {
    ($command, $doing, $done) = @_;
}

#
# Print the current TOD to STDOUT.
#
sub timestamp() {
    our @localtime = localtime;
    printf '%02d:%02d:%02d ', @localtime[2,1,0];
}

#
# Write a message if $verbosity >= 2.
#
sub progress_message {
    my $havelocaltime = 0;

    if ( $verbosity > 1 || $log_verbosity > 1 ) {
	my $line = "@_";
	my $leading = $line =~ /^(\s+)/ ? $1 : '';
	$line =~ s/\s+/ /g;

	if ( $verbosity > 1 ) {
	    timestamp, $havelocaltime = 1 if $timestamp;
	    #
	    # We use this function to display messages containing raw config file images which may contains tabs (including multiple tabs in succession).
	    # The following makes such messages look more readable and uniform
	    #
	    print "${leading}${line}\n";
	}

	if ( $log_verbosity > 1 ) {
	    our @localtime;

	    @localtime = localtime unless $havelocaltime;

	    printf $log '%s %2d %2d:%02d:%02d ', $abbr[$localtime[4]], @localtime[3,2,1,0];
	    print $log "${leading}${line}\n";
	}
    }
}

sub progress_message_nocompress {
    my $havelocaltime = 0;

    if ( $verbosity > 1 ) {
	timestamp, $havelocaltime = 1 if $timestamp;
	print "@_\n";
    }

    if ( $log_verbosity > 1 ) {
	our @localtime;

	@localtime = localtime unless $havelocaltime;

	printf $log '%s %2d %2d:%02d:%02d ', $abbr[$localtime[4]], @localtime[3,2,1,0];
	print $log "@_\n";
    }
}

#
# Write a message if $verbosity >= 1
#
sub progress_message2 {
    my $havelocaltime = 0;

    if ( $verbosity > 0 ) {
	timestamp, $havelocaltime = 1 if $timestamp;
	print "@_\n";
    }

    if ( $log_verbosity > 0 ) {
	our @localtime;

	@localtime = localtime unless $havelocaltime;

	printf $log '%s %2d %2d:%02d:%02d ', $abbr[$localtime[4]], @localtime[3,2,1,0];
	print $log "@_\n";
    }
}

#
# Write a message if $verbosity >= 0
#
sub progress_message3 {
    my $havelocaltime = 0;

    if ( $verbosity >= 0 ) {
	timestamp, $havelocaltime = 1 if $timestamp;
	print "@_\n";
    }

    if ( $log_verbosity >= 0 ) {
	our @localtime;

	@localtime = localtime unless $havelocaltime;

	printf $log '%s %2d %2d:%02d:%02d ', $abbr[$localtime[4]], @localtime[3,2,1,0];
	print $log "@_\n";
    }
}

#
# Push/Pop Indent
#
sub push_indent() {
    if ( $indent2 ) {
	$indent2 = '';
	$indent = $indent1 = $indent1 . "\t";
    } else {
	$indent2 = '    ';
	$indent = $indent1 . $indent2;
    }
}

sub pop_indent() {
    if ( $indent2 ) {
	$indent2 = '';
	$indent = $indent1;
    } else {
	$indent1 = substr( $indent1 , 0, -1 );
	$indent2 = '    ';
	$indent = $indent1 . $indent2;
    }
}

#
# Functions for copying files into the script
#
sub copy( $ ) {
    assert( $script_enabled );

    if ( $script ) {
	my $file = $_[0];

	open IF , $file or fatal_error "Unable to open $file: $!";

	while ( <IF> ) {
	    chomp;
	    if ( /^\s*$/ ) {
		print $script "\n" unless $lastlineblank;
		$lastlineblank = 1;
	    } else {
		if  ( $indent ) {
		    s/^(\s*)/$indent1$1$indent2/;
		    s/        /\t/ if $indent2;
		}

		print $script $_;
		print $script "\n";
		$lastlineblank = 0;
	    }
	}

	close IF;
    }
}

#
# This one handles line continuation and 'here documents'

sub copy1( $ ) {
    assert( $script_enabled );

    my $result = 0;

    if ( $script || $debug ) {
	my $file = $_[0];

	open IF , $file or fatal_error "Unable to open $file: $!";

	my ( $do_indent, $here_documents ) = ( 1, '');

	while ( <IF> ) {
	    chomp;

	    if ( /^${here_documents}\s*$/ ) {
		if ( $script ) {
		    print $script $here_documents if $here_documents;
		    print $script "\n";
		}

		if ( $debug ) {
		    print "GS-----> $here_documents" if $here_documents;
		    print "GS----->\n";
		}

		$do_indent = 1;
		$here_documents = '';
		next;
	    }

	    if ( $do_indent && /.*<<\s*([^ ]+)s*(.*)/ ) {
		$here_documents = $1;
		s/^(\s*)/$indent1$1$indent2/;
		s/        /\t/ if $indent2;
		$do_indent = 0;

		if ( $script ) {
		    print $script $_;
		    print $script "\n";
		}

		if ( $debug ) {
		    s/\n/\nGS-----> /g;
		    print "GS-----> $_\n";
		}

		$result = 1;
		next;
	    }

	    if ( $indent && $do_indent ) {
		s/^(\s*)/$indent1$1$indent2/;
		s/        /\t/ if $indent2;
	    }

	    if ( $script ) {
		print $script $_;
		print $script "\n";
	    }

	    $do_indent = ! ( $here_documents || /\\$/ );

	    $result = 1 unless $result || /^\s*$/ || /^\s*#/;

	    if ( $debug ) {
		s/\n/\nGS-----> /g;
		print "GS-----> $_\n";
	    }
	}

	close IF;
    }

    $lastlineblank = 0;

    $result;
}

#
# This one drops header comments and replaces them with a three-line banner
#
sub copy2( $$ ) {
    my ( $file, $trace ) = @_;

    assert( $script_enabled );
    my $empty = 1;

    if ( $script || $trace ) {
	my $file = $_[0];

	open IF , $file or fatal_error "Unable to open $file: $!";

	while ( <IF> ) {
	    $empty = 0, last unless /^#/;
	}

	unless ( $empty ) {
	    emit <<EOF;
################################################################################
#   Functions imported from $file
################################################################################
EOF
	    chomp;
	    emit( $_ ) unless /^\s*$/;

	    while ( <IF> ) {
		chomp;
		if ( /^\s*$/ ) {
		    unless ( $lastlineblank ) {
			print $script "\n" if $script;
			print "GS----->\n" if $trace;
		    }

		    $lastlineblank = 1;
		} else {
		    if  ( $indent ) {
			s/^(\s*)/$indent1$1$indent2/;
			s/        /\t/ if $indent2;
		    }

		    if ( $script ) {
			print $script $_;
			print $script "\n";
		    }

		    if ( $trace ) {
			s/\n/GS-----> \n/g;
			print "GS-----> $_\n";
		    }

		    $lastlineblank = 0;
		}
	    }

	    close IF;

	    unless ( $lastlineblank ) {
		print $script "\n" if $script;
		print "GS----->\n" if $trace;
	    }

	    emit( '################################################################################',
		  "#   End of imports from $file",
		  '################################################################################' );
	}
    }
}

#
# Create the temporary script file -- the passed file name is the name of the final file.
# We create a temporary file in the same directory so that we can use rename to finalize it.
#
sub create_temp_script( $$ ) {
    my ( $scriptfile, $export ) = @_;
    my $suffix;

    if ( $scriptfile eq '-' ) {
	$verbosity = -1;
	$script = undef;
	open( $script, '>&STDOUT' ) or fatal_error "Open of STDOUT failed";
	$file = '-';
	return 1;
    }

    eval {
	( $file, $dir, $suffix ) = fileparse( $scriptfile );
    };

    cleanup, die if $@;

    fatal_error "$dir is a Symbolic Link"        if -l $dir;
    fatal_error "Directory $dir does not exist"  unless -d _;
    fatal_error "Directory $dir is not writable" unless -w _;
    fatal_error "$scriptfile is a Symbolic Link" if -l $scriptfile;
    fatal_error "$scriptfile is a Directory"     if -d _;
    fatal_error "$scriptfile exists and is not a compiled script" if -e _ && ! -x _;
    fatal_error "An exported \u$globals{PRODUCT} compiled script may not be named '$globals{PRODUCT}'" if $export && "$file" eq $globals{PRODUCT} && $suffix eq '';

    eval {
	$dir = abs_path $dir unless $dir =~ m|^/|; # Work around http://rt.cpan.org/Public/Bug/Display.html?id=13851
	( $script, $tempfile ) = tempfile ( 'tempfileXXXX' , DIR => $dir );
    };

    fatal_error "Unable to create temporary file in directory $dir" if $@;

    $file = "$file.$suffix" if $suffix;
    $dir .= '/' unless substr( $dir, -1, 1 ) eq '/';
    $file = $dir . $file;

}

#
# Finalize the script file
#
sub finalize_script( $ ) {
    my $export = $_[0];
    close $script;
    $script = 0;

    if ( $file ne '-' ) {
	rename $tempfile, $file or fatal_error "Cannot Rename $tempfile to $file: $!";
	chmod 0700, $file or fatal_error "Cannot secure $file for execute access";
	progress_message3 "Shorewall configuration compiled to $file" unless $export;
    }
}

#
# Create the temporary aux config file.
#
sub create_temp_aux_config() {
    eval {
	( $script, $tempfile ) = tempfile ( 'tempfileXXXX' , DIR => $dir );
    };

    cleanup, die if $@;
}

#
# Finalize the aux config file.
#
sub finalize_aux_config() {
    close $script;
    $script = 0;
    rename $tempfile, "$file.conf" or fatal_error "Cannot Rename $tempfile to $file.conf: $!";
    progress_message3 "Shorewall configuration compiled to $file";
}

#
# Enable writes to the script file
#
sub enable_script() {
    $script_enabled = 1;
}

#
# Disable writes to the script file
#
sub disable_script() {
    $script_enabled = 0;
}

#
# Set $config{CONFIG_PATH}
#
sub set_config_path( $ ) {
    $config{CONFIG_PATH} = shift;
}

#
# Set $debug
#
sub set_debug( $ ) {
    $debug = shift;
}

#
# Search the CONFIG_PATH for the passed file
#
sub find_file($)
{
    my $filename=$_[0];

    return $filename if $filename =~ '/';

    my $directory;

    for $directory ( @config_path ) {
	my $file = "$directory$filename";
	return $file if -f $file;
    }

    "$globals{CONFDIR}/$filename";
}

sub split_list( $$ ) {
    my ($list, $type ) = @_;

    fatal_error "Invalid $type list ($list)" if $list =~ /^,|,$|,,|!,|,!$/;

    split /,/, $list;
}

sub split_list1( $$ ) {
    my ($list, $type ) = @_;

    fatal_error "Invalid $type list ($list)" if $list =~ /^,|,$|,,|!,|,!$/;

    my @list1 = split /,/, $list;
    my @list2;
    my $element = '';

    for ( @list1 ) {
	my $count;

	if ( ( $count = tr/(/(/ ) > 0 ) {
	    fatal_error "Invalid $type list ($list)" if $element || $count > 1;
	    s/\(//;
	    if ( ( $count = tr/)/)/ ) > 0 ) {
		fatal_error "Invalid $type list ($list)" if $count > 1;
		s/\)//;
		push @list2 , $_;
	    } else {
		$element = $_;
	    }
	} elsif ( ( $count =  tr/)/)/ ) > 0 ) {
	    fatal_error "Invalid $type list ($list)" unless $element && $count == 1;
	    s/\)//;
	    push @list2, join ',', $element, $_;
	    $element = '';
	} elsif ( $element ) {
	    $element = join ',', $element , $_;
	} else {
	    push @list2 , $_;
	}
    }

    @list2;
}

#
# Pre-process a line from a configuration file.

#    ensure that it has an appropriate number of columns.
#    supply '-' in omitted trailing columns.
#
sub split_line( $$$ ) {
    my ( $mincolumns, $maxcolumns, $description ) = @_;

    fatal_error "Shorewall Configuration file entries may not contain single quotes, double quotes, single back quotes or backslashes" if $currentline =~ /["'`\\]/;
    fatal_error "Non-ASCII gunk in file" if $currentline =~ /[^\s[:print:]]/;

    my @line = split( ' ', $currentline );

    my $line = @line;

    fatal_error "Invalid $description entry (too many columns)" if $line > $maxcolumns;

    $line-- while $line > 0 && $line[$line-1] eq '-';

    fatal_error "Invalid $description entry (too few columns)"  if $line < $mincolumns;

    push @line, '-' while @line < $maxcolumns;

    @line;
}

#
# Version of 'split_line' used on files with exceptions
#
sub split_line1( $$$;$ ) {
    my ( $mincolumns, $maxcolumns, $description, $nopad) = @_;

    fatal_error "Shorewall Configuration file entries may not contain double quotes, single back quotes or backslashes" if $currentline =~ /["`\\]/;

    my @line = split( ' ', $currentline );

    $nopad = { COMMENT => 0 } unless $nopad;

    my $first   = $line[0];
    my $columns = $nopad->{$first};

    if ( defined $columns ) {
	fatal_error "Invalid $first entry" if $columns && @line != $columns;
	return @line
    }

    fatal_error "Shorewall Configuration file entries may not contain single quotes" if $currentline =~ /'/;

    my $line = @line;

    fatal_error "Invalid $description entry (too many columns)" if $line > $maxcolumns;

    $line-- while $line > 0 && $line[$line-1] eq '-';

    fatal_error "Invalid $description entry (too few columns)"  if $line < $mincolumns;

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

    assert( ! defined $currentfile );

    if ( -f $fname && -s _ ) {
	$first_entry = 0;
	do_open_file $fname;;
    } else {
	'';
    }
}

#
# Pop the include stack
#
sub pop_include() {
    my $arrayref = pop @includestack;

    if ( $arrayref ) {
	( $currentfile, $currentfilename, $currentlinenumber ) = @$arrayref;
    } else {
	$currentfile = undef;
    }
}

#
# This function is normally called below in read_a_line() when EOF is reached. Clients of the
# module may also call the function to close the file before EOF
#

sub close_file() {
    if ( $currentfile ) {
	my $result = close $currentfile;

	pop_include;

	fatal_error "SHELL Script failed" unless $result;

	$first_entry = 0;

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
    pop_include;
}

#
# This function is called by in-line PERL to generate a line of input for the current file.
# If the in-line PERL returns an indication of success, then the generated lines will be
# processed as regular file input.
#
sub shorewall {
    unless ( $perlscript ) {
	fatal_error "shorewall() may not be called in this context" unless $currentfile;

	$dir ||= '/tmp/';

	eval {
	    ( $perlscript, $perlscriptname ) = tempfile ( 'perlscriptXXXX' , DIR => $dir );
	};

	fatal_error "Unable to create temporary file in directory $dir" if $@;
    }

    print $perlscript "@_\n";
}

#
# We don't announce that we are checking/compiling a file until we determine that the file contains
# at least one non-blank, non-commentary line.
#
# The argument to this function may be either a scalar or a function reference. When the first
# non-blank/non-commentary line is reached:
#
# - if a function reference was passed to first_entry(), that function is called
# - otherwise, the argument to first_entry() is passed to progress_message2().
#
# We do this processing in read_a_line() rather than in the higher-level routines because
# Embedded Shell/Perl scripts are processed out of read_a_line(). If we were to defer announcement
# until we get back to the caller of read_a_line(), we could issue error messages about parsing and
# running scripts in the file before we'd even indicated that we are processing it.
#
sub first_entry( $ ) {
    $first_entry = $_[0];
    my $reftype = reftype $first_entry;
    if ( $reftype ) {
	fatal_error "Invalid argument to first_entry()" unless $reftype eq 'CODE';
    }
}

sub embedded_shell( $ ) {
    my $multiline = shift;

    fatal_error "INCLUDEs nested too deeply" if @includestack >= 4;
    my ( $command, $linenumber ) = ( "/bin/sh -c '$currentline", $currentlinenumber );

    if ( $multiline ) {
	#
	# Multi-line script
	#
	fatal_error "Invalid BEGIN SHELL directive" unless $currentline =~ /^\s*$/;
	$command .= "\n";

	my $last = 0;

	while ( <$currentfile> ) {
	    $currentlinenumber++;
	    last if $last = s/^\s*END(\s+SHELL)?\s*;?//;
	    $command .= $_;
	}

	fatal_error ( "Missing END SHELL" ) unless $last;
	fatal_error ( "Invalid END SHELL directive" ) unless /^\s*$/;
    }

    $command .= q(');

    push @includestack, [ $currentfile, $currentfilename, $currentlinenumber ];
    $currentfile = undef;
    open $currentfile , '-|', $command or fatal_error qq(Shell Command failed);
    $currentfilename = "SHELL\@$currentfilename:$currentlinenumber";
    $currentline = '';
    $currentlinenumber = 0;
}

sub embedded_perl( $ ) {
    my $multiline = shift;

    my ( $command , $linenumber ) = ( qq(package Shorewall::User;\nno strict;\nuse Shorewall::Config qw/shorewall/;\n# line $currentlinenumber "$currentfilename"\n$currentline), $currentlinenumber );

    if ( $multiline ) {
	#
	# Multi-line script
	#
	fatal_error "Invalid BEGIN PERL directive" unless $currentline =~ /^\s*$/;
	$command .= "\n";

	my $last = 0;

	while ( <$currentfile> ) {
	    $currentlinenumber++;
	    last if $last = s/^\s*END(\s+PERL)?\s*;?//;
	    $command .= $_;
	}

	fatal_error ( "Missing END PERL" ) unless $last;
	fatal_error ( "Invalid END PERL directive" ) unless /^\s*$/;
    }

    unless (my $return = eval $command ) {
	if ( $@ ) {
	    #
	    # Perl found the script offensive or the script itself died
	    #
	    $@ =~ s/, <\$currentfile> line \d+//g;
	    fatal_error1 "$@";
	}

	unless ( defined $return ) {
	    fatal_error "Perl Script failed: $!" if $!;
	    fatal_error "Perl Script failed";
	}

	fatal_error "Perl Script Returned False";
    }

    if ( $perlscript ) {
	fatal_error "INCLUDEs nested too deeply" if @includestack >= 4;

	close $perlscript or assert(0);

	$perlscript = undef;

	push @includestack, [ $currentfile, $currentfilename, $currentlinenumber ];
	$currentfile = undef;

	open $currentfile, '<', $perlscriptname or fatal_error "Unable to open Perl Script $perlscriptname";

	push @tempfiles, $perlscriptname unless unlink $perlscriptname; #unlink fails on Cygwin

	$perlscriptname = '';

	$currentfilename = "PERL\@$currentfilename:$linenumber";
	$currentline = '';
	$currentlinenumber = 0;
    }
}

#
# Push/pop action params
#
sub push_params( $ ) {
    my @params = split /,/, $_[0];
    my $oldparams = \%actparms;

    %actparms = ();

    for ( my $i = 1; $i <= @params; $i++ ) {
	$actparms{$i} = $params[$i - 1];
    }

    $oldparams;
}

sub pop_params( $ ) {
    my $oldparms = shift;
    %actparms = %$oldparms;
}

#
# Read a line from the current include stack.
#
#   - Ignore blank or comment-only lines.
#   - Remove trailing comments.
#   - Handle Line Continuation
#   - Handle embedded SHELL and PERL scripts
#   - Expand shell variables from %params and %ENV.
#   - Handle INCLUDE <filename>
#

sub read_a_line(;$) {
    my $embedded_enabled = defined $_[0] ? shift : 1;

    while ( $currentfile ) {

	$currentline = '';
	$currentlinenumber = 0;

	while ( <$currentfile> ) {

	    $currentlinenumber = $. unless $currentlinenumber;

	    chomp;
	    #
	    # Suppress leading whitespace in certain continuation lines
	    #
	    s/^\s*// if $currentline =~ /[,:]$/;
	    #
	    # If this isn't a continued line, remove trailing comments. Note that
	    # the result may now end in '\'.
	    #
	    s/\s*#.*$// unless /\\$/;
	    #
	    # Continuation
	    #
	    chop $currentline, next if substr( ( $currentline .= $_ ), -1, 1 ) eq '\\';
	    #
	    # Now remove concatinated comments
	    #
	    $currentline =~ s/#.*$//;
	    #
	    # Ignore ( concatenated ) Blank Lines
	    #
	    $currentline = '', $currentlinenumber = 0, next if $currentline =~ /^\s*$/;
	    #
	    # Line not blank -- Handle any first-entry message/capabilities check
	    #
	    if ( $first_entry ) {
		#
		# $first_entry can contain either a function reference or a message. If it
		# contains a reference, call the function -- otherwise issue the message
		#
		reftype( $first_entry ) ? $first_entry->() : progress_message2( $first_entry );
		$first_entry = 0;
	    }
	    #
	    # Must check for shell/perl before doing variable expansion
	    #
	    if ( $embedded_enabled ) {
		if ( $currentline =~ s/^\s*(BEGIN\s+)?SHELL\s*;?// ) {
		    embedded_shell( $1 );
		    next;
		}

		if ( $currentline =~ s/^\s*(BEGIN\s+)?PERL\s*\;?// ) {
		    embedded_perl( $1 );
		    next;
		}
	    }

	    my $count = 0;
	    #
	    # Expand Shell Variables using %params and %ENV
	    #
	    #                            $1      $2   $3      -     $4
	    while ( $currentline =~ m( ^(.*?) \$({)? (\w+) (?(2)}) (.*)$ )x ) {

		my ( $first, $var, $rest ) = ( $1, $3, $4);

		my $val;

		if ( $var =~ /^\d+$/ ) {
		    fatal_error "Undefined parameter (\$$var)" unless exists $actparms{$var};
		    $val = $actparms{$var};
		} else {
		    fatal_error "Undefined shell variable (\$$var)" unless exists $params{$var};
		    $val = $params{$var};
		}

		$val = '' unless defined $val;
		$currentline = join( '', $first , $val , $rest );
		fatal_error "Variable Expansion Loop" if ++$count > 100;
	    }

	    if ( $currentline =~ /^\s*INCLUDE\s/ ) {

		my @line = split ' ', $currentline;

		fatal_error "Invalid INCLUDE command"    if @line != 2;
		fatal_error "INCLUDEs/Scripts nested too deeply" if @includestack >= 4;

		my $filename = find_file $line[1];

		fatal_error "INCLUDE file $filename not found" unless -f $filename;
		fatal_error "Directory ($filename) not allowed in INCLUDE" if -d _;

		if ( -s _ ) {
		    push @includestack, [ $currentfile, $currentfilename, $currentlinenumber ];
		    $currentfile = undef;
		    do_open_file $filename;
		} else {
		    $currentlinenumber = 0;
		}

		$currentline = '';
	    } else {
		print "IN===> $currentline\n" if $debug;
		return 1;
	    }
	}

	close_file;
    }
}

#
# Simple version of the above. Doesn't do line concatenation, shell variable expansion or INCLUDE processing
#
sub read_a_line1() {
    while ( $currentfile ) {
	while ( $currentline = <$currentfile> ) {
	    next if $currentline =~ /^\s*#/;
	    chomp $currentline;
	    next if $currentline =~ /^\s*$/;
	    $currentline =~ s/#.*$//;       # Remove Trailing Comments
	    fatal_error "Non-ASCII gunk in file" if $currentline =~ /[^\s[:print:]]/;
	    $currentlinenumber = $.;
	    print "IN===> $currentline\n" if $debug;
	    return 1;
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

    my $curval = $config{$var};

    if ( defined $curval && $curval ne '' ) {
	$curval = lc $curval;

	if (  $curval eq 'no' ) {
	    $config{$var} = '';
	} else {
	    fatal_error "Invalid value for $var ($val)" unless $curval eq 'yes';
	}
    } else {
	$config{$var} = $val;
    }
}

sub default_yes_no_ipv4 ( $$ ) {
    my ( $var, $val ) = @_;
    default_yes_no( $var, $val );
    warning_message "$var=Yes is ignored for IPv6" if $family == F_IPV6 && $config{$var};
}

sub numeric_option( $$$ ) {
    my ( $option, $default, $min ) = @_;

    my $value = $config{$option};

    my $val = $default;

    if ( defined $value && $value ne '' ) {
	$val = numeric_value $value;
	fatal_error "Invalid value ($value) for '$option'" unless defined $val && $val <= 32;
    }

    $val = $min if $val < $min;

    $config{$option} = $val;
}

sub make_mask( $ ) {
    0xffffffff >> ( 32 - $_[0] );
}

my @suffixes = qw(group range threshold nlgroup cprange qthreshold);

#
# Validate a log level -- Drop the trailing '!' and translate to numeric value if appropriate"
#
sub level_error( $ ) {
    fatal_error "Invalid log level ($_[0])";
}

sub validate_level( $ ) {
    my $rawlevel = $_[0];
    my $level    = uc $rawlevel;

    if ( defined $level && $level ne '' ) {
	$level =~ s/!$//;
	my $value = $validlevels{$level};

	if ( defined $value ) {
	    require_capability ( 'LOG_TARGET' , 'A log level other than NONE', 's' ) unless $value eq '';
	    return $value;
	}

	if ( $level =~ /^[0-7]$/ ) {
	    require_capability ( 'LOG_TARGET' , 'A log level other than NONE', 's' );
	    return $level;
	}

	if ( $level =~ /^(NFLOG|ULOG)[(](.*)[)]$/ ) {
	    my $olevel  = $1;
	    my @options = split /,/, $2;
	    my $prefix  = lc $olevel;
	    my $index   = $prefix eq 'ulog' ? 3 : 0;

	    level_error( $level ) if @options > 3;

	    for ( @options ) {
		if ( defined $_ and $_ ne '' ) {
		    level_error( $level ) unless /^\d+/;
		    $olevel .= " --${prefix}-$suffixes[$index] $_";
		}

		$index++;
	    }

	    require_capability ( 'LOG_TARGET' , 'A log level other than NONE', 's' );
	    return $olevel;
	}

	if ( $level =~ /^NFLOG --/ or $level =~ /^ULOG --/ ) {
	    require_capability ( 'LOG_TARGET' , 'A log level other than NONE', 's' );
	    return $rawlevel;
	}

	if ( $level eq 'LOGMARK' ) {
	    require_capability ( 'LOG_TARGET' , 'A log level other than NONE', 's' );
	    require_capability( 'LOGMARK_TARGET' , 'LOGMARK', 's' );
	    return 'LOGMARK';
	}

	level_error( $rawlevel );
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
    my $val = lc( $config{$var} || '' );

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
	    fatal_error "Invalid value ($val) for $var";
	}
    } else {
	$config{var} = $default
    }
}

#
# Produce a report of the detected capabilities
#
sub report_capability( $ ) {
    my $cap = $_[0];
    print "   $capdesc{$cap}: ";
    if ( $cap eq 'CAPVERSION' || $cap eq 'KERNELVERSION') {
	my $version = $capabilities{$cap};
	printf "%d.%d.%d\n", int( $version / 10000 ) , int ( ( $version % 10000 ) / 100 ) , int ( $version % 100 );
    } else {
	print $capabilities{$cap} ? "Available\n" : "Not Available\n";
    }
}

sub report_capabilities() {
    if ( $verbosity > 1 ) {
	print "Shorewall has detected the following capabilities:\n";

	for my $cap ( sort { $capdesc{$a} cmp $capdesc{$b} } keys %capabilities ) {
	    report_capability $cap;
	}
    }
}

#
# Search the current PATH for the passed executable
#
sub which( $ ) {
    my $prog = $_[0];

    for ( split /:/, $config{PATH} ) {
	return "$_/$prog" if -x "$_/$prog";
    }

    '';
}

#
# Load the kernel modules defined in the 'modules' file.
#
sub load_kernel_modules( ) {
    my $moduleloader = which( 'modprobe' ) || ( which 'insmod' );

    my $modulesdir = $config{MODULESDIR};

    unless ( $modulesdir ) {
	my $uname = `uname -r`;
	fatal_error "The command 'uname -r' failed" unless $? == 0;
	chomp $uname;
	$modulesdir = "/lib/modules/$uname/kernel/net/ipv4/netfilter:/lib/modules/$uname/kernel/net/netfilter:/lib/modules/$uname/extra:/lib/modules/$uname/extra/ipset";
    }

    my @moduledirectories = split /:/, $modulesdir;

    if ( $moduleloader && open_file( $config{LOAD_HELPERS_ONLY} ? 'helpers' : 'modules' ) ) {
	my %loadedmodules;

	$loadedmodules{$_}++ for split_list( $config{DONT_LOAD}, 'module' );

	progress_message2 "Loading Modules...";

	open LSMOD , '-|', 'lsmod' or fatal_error "Can't run lsmod";

	while ( <LSMOD> ) {
	    my $module = ( split( /\s+/, $_, 2 ) )[0];
	    $loadedmodules{$module}++ unless $module eq 'Module'
	}

	close LSMOD;

	$config{MODULE_SUFFIX} = 'o gz ko o.gz ko.gz' unless $config{MODULE_SUFFIX};

	my @suffixes = split /\s+/ , $config{MODULE_SUFFIX};

	while ( read_a_line ) {
	    fatal_error "Invalid modules file entry" unless ( $currentline =~ /^loadmodule\s+([a-zA-Z]\w*)\s*(.*)$/ );
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

sub qt1( $ ) {
    1 while system( "@_ > /dev/null 2>&1" ) == 4;
    $? == 0;
}

#
# Get the current kernel version
#
sub determine_kernelversion() {
    my $kernelversion=`uname -r`;

    if ( $kernelversion =~ /^(\d+)\.(\d+).(\d+)/ ) {
	$capabilities{KERNELVERSION} = sprintf "%d%02d%02d", $1 , $2 , $3;
    } else {
	fatal_error "Unrecognized Kernel Version Format ($kernelversion)";
    }
}

#
# Capability Reporting and detection.
#
sub have_capability( $ );

sub Nat_Enabled() {
    $family == F_IPV4 ? qt1( "$iptables -t nat -L -n" ) : '';
}

sub Persistent_Snat() {
    have_capability 'NAT_ENABLED' || return '';

    my $result = '';

    if ( qt1( "$iptables -t nat -N $sillyname" ) ) {
	$result = qt1( "$iptables -t nat -A $sillyname -j SNAT --to-source 1.2.3.4 --persistent" );
	qt1( "$iptables -t nat -F $sillyname" );
	qt1( "$iptables -t nat -X $sillyname" );

    }

    $result;
}

sub Mangle_Enabled() {
    if ( qt1( "$iptables -t mangle -L -n" ) ) {
	system( "$iptables -t mangle -N $sillyname" ) == 0 || fatal_error "Cannot Create Mangle chain $sillyname";
    }
}

sub Conntrack_Match() {
    if ( $family == F_IPV4 ) {
	qt1( "$iptables -A $sillyname -m conntrack --ctorigdst 192.168.1.1 -j ACCEPT" );
    } else {
	qt1( "$iptables -A $sillyname -m conntrack --ctorigdst ::1 -j ACCEPT" );
    }
}

sub New_Conntrack_Match() {
    have_capability 'CONNTRACK_MATCH' && qt1( "$iptables -A $sillyname -m conntrack -p tcp --ctorigdstport 22 -j ACCEPT" );
}

sub Old_Conntrack_Match() {
    ! qt1( "$iptables -A $sillyname -m conntrack ! --ctorigdst 1.2.3.4" );
}

sub Multiport() {
    qt1( "$iptables -A $sillyname -p tcp -m multiport --dports 21,22 -j ACCEPT" );
}

sub Kludgefree1() {
    have_capability 'MULTIPORT' && qt1( "$iptables -A $sillyname -p tcp -m multiport --sports 60 -m multiport --dports 99 -j ACCEPT" );
}

sub Kludgefree2() {
    have_capability 'PHYSDEV_MATCH' && qt1( "$iptables -A $sillyname -m physdev --physdev-in eth0 -m physdev --physdev-out eth0 -j ACCEPT" );
}

sub Kludgefree3() {
    if ( $family == F_IPV4 ) {
	qt1( "$iptables -A $sillyname -m iprange --src-range 192.168.1.5-192.168.1.124 -m iprange --dst-range 192.168.1.5-192.168.1.124 -j ACCEPT" );
    } else {
	qt1( "$iptables -A $sillyname -m iprange --src-range ::1-::2 -m iprange --dst-range 192.168.1.5-192.168.1.124 -j ACCEPT" );
    }
}

sub Kludgefree() {
    Kludgefree1 || Kludgefree2 || Kludgefree3;
}

sub Xmultiport() {
    qt1( "$iptables -A $sillyname -p tcp -m multiport --dports 21:22 -j ACCEPT" );
}

sub Policy_Match() {
    qt1( "$iptables -A $sillyname -m policy --pol ipsec --mode tunnel --dir in -j ACCEPT" );
}

sub Physdev_Match() {
    qt1( "$iptables -A $sillyname -m physdev --physdev-in eth0 -j ACCEPT" );
}

sub Physdev_Bridge() {
    qt1( "$iptables -A $sillyname -m physdev --physdev-is-bridged --physdev-in eth0 --physdev-out eth1 -j ACCEPT" );
}

sub IPRange_Match() {
    if ( $family == F_IPV4 ) {
	qt1( "$iptables -A $sillyname -m iprange --src-range 192.168.1.5-192.168.1.124 -j ACCEPT" );
    } else {
	qt1( "$iptables -A $sillyname -m iprange --src-range ::1-::2 -j ACCEPT" );
    }
}

sub Recent_Match() {
    qt1( "$iptables -A $sillyname -m recent --update -j ACCEPT" );
}

sub Owner_Match() {
    qt1( "$iptables -A $sillyname -m owner --uid-owner 0 -j ACCEPT" );
}

sub Connmark_Match() {
    qt1( "$iptables -A $sillyname -m connmark --mark 2  -j ACCEPT" );
}

sub Xconnmark_Match() {
    have_capability 'CONNMARK_MATCH' && qt1( "$iptables -A $sillyname -m connmark --mark 2/0xFF -j ACCEPT" );
}

sub Ipp2p_Match() {
    qt1( "$iptables -A $sillyname -p tcp -m ipp2p --edk -j ACCEPT" );
}

sub Old_Ipp2p_Match() {
    qt1( "$iptables -A $sillyname -p tcp -m ipp2p --ipp2p -j ACCEPT" ) if $capabilities{IPP2P_MATCH};
}

sub Length_Match() {
    qt1( "$iptables -A $sillyname -m length --length 10:20 -j ACCEPT" );
}

sub Enhanced_Reject() {
    if ( $family == F_IPV6 ) {
	qt1( "$iptables -A $sillyname -j REJECT --reject-with icmp6-adm-prohibited" );
    } else {
	qt1( "$iptables -A $sillyname -j REJECT --reject-with icmp-host-prohibited" );
    }
}

sub Comments() {
    qt1( qq($iptables -A $sillyname -j ACCEPT -m comment --comment "This is a comment" ) );
}

sub Hashlimit_Match() {
    if ( qt1( "$iptables -A $sillyname -m hashlimit --hashlimit-upto 3/min --hashlimit-burst 3 --hashlimit-name $sillyname --hashlimit-mode srcip -j ACCEPT" ) ) {
	! ( $capabilities{OLD_HL_MATCH} = 0 );
    } else {
	have_capability 'OLD_HL_MATCH';
    }
}

sub Old_Hashlimit_Match() {
    qt1( "$iptables -A $sillyname -m hashlimit --hashlimit 3/min --hashlimit-burst 3 --hashlimit-name $sillyname --hashlimit-mode srcip -j ACCEPT" );
}

sub Mark() {
    have_capability 'MANGLE_ENABLED' && qt1( "$iptables -t mangle -A $sillyname -j MARK --set-mark 1" );
}

sub Xmark() {
    have_capability 'MARK' && qt1( "$iptables -t mangle -A $sillyname -j MARK --and-mark 0xFF" );
}

sub Exmark() {
    have_capability 'MARK' && qt1( "$iptables -t mangle -A $sillyname -j MARK --set-mark 1/0xFF" );
}

sub Connmark() {
    have_capability 'MANGLE_ENABLED' && qt1( "$iptables -t mangle -A $sillyname -j CONNMARK --save-mark" );
}

sub Xconnmark() {
    have_capability 'XCONNMARK_MATCH' && have_capability 'XMARK' && qt1( "$iptables -t mangle -A $sillyname -j CONNMARK --save-mark --mask 0xFF" );
}

sub Classify_Target() {
    have_capability 'MANGLE_ENABLED' && qt1( "$iptables -t mangle -A $sillyname -j CLASSIFY --set-class 1:1" );
}

sub IPMark_Target() {
    have_capability 'MANGLE_ENABLED' && qt1( "$iptables -t mangle -A $sillyname -j IPMARK --addr src" );
}

sub Tproxy_Target() {
    have_capability 'MANGLE_ENABLED' && qt1( "$iptables -t mangle -A $sillyname -p tcp -j TPROXY --on-port 0 --tproxy-mark 1" );
}

sub Mangle_Forward() {
    have_capability 'MANGLE_ENABLED' && qt1( "$iptables -t mangle -L FORWARD -n" );
}

sub Raw_Table() {
    qt1( "$iptables -t raw -L -n" );
}

sub Old_IPSet_Match() {
    my $ipset  = $config{IPSET} || 'ipset';
    my $result = 0;

    $ipset = which $ipset unless $ipset =~ '/';

    if ( $ipset && -x $ipset ) {
	qt( "$ipset -X $sillyname" );

	if ( qt( "$ipset -N $sillyname iphash" ) ) {
	    if ( qt1( "$iptables -A $sillyname -m set --set $sillyname src -j ACCEPT" ) ) {
		qt1( "$iptables -D $sillyname -m set --set $sillyname src -j ACCEPT" );
		$result = $capabilities{IPSET_MATCH} = 1;
	    }

	    qt( "$ipset -X $sillyname" );
	}
    }

    $result;
}

sub IPSet_Match() {
    my $ipset  = $config{IPSET} || 'ipset';
    my $result = 0;

    $ipset = which $ipset unless $ipset =~ '/';

    if ( $ipset && -x $ipset ) {
	qt( "$ipset -X $sillyname" );

	if ( qt( "$ipset -N $sillyname iphash" ) ) {
	    if ( qt1( "$iptables -A $sillyname -m set --match-set $sillyname src -j ACCEPT" ) ) {
		qt1( "$iptables -D $sillyname -m set --match-set $sillyname src -j ACCEPT" );
		$result = ! ( $capabilities{OLD_IPSET_MATCH} = 0 );
	    } else {
		$result = have_capability 'OLD_IPSET_MATCH';
	    }

	    qt( "$ipset -X $sillyname" );
	}
    }

    $result;
}

sub Usepkttype() {
    qt1( "$iptables -A $sillyname -m pkttype --pkt-type broadcast -j ACCEPT" );
}

sub Addrtype() {
    qt1( "$iptables -A $sillyname -m addrtype --src-type BROADCAST -j ACCEPT" );
}

sub Tcpmss_Match() {
    qt1( "$iptables -A $sillyname -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1000:1500 -j ACCEPT" );
}

sub Nfqueue_Target() {
    qt1( "$iptables -A $sillyname -j NFQUEUE --queue-num 4" );
}

sub Realm_Match() {
    qt1( "$iptables -A $sillyname -m realm --realm 1" );
}

sub Helper_Match() {
    qt1( "$iptables -A $sillyname -m helper --helper \"ftp\"" );
}

sub Connlimit_Match() {
    qt1( "$iptables -A $sillyname -m connlimit --connlimit-above 8" );
}

sub Time_Match() {
    qt1( "$iptables -A $sillyname -m time --timestart 11:00" );
}

sub Goto_Target() {
    qt1( "$iptables -A $sillyname -g $sillyname1" );
}

sub Log_Target() {
    qt1( "$iptables -A $sillyname -j LOG" );
}

sub Logmark_Target() {
    qt1( "$iptables -A $sillyname -j LOGMARK" );
}

sub Flow_Filter() {
    $tc && system( "$tc filter add flow add help 2>&1 | grep -q ^Usage" ) == 0;
}

sub Fwmark_Rt_Mask() {
    $ip && system( "$ip rule add help 2>&1 | grep -q /MASK" ) == 0;
}

sub Mark_Anywhere() {
    qt1( "$iptables -A $sillyname -j MARK --set-mark 5" );
}

sub Header_Match() {
    qt1( "$iptables -A $sillyname -m ipv6header --header 255 -j ACCEPT" );
}

our %detect_capability =
    ( ADDRTYPE => \&Addrtype,
      CLASSIFY_TARGET => \&Classify_Target,
      COMMENTS => \&Comments,
      CONNLIMIT_MATCH => \&Connlimit_Match,
      CONNMARK => \&Connmark,
      CONNMARK_MATCH => \&Connmark_Match,
      CONNTRACK_MATCH => \&Conntrack_Match,
      ENHANCED_REJECT => \&Enhanced_Reject,
      EXMARK => \&Exmark,
      FLOW_FILTER => \&Flow_Filter,
      FWMARK_RT_MASK => \&Fwmark_Rt_Mask,
      GOTO_TARGET => \&Goto_Target,
      HASHLIMIT_MATCH => \&Hashlimit_Match,
      HEADER_MATCH => \&Header_Match,
      HELPER_MATCH => \&Helper_Match,
      IPMARK_TARGET => \&IPMark_Target,
      IPP2P_MATCH => \&Ipp2p_Match,
      IPRANGE_MATCH => \&IPRange_Match,
      IPSET_MATCH => \&IPSet_Match,
      OLD_IPSET_MATCH => \&Old_IPSet_Match,
      KLUDGEFREE => \&Kludgefree,
      LENGTH_MATCH => \&Length_Match,
      LOGMARK_TARGET => \&Logmark_Target,
      LOG_TARGET => \&Log_Target,
      MANGLE_ENABLED => \&Mangle_Enabled,
      MANGLE_FORWARD => \&Mangle_Forward,
      MARK => \&Mark,
      MARK_ANYWHERE => \&Mark_Anywhere,
      MULTIPORT => \&Multiport,
      NAT_ENABLED => \&Nat_Enabled,
      NEW_CONNTRACK_MATCH => \&New_Conntrack_Match,
      NFQUEUE_TARGET => \&Nfqueue_Target,
      OLD_CONNTRACK_MATCH => \&Old_Conntrack_Match,
      OLD_HL_MATCH => \&Old_Hashlimit_Match,
      OLD_IPP2P_MATCH => \&Old_Ipp2p_Match,
      OWNER_MATCH => \&Owner_Match,
      PERSISTENT_SNAT => \&Persistent_Snat,
      PHYSDEV_BRIDGE => \&Physdev_Bridge,
      PHYSDEV_MATCH => \&Physdev_Match,
      POLICY_MATCH => \&Policy_Match,
      RAW_TABLE => \&Raw_Table,
      REALM_MATCH => \&Realm_Match,
      RECENT_MATCH => \&Recent_Match,
      TCPMSS_MATCH => \&Tcpmss_Match,
      TIME_MATCH => \&Time_Match,
      TPROXY_TARGET => \&Tproxy_Target,
      USEPKTTYPE => \&Usepkttype,
      XCONNMARK_MATCH => \&Xconnmark_Match,
      XCONNMARK => \&Xconnmark,
      XMARK => \&Xmark,
      XMULTIPORT => \&Xmultiport,
    );

sub detect_capability( $ ) {
    my $capability = shift;
    my $function = $detect_capability{ $capability };

    assert( ( reftype( $function ) || '' ) eq 'CODE' );
    $function->();
}

#
# Report the passed capability
#
sub have_capability( $ ) {
    my $capability = shift;
    our %detect_capability;

    $capabilities{ $capability } = detect_capability( $capability ) unless defined $capabilities{ $capability };

    $capabilities{ $capability };
}

#
# Determine which optional facilities are supported by iptables/netfilter
#
sub determine_capabilities() {

    my $pid     = $$;

    $capabilities{CAPVERSION} = $globals{CAPVERSION};

    determine_kernelversion;

    $sillyname  = "fooX$pid";
    $sillyname1 = "foo1X$pid";

    qt1( "$iptables -N $sillyname" );
    qt1( "$iptables -N $sillyname1" );

    fatal_error 'Your kernel/iptables do not include state match support. No version of Shorewall will run on this system'
	unless
	    qt1( "$iptables -A $sillyname -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") ||
	    qt1( "$iptables -A $sillyname -m state --state ESTABLISHED,RELATED -j ACCEPT");;


    unless ( $config{ LOAD_HELPERS_ONLY } ) {
	#
	# Using 'detect_capability()' is a bit less efficient than calling the individual detection
	# functions but it ensures that %detect_capability is initialized properly.
	#
	$capabilities{NAT_ENABLED}     = detect_capability( 'NAT_ENABLED' );
	$capabilities{PERSISTENT_SNAT} = detect_capability( 'PERSISTENT_SNAT' );
	$capabilities{MANGLE_ENABLED}  = detect_capability( 'MANGLE_ENABLED' );

	if ( $capabilities{CONNTRACK_MATCH} = detect_capability( 'CONNTRACK_MATCH' ) ) {
	    $capabilities{NEW_CONNTRACK_MATCH} = detect_capability( 'NEW_CONNTRACK_MATCH' );
	    $capabilities{OLD_CONNTRACK_MATCH} = detect_capability( 'OLD_CONNTRACK_MATCH' );
	} else {
	    $capabilities{NEW_CONNTRACK_MATCH} = '';
	    $capabilities{OLD_CONNTRACK_MATCH} = '';
	}

	if ( $capabilities{ MULTIPORT } = detect_capability( 'MULTIPORT' ) ) {
	     $capabilities{KLUDGEFREE}  = Kludgefree1;
	}

	$capabilities{XMULTIPORT}   = detect_capability( 'XMULTIPORT' );
	$capabilities{POLICY_MATCH} = detect_capability( 'POLICY_MATCH' );

	if ( $capabilities{PHYSDEV_MATCH} = detect_capability( 'PHYSDEV_MATCH' ) ) {
	    $capabilities{PHYSDEV_BRIDGE} = detect_capability( 'PHYSDEV_BRIDGE' );
	    $capabilities{KLUDGEFREE}   ||= Kludgefree2;
	} else {
	    $capabilities{PHYSDEV_BRIDGE} = '';
	}

	if ( $capabilities{IPRANGE_MATCH} = detect_capability( 'IPRANGE_MATCH' ) ) {
	    $capabilities{KLUDGEFREE}   ||= Kludgefree3;
	}

	$capabilities{RECENT_MATCH}    = detect_capability( 'RECENT_MATCH' );
	$capabilities{OWNER_MATCH}     = detect_capability( 'OWNER_MATCH' );
	$capabilities{CONNMARK_MATCH}  = detect_capability( 'CONNMARK_MATCH' );
	$capabilities{XCONNMARK_MATCH} = detect_capability( 'XCONNMARK_MATCH' );
	$capabilities{IPP2P_MATCH}     = detect_capability( 'IPP2P_MATCH' );
	$capabilities{OLD_IPP2P_MATCH} = detect_capability( 'OLD_IPP2P_MATCH' );
	$capabilities{LENGTH_MATCH}    = detect_capability( 'LENGTH_MATCH' );
	$capabilities{ENHANCED_REJECT} = detect_capability( 'ENHANCED_REJECT' );
	$capabilities{COMMENTS}        = detect_capability( 'COMMENTS' );
	$capabilities{OLD_HL_MATCH}    = detect_capability( 'OLD_HL_MATCH' );
	$capabilities{HASHLIMIT_MATCH} = detect_capability( 'HASHLIMIT_MATCH' );
	$capabilities{MARK}            = detect_capability( 'MARK' );
	$capabilities{XMARK}           = detect_capability( 'XMARK' );
	$capabilities{EXMARK}          = detect_capability( 'EXMARK' );
	$capabilities{CONNMARK}        = detect_capability( 'CONNMARK' );
	$capabilities{XCONNMARK}       = detect_capability( 'XCONNMARK' );
	$capabilities{CLASSIFY_TARGET} = detect_capability( 'CLASSIFY_TARGET' );
	$capabilities{IPMARK_TARGET}   = detect_capability( 'IPMARK_TARGET' );
	$capabilities{TPROXY_TARGET}   = detect_capability( 'TPROXY_TARGET' );

	if ( $capabilities{MANGLE_ENABLED} ) {
	    qt1( "$iptables -t mangle -F $sillyname" );
	    qt1( "$iptables -t mangle -X $sillyname" );
	}

	$capabilities{MANGLE_FORWARD}  = detect_capability( 'MANGLE_FORWARD' );
	$capabilities{RAW_TABLE}       = detect_capability( 'RAW_TABLE' );
	$capabilities{IPSET_MATCH}     = detect_capability( 'IPSET_MATCH' );
	$capabilities{USEPKTTYPE}      = detect_capability( 'USEPKTTYPE' );
	$capabilities{ADDRTYPE}        = detect_capability( 'ADDRTYPE' );
	$capabilities{TCPMSS_MATCH}    = detect_capability( 'TCPMSS_MATCH' );
	$capabilities{NFQUEUE_TARGET}  = detect_capability( 'NFQUEUE_TARGET' );
	$capabilities{REALM_MATCH}     = detect_capability( 'REALM_MATCH' );
	$capabilities{HELPER_MATCH}    = detect_capability( 'HELPER_MATCH' );
	$capabilities{CONNLIMIT_MATCH} = detect_capability( 'CONNLIMIT_MATCH' );
	$capabilities{TIME_MATCH}      = detect_capability( 'TIME_MATCH' );
	$capabilities{GOTO_TARGET}     = detect_capability( 'GOTO_TARGET' );
	$capabilities{LOG_TARGET}      = detect_capability( 'LOG_TARGET' );
	$capabilities{LOGMARK_TARGET}  = detect_capability( 'LOGMARK_TARGET' );
	$capabilities{FLOW_FILTER}     = detect_capability( 'FLOW_FILTER' );
	$capabilities{FWMARK_RT_MASK}  = detect_capability( 'FWMARK_RT_MASK' );
	$capabilities{MARK_ANYWHERE}   = detect_capability( 'MARK_ANYWHERE' );


	qt1( "$iptables -F $sillyname" );
	qt1( "$iptables -X $sillyname" );
	qt1( "$iptables -F $sillyname1" );
	qt1( "$iptables -X $sillyname1" );

	$sillyname = $sillyname1 = undef;
    }
}

#
# Require the passed capability
#
sub require_capability( $$$ ) {
    my ( $capability, $description, $singular ) = @_;

    fatal_error "$description require${singular} $capdesc{$capability} in your kernel and iptables" unless have_capability $capability;
}

#
# Set default config path
#
sub ensure_config_path() {

    my $f = "$globals{SHAREDIR}/configpath";

    $globals{CONFDIR} = "/usr/share/$product/configfiles/" if $> != 0;

    unless ( $config{CONFIG_PATH} ) {
	fatal_error "$f does not exist" unless -f $f;

	open_file $f;

	$params{CONFDIR} = $globals{CONFDIR};

	while ( read_a_line ) {
	    if ( $currentline =~ /^\s*([a-zA-Z]\w*)=(.*?)\s*$/ ) {
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
	$_ .= '/' unless m|/$|;
    }

    if ( $shorewall_dir ) {
	$shorewall_dir = getcwd if $shorewall_dir =~ m|^(\./*)+$|;
	$shorewall_dir .= '/' unless $shorewall_dir =~ m|/$|;
	unshift @config_path, $shorewall_dir if $shorewall_dir ne $config_path[0];
	$config{CONFIG_PATH} = join ':', @config_path;
    }
}

#
# Set $shorewall_dir
#
sub set_shorewall_dir( $ ) {
    $shorewall_dir = shift;
    ensure_config_path;
}

#
# Small functions called by get_configuration. We separate them so profiling is more useful
#
sub process_shorewall_conf() {
    my $file = find_file "$product.conf";

    if ( -f $file ) {
	$globals{CONFIGDIR} =  $file;
	$globals{CONFIGDIR} =~ s/$product.conf//;

	if ( -r _ ) {
	    open_file $file;

	    first_entry "Processing $file...";

	    while ( read_a_line(0) ) {
		if ( $currentline =~ /^\s*([a-zA-Z]\w*)=(.*?)\s*$/ ) {
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
}

#
# Process the records in the capabilities file
#
sub read_capabilities() {
    while ( read_a_line1 ) {
	if ( $currentline =~ /^([a-zA-Z]\w*)=(.*)$/ ) {
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

    if ( $capabilities{CAPVERSION} ) {
	warning_message "Your capabilities file is out of date -- it does not contain all of the capabilities defined by $Product version $globals{VERSION}" unless $capabilities{CAPVERSION} >= $globals{CAPVERSION};
    } else {
	warning_message "Your capabilities file may not contain all of the capabilities defined by $Product version $globals{VERSION}";
    }

    unless ( $capabilities{KERNELVERSION} ) {
	warning_message "Your capabilities file does not contain a Kernel Version -- using 2.6.30";
	$capabilities{KERNELVERSION} = 20630;
    }

    for ( keys %capabilities ) {
	$capabilities{$_} = '' unless defined $capabilities{$_};
    }

}

#
# Get the system's capabilities, either by probing or by reading a capabilities file
#
sub get_capabilities( $ ) {
    my $export = $_[0];

    if ( ! $export && $> == 0 ) { # $> == $EUID
	$iptables = $config{$toolNAME};

	if ( $iptables ) {
	    fatal_error "$toolNAME=$iptables does not exist or is not executable" unless -x $iptables;
	} else {
	    fatal_error "Can't find $toolname executable" unless $iptables = which $toolname;
	}

	my $iptables_restore=$iptables . '-restore';

	fatal_error "$iptables_restore does not exist or is not executable" unless -x $iptables_restore;

	$tc = $config{TC} || which 'tc';

	if ( $tc ) {
	    fatal_error "TC=$tc does not exist or is not executable" unless -x $tc;
	}

	$ip = $config{IP} || which 'ip';

	if ( $ip ) {
	    fatal_error "IP=$ip does not exist or is not executable" unless -x $ip;
	}

	load_kernel_modules;

	if ( open_file 'capabilities' ) {
	    read_capabilities;
	} else {
	    determine_capabilities;
	}
    } else {
	unless ( open_file 'capabilities' ) {
	    fatal_error "The -e compiler option requires a capabilities file" if $export;
	    fatal_error "Compiling under non-root uid requires a capabilities file";
	}

	read_capabilities;
    }
}

#
# Deal with options that we no longer support
#
sub unsupported_yes_no( $ ) {
    my $option = shift;

    default_yes_no $option, '';

    fatal_error "$option=Yes is not supported by Shorewall $globals{VERSION}" if $config{$option};
}

sub unsupported_yes_no_warning( $ ) {
    my $option = shift;

    default_yes_no $option, '';

    warning_message "$option=Yes is not supported by Shorewall $globals{VERSION}" if $config{$option};
}

#
# Process the params file
#
sub get_params() {
    my $fn = find_file 'params';

    if ( -f $fn ) {
	progress_message2 "Processing $fn ...";

	my $command = "$globals{SHAREDIRPL}/getparams $fn " . join( ':', @config_path );
	#
	# getparams silently sources the params file under 'set -a', then executes 'export -p'
	#
	my @params = `$command`;

	fatal_error "Processing of $fn failed" if $?;

	if ( $debug ) {
	    print "Params:\n";
	    print $_ for @params;
	}
	
	my ( $variable , $bug );

	if ( $params[0] =~ /^declare/ ) {
	    #
	    # getparams was interpreted by bash
	    #
	    # - Variable names are preceded by 'declare -x '
	    # - Param values are delimited by double quotes
	    # - Embedded double quotes are escaped with '\\'
	    # - Valueless variables are supported (e.g., 'declare -x foo')
	    #
	    for ( @params ) {
		if ( /^declare -x (.*?)="(.*[^\\])"$/ ) {
		    $params{$1} = $2 unless $1 eq '_';
		} elsif ( /^declare -x (.*?)="(.*)$/ ) {
		    $params{$variable=$1}="${2}\n";
		} elsif ( /^declare -x (.*)\s+$/ || /^declare -x (.*)=""$/ ) {
		    $params{$1} = '';
		} else {
		    if ($variable) {
			s/"$//;
			$params{$variable} .= $_;
		    } else {
			warning_message "Param line ($_) ignored" unless $bug++;
		    }
		}	
	    }
	} elsif ( $params[0] =~ /^export (.*?)="/ ) {
	    #
	    # getparams interpreted by older (e.g., RHEL 5) Bash
	    #
	    # - Variable names preceded by 'export '
	    # - Variable values are delimited by double quotes
	    # - Embedded single quotes are escaped with '\'
	    #
	    for ( @params ) {
		if ( /^export (.*?)="(.*[^\\])"$/ ) {
		    $params{$1} = $2 unless $1 eq '_';
		} elsif ( /^export (.*?)="(.*)$/ ) {
		    $params{$variable=$1}="${2}\n";
		} elsif ( /^export (.*)\s+$/ || /^export (.*)=""$/ ) {
		    $params{$1} = '';
		} else {
		    if ($variable) {
			s/"$//;
			$params{$variable} .= $_;
		    } else {
			warning_message "Param line ($_) ignored" unless $bug++;
		    }
		}	
	    }
	} else {
	    #
	    # getparams was interpreted by dash/ash/busybox
	    #
	    # - Variable name preceded by 'export '
	    # - Param values are delimited by single quotes.
	    # - Embedded single quotes are transformed to the five characters '"'"'
	    #
	    for ( @params ) {
		if ( /^export (.*?)='(.*'"'"')$/ ) {
		    $params{$variable=$1}="${2}\n";		    
		} elsif ( /^export (.*?)='(.*)'$/ ) {
		    $params{$1} = $2 unless $1 eq '_';
		} elsif ( /^export (.*?)='(.*)$/ ) {
		    $params{$variable=$1}="${2}\n";
		} else {
		    if ($variable) {
			s/'$//;
			$params{$variable} .= $_;
		    } else {
			warning_message "Param line ($_) ignored" unless $bug++;
		    }				
		}
	    }
	}

	if ( $debug ) {
	    print "PARAMS:\n";
	    my $value;
	    while ( ($variable, $value ) = each %params ) {
		print "   $variable='$value'\n";
	    }
	}
    }
}

#
# - Read the shorewall.conf file
# - Read the capabilities file, if any
# - establish global hashes %config , %globals and %capabilities
#
sub get_configuration( $ ) {

    my $export = $_[0];

    $globals{EXPORT} = $export;

    our ( $once, @originalinc );

    @originalinc = @INC unless $once++;

    ensure_config_path;

    get_params;

    process_shorewall_conf;

    ensure_config_path;

    @INC = @originalinc;

    unshift @INC, @config_path;

    default 'PATH' , '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin';
    #
    # get_capabilities requires that the true settings of these options be established
    #
    default 'MODULE_PREFIX', 'o gz ko o.gz ko.gz';
    default_yes_no 'LOAD_HELPERS_ONLY'          , '';

    get_capabilities( $export );

    $globals{STATEMATCH} = '-m conntrack --ctstate' if have_capability 'CONNTRACK_MATCH';

    if ( my $rate = $config{LOGLIMIT} ) {
	my $limit;

	if ( $rate =~ /^[sd]:/ ) {
	    require_capability 'HASHLIMIT_MATCH', 'Per-ip log rate limiting' , 's';

	    $limit = "-m hashlimit ";

	    my $match = have_capability( 'OLD_HL_MATCH' ) ? 'hashlimit' : 'hashlimit-upto';
	    my $units;

	    if ( $rate =~ /^[sd]:((\d+)(\/(sec|min|hour|day))):(\d+)$/ ) {
		fatal_error "Invalid rate ($1)" unless $2;
		fatal_error "Invalid burst value ($5)" unless $5;

		$limit .= "--$match $1 --hashlimit-burst $5 --hashlimit-name lograte --hashlimit-mode ";
		$units = $4;
	    } elsif ( $rate =~ /^[sd]:((\d+)(\/(sec|min|hour|day))?)$/ ) {
		fatal_error "Invalid rate ($1)" unless $2;
		$limit .= "--$match $1 --hashlimit-name lograte --hashlimit-mode ";
		$units = $4;
	    } else {
		fatal_error "Invalid rate ($rate)";
	    }

	    $limit .= $rate =~ /^s:/ ? 'srcip ' : 'dstip ';

	    if ( $units && $units ne 'sec' ) {
		my $expire = 60000; # 1 minute in milliseconds

		if ( $units ne 'min' ) {
		    $expire *= 60; #At least an hour
		    $expire *= 24 if $units eq 'day';
		}

		$limit .= "--hashlimit-htable-expire $expire ";
	    }
	} elsif ( $rate =~ /^((\d+)(\/(sec|min|hour|day))):(\d+)$/ ) {
	    fatal_error "Invalid rate ($1)" unless $2;
	    fatal_error "Invalid burst value ($5)" unless $5;
	    $limit = "-m limit --limit $1 --limit-burst $5 ";
	} elsif ( $rate =~ /^(\d+)(\/(sec|min|hour|day))?$/ )  {
	    fatal_error "Invalid rate (${1}${2})" unless $1;
	    $limit = "-m limit --limit $rate ";
	} else {
	    fatal_error "Invalid rate ($rate)";
	}

	$globals{LOGLIMIT} = $limit;

	warning_message "LOGRATE Ignored when LOGLIMIT is specified"  if $config{LOGRATE};
	warning_message "LOGBURST Ignored when LOGLIMIT is specified" if $config{LOGBURST};

    } elsif ( $config{LOGRATE} || $config{LOGBURST} ) {
	if ( defined $config{LOGRATE} ) {
	    fatal_error"Invalid LOGRATE ($config{LOGRATE})" unless $config{LOGRATE}  =~ /^\d+\/(second|minute)$/;
	}

	if ( defined $config{LOGBURST} ) {
	    fatal_error"Invalid LOGBURST ($config{LOGBURST})" unless $config{LOGBURST} =~ /^\d+$/;
	}

	$globals{LOGLIMIT}  = '-m limit ';
	$globals{LOGLIMIT} .= "--limit $config{LOGRATE} "        if defined $config{LOGRATE};
	$globals{LOGLIMIT} .= "--limit-burst $config{LOGBURST} " if defined $config{LOGBURST};
    } else {
	$globals{LOGLIMIT} = '';
    }

    check_trivalue ( 'IP_FORWARDING', 'on' );

    my $val;

    if ( have_capability( 'KERNELVERSION' ) < 20631 ) {
	check_trivalue ( 'ROUTE_FILTER',  '' );
    } else {
	$val = $config{ROUTE_FILTER};
	if ( defined $val ) {
	    if ( $val =~ /\d+/ ) {
		fatal_error "Invalid value ($val) for ROUTE_FILTER" unless $val < 3;
	    } else {
		check_trivalue( 'ROUTE_FILTER', '' );
	    }
	} else {
	    check_trivalue( 'ROUTE_FILTER', '' );
	}
    }

    if ( $family == F_IPV6 ) {
	$val = $config{ROUTE_FILTER};
	fatal_error "ROUTE_FILTER=$val is not supported in IPv6" if $val && $val ne 'off';
    }

    if ( $family == F_IPV4 ) {
	check_trivalue ( 'LOG_MARTIANS',  'on' );
    } else {
	check_trivalue ( 'LOG_MARTIANS',  'off' );
	fatal_error "LOG_MARTIANS=On is not supported in IPv6" if $config{LOG_MARTIANS} eq 'on';
    }

    default 'STARTUP_LOG'   , '';

    if ( $config{STARTUP_LOG} ne '' ) {
	if ( defined $config{LOG_VERBOSITY} ) {
	    if ( $config{LOG_VERBOSITY} eq '' ) {
		$config{LOG_VERBOSITY} = 2;
	    } else {
		my $val = numeric_value( $config{LOG_VERBOSITY} );
		fatal_error "Invalid LOG_VERBOSITY ($config{LOG_VERBOSITY} )" unless defined( $val ) && ( $val >= -1 ) && ( $val <= 2 );
		$config{STARTUP_LOG} = '' if $config{LOG_VERBOSITY} < 0;
		$config{LOG_VERBOSITY} = $val;
	    }
	} else {
	    $config{LOG_VERBOSITY} = 2;
	}
    } else {
	$config{LOG_VERBOSITY} = -1;
    }

    default_yes_no 'ADD_IP_ALIASES'             , 'Yes';
    default_yes_no 'ADD_SNAT_ALIASES'           , '';
    default_yes_no 'DETECT_DNAT_IPADDRS'        , '';
    default_yes_no 'DETECT_DNAT_IPADDRS'        , '';
    default_yes_no 'CLEAR_TC'                   , $family == F_IPV4 ? 'Yes' : '';

    if ( defined $config{CLAMPMSS} ) {
	default_yes_no 'CLAMPMSS'                   , '' unless $config{CLAMPMSS} =~ /^\d+$/;
    } else {
	$config{CLAMPMSS} = '';
    }

    unless ( $config{ADD_IP_ALIASES} || $config{ADD_SNAT_ALIASES} ) {
	$config{RETAIN_ALIASES} = '';
    } else {
	default_yes_no_ipv4 'RETAIN_ALIASES'             , '';
    }

    default_yes_no 'ADMINISABSENTMINDED'        , '';
    default_yes_no 'BLACKLISTNEWONLY'           , '';
    default_yes_no 'DISABLE_IPV6'               , '';

    unsupported_yes_no_warning 'DYNAMIC_ZONES';
    unsupported_yes_no         'BRIDGING';
    unsupported_yes_no_warning 'RFC1918_STRICT';

    default_yes_no 'SAVE_IPSETS'                , '';
    default_yes_no 'STARTUP_ENABLED'            , 'Yes';
    default_yes_no 'DELAYBLACKLISTLOAD'         , '';
    default_yes_no 'MAPOLDACTIONS'              , 'Yes';

    warning_message 'DELAYBLACKLISTLOAD=Yes is not supported by Shorewall ' . $globals{VERSION} if $config{DELAYBLACKLISTLOAD};

    default_yes_no 'LOGTAGONLY'                 , ''; $globals{LOGTAGONLY} = $config{LOGTAGONLY};

    default_yes_no 'FASTACCEPT'                 , '';

    fatal_error "BLACKLISTNEWONLY=No may not be specified with FASTACCEPT=Yes" if $config{FASTACCEPT} && ! $config{BLACKLISTNEWONLY};

    default_yes_no 'IMPLICIT_CONTINUE'          , '';
    default_yes_no 'HIGH_ROUTE_MARKS'           , '';
    default_yes_no 'TC_EXPERT'                  , '';
    default_yes_no 'USE_ACTIONS'                , 'Yes';

    warning_message 'USE_ACTIONS=No is not supported by Shorewall ' . $globals{VERSION} unless $config{USE_ACTIONS};

    default_yes_no 'EXPORTPARAMS'               , '';
    default_yes_no 'EXPAND_POLICIES'            , '';
    default_yes_no 'KEEP_RT_TABLES'             , '';
    default_yes_no 'DELETE_THEN_ADD'            , 'Yes';
    default_yes_no 'AUTO_COMMENT'               , 'Yes';
    default_yes_no 'MULTICAST'                  , '';
    default_yes_no 'MARK_IN_FORWARD_CHAIN'      , '';
    default_yes_no 'MANGLE_ENABLED'             , have_capability 'MANGLE_ENABLED' ? 'Yes' : '';
    default_yes_no 'NULL_ROUTE_RFC1918'         , '';
    default_yes_no 'USE_DEFAULT_RT'             , '';
    default_yes_no 'RESTORE_DEFAULT_ROUTE'      , 'Yes';
    default_yes_no 'AUTOMAKE'                   , '';
    default_yes_no 'WIDE_TC_MARKS'              , '';
    default_yes_no 'TRACK_PROVIDERS'            , '';
    default_yes_no 'ACCOUNTING'                 , 'Yes';
    default_yes_no 'OPTIMIZE_ACCOUNTING'        , '';
    default_yes_no 'DYNAMIC_BLACKLIST'          , 'Yes';
    default_yes_no 'REQUIRE_INTERFACE'          , '';
    default_yes_no 'FORWARD_CLEAR_MARK'         , have_capability 'MARK' ? 'Yes' : '';
    default_yes_no 'COMPLETE'                   , '';

    require_capability 'MARK' , 'FOREWARD_CLEAR_MARK=Yes', 's', if $config{FORWARD_CLEAR_MARK};

    numeric_option 'TC_BITS',          $config{WIDE_TC_MARKS} ? 14 : 8 , 0;
    numeric_option 'MASK_BITS',        $config{WIDE_TC_MARKS} ? 16 : 8,  $config{TC_BITS};
    numeric_option 'PROVIDER_BITS' ,   8, 0;
    numeric_option 'PROVIDER_OFFSET' , $config{HIGH_ROUTE_MARKS} ? $config{WIDE_TC_MARKS} ? 16 : 8 : 0, 0;

    if ( $config{PROVIDER_OFFSET} ) {
	$config{PROVIDER_OFFSET} = $config{MASK_BITS} if $config{PROVIDER_OFFSET} < $config{MASK_BITS};
	fatal_error 'PROVIDER_BITS + PROVIDER_OFFSET > 31' if $config{PROVIDER_BITS} + $config{PROVIDER_OFFSET} > 31;
	$globals{EXCLUSION_MASK} = 1 << ( $config{PROVIDER_OFFSET} + $config{PROVIDER_BITS} );
    } elsif ( $config{MASK_BITS} >= $config{PROVIDER_BITS} ) {
	$globals{EXCLUSION_MASK} = 1 << $config{MASK_BITS};
    } else {
	$globals{EXCLUSION_MASK} = 1 << $config{PROVIDER_BITS};
    }

    $globals{TC_MAX}                 = make_mask( $config{TC_BITS} );
    $globals{TC_MASK}                = make_mask( $config{MASK_BITS} );
    $globals{PROVIDER_MIN}           = 1 << $config{PROVIDER_OFFSET};
    $globals{PROVIDER_MASK}          = make_mask( $config{PROVIDER_BITS} ) << $config{PROVIDER_OFFSET};

    if ( ( my $userbits = $config{PROVIDER_OFFSET} - $config{TC_BITS} ) > 0 ) {
	$globals{USER_MASK} = make_mask( $userbits ) << $config{TC_BITS};
    } else {
	$globals{USER_MASK} = 0;
    }

    if ( defined ( $val = $config{ZONE2ZONE} ) ) {
	fatal_error "Invalid ZONE2ZONE value ( $val )" unless $val =~ /^[2-]$/;
    } else {
	$config{ZONE2ZONE} = '2';
    }

    default 'BLACKLIST_DISPOSITION'    , 'DROP';

    default_log_level 'BLACKLIST_LOGLEVEL',  '';
    default_log_level 'MACLIST_LOG_LEVEL',   '';
    default_log_level 'TCP_FLAGS_LOG_LEVEL', '';
    default_log_level 'RFC1918_LOG_LEVEL',   '';

    warning_message "RFC1918_LOG_LEVEL=$config{RFC1918_LOG_LEVEL} ignored. The 'norfc1918' interface/host option is no longer supported" if $config{RFC1918_LOG_LEVEL};

    default_log_level 'SMURF_LOG_LEVEL',     '';
    default_log_level 'LOGALLNEW',           '';

    $globals{MACLIST_TARGET} = 'reject';

    if ( $val = $config{MACLIST_DISPOSITION} ) {
	unless ( $val eq 'REJECT' ) {
	    if ( $val eq 'DROP' ) {
		$globals{MACLIST_TARGET} = 'DROP';
	    } elsif ( $val eq 'ACCEPT' ) {
		$globals{MACLIST_TARGET} = 'RETURN';
	    } else {
		fatal_error "Invalid value ($config{MACLIST_DISPOSITION}) for MACLIST_DISPOSITION"
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

    default 'TC_ENABLED' , $family == F_IPV4 ? 'Internal' : 'no';

    $val = "\L$config{TC_ENABLED}";

    if ( $val eq 'yes' ) {
	my $file = find_file 'tcstart';
	fatal_error "Unable to find tcstart file" unless -f $file;
	$globals{TC_SCRIPT} = $file;
    } elsif ( $val eq 'internal' ) {
	$config{TC_ENABLED} = 'Internal';
     } elsif ( $val eq 'shared' ) {
	$config{TC_ENABLED} = 'Shared';
    } elsif ( $val eq 'simple' ) {
	$config{TC_ENABLED} = 'Simple';
    } else {
	fatal_error "Invalid value ($config{TC_ENABLED}) for TC_ENABLED" unless $val eq 'no';
	$config{TC_ENABLED} = '';
    }

    if ( $config{TC_ENABLED} ) {
	fatal_error "TC_ENABLED=$config{TC_ENABLED} is not allowed with MANGLE_ENABLED=No" unless $config{MANGLE_ENABLED};
	require_capability 'MANGLE_ENABLED', "TC_ENABLED=$config{TC_ENABLED}", 's';
    }

    if ( $val = $config{TC_PRIOMAP} ) {
	my @priomap = split ' ',$val;
	fatal_error "Invalid TC_PRIOMAP ($val)" unless @priomap == 16;
	for ( @priomap ) {
	    fatal_error "Invalid TC_PRIOMAP entry ($_)" unless /[1-3]/;
	    $_--;
	}

	$config{TC_PRIOMAP} = join ' ', @priomap;
    } else {
	$config{TC_PRIOMAP} = '1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1';
    }

    default 'RESTOREFILE'           , 'restore';
    default 'IPSECFILE'             , 'zones';
    default 'DROP_DEFAULT'          , 'Drop';
    default 'REJECT_DEFAULT'        , 'Reject';
    default 'QUEUE_DEFAULT'         , 'none';
    default 'NFQUEUE_DEFAULT'       , 'none';
    default 'ACCEPT_DEFAULT'        , 'none';
    default 'OPTIMIZE'              , 0;

    fatal_error 'IPSECFILE=ipsec is not supported by Shorewall ' . $globals{VERSION} if $config{IPSECFILE} eq 'ipsec';
    fatal_error "Invalid IPSECFILE value ($config{IPSECFILE}"                    unless $config{IPSECFILE} eq 'zones';

    for my $default qw/DROP_DEFAULT REJECT_DEFAULT QUEUE_DEFAULT NFQUEUE_DEFAULT ACCEPT_DEFAULT/ {
	$config{$default} = 'none' if "\L$config{$default}" eq 'none';
    }

    $val = numeric_value $config{OPTIMIZE};

    fatal_error "Invalid OPTIMIZE value ($config{OPTIMIZE})" unless defined( $val ) && $val >= 0 && ( $val & ( 4096 ^ -1 ) ) <= 15;

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

	fatal_error "LOGFORMAT string is longer than 29 characters ($val)" if length $result > 29;

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

	cleanup, die $@ if $@;

	fatal_error "LOCKFILE=$config{LOCKFILE}: Directory $dir does not exist" unless $export or -d $dir;
    } else {
	$config{LOCKFILE} = '';
    }
}

#
# The values of the options in @propagateconfig are copied to the script file in OPTION=<value> format.
#
sub propagateconfig() {
    for my $option ( @propagateconfig ) {
	my $value = $config{$option};
	$value = '' unless defined $value;
	emit "$option=\"$value\"";
    }
}

#
# Add a shell script file to the output script -- Return true if the
# file exists and is not in /usr/share/shorewall/ and is non-empty.
#
sub append_file( $;$$ ) {
    my ( $file, $nomsg, $unindented ) = @_;
    my $user_exit = find_file $file;
    my $result = 0;
    my $save_indent = $indent;
    
    $indent = '' if $unindented;

    unless ( $user_exit =~ m(^/usr/share/shorewall6?/) ) {
	if ( -f $user_exit ) {
	    if ( $nomsg ) {
		#
		# Suppress progress message
		#
		$result = copy1 $user_exit;
	    } else {
		#
		# Include progress message -- Pretend progress_message call was in the file
		#
		$result = 1;
		save_progress_message "Processing $user_exit ...";
		copy1 $user_exit;
	    }
	}
    }

    $indent = $save_indent;

    $result;
}

#
# Run a Perl extension script
#
sub run_user_exit( $ ) {
    my $chainref = $_[0];
    my $file = find_file $chainref->{name};

    if ( -f $file ) {
	progress_message2 "Processing $file...";

	my $command = qq(package Shorewall::User;\nno strict;\n# line 1 "$file"\n) . `cat $file`;

	unless (my $return = eval $command ) {
	    fatal_error "Couldn't parse $file: $@" if $@;

	    unless ( defined $return ) {
		fatal_error "Couldn't do $file: $!" if $!;
		fatal_error "Couldn't do $file";
	    }

	    fatal_error "$file returned a false value";
	}
    }
}

sub run_user_exit1( $ ) {
    my $file = find_file $_[0];

    if ( -f $file ) {
	progress_message2 "Processing $file...";
	#
	# File may be empty -- in which case eval would fail
	#
	push_open $file;

	if ( read_a_line1 ) {
	    close_file;

	    my $command = qq(package Shorewall::User;\n# line 1 "$file"\n) . `cat $file`;

	    unless (my $return = eval $command ) {
		fatal_error "Couldn't parse $file: $@" if $@;

		unless ( defined $return ) {
		    fatal_error "Couldn't do $file: $!" if $!;
		    fatal_error "Couldn't do $file";
		}

		fatal_error "$file returned a false value";
	    }
	} else {
	    pop_open;
	}
    }
}

sub run_user_exit2( $$ ) {
    my ($file, $chainref) = ( find_file $_[0], $_[1] );

    if ( -f $file ) {
	progress_message2 "Processing $file...";
	#
	# File may be empty -- in which case eval would fail
	#
	push_open $file;

	if ( read_a_line1 ) {
	    close_file;

	    unless (my $return = eval `cat $file` ) {
		fatal_error "Couldn't parse $file: $@" if $@;

		unless ( defined $return ) {
		    fatal_error "Couldn't do $file: $!" if $!;
		    fatal_error "Couldn't do $file";
		}

		fatal_error "$file returned a false value";
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

	emit "[ -n \"\${$option:=$value}\" ]" if defined $value && $value ne '';
    }

    sub conditionally_add_option1( $ ) {
	my $option = $_[0];

	my $value = $config{$option};

	emit "$option=\"$value\"" if $value;
    }

    create_temp_aux_config;

    my $date = localtime;

    emit "#\n# Shorewall auxiliary configuration file created by Shorewall version $globals{VERSION} - $date\n#";

    for my $option qw(VERBOSITY LOGFILE LOGFORMAT IPTABLES IP6TABLES IP TC IPSET PATH SHOREWALL_SHELL SUBSYSLOCK LOCKFILE RESTOREFILE) {
	conditionally_add_option $option;
    }

    conditionally_add_option1 'TC_ENABLED';

    my $fn = find_file 'scfilter';

    if ( -f $fn ) {
	emit( '',
	      'show_connections_filter() {' );
	push_indent;
	append_file( $fn,1 ) or emit 'cat -';
	pop_indent;
	emit '}';
    }

    $fn = find_file 'dumpfilter';

    if ( -f $fn ) {
	emit( '',
	      'dump_filter() {' );
	push_indent;
	append_file( $fn,1 ) or emit 'cat -';
	pop_indent;
	emit '}';
    }

    finalize_aux_config;
}

END {
    cleanup;
}

1;
