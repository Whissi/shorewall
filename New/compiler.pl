#! /usr/bin/perl -w

use strict;
#
# IPSEC Option types
#
use constant { NOTHING    => 'NOTHING',
	       NUMERIC    => '0x[\da-fA-F]+|\d+',
	       NETWORK    => '\d+.\d+.\d+.\d+(\/\d+)?',
	       IPSECPROTO => 'ah|esp|ipcomp',
	       IPSECMODE  => 'tunnel|transport'
	       };
#
# Misc Globals
#
my %env  =   ( SHAREDIR => '/usr/share/shorewall' ,
	       CONFDIR =>  '/etc/shorewall',
	       LOGPARMS => '',
	       VERSION =>  '3.9.0',
	       );
#
# From shorewall.conf file
#
my %config = ( STARTUP_ENABLED => undef,
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
	       #
	       # Packet Disposition
	       #
	       MACLIST_DISPOSITION => undef,
	       TCP_FLAGS_DISPOSITION => undef,
	       BLACKLIST_DISPOSITION => undef,
	       ORIGINAL_POLICY_MATCH => undef,
	       );
#
# From parsing the capabilities file
#
my %capabilities = 
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

my $line; # Current config file line

my @zones;
my %zones;
my %zone_children;
my %zone_parents;
my %zone_hosts;
my %zone_options;
my %zone_interfaces;
my %zone_exclusions;
my $firewall_zone;

my @interfaces;
my %interfaces;
my %interface_broadcast;
my %interface_options;
my %interface_zone;

my @policy_chains;
my %chain_table = ( raw    => {} , 
		    mangle => {},
		    nat    => {},
		    filter => {} );

my $nat_table    = $chain_table{nat};
my $mangle_table = $chain_table{mangle};
my $filter_table = $chain_table{filter};

my $comment = '';

my %indent;

my $exclseq = 0;

my $iprangematch = 0;
my $ipsetmatch   = 0;

my $section  = 'ESTABLISHED';

my %sections = ( ESTABLISHED => 0,
		 RELATED     => 0,
		 NEW         => 0
		 );

my $sectioned = 0;

my @allipv4 = ( '0.0.0.0/0' );

use constant { ALLIPv4 => '0.0.0.0/0' };

my @rfc1918_networks = ( "10.0.0.0/24", "172.16.0.0/12", "192.168.0.0/16" );

use constant { STANDARD => 1,
	       NATRULE  => 2,
	       BUILTIN  => 4,
	       NONAT    => 8,
	       NATONLY  => 16,
	       REDIRECT => 32,
	       ACTION   => 64,
	       MACRO    => 128,
	       LOGRULE  => 256,
	   };

my %all_actions = ('ACCEPT'       => STANDARD,
		   'ACCEPT+'      => STANDARD  + NONAT,
		   'ACCEPT!'      => STANDARD,
		   'NONAT'        => STANDARD  + NONAT,
		   'DROP'         => STANDARD,
		   'DROP!'        => STANDARD,
		   'REJECT'       => STANDARD,
		   'REJECT!'      => STANDARD,
		   'DNAT'         => NATRULE,
		   'DNAT-'        => NATRULE  + NATONLY,
		   'REDIRECT'     => NATRULE  + REDIRECT,
		   'REDIRECT-'    => NATRULE  + REDIRECT + NATONLY,
		   'LOG'          => STANDARD + LOGRULE,
		   'CONTINUE'     => STANDARD,
		   'QUEUE'        => STANDARD,
		   'SAME'         => NATRULE,
		   'SAME-'        => NATRULE  + NATONLY,
		   'dropBcast'    => BUILTIN  + ACTION,
		   'allowBcast'   => BUILTIN  + ACTION,
		   'dropNotSyn'   => BUILTIN  + ACTION,
		   'rejNotSyn'    => BUILTIN  + ACTION,
		   'dropInvalid'  => BUILTIN  + ACTION,
		   'allowInvalid' => BUILTIN  + ACTION,
		   'allowinUPnP'  => BUILTIN  + ACTION,
		   'forwardUPnP'  => BUILTIN  + ACTION,
		   'Limit'        => BUILTIN  + ACTION,
		   );

my %actions;

my %usedactions;

my %logactionchains;

my %macros;

my %default_actions = ( DROP     => 'none' ,
			REJECT   => 'none' ,
			ACCEPT   => 'none' ,
			QUEUE    => 'none' );

sub ensure_config_path() {
    $config{CONFIG_PATH}  = $env{CONFDIR} . $env{SHAREDIR} unless $config{CONFIG_PATH};

    if ( $ENV{SHOREWALL_DIR} ) {
	( my ( $firstdir ) = $config{CONFIG_PATH} ) =~ s/:.*//; 
	$config{CONFIG_PATH} = "$ENV{SHOREWALL_DIR}:" . $config{CONFIG_PATH} if $ENV{SHOREWALL_DIR} ne $firstdir;
    }
}
 	
#
# Search the CONFIG_PATH for the passed file
#
sub find_file($) 
{
    my $filename=$_[0];

    if ( $filename =~ '/.*' ) {
	return $filename;
    }

    my $directory;

    for $directory ( split ':', $config{CONFIG_PATH} ) {
	my $file = "$directory/$filename";
	return $file if -f $file;
    }

    "$env{CONFDIR}/$filename";
}
    
#
# Issue a Warning Message
#
sub warning_message 
{
    print STDERR "   WARNING: @_\n";
}

#
# Fatal Error
#
sub fatal_error
{
    print STDERR "   ERROR: @_\n";
    exit 2;
}

sub progress_message {
    if ( $ENV{VERBOSE} > 1 ) {
	my $ts = '';
	$ts = ( localtime ) . ' ' if $ENV{TIMESTAMP};
	print "${ts}@_\n";
    }
}

sub progress_message2 {
    if ( $ENV{VERBOSE} > 0 ) {
	my $ts = '';
	$ts = ( localtime ) . ' ' if $ENV{TIMESTAMP};
	print "${ts}@_\n";
    }
}

sub progress_message3 {
    if ( $ENV{VERBOSE} >= 0 ) {
	my $ts = '';
	$ts = ( localtime ) . ' ' if $ENV{TIMESTAMP};
	print "${ts}@_\n";
    }
}

sub default ( $$ ) {
    my ( $var, $val ) = @_;

    $config{$var} = $val unless defined $config{$var};
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

#
# Parse the passed option list and return a reference to a hash as follows:
#
# => mss   = <MSS setting>
# => ipsec = <-m policy arguments to match options>
#
sub parse_zone_option_list($)
{
    my %validoptions = ( mss          => NUMERIC,
		         strict       => NOTHING,
		         next         => NOTHING,
		         reqid        => NUMERIC,
		         spi          => NUMERIC,
		         proto        => IPSECPROTO,
		         mode         => IPSECMODE,
		         "tunnel-src" => NETWORK,
		         "tunnel-dst" => NETWORK,
		       );

    #
    # Hash of options that have their own key in the returned hash.
    #
    my %key = ( mss => "mss" );

    my $list=$_[0];
    my %h;
    my $options = '';
    my $fmt;

    if ( $list ne '-' ) {
	for my $e ( split ',' , $list ) {
	    my $val    = undef;
	    my $invert = '';

	    if ( $e =~ /([\w-]+)!=(.+)/ ) {
		$val    = $2;
		$e      = $1;
		$invert = '! ';
	    } elsif ( $e =~ /([\w-]+)=(.+)/ ) {
		$val = $2;
		$e   = $1;
	    }
	    
	    $fmt = $validoptions{$e};

	    fatal_error "Invalid Option ($e)" unless $fmt;
	    
	    if ( $fmt eq NOTHING ) {
		fatal_error "Option $e does not take a value: Zone \"$line\"" if defined $val;
	    } else {
		fatal_error "Invalid value ($val) for option \"$e\" in Zone \"$line\"" unless $val =~ /^($fmt)$/;
	    }
	    
	    if ( $key{$e} ) {
		$h{$e} = $val;
	    } else {
		$options .= $invert;
		$options .= "--$e ";
		$options .= "$val "if defined $val;
	    }
	}
    }

    $h{ipsec} = $options ? "$options " : '';

    \%h;   
}

#
# Parse the zones file. Generates the following information:
#
#     zones         => <zone type>
#     zone_children => <Ref to Empty List>
#     zone_parents  => <List of parent zones>
#     zone_options  => in_out => mss   => <mss value>
#                             => ipsec => "ipsec selection string"
#                             => routeback => 1
#                     in     ...
#                     out    ...
#     
sub determine_zones()
{
    my @z;

    open ZONES, "$ENV{TMP_DIR}/zones" or fatal_error "Unable to open stripped zones file: $!";

    while ( $line = <ZONES> ) {
	chomp $line;
	$line =~ s/\s+/ /g;
	
	my @parents;

	my ($zone, $type, $options, $in_options, $out_options, $extra) = split /\s+/, $line;

	fatal_error("Invalid zone file entry: $line") if $extra;

	if ( $zone =~ /(\w+):([\w,]+)/ ) {
	    $zone = $1;
	    @parents = split ',', $2;

	    for my $p ( @parents ) {
		fatal_error "Invalid Parent List ($2)" unless $p;
		fatal_error "Unknown parent zone ($p)" unless $zones{$p};
		fatal_error 'Subzones of firewall zone not allowed' if $zones{$p} eq 'firewall';
		push @{$zone_children{$p}}, $zone;
	    }
	}

	fatal_error "Invalid zone name: $zone" unless "\L$zone" =~ /^[a-z]\w*$/ && length $zone <= $env{MAXZONENAMELENGTH};
	fatal_error "Invalid zone name: $zone" if $zone =~ /^all2|2all$/;
	
	$zone_parents{$zone}    = \@parents;
	$zone_exclusions{$zone} = [];
	
	fatal_error( "Duplicate zone name: $zone\n" ) if $zones{$zone};

	$type = "ipv4" unless $type;

	if ( $type =~ /ipv4/i ) {
	    $zones{$zone} = 'ipv4';
	} elsif ( $type =~ /^ipsec4?$/i ) {
	    $zones{$zone} = 'ipsec4';
	} elsif ( $type eq 'firewall' ) {
	    fatal_error 'Firewall zone may not be nested' if @parents;
	    fatal_error "Only one firewall zone may be defined: $zone" if $firewall_zone;
	    $firewall_zone = $zone;
	    $zones{$zone} = "firewall";
	} elsif ( $type eq '-' ) {
	    $type = 'ipv4';
	} else {
	    fatal_error "Invalid zone type ($type)" ;
	}

	my %zone_hash;

	$zone_hash{in_out}   = parse_zone_option_list( $options || '');
	$zone_hash{in}       = parse_zone_option_list( $in_options || '');
	$zone_hash{out}      = parse_zone_option_list( $out_options || '');
	$zone_hash{complex}  = ($type eq 'ipsec4' || $options || $in_options || $out_options ? 1 : 0);

	$zone_options{$zone} = \%zone_hash;

	$zone_interfaces{$zone} = {};
	$zone_children{$zone}   = [];

	push @z, $zone;
    }

    close ZONES;

    my $pushed = 1;
    my %ordered;

    while ( $pushed )
    {
	$pushed = 0;
      ZONE:
	for my $zone ( @z ) {
	    unless ( $ordered{$zone} ) {
		for my $child ( @{$zone_children{$zone}} ) {
		    next ZONE unless $ordered{$child};
		}
		$ordered{$zone} = 1;
		push @zones, $zone;
		$pushed = 1; 
	    }
	}
    }
}

#
# Add an entry to the zone_hosts hash.
#
#   %zone_hosts -> zone => (ipsec|ipv4) => <interface> => <Array> => options => <option1> => value1
#                                                                               <option2> => value2
#                                                                 => hosts   =  <network>
#
sub add_group_to_zone($$$$$)
{
    my ($zone, $type, $interface, $networks, $options) = @_;
    my $typeref;
    my $interfaceref;
    my $arrayref;
    my $zonetype = $zones{$zone};
    my $ifacezone = $interface_zone{$interface};

    $zone_interfaces{$zone}{$interface} = 1;

    my @newnetworks;
    my @exclusions;
    my $new = \@newnetworks;
    my $switched = 0;

    $ifacezone = '' unless defined $ifacezone;

    for my $host ( @$networks ) {
	if ( $host =~ /^!.*/ ) {
	    fatal_error "Invalid host group: @$networks" if $switched;
	    $switched = 1;
	    $new = \@exclusions;
	}

	unless ( $switched ) {
	    if ( $type eq $zonetype ) {
		fatal_error "Duplicate Host Group ($interface:$host) in zone $zone" if $ifacezone eq $zone;
		$ifacezone = $zone if $host eq ALLIPv4;
	    }
	}
	    
	push @$new, $switched ? "$interface:$host" : $host;
    }

    $zone_options{$zone}{in_out}{routeback} = 1 if $options->{routeback};

    $typeref      = ( $zone_hosts{$zone}          || ( $zone_hosts{$zone} = {} ) );
    $interfaceref = ( $typeref->{$type}           || ( $interfaceref = $typeref->{$type} = {} ) );
    $arrayref     = ( $interfaceref->{$interface} || ( $interfaceref->{$interface} = [] ) );

    $zone_options{$zone}{complex} = 1 if @$arrayref || ( @newnetworks > 1 );

    my %h;

    $h{options} = $options;
    $h{hosts}   = \@newnetworks;
    $h{ipsec}   = $type eq 'ipsec' ? 'ipsec' : 'none';

    push @{$zone_exclusions{$zone}}, @exclusions;
    push @{$arrayref}, \%h;
}

#
# Parse the interfaces file. Generates the following information
#
# @interfaces          => File-ordered list of interfaces from interfaces file.
# %interfaces          => Interface name without trailing '+'; this hash is extended as names are found to match wildcards.
# %interface_broadcast => List of broadcast addresses (or detect).
# %interface_options   => Option1 => Value1
#                      => Option2 => Value2
#                         ...
# %interface_zone      => Zone associated with interface, if any.
#	 
sub validate_interfaces_file()
{
    my %validoptions = (
			arp_filter => 1,
			arp_ignore => 1,
			blacklist => 1,
			detectnets => 1,
			dhcp => 1,
			maclist => 1,
			logmartians => 1,
			norfc1918 => 1,
			nosmurfs => 1,
			proxyarp => 1,
			routeback => 1,		
			routefilter => 1,
			sourceroute => 1,
			tcpflags => 1,
			upnp => 1,
			);
    
    open INTERFACES, "$ENV{TMP_DIR}/interfaces" or fatal_error "Unable to open stripped interfaces file: $!";

    while ( $line = <INTERFACES> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ($zone, $interface, $networks, $options, $extra) = split /\s+/, $line;

	fatal_error "Invalid interfaces entry: $line" if $extra;

	if ( $zone eq '-' ) {
	    $zone = '';
	} else {
	    my $type = $zones{$zone};

	    fatal_error "Unknown zone ($zone)" unless $type;
	    fatal_error "Firewall zone not allowed in ZONE column of interface record" if $type eq 'firewall';
	}

	$networks = '' if $networks eq '-';
	$options  = '' if $networks eq '-';

	fatal_error "Duplicate Interface ($interface)" if $interfaces{$interface};

	fatal_error "Invalid Interface Name: $interface" if $interface =~ /:|^\+$/;

	( $interfaces{$interface} = $interface ) =~ s/\+$// ;

	if ( $networks && $networks ne '-' )
	{
	    my @broadcast = split ',', $networks; 
	    $interface_broadcast{$interface} = \@broadcast;
	}

	if ( $options )
	{
	    my %options;

	    for my $option (split ',', $options )
	    {
		next if $option eq '-';

		if ( $validoptions{$option} ) {
		    $options{$option} = 1;
		} elsif ( $option =~ /^arp_filter=([1-3,8])$/ ) {
		    $options{arp_filter} = $1;
		} else {
		    warning_message("Invalid Interface option ($option) ignored");
		}
	    }

	    $zone_options{$zone}{in_out}{routeback} = 1 if $options{routeback};

	    $interface_options{$interface} = \%options;
	}

	push @interfaces, $interface;

	add_group_to_zone( $zone, $zones{$zone}, $interface, \@allipv4, {} ) if $zone;
	
    	$interface_zone{$interface} = $zone; #Must follow the call to add_group_to_zone()

	progress_message "   Interface \"$line\" Validated";

    }		
		
    close INTERFACES;
}

#
# Dump the tables built by validate_interface_file
#
sub dump_interface_info()
{
    print "\n";

    for my $interface ( @interfaces ) {
	print "Interface: $interface\n";
	my $root = $interfaces{$interface};
	print "   Root = $root\n";
	my $bcastref = $interface_broadcast{$interface};
	if ( $bcastref ) {
	    my $spaces = '';
	    print '   Broadcast: ';
	    for my $addr (@$bcastref) {
		print "${spaces}${addr}\n";
		$spaces = '              ';
	    }
	}

	my $options = $interface_options{$interface};

	if ( $options ) {
	    print '     Options: ';
	    my $spaces = '';
	    for my $option ( keys %$options ) {
		my $val = ${$options}{$option};
		print "${spaces}${option} = $val\n";
		$spaces = '              ';
	    }
	}

	my $zone = $interface_zone{$interface};
	print "        zone: $zone\n" if $zone;
    }

    print "\n";
}

#
# Returns true if passed interface matches an entry in /etc/shorewall/interfaces
#
# If the passed name matches a wildcard, a entry for the name is added in %interfaces to speed up validation of other references to that name.
#
sub known_interface($)
{
    my $interface = $_[0];

    return 1 if exists $interfaces{$interface};

    for my $i ( @interfaces ) {
	my $val = $interfaces{$i};
	next if $val eq $i;
	my $len = length $val;
	if ( substr( $interface, 0, $len ) eq $val ) {
	    #
	    # Cache this result for future reference
	    #
	    $interfaces{$interface} = undef;
	    return 1;
	}
    }

    0;
}

#
# Validates the hosts file. Generates entries in %zone_hosts as described above.
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

	my $type = $zones{$zone};

	fatal_error "Unknown ZONE ($zone)" unless $type;
	fatal_error 'Firewall zone not allowed in ZONE column of hosts record' if $type eq 'firewall';

	my $interface;

	if ( $hosts =~ /^([\w.@%-]+):(.*)$/ ) {
	    $interface = $1;
	    $hosts = $2;
	    $zone_options{$zone}{complex} = 1 if $hosts =~ /^\+/;
	    fatal_error "Unknown interface ($interface)" unless $interfaces{$interface};
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
		    $zone_options{$zone}{complex} = 1;
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

#
# Dump out all information about zones.
#
sub dump_zone_info() 
{
    print "\n";

    for my $zone ( @zones )
    {
	my $typeref   = $zone_hosts{$zone};
	my $type      = $zones{$zone};
	my $optionref = $zone_options{$zone};
	my $groupref;    

	print "Zone: $zone\n";
	
	my $zonetype = $zones{$zone};

	print "   Type: $zonetype\n";
	print "   Parents:\n";

	my $parentsref = $zone_parents{$zone};

	for my $parent ( @$parentsref ) {
	    print "      $parent\n";
	}

	if ( %$optionref ) {
	    print "   Options:\n";

	    for my $opttype ( keys %$optionref ) {
		if ( $opttype eq 'complex' ) {
		    print "      Complex: $optionref->{$opttype}\n";
		} else {
		    print "      $opttype:\n";
		    for my $option ( keys %{$optionref->{$opttype}}) {
			my $val = $optionref->{$opttype}{$option};
			print "         $option=$val\n";
		    }
		}
	    }
	}
	
	if ( $typeref ) {
	    print "   Host Groups:\n";
	    for my $type ( sort keys %$typeref ) {
		my $interfaceref = $typeref->{$type};
		
		print "      Type: $type\n";
	
		for my $interface ( sort keys %$interfaceref ) {
		    my $arrayref = $interfaceref->{$interface};
		    
		    print "         Interface: $interface\n";
		    
		    for my $groupref ( @$arrayref ) {
			my $hosts     = $groupref->{hosts};
			my $options   = $groupref->{options};
			my $ipsec     = $groupref->{ipsec};
			
			if ( $ipsec ) {
			    print "            Ipsec: $ipsec\n" ;
			}

			if ( $hosts ) {
			    my $space = '';
			    print "            Hosts: " ;
			    for my $host ( @{$hosts} ) {
				print "${space}${host}\n";
				$space = '            ';
			    }
			}       
			
			if ( $options ) {
			    print "            Options: ";
			    for my $option (sort keys %$options ) {
				print "$option ";
			    }
			    print "\n";
			}
		    }
		}
	    }
	} else {
	    #
	    # Empty ?
	    #
	    print "   ***Empty***\n" if $zonetype ne 'firewall';
	}
    }

    print "\n";
}

#
# Report about zones.
#
sub zone_report() 
{
    for my $zone ( @zones )
    {
	my $hostref   = $zone_hosts{$zone};
	my $type      = $zones{$zone};
	my $optionref = $zone_options{$zone};
	my $groupref;    

	progress_message "   $zone ($type)";

	if ( $hostref ) {
	    for my $type ( sort keys %$hostref ) {
		my $interfaceref = $hostref->{$type};
		
		for my $interface ( sort keys %$interfaceref ) {
		    my $arrayref = $interfaceref->{$interface};
		    for my $groupref ( @$arrayref ) {
			my $hosts     = $groupref->{hosts};
			if ( $hosts ) {
			    my $grouplist = join ',', ( @$hosts );
			    progress_message "      $interface:$grouplist";
			}
		    }

		}
	    }
	} else {
	    print STDERR "      *** $zone is an EMPTY ZONE ***\n" if $type ne 'firewall';
	}
    }
}

#
# Create a new chain and return a reference to it.
#
sub new_chain($$)
{
    my ($table, $chain) = @_;
    my %ch;
    my @rules;
    
    $ch{name} = $chain;
    $ch{log} = 1 if $env{LOGRULENUMBERS};
    $ch{rules} = \@rules;
    $ch{table} = $table;
    $chain_table{$table}{$chain} = \%ch;
    \%ch;
}

#
# Create a chain if it doesn't exist already
#
sub ensure_chain($$)
{
    my ($table, $chain) = @_;

    my $ref =  $chain_table{$table}{$chain};
    
    return $ref if $ref;

    new_chain $table, $chain;
}

sub finish_chain_section( $$ );

#
# Create a filter chain if necessary. Optionally populate it with the appropriate ESTABLISHED,RELATED rule(s) and perform SYN rate limiting.
#
sub ensure_filter_chain( $$ )
{
    my ($chain, $populate) = @_;

    my $chainref = $filter_table->{$chain};

    unless ( $chainref ) {
	$chainref    = new_chain 'filter' , $chain;
    }
    
    if ( $populate and ! $chainref->{referenced} ) {
	if ( $section eq 'NEW' or $section eq 'DONE' ) {
	    finish_chain_section $chainref , 'ESTABLISHED,RELATED';
	} elsif ( $section eq 'ESTABLISHED' ) {
	    finish_chain_section $chainref , 'ESTABLISHED';
	}
    }

    $chainref->{referenced} = 1;
	    
    $chainref;
}

#
# Add a builtin chain
#
sub new_builtin_chain($$$)
{
    my $chainref = new_chain $_[0],$_[1];
    $chainref->{referenced} = 1;
    $chainref->{policy}     = $_[2];
    $chainref->{builtin}    = 1;
}

sub new_standard_chain($) {
    my $chainref = new_chain 'filter' ,$_[0];
    $chainref->{referenced} = 1;
    $chainref;
}    

#
# Add all builtin chains to the chain table
#
#
sub initialize_chain_table()
{
    for my $chain qw/OUTPUT PREROUTING/ {
	new_builtin_chain 'raw', $chain, 'ACCEPT';
    }

    for my $chain qw/INPUT OUTPUT FORWARD/ {
	new_builtin_chain 'filter', $chain, 'DROP';
    }

    for my $chain qw/PREROUTING POSTROUTING OUTPUT/ {
	new_builtin_chain 'nat', $chain, 'ACCEPT';
    }

    for my $chain qw/PREROUTING INPUT FORWARD OUTPUT POSTROUTING/ {
	new_builtin_chain 'mangle', $chain, 'ACCEPT';
    }
	
    if ( $capabilities{MANGLE_FORWARD} ) {
	for my $chain qw/ FORWARD POSTROUTING / {
	    new_builtin_chain 'mangle', $chain, 'ACCEPT';
	}
    }
}

#
# Dump the contents of the Chain Table
#
sub dump_chain_table()
{
    print "\n";

    for my $table qw/filter nat mangle/ {
	print "Table: $table\n";

	for my $chain ( sort keys %{$chain_table{$table}} ) {
	    my $chainref = $chain_table{$table}{$chain};
	    print "   Chain $chain:\n";
	    
	    if ( $chainref->{is_policy} ) {
		print "      This is a policy chain\n";
		my $val = $chainref->{is_optional} ? 'Yes' : 'No';
		print "         Optional:  $val\n";
		print "         Log Level: $chainref->{loglevel}\n" if $chainref->{loglevel};
		print "         Syn Parms: $chainref->{synparams}\n" if $chainref->{synparams};
		print "         Default:   $chainref->{default}\n" if $chainref->{default};
	    }
		
	    print "      Policy chain: $chainref->{policychain}{name}\n" if $chainref->{policychain} ;
	    print "      Policy: $chainref->{policy}\n"                  if $chainref->{policy};
	    print "      Referenced\n" if $chainref->{referenced};

	    if ( @{$chainref->{rules}} ) {
		print "      Rules:\n";
		for my $rule (  @{$chainref->{rules}} ) {
		    print "         $rule\n";
		}
	    }   
	}
    }
}
	
#
# This function determines the logging for a subordinate action or a rule within a subordinate action
#
sub merge_levels ($$) {
    my ( $superior, $subordinate ) = @_;

    my @supparts = split /:/, $superior;
    my @subparts = split /:/, $subordinate;

    my $subparts = @subparts;

    my $target   = $subparts[0];

    push @subparts, '' while @subparts < 3;   #Avoid undefined values

    my $level = $supparts[1];
    my $tag   = $supparts[2];

    if ( @supparts == 3 ) {
	return "$target:none!:$tag"   if $level eq 'none!';
	return "$target:$level:$tag"  if $level =~ /!$/;
	return $subordinate           if $subparts >= 2;
	return "$target:$level";
    } 

    if ( @supparts == 2 ) {
	return "$target:none!"        if $level eq 'none!';
	return "$target:$level"       if ($level =~ /!$/) || ($subparts < 2);
    }

    $subordinate;
}

#
# Return ( action, level[:tag] ) from passed full action 
#
sub split_action ( $ ) {
    my $action = $_[0];
    my @a = split /:/ , $action;
    fatal_error "Invalid ACTION $action in rule \"$line\"" if ( $action =~ /::/ ) || ( @a > 3 );
    ( shift @a, join ":", @a );
}

#
# Get Action Type
#
sub isolate_action( $ ) {
    my ( $action , $undef ) = split '/', $_[0];
    $all_actions{$action} || '';
}

# This function substitutes the second argument for the first part of the first argument up to the first colon (":")
#
# Example:
#
#         substitute_action DNAT PARAM:info:FTP
#
#         produces "DNAT:info:FTP"
#
sub substitute_action( $$ ) {
    my ( $param, $action ) = @_;

    if ( $action =~ /:/ ) {
	my $logpart = (split_action $action)[1];
	$logpart =~ s!/$!!;
	return "$param:$logpart";
    }

    $param;
}

#
# Define an Action
#
sub new_action( $ ) {

    my $action = $_[0];

    my %h;

    $h{actchain}   = 0;
    $h{requires} = {};
    $actions{$action} = \%h;
}

#
# Add an entry to the requiredby hash
#
sub add_requiredby ( $$ ) {
    my ($requires , $requiredby ) = @_;
    $actions{$requiredby}{requires}{$requires} = 1;
}

#
# Create and record a log action chain -- Log action chains have names
# that are formed from the action name by prepending a "%" and appending
# a 1- or 2-digit sequence number. In the functions that follow,
# the CHAIN, LEVEL and TAG variable serves as arguments to the user's
# exit. We call the exit corresponding to the name of the action but we
# set CHAIN to the name of the iptables chain where rules are to be added.
# Similarly, LEVEL and TAG contain the log level and log tag respectively.
#
# For each <action>, we maintain two variables:
#
#    <action>_actchain - The action chain number.
#    <action>_chains   - List of ( level[:tag] , chainname ) pairs
#
# The maximum length of a chain name is 30 characters -- since the log
# action chain name is 2-3 characters longer than the base chain name,
# this function truncates the original chain name where necessary before
# it adds the leading "%" and trailing sequence number.#
# 
sub createlogactionchain( $$ ) {
    my ( $action, $level ) = @_;
    my $chain = $action;
    my $actionref = $actions{$action};
    my $chainref;

    $chain = substr $chain, 0, 28 if ( length $chain ) > 28;
	
    while ( $chain_table{'%' . $chain . $actionref->{actchain}} ) {
	$chain = substr $chain, 0, 27 if ++($actionref->{actchain}) == 10 and length $chain == 28;
    }

    $actionref = new_action $action unless $actionref;

    $actionref->{actchain}++;

    $level = 'none' unless $level;

    $logactionchains{"$action:$level"} = new_chain 'filter', '%' . $chain . $actionref->{actchain};

    #
    # Fixme -- action file
    #
}

#
# Create an action chain and run it's associated user exit
#
sub createactionchain( $ ) {
    my ( $action , $level ) = split_action $_[0];

    if ( $level ) {
	if ( $level eq 'none' ) {
	    $logactionchains{"$action:none"} = new_chain 'filter', $action;
	} else {
	    createlogactionchain $action , $level;
	}
    } else {
	$logactionchains{"$action:none"} = new_chain 'filter', $action;
    }
}

#
# Find the chain that handles the passed action. If the chain cannot be found,
# a fatal error is generated and the function does not return.
#
sub find_logactionchain( $ ) {
    my $fullaction = $_[0];
    my ( $action, $level ) = split_action $fullaction;

    $level = 'none' unless $level;

    fatal_error "Fatal error in find_logactionchain" unless $logactionchains{"$action:$level"};
}

#
# Combine fields from a macro body with one from the macro invocation
#
sub merge_macro_source_dest( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( $invocation ) {
	if ( $body ) {
	    return $body if $invocation eq '-';
	    return "$body:$invocation" if $invocation =~ /.*?\.*?\.|^\+|^~|^!~/;
	    return "$invocation:$body";
	}
    }
    
    $body || '';
}

sub merge_macro_column( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( $invocation ) {
	return ( $body || '') if $invocation eq '-';
	$invocation || '';
    } else {
	$body || '';
    }
}

#
# Create a new policy chain and return a reference to it.
#
sub new_policy_chain($$$)
{
    my ($chain, $policy, $optional) = @_;

    my $chainref = new_chain 'filter', $chain; 
    
    $chainref->{is_policy}   = 1;
    $chainref->{policy}      = $policy;
    $chainref->{is_optional} = $optional;
    $chainref->{policychain} = $chainref;
    
    $filter_table->{$chain} = $chainref;
}

#
# Set the passed chain's policychain and policy to the passed values.
#
sub set_policy_chain($$$)
{
    my ($chain1, $chainref, $policy) = @_;

    my $chainref1 = $filter_table->{$chain1};
    $chainref1 = new_chain 'filter', $chain1 unless $chainref1;
    unless ( $chainref1->{policychain} ) {
	$chainref1->{policychain} = $chainref;
	$chainref1->{policy} = $policy;
    }
}

#
# Display a policy
#
sub print_policy($$$$)
{
    my ( $source, $dest, $policy , $chain ) = @_;
    progress_message "   Policy for $source to $dest is $policy using chain $chain" 
	unless ( $source eq $dest ) || ( $source eq 'all' ) || ( $dest eq 'all' );
}

#
# Try to find a macro file -- RETURNS false if the file doesn't exist or MACRO if it does.
# If the file exists, the macro is entered into the 'all_actions' table and the fully-qualified
# name of the file is stored in the 'macro' table.
#
sub find_macro( $ )
{
    my $macro = $_[0];
    my $macrofile = find_file "macro.$macro";

    if ( -f $macrofile ) {
	$macros{$macro} = $macrofile;
	$all_actions{$macro} = MACRO;
    }
}    

#
# Process the policy file
#
sub validate_policy()
{
    my %validpolicies = ( 
			  ACCEPT => undef,
			  REJECT => undef,
			  DROP   => undef,
			  CONTINUE => undef,
			  QUEUE => undef,
			  NONE => undef
			  );
    
    my %map = ( DROP_DEFAULT   => 'DROP' ,
		REJECT_DEFAULT => 'REJECT' ,
		ACCEPT_DEFAULT => 'ACCEPT' ,
		QUEUE_DEFAULT  => 'QUEUE' );
	  
    my $zone;

    use constant { OPTIONAL => 1 };

    for my $option qw/DROP_DEFAULT REJECT_DEFAULT ACCEPT_DEFAULT QUEUE_DEFAULT/ {
	my $action = $config{$option};
	next if $action eq 'none';
	my $actiontype = $all_actions{$action};
  
	if ( defined $actiontype ) {
	    fatal_error "Invalid setting ($action) for $option" unless $actiontype & ACTION;
	} else {
	    fatal_error "Default Action/Macro $option=$action not found";
	}

	unless ( $usedactions{$action} ) {
	    $usedactions{$action} = 1;
	    createactionchain $action;
	}

	$default_actions{$map{$option}} = $action;
    }
    
    for $zone ( @zones ) {
	push @policy_chains, ( new_policy_chain "${zone}2${zone}", 'ACCEPT', OPTIONAL );

	if ( $config{IMPLICIT_CONTINUE} && ( @{$zone_parents{$zone}} ) ) {
	    for my $zone1 ( @zones ) {
		next if $zone eq $zone1;
		push @policy_chains, ( new_policy_chain "${zone}2${zone1}", 'CONTINUE', OPTIONAL );
		push @policy_chains, ( new_policy_chain "${zone1}2${zone}", 'CONTINUE', OPTIONAL );
	    }
	}
    }

    open POLICY, "$ENV{TMP_DIR}/policy" or fatal_error "Unable to open stripped policy file: $!";

    while ( $line = <POLICY> ) {
	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $client, $server, $policy, $loglevel, $synparams , $extra ) = split /\s+/, $line;
	
	fatal_error "Invalid policy file entry: $line" if $extra;

	$loglevel  = '' unless defined $loglevel;
	$synparams = '' unless defined $synparams;
	$loglevel  = '' if $loglevel  eq '-';
	$synparams = '' if $synparams eq '-';
	
	my $clientwild = ( "\L$client" eq 'all' );

	fatal_error "Undefined zone $client" unless $clientwild || $zones{$client};

	my $serverwild = ( "\L$server" eq 'all' );

	fatal_error "Undefined zone $server" unless $serverwild || $zones{$server};

	( $policy , my $default ) = split /:/, $policy;

	if ( "\L$policy" eq 'none' ) {
	    $default = 'none';
	} elsif ( $default ) {
	    my $defaulttype = $all_actions{$default};
	    
	    if ( $defaulttype & ACTION ) {
		unless ( $usedactions{$default} ) {
		    $usedactions{$default} = 1;
		    createactionchain $default;
		}
	    } else {
		fatal_error "Unknown Default Action ($default) in policy \"$line\"";
	    }	    
	} else {
	    $default = $default_actions{$policy} || '';
	}

	fatal_error "Invalid policy $policy" unless exists $validpolicies{$policy};

	if ( $policy eq 'NONE' ) {
	    fatal_error "$client, $server, $policy, $loglevel, $synparams: NONE policy not allowed to/from firewall zone"
		if ( $zones{$client} eq 'firewall' ) || ( $zones{$server} eq 'firewall' );
	    fatal_error "$client $server $policy $loglevel $synparams: NONE policy not allowed with \"all\""
		if $clientwild || $serverwild;
	}
	
	my $chain = "${client}2${server}";
	my $chainref;

	if ( defined $filter_table->{$chain} ) {
	    $chainref = $filter_table->{$chain};
	    
	    if ( $chainref->{is_policy} ) {
		if ( $chainref->{is_optional} ) {
		    $chainref->{is_optional} = 0;
		} else {
		    fatal_error "Duplicate policy: $client $server $policy";
		}
	    } else {
		$chainref->{is_policy} = 1;
		$chainref->{policy} = $policy;
		$chainref->{policy_chain} = $chainref;
		push @policy_chains, ( $chainref );
	    }
	} else {
	    $chainref = new_policy_chain $chain, $policy, 0;
	    push @policy_chains, ( $chainref );
	}

	$chainref->{loglevel}  = $loglevel  if $loglevel;
	$chainref->{synparams} = $synparams if $synparams;
	$chainref->{default}   = $default   if $default;

	if ( $clientwild ) {
	    if ( $serverwild ) {
		for my $zone ( @zones , 'all' ) {
		    for my $zone1 ( @zones , 'all' ) {
			set_policy_chain "${zone}2${zone1}", $chainref, $policy;
			print_policy $zone, $zone1, $policy, $chain;
		    }
		}
	    } else {
		for my $zone ( @zones ) {
		    set_policy_chain "${zone}2${server}", $chainref, $policy;
		    print_policy $zone, $server, $policy, $chain;
		}
	    }
	} elsif ( $serverwild ) {
	    for my $zone ( @zones , 'all' ) {
		set_policy_chain "${client}2${zone}", $chainref, $policy;
		print_policy $client, $zone, $policy, $chain;
	    }
	    
	} else {
	    print_policy $client, $server, $policy, $chain;
	}
    }

    close POLICY;	    
}

#
# Add a rule to a chain. Arguments are:
#
#    Chain reference , Rule
#
sub add_rule($$)
{
    my ($chainref, $rule) = @_;
    
    $rule .= " -m comment --comment \"$comment\"" if $comment;

    push @{$chainref->{rules}}, $rule;

    $chainref->{referenced} = 1;

    $iprangematch = 0;
    $ipsetmatch   = 0;
}

#
# Insert a rule into a chain. Arguments are:
#
#    Table , Chain , Rule Number, Rule
#
sub insert_rule($$$)
{
    my ($chainref, $number, $rule) = @_;
    
    $rule .= "-m comment --comment \"$comment\"" if $comment;

    splice @{$chainref->{rules}}, $number - 1, 0,  $rule;

    $chainref->{referenced} = 1;
    
    $iprangematch = 0;
    $ipsetmatch   = 0;
}

#
# Form the name of a chain. 
#
sub chain_base($) {
    my $chain = $_[0];

    $chain =~ s/^@/at_/;
    $chain =~ s/[.\-%@]/_/g;
    $chain;
}

#
# Forward Chain for an interface
#
sub forward_chain($)
{
    chain_base $_[0] . '_fwd';
}

#
# Input Chain for an interface
#
sub input_chain($)
{
    chain_base $_[0] . '_in';
}

#
# Output Chain for an interface
#
sub output_chain($)
{
    chain_base $_[0] . '_out';
}

#
# Masquerade Chain for an interface
#
sub masq_chain($)
{
    chain_base $_[0] . '_masq';
}

#
# Syn_chain
#
sub syn_chain ( $ ) {
    '@' . $_[0];
}
#
# MAC Verification Chain for an interface
#
sub mac_chain( $ )
{
    chain_base $_[0] . '_mac';
}

sub macrecent_target($)
{
     $config{MACLIST_TTL} ? chain_base $_[0] . '_rec' : 'RETURN';
}

#
# Functions for creating dynamic zone rules
#
sub dynamic_fwd( $ )
{
    chain_base $_[0] . '_dynf';
}

sub dynamic_in( $ )
{
    chain_base $_[0] . '_dyni';
}

sub dynamic_out( $ ) # $1 = interface
{
    chain_base $_[0] . '_out';
}

sub dynamic_chains( $ ) #$1 = interface
{
    my $c = chain_base $_[0];

    [ $c . '_dyni' , $c . '_dynf' , $c . '_dyno' ];
}

#
# DNAT Chain from a zone
#
sub dnat_chain( $ )
{
    chain_base $_[0] . '_dnat';
}

#
# SNAT Chain to an interface
#
sub snat_chain( $ )
{
    chain_base $_[0] . '_snat';
}

#
# ECN Chain to an interface
#
sub ecn_chain( $ )
{
    chain_base $_[0] . '_ecn';
}

#
# First chains for an interface
#
sub first_chains( $ ) #$1 = interface
{
    my $c = chain_base $_[0];

    [ $c . '_fwd', $c . '_in' ];
}

#
# Handle parsing of PROTO, DEST PORT(S) , SOURCE PORTS(S). Returns the appropriate match string.
#
sub do_proto( $$$ )
{
    my ($proto, $ports, $sports ) = @_;

    my $output = '';
    
    $proto  = '' unless defined $proto;
    $ports  = '' unless defined $ports;
    $sports = '' unless defined $sports;

    $proto  = '' if $proto  eq '-';
    $ports  = '' if $ports  eq '-';
    $sports = '' if $sports eq '-';

    if ( $proto ) {
	if ( $proto =~ /^(tcp|udp|6|17)$/i ) {
	    $output = "-p $proto ";
	    if ( $ports ) {
		my @ports = split /,/, $ports;
		my $count = @ports; 

		if ( $count > 1 ) {
		    fatal_error "Port list requires Multiport support in your kernel/iptables: $ports" unless $capabilities{MULTIPORT};
		    fatal_error "Port range in a list requires Extended Multiport Support in your kernel/iptables: $ports" unless $capabilities{XMULTIPORT};
		    
		    for my $port ( @ports ) {
			$count++ if $port =~ /:/;
		    }
 
		    fatal_error "Too many entries in port list: $ports" if $count > 15;

		    $output .= "-m multiport --dports $ports ";
		}  else {
		    $output .= "--dport $ports ";
		}
	    }
			
	    if ( $sports ) {
		my @ports = split /,/, $sports;
		my $count = @ports; 

		if ( $count > 1 ) {
		    fatal_error "Port list requires Multiport support in your kernel/iptables: $sports" unless $capabilities{MULTIPORT};
		    fatal_error "Port range in a list requires Extended Multiport Support in your kernel/iptables: $sports" unless $capabilities{XMULTIPORT};
		    
		    for my $port ( @ports ) {
			$count++ if $port =~ /:/;
		    }
 
		    fatal_error "Too many entries in port list: $sports" if $count > 15;

		    $output .= "-m multiport --sports $sports ";
		}  else {
		    $output .= "--sport $sports ";
		}
	    }
	} elsif ( $proto =~ /^(icmp|1)$/i ) {
	    $output .= "-p icmp --icmp-type $ports " if $ports;
	    fatal_error 'SOURCE PORT(S) not permitted with ICMP' if $sports;
	} elsif ( $proto =~ /^(ipp2p(:(tcp|udp|all)))?$/i ) {
	    fatal_error 'PROTO = ipp2p requires IPP2P match support in your kernel/iptables' unless $capabilities{IPP2P};
	    $proto = $2 ? $3 : 'tcp';
	    $ports = 'ipp2p' unless $ports;
	    $output .= "-p $proto -m ipp2p --$ports ";
	}
    } elsif ( $ports || $sports ) {
	fatal_error "SOURCE/DEST PORT(S) not allowed without PROTO, rule \"$line\""
    }

    $output;
}

sub mac_match( $ ) {
    my $mac = $_[0];

    $mac =~ s/^(!?)~//;
    $mac =~ s/^!// if my $invert = $1 ? '! ' : ''; 
    $mac =~ s/-/:/g;

    "--match mac --mac-source ${invert}$mac ";
}

#
# Mark validatation functions
#
sub verify_mark( $ ) {
    my $mark  = $_[0];
    my $limit = $config{HIGH_ROUTE_MARKS} ? 0xFF : 0xFFFF;

    fatal_error "Invalid Mark or Mask value: $mark" 
	unless "\L$mark" =~ /$(0x[a-f0-9]+|0[0-7]*|[0-9]*)$/ and $mark <= $limit;
}

sub verify_small_mark( $ ) {
    verify_mark ( (my $mark) = $_[0] );
    fatal_error "Mark value ($mark) too large" if $mark > 0xFF;
}

sub validate_mark( $ ) {
    for ( split '/', $_[0] ) {
	verify_mark $_;
    }
}

#
# Generate an appropriate -m [conn]mark match string for the contents of a MARK column
#

sub do_test ( $$ )
{
    my ($testval, $mask) = @_;
    
    return '' unless $testval and $testval ne '-';

    my $invert = $testval =~ s/^!// ? '! ' : '';
    my $match =  $testval =~ s/:C$// ? '-m connmark ' : '-m mark ';
    
    $testval .= '/0xFF' unless ( $testval =~ '/' );

    "${invert}$match $testval ";
}
    

#
# Create a "-m limit" match for the passed LIMIT/BURST
#
sub do_ratelimit( $ ) {
    my $rate = $_[0];

    return '' unless $rate and $rate ne '-';
    
    if ( $rate =~ /^([^:]+):([^:]+)$/ ) {
	"-m limit --limit $1 --limit-burst $2 ";
    } else {
	"-m limit --limit $rate ";
    }
}

#
# Create a "-m owner" match for the passed USER/GROUP
#
sub do_user( $ ) {
    my $user = $_[0];
    my $rule = ' -m owner';

    return '' unless $user and $user ne '-';

    if ( $user =~ /^(!)?(.*)\+(.*)$/ ) {
	$rule .= "! --cmd-owner $2 " if $2;
	$user = "!$1";
    } elsif ( $user =~ /^(.*)\+(.*)$/ ) {
	$rule .= "--cmd-owner $2 " if $2;
	$user = $1;
    }
	
    if ( $user =~ /^!(.*):(.*)$/ ) {
	$rule .= "! --uid-owner $1 " if $1;
	$rule .= "! --gid-owner $2 " if $2;
    } elsif ( $user =~ /^(.*):(.*)$/ ) {
	$rule .= "--uid-owner $1 " if $1;
	$rule .= "--gid-owner $2 " if $2;
    } elsif ( $user =~ /^!/ ) {
	$rule .= "! --uid-owner $user ";
    } else {
	$rule .= "--uid-owner $user ";
    }

    $rule;
}
	
#
# Avoid generating a second '-m iprange' in a single rule.
#
sub iprange_match() {
    my $match = '';
    unless ( $iprangematch ) {
	$match = '-m iprange ';
	$iprangematch = 1;
    }

    $match;
}

#
# Match a Source. Currently only handles IP addresses and ranges
#
sub match_source_net( $ ) {
    my $net = $_[0];
    
    if ( $net =~ /^(!?).*\..*\..*\..*-.*\..*\..*\..*/ ) {
	$net =~ s/!// if my $invert = $1 ? '! ' : '';

	iprange_match . "${invert}--src-range $net ";
    } elsif ( $net =~ /^(!?)~(.*)$/ ) {
	( $net = $2 ) =~ s/-/:/g;
	"-m mac --mac-source $1 $net "
    } elsif ( $net =~ /^!/ ) {
	$net =~ s/!//;
	"-s ! $net ";
    } else {
	$net eq ALLIPv4 ? '' : "-s $net ";
    }
}

#
# Match a Source. Currently only handles IP addresses and ranges
#
sub match_dest_net( $ ) {
    my $net = $_[0];
    
    if ( $net =~ /^(!?).*\..*\..*\..*-.*\..*\..*\..*/ ) {
	$net =~ s/!// if my $invert = $1 ? '! ' : '';

	iprange_match . "${invert}--src-range $net ";
    } elsif ( $net =~ /^!/ ) {
	$net =~ s/!//;
	"-d ! $net ";
    } else {
	$net eq ALLIPv4 ? '' : "-d $net ";
    }
}

#
# Match original destination
#
sub match_orig_dest ( $ ) {
    my $net = $_[0];

    return '' if $net eq ALLIPv4;
    
    if ( $net =~ /^!/ ) {
	$net =~ s/!//;
	"-m conntrack --ctorigdst ! $net ";
    } else {
	$net eq ALLIPv4 ? '' : "-m conntrack --ctorigdst $net ";
    }
}


#
# Match Source IPSEC
#
sub match_ipsec_in( $$ ) {
    my ( $zone , $hostref ) = @_;
    my $match = '-m policy --dir in --pol ';
    my $optionsref = $zone_options{$zone};

    if ( $zones{$zone} eq 'ipsec4' ) {
	$match .= "ipsec $optionsref->{in_out}{ipsec}$optionsref->{in}{ipsec}";
    } elsif ( $capabilities{POLICY_MATCH} ) { 
	$match .= "$hostref->{ipsec} $optionsref->{in_out}{ipsec}$optionsref->{in}{ipsec}";
    } else {
	'';
    }
}
    
#
# Match Dest IPSEC
#
sub match_ipsec_out( $$ ) {
    my ( $zone , $hostref ) = @_;
    my $match = '-m policy --dir out --pol ';
    my $optionsref = $zone_options{$zone};

    if ( $zones{$zone} eq 'ipsec4' ) {
	$match .= "ipsec $optionsref->{in_out}{ipsec}$optionsref->{out}{ipsec}";
    } elsif ( $capabilities{POLICY_MATCH} ) { 
	$match .= "$hostref->{ipsec} $optionsref->{in_out}{ipsec}$optionsref->{out}{ipsec}"
    } else {
	'';
    }
}
    
#
# Generate a log message
#
sub log_rule_limit( $$$$$$$$ ) {
    my ($level, $chainref, $chain, $disposition, $limit, $tag, $command, $predicates ) = @_;

    my $prefix;

    $limit = $env{LOGLIMIT} unless $limit;

    if ( $tag ) {
	if ( $config{LOGTAGONLY} ) {
	    $chain = $tag;
	    $tag   = '';
	} else {
	    $tag .= ' ';
	}
    } else {
	$tag = '' unless defined $tag;
    }

    if ( $env{LOGRULENUMBERS} ) {
	$prefix = (sprintf $config{LOGFORMAT} , $chain , $chainref->{log}++, $disposition ) . $tag;
    } else {
	$prefix = (sprintf $config{LOGFORMAT} , $chain , $disposition) . $tag;
    }

    if ( length $prefix > 29 ) {
	$prefix = substr $prefix, 0, 29;
	warning_message "Log Prefix shortened to \"$prefix\"";
    }

    if ( $level eq 'ULOG' ) {
	$prefix = "-j ULOG $env{LOGPARMS} --ulog-prefix \"$prefix\" ";
    } else {
	$prefix = "-j LOG $env{LOGPARMS} --log-level $level --log-prefix \"$prefix\" ";
    }

    if ( $command eq 'add' ) {
	add_rule ( $chainref, $predicates . $prefix );
    } else {
	insert_rule ( $chainref , 1 , $predicates . $prefix );
    }
}

sub log_rule( $$$$ ) {
    my ( $level, $chainref, $disposition, $predicates ) = @_;

    log_rule_limit $level, $chainref, $chainref->{name} , $disposition, $env{LOGLIMIT}, '', 'add', $predicates;
}
	
#
# This function provides a uniform way to generate rules (something the original Shorewall sorely needed).
# 
sub finish_rule( $$$$$$$$$ )
{
    my ($chainref , $rule, $source, $dest, $origdest, $target, $loglevel , $disposition, $exceptionrule ) = @_;
    my ($iiface, $diface, $inets, $dnets, $iexcl, $dexcl, $onets , $oexcl );

    #
    # Isolate Source Interface, if any
    #
    if ( $source ) {
	if ( $source eq '-' ) {
	    $source = '';
	} elsif ( $source =~ /^([^:]+):([^:]+)$/ ) {
	    $iiface = $1;
	    $inets  = $2;
	} elsif ( $source =~ /\+|~|\..*\./ ) {
	    $inets = $source;
	} else {
	    $iiface = $source;
	}
    } else {
	$source = '';
    }
    #
    # Verify Inteface, if any
    #
    if ( $iiface ) {
	fatal_error "Unknown Interface ($iiface): \"$line\"" unless known_interface $iiface;
	$rule .= "-i $iiface ";
    }

    #
    # Isolate Destination Interface, if any
    #
    if ( $dest ) {
	if ( $dest eq '-' ) {
	    $dest = '';
	} elsif ( $dest =~ /^([^:]+):([^:]+)$/ ) {
	    $diface = $1;
	    $dnets  = $2;
	} elsif ( $dest =~ /\+|~|\..*\./ ) {
	    $dnets = $dest;
	} else {
	    $diface = $dest;
	}
    } else {
	$dest = '';
    }
    #
    # Verify Destination Interface, if any
    #
    if ( $diface ) {
	fatal_error "Unknown Interface ($diface) in rule \"$line\"" unless known_interface $diface;
	$rule .= "-o $diface ";
    }
    
    #
    # Handle Log Level
    #
    my $logtag;

    if ( $loglevel ) {
	( $loglevel, $logtag ) = split /:/, $loglevel;
	
	if ( $loglevel =~ /^none!?$/i ) {
	    return 1 if $disposition eq 'LOG';
	    $loglevel = $logtag = '';
	}
    }

    #
    # Determine if there is Source Exclusion
    #

    if ( $inets ) {
	if ( $inets =~ /^([^!]+)?!([^!]+)$/ ) {
	    $inets = $1;
	    $iexcl = $2;
	} else {
	    $iexcl = '';
	}

	if ( ! $inets ) {
	    my @iexcl = split /,/, $iexcl;
	    if ( @iexcl == 1 ) {
		$rule .= match_source_net "!$iexcl ";
		$iexcl = '';
	    }
	}
    } else {
	$iexcl = '';
    }

    #
    # Determine if there is Destination Exclusion
    #    $dexcl = '';


    if ( $dnets ) {
	if ( $dnets =~ /^([^!]+)?!([^!]+)$/ ) {
	    $dnets = $1;
	    $dexcl = $2;
	} else {
	    $dexcl = '';
	}

	if ( ! $dnets ) {
	    my @dexcl = split /,/, $dexcl;
	    if ( @dexcl == 1 ) {
		$rule .= match_dest_net "!$dexcl ";
		$dexcl = '';
	    }
	}
    } else {
	$dexcl = '';
    }

    if ( $origdest ) {
	if ( $origdest =~ /^([^!]+)?!([^!]+)$/ ) {
	    $onets = $1;
	    $oexcl = $2;
	} else {
	    $oexcl = '';
	}

	if ( ! $onets ) {
	    my @oexcl = split /,/, $oexcl;
	    if ( @oexcl == 1 ) {
		$rule .= "-m conntrack --ctorigdst ! $oexcl ";
		$oexcl = '';
	    }
	}
    } else {
	$oexcl = '';
    }

    $inets = ALLIPv4 unless $inets;
    $dnets = ALLIPv4 unless $dnets;
    $onets = ALLIPv4 unless $onets;

    if ( $iexcl || $dexcl || $oexcl ) {
	#
	# We have non-trivial exclusion -- need to create an exclusion chain
	#
	my $echain = "excl$exclseq";

	$exclseq++;
	
	#
	# Use the current rule and sent all possible matches to the exclusion chain
	#
	for my $onet ( split /,/, $onets ) {
	    $onet = match_orig_dest $onet;
	    for my $inet ( split /,/, $inets ) {
		$inet = match_source_net $inet;
		for my $dnet ( split /,/, $dnets ) {
		    add_rule $chainref, $rule . $inet . ( match_dest_net $dnet ) . $onet . "-j $echain";
		}
	    }
	}
	
	#
	# The final rule in the exclusion chain will not qualify the source or destination 
	#
	$inets = ALLIPv4;
	$dnets = ALLIPv4;
	
	#
	# Create the Exclusion Chain
	#
	my $echainref = new_chain $chainref->{table}, $echain;

	#
	# Generate RETURNs for each exclusion
	#
	for my $net ( split ',', $iexcl ) {
	    add_rule $echainref, ( match_source_net $net ) . '-j RETURN';
	}

	for my $net ( split ',', $dexcl ) {
	    add_rule $echainref, ( match_dest_net $net ) . '-j RETURN';
	}

	for my $net ( split ',', $oexcl ) {
	    add_rule $echainref, ( match_orig_dest $net ) . '-j RETURN';
	}

	#
	# Log rule
	#
	log_rule_limit $loglevel , $echainref , $chainref->{name}, $disposition , '',  $logtag , 'add' , '' if $loglevel;
	#
	# Generate Final Rule
	# 
	add_rule $echainref, $exceptionrule . $target unless $disposition eq 'LOG';

    } else {
	#
	# No exclusions
	#
	for my $onet ( split /,/, $onets ) {
	    $onet = match_orig_dest $onet;
	    for my $inet ( split /,/, $inets ) {
		$inet = match_source_net $inet;
		for my $dnet ( split /,/, $dnets ) {
		    log_rule_limit $loglevel , $chainref , $chainref->{name}, $disposition , '' , $logtag , 'add' , $rule . $inet . match_dest_net( $dnet ) . $onet if $loglevel;
		    add_rule $chainref, $rule . $inet . match_dest_net( $dnet ) . $onet . $target unless $disposition eq 'LOG';
		}
	    }
	}
    }	
}

sub process_tos() {
    my $chain    = 'pretos';
    my $stdchain = 'PREROUTING';

    if ( -s "$ENV{TMP_DIR}/tos" ) {
	progress_message2 'Setting up TOS...';

	my $pretosref = new_chain 'mangle' , 'pretos';
	my $outtosref = new_chain 'mangle' , 'outtos';

	open TOS, "$ENV{TMP_DIR}/tos" or fatal_error "Unable to open stripped tos file: $!";

	while ( $line = <TOS> ) {
	    
	    chomp $line;
	    $line =~ s/\s+/ /g;
	    
	    my ($source, $dest, $proto, $sports, $ports, $extra) = split /\s+/, $line;
	    
	    fatal_error "Invalid tos file entry: \"$line\"" if $extra;
	}

	close TOS;

	$comment = '';
    }
}

#
# Handle IPSEC Options in a masq record
#
sub do_ipsec_options($) 
{
    my %validoptions = ( strict       => NOTHING,
		         next         => NOTHING,
		         reqid        => NUMERIC,
		         spi          => NUMERIC,
		         proto        => IPSECPROTO,
		         mode         => IPSECMODE,
		         "tunnel-src" => NETWORK,
		         "tunnel-dst" => NETWORK,
		       );
    my $list=$_[0];
    my $options = '-m policy';
    my $fmt;

    for my $e ( split ',' , $list ) {
        my $val    = undef;
	my $invert = '';

        if ( $e =~ /([\w-]+)!=(.+)/ ) {
            $val    = $2;
            $e      = $1;
	    $invert = '! ';
        } elsif ( $e =~ /([\w-]+)=(.+)/ ) {
            $val = $2;
            $e   = $1;
        }

	$fmt = $validoptions{$e};

	fatal_error "Invalid Option ($e)" unless $fmt;

	if ( $fmt eq NOTHING ) {
	    fatal_error "Option $e does not take a value" if defined $val;
	} else {
	    fatal_error "Invalid value ($val) for option \"$e\"" unless $val =~ /^($fmt)$/;
	}

	$options .= $invert;
	$options .= "--$e";
	$options .= " $val" if defined $val;
    }

    $options . ' ';
}

#
# Process a single rule from the the masq file
#
sub setup_one_masq($$$$$$)
{
    my ($fullinterface, $networks, $addresses, $proto, $ports, $ipsec) = @_;

    my $rule = '';
    my $pre_nat;
    my $add_snat_aliases = $config{ADD_SNAT_ALIASES};
    my $destnets = '';
    my $target = '-j MASQUERADE ';

    #
    # Take care of missing ADDRESSES column
    #
    $addresses = '' unless defined $addresses;
    $addresses = '' if $addresses eq '-';

    #
    # Handle IPSEC options, if any
    #
    if ( $ipsec && $ipsec ne '-' ) {
	fatal_error "Non-empty IPSEC column requires policy match support in your kernel and iptables"  unless $env{ORIGINAL_POLICY_MATCH};

	if ( $ipsec =~ /^yes$/i ) {
	    $rule .= '-m policy --pol ipsec --dir out ';
	} elsif ( $ipsec =~ /^no$/i ) {
	    $rule .= '-m policy --pol none --dir out ';
	} else {
	    $rule .= do_ipsec_options $ipsec;
	}
    }

    #
    # Leading '+'
    #
    if ( $fullinterface =~ /^\+/ ) {
	$pre_nat = 1;
	$fullinterface =~ s/\+//;
    }

    #
    # Parse the remaining part of the INTERFACE column
    #
    if ( $fullinterface =~ /^([^:]+)::([^:]*)$/ ) {
	$add_snat_aliases = undef;
	$destnets = $2;
	$fullinterface = $1;
    } elsif ( $fullinterface =~ /^([^:]+:[^:]+):([^:]+)$/ ) {
	$destnets = $2;
	$fullinterface = $1;
    } elsif ( $fullinterface =~ /^([^:]+):$/ ) {
	$add_snat_aliases = undef;
	$fullinterface = $1;
    } elsif ( $fullinterface =~ /^([^:]+):([^:]*)$/ ) {
	my ( $one, $two ) = ( $1, $2 );
	if ( $2 =~ /\./ ) {
	    $fullinterface = $one;
	    $destnets = $two;
	}	
    } 

    #
    # Isolate and verify the interface part
    #
    ( my $interface = $fullinterface ) =~ s/:.*//;

    fatal_error "Unknown interface $interface, rule \"$line\"" unless $interfaces{$interface};

    #
    # If there is no source or destination then allow all addresses
    #
    $networks = ALLIPv4 unless $networks;
    $destnets = ALLIPv4 unless $destnets;

    #
    # Handle Protocol and Ports
    #
    $rule .= do_proto $proto, $ports, '';

    #
    # Parse the ADDRESSES column
    #
    if ( $addresses ) {
	if ( $addresses =~ /^SAME:nodst:/ ) {
	    $target = '-j SAME ';
	    $addresses =~ s/.*://;
	    for my $addr ( split /,/, $addresses ) {
		$target .= "--to $addr ";
	    }
	} elsif (  $addresses =~ /^SAME:nodst:/ ) {
	    $target = '-j SAME --nodst ';
	    $addresses =~ s/.*://;
	    for my $addr ( split /,/, $addresses ) {
		$target .= "--to $addr ";
	    }
	} else {
	    my $addrlist = '';
	    for my $addr ( split /,/, $addresses ) {
		if ( $addr =~ /^.*\..*\..*\./ ) {
		    $target = '-j SNAT ';
		    $addrlist .= "--to-source $addr ";
		} else {
		    $addr =~ s/^://;
		    $addrlist .= "--to-ports $addr ";
		} 
	    }

	    $target .= $addrlist;
	}
    }  

    #
    # And Generate the Rule(s)
    #
    finish_rule ensure_chain('nat', $pre_nat ? snat_chain $interface : masq_chain $interface), $rule, $networks, $destnets, '', $target, '', '' , '';

    progress_message "   Masq record \"$line\" compiled";

}

#
# Process the masq file
#
sub setup_masq() 
{
    open MASQ, "$ENV{TMP_DIR}/masq" or fatal_error "Unable to open stripped zones file: $!";

    while ( $line = <MASQ> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ($fullinterface, $networks, $addresses, $proto, $ports, $ipsec, $extra) = split /\s+/, $line;

	if ( $fullinterface eq 'COMMENT' ) {
	    if ( $capabilities{COMMENTS} ) {
		( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		$comment =~ s/\s*$//;
	    } else {
		warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
	    }
	} else {
	    fatal_error "Invalid masq file entry: \"$line\"" if $extra;
	    setup_one_masq $fullinterface, $networks, $addresses, $proto, $ports, $ipsec;
	}
    }

    close MASQ;

    $comment = '';

}

#
# Validate the ALL INTERFACES or LOCAL column in the NAT file
#
sub validate_nat_column( $$ ) {
    my $ref = $_[1];
    my $val = $$ref;

    if ( defined $val ) {
	unless ( ( $val = "\L$val" ) eq 'yes' ) {
	    if ( ( $val eq 'no' ) || ( $val eq '-' ) ) {
		$$ref = '';
	    } else {
		fatal_error "Invalid value ($val) for $_[0] in NAT entry \"$line\"";
	    }
	}
    } else {
	$$ref = '';
    }
}

sub add_nat_rule( $$ ) {
    add_rule ensure_chain( 'nat', $_[0] ) , $_[1];
}
    
#
# Process a record from the NAT file
#
sub do_one_nat( $$$$$ )
{
    my ( $external, $interface, $internal, $allints, $localnat ) = @_;

    my $add_ip_aliases = $config{ADD_IP_ALIASES};

    my $policyin = '';
    my $policyout = '';

    if ( $capabilities{POLICY_MATCH} ) {
	$policyin = ' -m policy --pol none --dir in';
	$policyout =  '-m policy --pol none --dir out';
    }

    fatal_error "Invalid nat file entry \"$line\"" 
	unless defined $interface and defined $internal;

    if ( $add_ip_aliases ) {
	if ( $interface =~ s/:$// ) {
	    $add_ip_aliases = '';
	} else {
	    #
	    # Fixme
	    #
	}
    } else {
	$interface =~ s/:$//;
    }

    validate_nat_column 'ALL INTERFACES', \$allints;
    validate_nat_column 'LOCAL'         , \$localnat;
    
    if ( $allints ) {
	add_nat_rule 'nat_in' ,  "-d $external $policyin  -j DNAT --to-destination $internal";
	add_nat_rule 'nat_out' , "-s $internal $policyout -j SNAT --to-source $external";
    } else {
	add_nat_rule input_chain( $interface ) ,  "-d $external $policyin -j DNAT --to-destination $internal";
	add_nat_rule output_chain( $interface ) , "-s $internal $policyout -j SNAT --to-source $external";
    }
	
    add_nat_rule 'OUTPUT' , "-d $external$policyout -j DNAT --to-destination $internal " if $localnat;

    #
    # Fixme -- add_ip_aliases
    #
    progress_message "   NAT entry \"$line\" compiled";
}

#
# Process NAT file
#
sub setup_nat() {
    
    open NAT, "$ENV{TMP_DIR}/nat" or fatal_error "Unable to open stripped nat file: $!";

    while ( $line = <NAT> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $external, $interface, $internal, $allints, $localnat, $extra ) = split /\s+/, $line;

	if ( $external eq 'COMMENT' ) {
	    if ( $capabilities{COMMENTS} ) {
		( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		$comment =~ s/\s*$//;
	    } else {
		warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
	    }
	} else {
	    fatal_error "Invalid nat file entry: \"$line\"" if $extra;
	    do_one_nat $external, $interface, $internal, $allints, $localnat;
	}
	
    }

    close NAT;

    $comment = '';
}

sub add_rule_pair( $$$$ ) {
    my ($chainref , $predicate , $target , $level ) = @_;

    log_rule $level, $chainref, $target,  , $predicate,  if $level;
    add_rule $chainref , "${predicate}-j $target";
}

#
# Returns reference to array of interfaces with the passed option
#
sub find_interfaces_by_option( $ ) {
    my $option = $_[0];
    my @ints = ();

    for my $interface ( @interfaces ) {
	my $optionsref = $interface_options{$interface};
	if ( $optionsref && $optionsref->{$option} ) {
	    push @ints , $interface;
	}
    }

    \@ints;
}

#
# Returns a reference to a array of host entries. Each entry is a 
# reference to an array containing ( interface , group type {ipsec|none} , network ); 
#
sub find_hosts_by_option( $ ) {
    my $option = $_[0];
    my @hosts;

    for my $zone ( keys %zone_hosts ) {
	while ( my ($type, $interfaceref) = each %{$zone_hosts{$zone}} ) {
	    while ( my ( $interface, $arrayref) = ( each %{$interfaceref} ) ) {
		for my $host ( @{$arrayref} ) {
		    if ( $host->{$option} ) {
			for my $net ( @{$host->{hosts}} ) {
			    push @hosts, [ $interface, $type eq 'ipsec4' ? 'ipsec' : 'none' , $net ];
			}
		    }
		}
	    }
	}
    }

    for my $interface ( @interfaces ) {
	my $optionsref = $interface_options{$interface};
	if ( $optionsref && $optionsref->{$option} ) {
	    push @hosts, [ $interface, 'none', ALLIPv4 ];
	}
    }

    \@hosts;
}

sub setup_rfc1918_filteration( $ ) {

    my $listref      = $_[0];
    my $norfc1918ref = new_standard_chain 'norfc1918';
    my $rfc1918ref   = new_standard_chain 'rfc1918';
    my $chainref     = $norfc1918ref;

    log_rule $config{RFC1918_LOG_LEVEL} , $rfc1918ref , 'DROP' , '';

    add_rule $rfc1918ref , '-j DROP';

    if ( $config{RFC1918_STRICT} ) {
	$chainref = new_standard_chain 'rfc1918d';
    } 

    open RFC, "$ENV{TMP_DIR}/rfc1918" or fatal_error "Unable to open stripped rfc1918 file: $!"; 
	    
    while ( $line = <RFC> ) {
	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $networks, $target, $extra ) = split /\s+/, $line;
	
	my $s_target;

	if ( $target eq 'logdrop' ) {
	    $target   = 'rfc1918';
	    $s_target = 'rfc1918';
	} elsif ( $target eq 'DROP' ) {
	    $s_target = 'DROP';
	} elsif ( $target eq 'RETURN' ) {
	    $s_target = $config{RFC1918_LOG_LEVEL} ? 'rfc1918d' : 'RETURN';
	} else {
	    fatal_error "Invalid target ($target) for $networks";
	}

	for my $network ( split /,/, $networks ) {
	    add_rule $norfc1918ref , match_source_net( $network ) . "-j $s_target";
	    add_rule $chainref , match_orig_dest( $network ) . "-j $target" ;
	}
    }

    close RFC;

    add_rule $norfc1918ref , '-j rfc1918d' if $config{RFC1918_STRICT};

    for my $hostref  ( @$listref ) {
	my $interface = $hostref->[0];
	my $ipsec     = $hostref->[1];
	my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in "  : '';
	for my $chain ( @{first_chains $interface}) {
	    add_rule $filter_table->{$chain} , '-m state --state NEW ' . match_source_net( $hostref->[2]) . "${policy}-j norfc1918";
	}
    }
}

sub setup_syn_flood_chains() {
    for my $chainref ( @policy_chains ) {
	my $limit = $chainref->{synparams};
	if ( $limit ) {
	    my $level = $chainref->{loglevel};
	    ( $limit, my $burst ) = split ':', $limit;
	    $burst = $burst ? "--limit-burst $burst " : '';
	    my $synchainref = new_chain 'filter' , syn_chain $chainref->{name};
	    add_rule $synchainref , "-m limit --limit $limit ${burst}-j RETURN";
	    log_rule_limit $level , $synchainref , $chainref->{name} , 'DROP', '-m limit --limit 5/min --limit-burst 5' , '' , 'add' , '' if $level;
	    add_rule $synchainref, '-j DROP';
	}
    }
}

sub setup_blacklist() {

    my ( $level, $disposition ) = @config{'BLACKLIST_LOGLEVEL', 'BLACKLIST_DISPOSITION' };

    progress_message2 "   Setting up Blacklist...";

    open BL, "$ENV{TMP_DIR}/blacklist" or fatal_error "Unable to open stripped blacklist file: $!";

    progress_message( "      Processing " . find_file 'blacklist' . '...' );

    while ( $line = <BL> ) {

	chomp $line;
	$line =~ s/\s+/ /g;
	
	my ( $networks, $protocol, $ports , $extra ) = split /\s+/, $line;
	
	fatal_error "Invalid blacklist entry: \"$line\"" if $extra;

	finish_rule 
	    ensure_filter_chain( 'blacklst' , 0 ) ,
	    do_proto( $protocol , $ports, '' ) ,
	    $networks ,
	    '' ,
	    '' ,
	    '-j ' . ($disposition eq 'REJECT' ? 'reject' : $disposition),
	    $level ,
	    $disposition ,
	    '';
	
	progress_message "         \"$line\" added to blacklist";
    }

    close BL;

    my $hosts = find_hosts_by_option 'blacklist';

    my $state = $config{BLACKLISTNEWONLY} ? '-m state --state NEW,INVALID ' : '';
    
    for my $hostref ( @$hosts ) {
	my $interface = $hostref->[0];
	my $ipsec     = $hostref->[1];
	my $policy    = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	my $network   = $hostref->[2];
	my $source    = match_source_net $network;
   
	for my $chain ( @{first_chains $interface}) {
	    add_rule $filter_table->{$chain} , "${source}${state}${policy}-j blacklst";
	}

	progress_message "   Blacklisting enabled on ${interface}:${network}";
    }
}

sub add_common_rules() {
    my $interface;
    my $chainref;
    my $level;
    my $target;
    my $rule;
    my $list;
    my $chain;

    my $rejectref = new_standard_chain 'reject';

    new_standard_chain 'dynamic';

    my $state = $config{BLACKLISTNEWONLY} ? '-m state --state NEW,INVALID' : '';

    for $interface ( @interfaces ) {
	for $chain ( input_chain $interface , forward_chain $interface ) {
	    add_rule new_standard_chain( $chain ) , "$state -j dynamic";
	}

	new_standard_chain output_chain( $interface );
    }

    $level = $env{BLACKLIST_LOG_LEVEL} || 'info';

    add_rule_pair new_standard_chain( 'logdrop' ),   ' ' , 'DROP'   , $level ;
    add_rule_pair new_standard_chain( 'logreject' ), ' ' , 'REJECT' , $level ;

    setup_blacklist;

    $list = find_hosts_by_option 'nosmurfs';

    if ( $capabilities{ADDRTYPE} ) {
	$chainref = new_standard_chain 'smurfs';

	add_rule_pair $chainref, '-m addrtype --src-type BROADCAST ', 'DROP', $config{SMURF_LOG_LEVEL} ;
	add_rule_pair $chainref, '-m addrtype --src-type MULTICAST ', 'DROP', $config{SMURF_LOG_LEVEL} ;

	add_rule $rejectref , '-m addrtype --src-type BROADCAST -j DROP';
	add_rule $rejectref , '-m addrtype --src-type MULTICAST -j DROP';
    } elsif ( @$list ) {
	fatal_error "The nosmurfs option requires Address Type Match in your kernel and iptables";
    }
    
    if ( @$list ) {
	progress_message2 '   Adding Anti-smurf Rules';
	for my $hostref  ( @$list ) {
	    $interface = $hostref->[0];
	    my $ipsec  = $hostref->[1];
	    my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    for $chain ( @{first_chains $interface}) {
		add_rule $filter_table->{$chain} , '-m state --state NEW,INVALID ' . match_source_net( $hostref->[2]) . "${policy}-j smurfs";
	    }
	}
    }
		
    add_rule $rejectref , '-p tcp -j REJECT --reject-with tcp-reset';
   
    if ( $capabilities{ENHANCED_REJECT} ) {
	add_rule $rejectref , '-p udp -j REJECT';
	add_rule $rejectref, '-p icmp -j REJECT --reject-with icmp-host-unreachable';
	add_rule $rejectref, '-j REJECT --reject-with icmp-host-prohibited';
    } else {
	add_rule $rejectref , '-j REJECT';
    }

    $list = find_interfaces_by_option 'dhcp';

    if ( @$list ) {
	progress_message2 '   Adding rules for DHCP';

	for $interface ( @$list ) {
	    for $chain ( @{first_chains $interface}) {
		add_rule $filter_table->{$chain} , '-p udp --dport 67:68 -j ACCEPT';
	    }

	    add_rule $filter_table->{forward_chain $interface} , "-p udp -o $interface --dport 67:68 -j ACCEPT" if $interface_options{$interface}{routeback};
	}
    }

    $list = find_hosts_by_option 'norfc1918';

    if ( @$list ) {
	progress_message2 '   Enabling RFC1918 Filtering';

	setup_rfc1918_filteration $list;
    }

    $list = find_hosts_by_option 'tcpflags';

    if ( @$list ) {
	my $disposition;

	progress_message2 '   Compiling TCP Flags checking...';
	
	$chainref = new_standard_chain 'tcpflags';

	if ( $config{TCP_FLAGS_LOG_LEVEL} ) {
	    my $logflagsref = new_standard_chain 'logflags';
	    
	    my $savelogparms = $env{LOGPARMS};

	    $env{LOGPARMS} = "$env{LOGPARMS} --log-ip-options" unless $config{TCP_FLAGS_LOG_LEVEL} eq 'ULOG';
	    
	    log_rule $config{TCP_FLAGS_LOG_LEVEL} , $logflagsref , $config{TCP_FLAGS_DISPOSITION}, '';
	    
	    $env{LOGPARMS} = $savelogparms;
									
	    if ( $config{TCP_FLAGS_DISPOSITION} eq 'REJECT' ) {
		add_rule $logflagsref , '-j REJECT --reject-with tcp-reset';
	    } else {
		add_rule $logflagsref , "-j $config{TCP_FLAGS_DISPOSITION}";
	    }

	    $disposition = 'logflags';
	} else {
	    $disposition = $config{TCP_FLAGS_DISPOSITION};
	}

	add_rule $chainref , "-p tcp --tcp-flags ALL FIN,URG,PSH -j $disposition";
	add_rule $chainref , "-p tcp --tcp-flags ALL NONE        -j $disposition";
	add_rule $chainref , "-p tcp --tcp-flags SYN,RST SYN,RST -j $disposition";
	add_rule $chainref , "-p tcp --tcp-flags SYN,FIN SYN,FIN -j $disposition";
	add_rule $chainref , "-p tcp --syn --sport 0 -j $disposition";

	for my $hostref  ( @$list ) {
	    $interface = $hostref->[0];
	    my $ipsec  = $hostref->[1];
	    my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    for $chain ( @{first_chains $interface}) {
		add_rule $filter_table->{$chain} , '-p tcp ' . match_source_net( $hostref->[2]) . "${policy}-j tcpflags";
	    }
	}
    }

    if ( $config{DYNAMIC_ZONES} ) {
	for $interface ( @interfaces) {
	    for $chain ( @{dynamic_chains $interface} ) {
		new_standard_chain '$chain';
	    }
	}
	
	(new_chain 'nat' , $chain = dynamic_in($interface) )->{referenced} = 1; 
	    
	add_rule $filter_table->{input_chain $interface},  "-j $chain";
	add_rule $filter_table->{forward_chain $interface}, '-j ' . dynamic_fwd $interface;
	add_rule $filter_table->{output_chain $interface},  '-j ' . dynamic_out $interface;
    }	

    $list = find_interfaces_by_option 'upnp';

    if ( @$list ) {
	progress_message2 '   Compiling UPnP';

	(new_chain 'nat', 'UPnP')->{referenced} = 1;

	for $interface ( @$list ) {
	    add_rule $nat_table->{PREROUTING} , "-i $interface -j UPnP";
	}
    }

    setup_syn_flood_chains;
}

#
# Policy Rule application
#
sub policy_rules( $$$$ ) {
    my ( $chainref , $target, $loglevel, $default ) = @_;

    add_rule $chainref, "-j $default" if $default && $default ne 'none';

    log_rule $loglevel , $chainref , $target , '' if $loglevel;

    fatal_error "Null target in policy_rules()" unless $target;

    add_rule $chainref , ( '-j ' . ( $target eq 'REJECT' ? 'reject' : $target ) );
}

sub report_syn_flood_protection() {
    progress_message '      Enabled SYN flood protection';
}

sub default_policy( $$$ ) {
    my $chainref   = $_[0];
    my $policyref  = $chainref->{policychain};
    my $synparams  = $policyref->{synparams};
    my $default    = $policyref->{default};
    my $policy     = $policyref->{policy};
    my $loglevel   = $policyref->{loglevel};

    fatal_error "No default policy for $_[1] to zone $_[2]" unless $policyref;

    if ( $chainref eq $policyref ) {
	policy_rules $chainref , $policy, $loglevel , $default;
    } else {
	if ( $policy eq 'ACCEPT' || $policy eq 'QUEUE' ) {
	    if ( $synparams ) {
		report_syn_flood_protection;
		policy_rules $chainref , $policy , $loglevel , $default;
	    } else {
		add_rule $chainref,  "-j $policyref->{name}";
		$chainref = $policyref;
	    }
	} elsif ( $policy eq 'CONTINUE' ) {
	    report_syn_flood_protection if $synparams;
	    policy_rules $chainref , $policy , $loglevel , $default;
	} else {
	    report_syn_flood_protection if $synparams;
	    add_rule $chainref , "-j $policyref->{name}";
	    $chainref = $policyref;
	}
    }

    progress_message "   Policy $policy from $_[1] to $_[2] using chain $chainref->{name}";
    
}

sub apply_policy_rules() {
    for my $chainref ( @policy_chains ) {
	my $policy = $chainref->{policy};
	my $loglevel = $chainref->{loglevel};
	my $optional = $chainref->{is_optional};
	my $default  = $chainref->{default};
	my $name     = $chainref->{name};

	if ( $policy ne 'NONE' ) {
	    if ( ! $chainref->{referenced} && ( ! $optional && $policy ne 'CONTINUE' ) ) {
		ensure_filter_chain $name, 1;
	    }

	    if ( $name =~ /^all2|2all$/ ) {
		policy_rules $chainref , $policy, $loglevel , $default;
	    }

	}
    }

    for my $zone ( @zones ) {
	for my $zone1 ( @zones ) {
	    my $chainref = $filter_table->{"${zone}2${zone1}"};
	    default_policy $chainref, $zone, $zone1 if $chainref->{referenced};
	}
    }
}

#
# Complete a standard chain
#
#	- run any supplied user exit
#	- search the policy file for an applicable policy and add rules as
#	  appropriate
#	- If no applicable policy is found, add rules for an assummed
#	  policy of DROP INFO
#
sub complete_standard_chain ( $$$ ) {
    my ( $stdchainref, $zone, $zone2 ) = @_;

    my $ruleschainref = $filter_table->{"${zone}2${zone2}"};
    my ( $policy, $loglevel, $default ) = ( 'DROP', 'info', $config{DROP_DEFAULT} );
    my $policychainref;

    $policychainref = $ruleschainref->{policychain} if $ruleschainref;

    if ( $policychainref ) {
	$policy    = $policychainref->{policy};
	$loglevel  = $policychainref->{loglevel};
	$default   = $policychainref->{default};
    }

    policy_rules $stdchainref , $policy , $loglevel, $default;
}

my %tcs = ( t => { chain  => 'tcpost',
		   connmark => 0,
		   fw       => 1
		   } ,
	    ct => { chain  => 'tcpost' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 1 			
		    } ,
	    c  => { target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 1 
		    } ,
	    p  => { chain    => 'tcpre' ,
		    connmark => 0 ,
		    fw       => 0
		    } ,
	    cp => { chain    => 'tcpre' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0
		    } ,
	    f =>  { chain    => 'tcfor' ,
		    connmark => 0 ,
		    fw       => 0
		    } ,
	    cf => { chain    => 'tcfor' ,
		    fw       => 0 ,
		    connmark => 1 ,
		    } ,
	    t  => { chain    => 'tcpost' ,
		    connmark => 0 ,
		    fw       => 0
		    } ,
	    ct => { chain    => 'tcpost' ,
		    target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0
		    } ,
	    c  => { target => 'CONNMARK --set-mark' ,
		    connmark => 1 ,
		    fw       => 0
		    }
	    );

use constant { NOMARK    => 0 ,
	       SMALLMARK => 1 ,
	       HIGHMARK  => 2 
	       };
	       
my @tccmd = ( { pattern   => 'SAVE' ,
		target    => 'CONNMARK --save-mark --mask' ,
		mark      => SMALLMARK ,
		mask      => '0xFF'
		} ,
	      { pattern   => 'RESTORE' ,
		target => 'CONNMARK --restore-mark --mask' ,
		mark      => SMALLMARK ,
		mask      => '0xFF'
		} ,
	      { pattern   => 'CONTINUE',
		target    => 'RETURN' ,
		mark      => NOMARK ,
		mask      => '' 
		} ,
	      { pattern   => '\|.*' ,
		target    => 'MARK --or-mark' ,
		mark      => HIGHMARK ,
		mask      => '' } ,
	      { pattern   => '&.*' ,
		target    => 'MARK --and-mark ' ,
		mark      => HIGHMARK ,
		mask      => '' 
		}
	      );

sub process_tc_rule( $$$$$$$$$$ ) {
    my ( $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $extra ) = @_;

    my $original_mark = $mark;

    ( $mark, my $designator ) = split /:/, $mark;

    my $chain  = $env{MARKING_CHAIN};
    my $target = 'MARK --set-mark';
    my $tcsref;
    my $connmark = 0;
    my $classid  = 0;

    if ( $source ) {
	if ( $source eq $firewall_zone ) {
	    $chain = 'tcout';
	    $source = '';
	} else {
	    $chain = 'tcout' if $source =~ s/^($firewall_zone)://;
	}
    }

    if ( $designator ) {
	$tcsref = $tcs{$designator};
	
	if ( $tcsref ) {
	    if ( $chain eq 'tcout' ) {
		fatal_error "Invalid chain designator for source $firewall_zone; rule \"$line\"" unless $tcsref->{fw};
	    }

	    $chain    = $tcsref->{chain}  if $tcsref->{chain};
	    $target   = $tcsref->{target} if $tcsref->{target};
	    $mark     = "$mark/0xFF"      if $connmark = $tcsref->{connmark};
	    
	} else {
	    fatal_error "Invalid MARK ($original_mark) in rule \"$line\"" unless $mark =~ /^([0-9]+|0x[0-9a-f]+)$/ and $designator =~ /^([0-9]+|0x[0-9a-f]+)$/;
	    $chain   = 'tcpost';
	    $classid = 1;
	    $mark    = $original_mark;
	    $target  = 'CLASSIFY --set-class';
	}
    }

    my $mask = 0xffff;

    my ($cmd, $rest) = split '/', $mark;

    unless ( $classid )
	{
	  MARK:
	    {
	  PATTERN:
		for my $tccmd ( @tccmd ) {
		    if ( $cmd =~ /^($tccmd->{pattern})$/ ) {
			fatal_error "$mark not valid with :C[FP]" if $connmark;
			
			$target      = "$tccmd->{target} ";
			my $marktype = $tccmd->{mark};
			
			$mark   =~ s/^[!&]//;
			
			if ( $rest ) {
			    fatal_error "Invalid MARK ($original_mark)" if $marktype == NOMARK;

			    $mark = $rest if $tccmd->{mask};

			    if ( $marktype == SMALLMARK ) {
				verify_small_mark $mark;
			    } else {
				validate_mark $mark;
			    }
			} elsif ( $tccmd->{mask} ) {
			    $mark = $tccmd->{mask};
			}
			
			last MARK;
		    }
		}
	    }
	    
	    validate_mark $mark;

	    fatal_error 'Marks < 256 may not be set in the PREROUTING chain when HIGH_ROUTE_MARKS=Yes' 
		if $cmd and $chain eq 'tcpre' and $cmd <= 0xFF and $config{HIGH_ROUTE_MARKS};
	}

    finish_rule 
	ensure_chain( 'mangle' , $chain ) ,
	do_proto( $proto, $ports, $sports) . do_test( $testval, $mask ) ,
	$source ,
	$dest ,
	'' ,
	"-j $target $mark" ,
	'' ,
	'' ,
	'';
    
    progress_message "   TC Rule \"$line\" compiled";
    
}
	
#
# Process the tcrules file
#
sub process_tcrules() {
    
    open TC, "$ENV{TMP_DIR}/tcrules" or fatal_error "Unable to open stripped tcrules file: $!";

    while ( $line = <TC> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos , $extra ) = split /\s+/, $line;

	if ( $mark eq 'COMMENT' ) {
	    if ( $capabilities{COMMENTS} ) {
		( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		$comment =~ s/\s*$//;
	    } else {
		warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
	    }
	} else {
	    fatal_error "Invalid tcrule: \"$line\"" if $extra;
	    process_tc_rule $mark, $source, $dest, $proto, $ports, $sports, $user, $testval, $length, $tos
	}
	
    }

    close NAT;

    $comment = '';
}

my %maclist_targets = ( ACCEPT => { target => 'RETURN' , mangle => 1 } ,
			REJECT => { target => 'reject' , mangle => 0 } ,
			DROP   => { target => 'DROP' ,   mangle => 1 } );

sub setup_mac_lists( $ ) {

    my $phase = $_[0];

    my %maclist_interfaces;

    my $table = $config{MACLIST_TABLE};

    my $maclist_hosts = find_hosts_by_option 'maclist';

    for my $hostref ( $maclist_hosts ) {
	$maclist_interfaces{ $hostref->[0][0] } = 1;
    }

    my @maclist_interfaces = ( sort keys %maclist_interfaces );
    
    progress_message "   Compiling MAC Verification for @maclist_interfaces -- Phase $phase...";

    if ( $phase == 1 ) {
	for my $interface ( @maclist_interfaces ) {
	    my $chainref = new_chain $table , mac_chain $interface;
	    
	    add_rule $chainref , '-s 0.0.0.0 -d 255.255.255.255 -p udp --dport 67:68 -j RETURN'
		if ( $table eq 'mangle' ) && $interface_options{$interface}{dhcp};
	    
	    if ( $config{MACLIST_TTL} ) {
		my $chain1ref = new_chain $table, macrecent_target $interface;

		my $chain = $chainref->{name};

		add_rule $chainref, "-m recent --rcheck --seconds $config{MACLIST_TTL} --name $chain -j RETURN";
		add_rule $chainref, "-j $chain1ref->{name}";
		add_rule $chainref, "-m recent --update --name $chain -j RETURN";
		add_rule $chainref, "-m recent --set --name $chain";
	    }
	}

	open MAC, "$ENV{TMP_DIR}/maclist" or fatal_error "Unable to open stripped maclist file: $!";

	while ( $line = <MAC> ) {

	    chomp $line;
	    $line =~ s/\s+/ /g;

	    my ( $disposition, $interface, $mac, $addresses , $extra ) = split /\s+/, $line;

	    if ( $disposition eq 'COMMENT' ) {
		if ( $capabilities{COMMENTS} ) {
		    ( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		    $comment =~ s/\s*$//;
		} else {
		    warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
		}
	    } else {
		fatal_error "Invalid maclist entry: \"$line\"" if $extra;
	       
		( $disposition, my $level ) = split /:/, $disposition;

		my $targetref = $maclist_targets{$disposition};

		fatal_error "Invalid DISPOSITION ( $disposition) in rule \"$line\"" if ( $table eq 'mangle' ) && ! $targetref->{mangle};

		fatal_error "No hosts on $interface have the maclist option specified: \"$line\"" unless $maclist_interfaces{$interface};

		my $chainref = $chain_table{$table}{( $config{MACLIST_TTL} ? macrecent_target $interface : mac_chain $interface )};

		$mac       = '' unless $mac && ( $mac ne '-' );
		$addresses = '' unless $addresses && ( $addresses ne '-' );

		fatal_error "You must specify a MAC address or an IP address" unless $mac || $addresses;

		$mac = mac_match $mac if $mac;

		if ( $addresses ) {
		    for my $address ( split ',', $addresses ) {
			my $source = match_source_net $address;
			log_rule_limit $level, $chainref , mac_chain( $interface) , $disposition, '', '', 'add' , "${mac}${source}" if $level;
			add_rule $chainref , "${mac}${source}-j $targetref->{target}";
		    }
		} else {
		    log_rule_limit $level, $chainref , mac_chain( $interface) , $disposition, '', '', 'add' , $mac if $level;
		    add_rule $chainref , "$mac-j $targetref->{target}";
		}

		progress_message "      Maclist entry \"$line\" compiled";
	    }
	}

	close MAC;

	$comment = '';
        #
        # Generate jumps from the input and forward chains
        #
	for my $hostref ( @$maclist_hosts ) {
	    my $interface = $hostref->[0];
	    my $ipsec  = $hostref->[1];
	    my $policy = $capabilities{POLICY_MATCH} ? "-m policy --pol $ipsec --dir in " : '';
	    my $source = match_source_net $hostref->[2];
	    my $target = mac_chain $interface;
	    if ( $table eq 'filter' ) {
		for my $chain ( @{first_chains $interface}) {
		    add_rule $filter_table->{$chain} , "${source}-m state --statue NEW ${policy}-j $target";
		}
	    } else {
		add_rule $mangle_table->{PREROUTING}, "-i $interface ${source}-m state --state NEW ${policy}-j $target";
	    }
	}
    } else {
	my $target      = $env{MACLIST_TARGET};
	my $level       = $config{MACLIST_LOG_LEVEL};
	my $disposition = $config{MACLIST_DISPOSITION};

	for my $interface ( @maclist_interfaces ) {
	    my $chainref = $chain_table{$table}{( $config{MACLIST_TTL} ? macrecent_target $interface : mac_chain $interface )};
	    my $chain    = mac_chain $interface;
	    log_rule_limit $level, $chainref , $chain , $disposition, '', '', 'add', '';
	    add_rule $chainref, "-j $target";
	}
    }
}

#
# Add ESTABLISHED,RELATED rules and synparam jumps to the passed chain 
#
sub finish_chain_section ($$) {
    my ($chainref, $state ) = @_;
    my $chain = $chainref->{name};

    add_rule $chainref, "-m state --state $state -j ACCEPT" unless $config{FASTACCEPT};
    
    if ($sections{RELATED} ) {
	if ( $chainref->{is_policy} ) {
	    if ( $chainref->{synparams} ) {
		my $synchainref = ensure_chain 'filter', "\@$chain";
		if ( $section eq 'DONE' ) {
		    if ( $chainref->{policy} =~ /^(ACCEPT|CONTINUE|QUEUE)$/ ) {
			add_rule $chainref, "-p tcp --syn -j $synchainref->{name}";
		    } 
		} else {
		    add_rule $chainref, "-p tcp --syn -j $synchainref->{name}";
		}
	    }
	} else {
	    my $policychainref = $chainref->{policychain};
	    if ( $policychainref->{synparams} ) {
		my $synchainref = ensure_chain 'filter', "\@$policychainref->{name}";
		add_rule $synchainref, "-p tcp --syn -j $synchainref->{name}";
	    }
	}
    }
}		    

#
# Do section-end processing
# 
sub finish_section ( $ ) {
    my $sections = $_[0];

    for my $zone ( @zones ) {
	for my $zone1 ( @zones ) {
	    my $chainref = $chain_table{'filter'}{"${zone}2${zone1}"};
	    if ( $chainref->{referenced} ) {
		finish_chain_section $chainref, $sections;
	    }
	}
    }
}

sub process_rule1 ( $$$$$$$$$ );

#
# Expand a macro rule from the rules file
#
sub process_macro ( $$$$$$$$$$$ ) {
    my ($macrofile, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user) = @_;

    progress_message "..Expanding Macro $macrofile...";

    open M, $macrofile or fatal_error "Unable to open $macrofile: $!";

    while ( $line = <M> ) {
	chomp $line;
	next if $line =~ /^\s*#/;
	next if $line =~ /^\s*$/;
	$line =~ s/\s+/ /g;
	$line =~ s/#.*$//;
	
	my ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split /\s+/, $line;
	
	$mtarget = merge_levels $target, $mtarget;
	
	if ( $mtarget =~ /^PARAM:?/ ) {
	    fatal_error 'PARAM requires that a parameter be supplied in macro invocation' unless $param;
	    $mtarget = substitute_action $param,  $mtarget;
	}

	my $action     = isolate_action $mtarget;
	my $actiontype = $all_actions{$action};

	if ( $actiontype & ACTION ) {
	    unless ( $usedactions{$action} ) {
		createactionchain $mtarget;
		$usedactions{$mtarget} = 1;
	    }
	    
	    $mtarget = find_logactionchain $mtarget;
	} else {
	    fatal_error "Invalid Action ($mtarget) in rule \"$line\""  unless $actiontype & STANDARD;
	}

	if ( $msource ) {
	    if ( ( $msource eq '-' ) || ( $msource eq 'SOURCE' ) ) {
		$msource = $source || '';
	    } elsif ( $msource eq 'DEST' ) {
		$msource = $dest || '';
	    } else {
		$msource = merge_macro_source_dest $msource, $source;
	    }
	} else {
	    $msource = '';
	}

	$msource = '' if $msource eq '-';
		
	if ( $mdest ) {
	    if ( ( $mdest eq '-' ) || ( $mdest eq 'DEST' ) ) {
		$mdest = $dest || '';
	    } elsif ( $mdest eq 'SOURCE' ) {
		$mdest = $source || '';
	    } else {
		$mdest = merge_macro_source_dest $mdest, $dest;
	    }
	} else {
	    $mdest = '';
	}

	$mdest   = '' if $mdest   eq '-';

	$mproto  = merge_macro_column $mproto,  $proto;
	$mports  = merge_macro_column $mports,  $ports;
	$msports = merge_macro_column $msports, $sports;
	$mrate   = merge_macro_column $mrate,   $rate;
	$muser   = merge_macro_column $muser,   $user;
	
	process_rule1 $mtarget, $msource, $mdest, $mproto, $mports, $msports, $origdest, $rate, $user;

	progress_message "   Rule \"$line\" Compiled";    }

    close M;

    progress_message '..End Macro'
}

#
# Once a rule has been completely resolved by macro expansion, it is processed by this function.
#
sub process_rule1 ( $$$$$$$$$ ) {
    my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user ) = @_;
    my ( $action, $loglevel) = split_action $target;
    my $rule = '';

    $proto     = '' unless defined $proto;
    $ports     = '' unless defined $ports;
    $sports    = '' unless defined $sports;
    $origdest  = '' unless defined $origdest;
    $ratelimit = '' unless defined $ratelimit;
    $user      = '' unless defined $user;
    
    #
    # Determine the validity of the action
    #
    my $actiontype = $all_actions{$action} || find_macro isolate_action $action;

    fatal_error "Unknown action ($action) in rule \"$line\"" unless $actiontype;

    if ( $actiontype == MACRO ) {
	process_macro 
	    $macros{isolate_action $action}, $
	    target , 
	    (split '/', $action)[1] , 
	    $source, 
	    $dest, 
	    $proto, 
	    $ports, 
	    $sports, 
	    $origdest, 
	    $ratelimit, 
	    $user;
	return;
    }
    #
    # We can now dispense with the postfix characters
    #
    $action =~ s/[\+\-!]$//;
    #
    # Mark target as used
    #
    if ( $actiontype & ACTION ) {
	unless ( $usedactions{target} ) {
	    $usedactions{$target} = 1;
	    createactionchain $target;
	}
    }
    #
    # Take care of irregular syntax and targets
    #
    if ( $actiontype & REDIRECT ) {
	if ( $dest eq '-' ) {
	    $dest = "$firewall_zone";
	} else {
	    $dest = "$firewall_zone" . '::' . "$dest";
	}
    } elsif ( $action eq 'REJECT' ) {
	$action = 'reject';
    } elsif ( $action eq 'CONTINUE' ) {
	$action = 'RETURN';
    }
    #
    # Isolate and validate source and destination zones
    #
    my $sourcezone;
    my $destzone;

    if ( $source =~ /^(.+?):(.*)/ ) {
	$sourcezone = $1;
	$source = $2;
    } else {
	$sourcezone = $source;
	$source = ALLIPv4;
    }
    
    if ( $dest =~ /^(.+?):(.*)/ ) {
	$destzone = $1;
	$dest = $2;
    } else {
	$destzone = $dest;
	$dest = ALLIPv4;
    }

    fatal_error "Unknown source zone ($sourcezone) in rule \"$line\"" unless $zones{$sourcezone}; 
    fatal_error "Unknown destination zone ($destzone) in rule \"$line\"" unless $zones{$destzone};
    #
    # Take care of chain
    #
    my $chain    = "${sourcezone}2${destzone}";
    my $chainref = ensure_filter_chain $chain, 1;
    #
    # Validate Policy
    #
    my $policy   = $chainref->{policy};
    fatal_error "No policy defined from $sourcezone to zone $destzone" unless $policy;
    fatal_error "Rules may not override a NONE policy: rule \"$line\"" if $policy eq 'NONE';
    #
    # Generate Fixed part of the rule
    #
    $rule = do_proto $proto, $ports, $sports . do_ratelimit( $ratelimit ) . ( do_user $user );

    $origdest = ALLIPv4 unless $origdest and $origdest ne '-';
    #
    # Generate NAT rule(s), if any
    #
    if ( $actiontype & NATRULE ) {
	my ( $server, $serverport , $natchain );
	fatal_error "$target rules not allowed in the $section SECTION"  if $section ne 'NEW';
	#
	# Isolate server port
	#
	if ( $dest =~ /^(.*)(:(\d+))$/ ) {
	    $server = $1;
	    $serverport = $3;
	} else {
	    $server = $dest;
	    $serverport = '';
	}
	#
	# After DNAT, dest port will be the server port
	#
	$ports = $serverport if $serverport;

	fatal_error "A server must be specified in the DEST column in $action rules: \"$line\"" unless ( $actiontype & REDIRECT ) || $server;
	fatal_error "Invalid server ($server), rule: \"$line\"" if $server =~ /:/;
	#
	# Generate the target
	#
	my $target = '';

	if ( $action eq 'SAME' ) {
	    fatal_error 'Port mapping not allowed in SAME rules' if $serverport;
	    $target = '-j SAME ';
	    for my $serv ( split /,/, $server ) {
		$target .= "--to $serv ";
	    }

	    $serverport = $ports;
	} elsif ( $action eq ' -j DNAT' ) {
	    $serverport = ":$serverport" if $serverport;
	    for my $serv ( split /,/, $server ) {
		$target .= "--to ${serv}${serverport} ";
	    }
	} else {
	    $target = '-j REDIRECT --to-port ' . ( $serverport ? $serverport : $ports );
	}

	#
	# And generate the nat table rule(s)
	#
	finish_rule
	    ensure_chain ('nat' , $zones{$sourcezone} eq 'firewall' ? 'OUTPUT' : dnat_chain $sourcezone ) ,
	    $rule ,
	    $source ,
	    $origdest ,
	    '' ,
	    $target ,
	    $loglevel ,
	    $action , 
	    $serverport ? do_proto( $proto, '', '' ) : '';
	#
	# After NAT, the destination port will be the server port; Also, we log NAT rules in the nat table rather than in the filter table.
	#
	unless ( $actiontype & NATONLY ) {
	    $rule = do_proto $proto, $ports, $sports . do_ratelimit( $ratelimit ) . do_user $user;
	    $loglevel = '';
	}
    } elsif ( $actiontype & NONAT ) {
	#
	# NONAT or ACCEPT+ -- May not specify a destination interface
	#
	fatal_error "Invalid DEST ($dest) in $action rule \"$line\"" if $dest =~ /:/;
 
	finish_rule
	    ensure_chain ('nat' , $zones{$sourcezone} eq 'firewall' ? 'OUTPUT' : dnat_chain $sourcezone) ,
	    $rule ,
	    $source ,
	    $dest ,
	    '' ,
	    '-j RETURN ' ,
	    $loglevel ,
	    $action ,
	    '';
    }
    #
    # Add filter table rule, unless this is a NATONLY rule type
    #
    unless ( $actiontype & NATONLY ) {
	finish_rule
	    ensure_chain ('filter', $chain ) ,
	    $rule ,
	    $source ,
	    $dest ,
	    $origdest ,
	    "-j $action " ,
	    $loglevel ,
	    $action ,
	    '';
    }
}

#
# Process a Record in the rules file
#
sub process_rule ( $$$$$$$$$ ) {
    my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user ) = @_;
    my $intrazone = 0;
    my $includesrcfw = 1;
    my $includedstfw = 1;
    my $optimize = $config{OPTIMIZE};
    #
    # Section Names are optional so once we get to an actual rule, we need to be sure that
    # we close off any missing sections.
    #
    unless ( $sectioned ) {
	finish_section 'ESTABLISHED,RELATED';
	$section = 'NEW';
	$sectioned = 1;
    }
    #
    # Handle Wildcards
    #
    if ( $source =~ /^all[-+]/ ) {
	if ( $source eq 'all+' ) {
	    $source = 'all';
	    $intrazone = 1;
	} elsif ( ( $source eq 'all+-' ) || ( $source eq 'all-+' ) ) {
	    $source = 'all';
	    $intrazone = 1;
	    $includesrcfw = 0;
	} elsif ( $source eq 'all-' ) {
	    $source = 'all';
	    $includesrcfw = 0;
	}
    }

    if ( $dest =~ /^all[-+]/ ) {
	if ( $dest eq 'all+' ) {
	    $dest = 'all';
	    $intrazone = 1;
	} elsif ( ( $dest eq 'all+-' ) || ( $dest eq 'all-+' ) ) {
	    $dest = 'all';
	    $intrazone = 1;
	    $includedstfw = 0;
	} elsif ( $source eq 'all-' ) {
	    $dest = 'all';
	    $includedstfw = 0;
	}
    }

    my $action = isolate_action $target;

    $optimize = 0 if $action =~ /!^/;

    if ( $source eq 'all' ) {
	for my $zone ( @zones ) {
	    if ( $includesrcfw || ( $zones{$zone} ne 'firewall' ) ) {
		if ( $dest eq 'all' ) {
		    for my $zone1 ( @zones ) {
			if ( $includedstfw || ( $zones{$zone1} ne 'firewall' ) ) {
			    if ( $intrazone || ( $zone ne $zone1 ) ) {
				my $policychainref = $filter_table->{"${zone}2${zone1}"}{policychain};
				fatal_error "No policy from zone $zone to zone $zone1" unless $policychainref;
				if ( ( ( my $policy ) = $policychainref->{policy} ) ne 'NONE' ) {
				    if ( $optimize > 0 ) {
					my $loglevel = $policychainref->{loglevel};
					if ( $loglevel ) {
					    next if $target eq "${policy}:$loglevel}";
					} else {
					    next if $action eq $policy;
					}
				    }
				    process_rule1 $target, $zone, $zone1 , $proto, $ports, $sports, $origdest, $ratelimit, $user;
				}
			    }
			} 
		    }
		} else {
		    process_rule1 $target, $zone, $dest , $proto, $ports, $sports, $origdest, $ratelimit, $user;
		}
	    } 
	}
    } elsif ( $dest eq 'all' ) {
	for my $zone1 ( @zones ) {
	    my $zone = ( split /:/, $source )[0];
	    if ( ( $includedstfw || ( $zones{$zone1} ne 'firewall') ) &&( ( $zone ne $zone1 ) || $intrazone) ) {
		process_rule1 $target, $source, $zone1 , $proto, $ports, $sports, $origdest, $ratelimit, $user;
	    }
	}
    } else {
	process_rule1  $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user;
    }

    progress_message "   Rule \"$line\" Compiled";
}

#
# Process the Rules File
#
sub process_rules() {

    open RULES, "$ENV{TMP_DIR}/rules" or fatal_error "Unable to open stripped rules file: $!";

    while ( $line = <RULES> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user, $extra ) = split /\s+/, $line;

	if ( $target eq 'COMMENT' ) {
	    if ( $capabilities{COMMENTS} ) {
		( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		$comment =~ s/\s*$//;
	    } else {
		warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
	    }
	} elsif ( $target eq 'SECTION' ) {
	    fatal_error "Invalid SECTION $source" unless defined $sections{$source};
	    fatal_error "Duplicate or out of order SECTION $source" if $sections{$source};
	    fatal_error "Invalid Section $source $dest" if $dest;
	    $sectioned = 1;
	    $sections{$source} = 1;

	    if ( $section eq 'RELATED' ) {
		$sections{ESTABLISHED} = 1;
		finish_section 'ESTABLISHED';
	    } elsif ( $section eq 'NEW' ) {
		@sections{'ESTABLISHED','RELATED'} = ( 1, 1 );
		finish_section ( ( $section eq 'RELATED' ) ? 'RELATED' : 'ESTABLISHED,RELATED' );
	    }

	    $section = $source;
	} else {
	    fatal_error "Invalid rules file entry: \"$line\"" if $extra;
	    process_rule $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user;
	}
    }
	
    close RULES;

    $comment = '';
    $section = 'DONE';
}

#
# Here starts the tunnel stuff -- we really should get rid of this crap...
#
sub setup_one_ipsec {
    my ($inchainref, $outchainref, $kind, $source, $dest, $gatewayzones) = @_;

    ( $kind, my $qualifier ) = split /:/, $kind;

    fatal_error "Invalid IPSEC modifier ($qualifier) in tunnel \"$line\"" if $qualifier && ( $qualifier ne 'noah' );

    my $noah = $qualifier || ($kind ne 'ipsec' );

    my $options = '-m $state --state NEW -j ACCEPT';

    add_rule $inchainref,  "-p 50 $source -j ACCEPT"; 
    add_rule $outchainref, "-p 50 $dest   -j ACCEPT"; 

    unless ( $noah ) {
	add_rule $inchainref,  "-p 51 $source -j ACCEPT"; 
	add_rule $outchainref, "-p 51 $dest   -j ACCEPT"; 
    }

    add_rule $outchainref,  "-p udp $dest --dport 500 $options";

    if ( $kind eq 'ipsec' ) {
	add_rule $inchainref, "-p udp $source --dport $options";
    } else {
	add_rule $inchainref, "-p udp $source -m multiport --dports 500,4500 $options";
    }

    for my $zone ( split /,/, $gatewayzones ) {
	fatal_error "Invalid zone ($zone) in tunnel \"$line\"" unless $zones{$zone} eq 'ipv4';
	$inchainref  = ensure_filter_chain "${zone}2${firewall_zone}", 1;
	$outchainref = ensure_filter_chain "${firewall_zone}2${zone}", 1;
	
	unless ( $capabilities{POLICY_MATCH} ) {
	    add_rule $inchainref,  "-p 50 $source -j ACCEPT";
	    add_rule $outchainref, "-p 50 $dest -j ACCEPT";
	    
	    unless ( $noah ) {
		add_rule $inchainref,  "-p 51 $source -j ACCEPT";
		add_rule $outchainref, "-p 51 $dest -j ACCEPT";
	    }
	}

	if ( $kind eq 'ipsec' ) {
	    add_rule $inchainref,  "-p udp $source --dport 500 $options";
	    add_rule $outchainref, "-p udp $dest --dport 500 $options";
	} else {
	    add_rule $inchainref,  "-p udp $source -m multiport --dports 500,4500 $options";
	    add_rule $outchainref, "-p udp $dest -m multiport --dports 500,4500 $options";
	}
    }
}

sub setup_one_other {
    my ($inchainref, $outchainref, $kind, $source, $dest , $protocol) = @_;

    add_rule $inchainref ,  "-p $protocol $source -j ACCEPT";
    add_rule $outchainref , "-p $protocol $dest -j ACCEPT";
}

sub setup_pptp_client {
    my ($inchainref, $outchainref, $kind, $source, $dest ) = @_;

    add_rule $outchainref,  "-p 47 $dest -j ACCEPT";
    add_rule $inchainref,   "-p 47 $source -j ACCEPT";
    add_rule $outchainref,  "-p tcp --dport 1723 $dest -j ACCEPT"
}

sub setup_pptp_server {
    my ($inchainref, $outchainref, $kind, $source, $dest ) = @_;

    add_rule $inchainref,  "-p 47 $dest -j ACCEPT";
    add_rule $outchainref, "-p 47 $source -j ACCEPT";
    add_rule $inchainref,  "-p tcp --dport 1723 $dest -j ACCEPT"
}

sub setup_one_openvpn {
    my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

    my $protocol = 'udp';
    my $port     = 1194;

    ( $kind, my ( $proto, $p ) ) = split /:/, $kind;

    $port     = $p     if $p;
    $protocol = $proto if $proto;

    add_rule $inchainref,  "-p $protocol $source --dport $port -j ACCEPT";
    add_rule $outchainref, "-p $protocol $dest --dport $port -j ACCEPT";
}

sub setup_one_openvpn_client {
    my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

    my $protocol = 'udp';
    my $port     = 1194;

    ( $kind, my ( $proto, $p ) ) = split /:/, $kind;

    $port     = $p     if $p;
    $protocol = $proto if $proto;

    add_rule $inchainref,  "-p $protocol $source --sport $port -j ACCEPT";
    add_rule $outchainref, "-p $protocol $dest --dport $port -j ACCEPT";
}

sub setup_one_openvpn_server {
    my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

    my $protocol = 'udp';
    my $port     = 1194;

    ( $kind, my ( $proto, $p ) ) = split /:/, $kind;

    $port     = $p     if $p;
    $protocol = $proto if $proto;

    add_rule $inchainref,  "-p $protocol $source --dport $port -j ACCEPT";
    add_rule $outchainref, "-p $protocol $dest --sport $port -j ACCEPT";
}

sub setup_one_generic {
    my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

    my $protocol = 'udp';
    my $port     = '--dport 5000';

    if ( $kind =~ /.*:.*:.*/ ) {
	( $kind, $protocol, $port) = split /:/, $kind;
	$port = "--dport $port";
    } else {
	$port = '';
	( $kind, $protocol ) = split /:/ , $kind if $kind =~ /.*:.*/;
    }

    add_rule $inchainref,  "-p $protocol $source $port -j ACCEPT";
    add_rule $outchainref, "-p $protocol $dest $port -j ACCEPT";
}

sub setup_one_tunnel($$$$) {
    my ( $kind , $zone, $gateway, $gatewayzones ) = @_;
    
    fatal_error "Invalid zone ($zone) in tunnel \"$line\"" unless $zones{$zone} eq 'ipv4';

    my $inchainref  = ensure_filter_chain "${zone}2${firewall_zone}", 1;
    my $outchainref = ensure_filter_chain "${firewall_zone}2${zone}", 1;

    my $source = match_source_net $gateway;
    my $dest   = match_dest_net   $gateway;
  
    my %tunneltypes = ( 'ipsec'         => { function => \&setup_one_ipsec ,         params   => [ $kind, $source, $dest , $gatewayzones ] } ,
			'ipsecnat'      => { function => \&setup_one_ipsec ,         params   => [ $kind, $source, $dest , $gatewayzones ] } ,
			'ipip'          => { function => \&setup_one_other,          params   => [ $source, $dest , 4 ] } ,
			'gre'           => { function => \&setup_one_other,          params   => [ $source, $dest , 47 ] } ,
			'6to4'          => { function => \&setup_one_other,          params   => [ $source, $dest , 41 ] } ,
			'pptpclient'    => { function => \&setup_pptp_client,        params   => [ $kind, $source, $dest ] } ,
			'pptpserver'    => { function => \&setup_pptp_server,        params   => [ $kind, $source, $dest ] } ,
			'openvpn'       => { function => \&setup_one_openvpn,        params   => [ $kind, $source, $dest ] } ,
			'openvpnclient' => { function => \&setup_one_openvpn_client, params   => [ $kind, $source, $dest ] } ,
			'openvpnserver' => { function => \&setup_one_openvpn_server, params   => [ $kind, $source, $dest ] } ,
			'generic'       => { function => \&setup_one_generic ,       params   => [ $kind, $source, $dest ] } ,
			);

    $kind = "\L$kind";

    (my $type) = split /:/, $kind;

    my $tunnelref = $tunneltypes{ $type };

    fatal_error "Tunnels of type $type are not supported: Tunnel \"$line\"" unless $tunnelref;

    $tunnelref->{function}->( $inchainref, $outchainref, @{$tunnelref->{params}} );

    progress_message "   Tunnel \"$line\" Compiled";
}

sub setup_tunnels() {

    open TUNNELS, "$ENV{TMP_DIR}/tunnels" or fatal_error "Unable to open stripped tunnels file: $!";

    while ( $line = <TUNNELS> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $kind, $zone, $gateway, $gatewayzones, $extra ) = split /\s+/, $line;

	if ( $kind eq 'COMMENT' ) {
	    if ( $capabilities{COMMENTS} ) {
		( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		$comment =~ s/\s*$//;
	    } else {
		warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
	    }
	} else {
	    fatal_error "Invalid Tunnels file entry: \"$line\"" if $extra;
	    setup_one_tunnel $kind, $zone, $gateway, $gatewayzones;
	}
    }
	
    close TUNNELS;

    $comment = '';
}    

#
# The following small functions generate rules for the builtin actions of the same name
#
sub dropBcast( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    if ( $level ) {
	log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -m pkttype --pkt-type broadcast';
	log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -m pkttype --pkt-type multicast';
    }

    add_rule $chainref, '-m pkttype --pkt-type broadcast -j DROP';
    add_rule $chainref, '-m pkttype --pkt-type multicast -j DROP';
}

sub allowBcast( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    if ( $level ) {
	log_rule_limit $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add', ' -m pkttype --pkt-type broadcast';
	log_rule_limit $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add', ' -m pkttype --pkt-type multicast';
    }

    add_rule $chainref, '-m pkttype --pkt-type broadcast -j ACCEPT';
    add_rule $chainref, '-m pkttype --pkt-type multicast -j ACCEPT';
}

sub dropNotSyn ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    log_rule_limit $level, $chainref, 'dropNotSyn' , 'DROP', '', $tag, 'add', '-p tcp ! --syn ' if $level;    
    add_rule $chainref , '-p tcp ! --syn -j DROP';
}

sub rejNotSyn ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    log_rule_limit $level, $chainref, 'rejNotSyn' , 'REJECT', '', $tag, 'add', '-p tcp ! --syn ' if $level;    
    add_rule $chainref , '-p tcp ! --syn -j REJECT';
}

sub dropInvalid ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    log_rule_limit $level, $chainref, 'dropInvalid' , 'DROP', '', $tag, 'add', '-m state --state INVALID ' if $level;    
    add_rule $chainref , '-m state --state INVALID -j REJECT';
}

sub allowInvalid ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    log_rule_limit $level, $chainref, 'allowInvalid' , 'ACCEPT', '', $tag, 'add', '-m state --state INVALID ' if $level;    
    add_rule $chainref , '-m state --state INVALID -j ACCEPT';
}

sub forwardUPnP ( $$$ ) {
}

sub allowinUPnP ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    if ( $level ) {
	log_rule_limit $level, $chainref, 'allowinUPnP' , 'ACCEPT', '', $tag, 'add', '-p udp --dport 1900 ';
	log_rule_limit $level, $chainref, 'allowinUPnP' , 'ACCEPT', '', $tag, 'add', '-p tcp --dport 49152 ';
    }

    add_rule $chainref, '-p udp --dport 1900 -j ACCEPT';
    add_rule $chainref, '-p tcp --dport 49152 -j ACCEPT';
}

sub Limit( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    my @tag = split $tag;

    fatal_error 'Limit rules must include <set name>,<max connections>,<interval> as the log tag' unless @tag == 3;

    add_rule $chainref, '-m recent --name $tag[0] --set';
    
    if ( $level ) {
	my $xchainref = new_chain 'filter' , "$chainref->{name}%";
	log_rule_limit $level, $xchainref, $tag[0], 'DROP', '', '', 'add', '';
	add_rule $xchainref, '-j DROP';
	add_rule $chainref,  "-m recent --name $tag[0] --update --seconds $tag[2] --hitcount $(( $tag[1] + 1 )) -j $chainref->{name}%";
    } else {
	add_rule $chainref, "-m recent --update --name $tag[0] --seconds $tag[2] --hitcount $(( $tag[1] + 1 )) -j DROP";
    }

    add_rule $chainref, '-j ACCEPT';
}

#
# This function is called to process each rule generated from an action file.
#
sub process_action( $$$$$$$$$$ ) {
    my ($chainref, $actionname, $target, $source, $dest, $proto, $ports, $sports, $rate, $user ) = @_;

    my ( $action , $level ) = split_action $target;

    finish_rule ( $chainref ,
		  do_proto( $proto, $ports, $sports ) . do_ratelimit( $rate ) . do_user $user , 
		  $source ,
		  $dest ,
		  '', #Original Dest
		  '-j ' . ($action eq 'REJECT' ? 'reject' : $action eq 'CONTINUE' ? 'RETURN' : $action),
		  $level ,
		  $action ,
		  '' );
}
    
#
# Generate chain for non-builtin action invocation
#	
sub process_action3( $$$$$ ) {
    my ( $chainref, $wholeaction, $action, $level, $tag ) = @_;
    my $actionfile = find_file "action.$action";

    fatal_error "Missing Action File: $actionfile" unless -f $actionfile;

    progress_message2 "Processing $actionfile for chain $chainref->{name}...";

    open A, $actionfile or fatal_error "Unable to open $actionfile: $!";

    while ( $line = <A> ) {
	chomp $line;
	next if $line =~ /^\s*#/;
	next if $line =~ /^\s*$/;
	$line =~ s/\s+/ /g;
	$line =~ s/#.*$//;
		
	my ($target, $source, $dest, $proto, $ports, $sports, $rate, $user , $extra ) = split /\s+/, $line;

	my $target2 = merge_levels $wholeaction, $target;

	my ( $action2 , $level2 ) = split_action $target2;

	my $action2type = isolate_action $action2;

	unless ( $action2type == STANDARD ) {
	    if ( $target eq 'COMMENT' ) {
		if ( $capabilities{COMMENTS} ) {
		    ( $comment = $line ) =~ s/^\s*COMMENT\s*//;
		    $comment =~ s/\s*$//;
		} else {
		    warning_message "COMMENT ignored -- requires comment support in iptables/Netfilter";
		}
	    } elsif ( $action2type & ACTION ) {
		$target2 = (find_logactionchain ( $target = $target2 ))->{name};
	    } else {
		die "Internal Error" unless $action2type == MACRO;
	    }
	}

	if ( $action2type == MACRO ) {
	    ( $action2, my $param ) = split '/', $action2;

	    fatal_error "Null Macro" unless my $fn = $macros{$action2};

	    progress_message "..Expanding Macro $fn...";

	    open M, $fn or fatal_error "Can't open $fn: $!";
	    
	    while ( $line = <M> ) {
		next if $line =~ /^\s*#/;
		next if $line =~ /^\s*$/;
		$line =~ s/\s+/ /g;
		$line =~ s/#.*$//;
			    
		my ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split /\s+/, $line;
		
		if ( $mtarget =~ /^PARAM:?/ ) {
		    fatal_error 'PARAM requires that a parameter be supplied in macro invocation' unless $param;
		    $mtarget = substitute_action $param,  $mtarget;
		}

		if ( $msource ) {
		    if ( ( $msource eq '-' ) || ( $msource eq 'SOURCE' ) ) {
			$msource = $source || '';
		    } elsif ( $msource eq 'DEST' ) {
			$msource = $dest || '';
		    } else {
			$msource = merge_macro_source_dest $msource, $source;
		    }
		} else {
		    $msource = '';
		}

		$msource = '' if $msource eq '-';
		
		if ( $mdest ) {
		    if ( ( $mdest eq '-' ) || ( $mdest eq 'DEST' ) ) {
			$mdest = $dest || '';
		    } elsif ( $mdest eq 'SOURCE' ) {
			$mdest = $source || '';
		    } else {
			$mdest = merge_macro_source_dest $mdest, $dest;
		    }
		} else {
		    $mdest = '';
		}

		$mdest   = '' if $mdest   eq '-';

		$mproto  = merge_macro_column $mproto,  $proto;
		$mports  = merge_macro_column $mports,  $ports;
		$msports = merge_macro_column $msports, $sports;
		$mrate   = merge_macro_column $mrate,   $rate;
		$muser   = merge_macro_column $muser,   $user;

		process_action $chainref, $action, $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser;
	    }

	    close M;
	    
	    progress_message '..End Macro'

	} else {
	    process_action $chainref, $action, $target2, $source, $dest, $proto, $ports, $sports, $rate, $user;
	} 
    }

    $comment = '';
}	

#
# The next three functions implement the three phases of action processing.
#
# The first phase (process_actions1) occurs before the rules file is processed. ${SHAREDIR}/actions.std
# and ${CONFDIR}/actions are scanned (in that order) and for each action:
#
#      a) The related action definition file is located and scanned.
#      b) Forward and unresolved action references are trapped as errors.
#      c) A dependency graph is created using the 'requires' field in the 'actions' table.
#
# As the rules file is scanned, each action[:level[:tag]] is merged onto the 'usedactions' hash. When an <action>
# is merged into the hash, its action chain is created. Where logging is specified, a chain with the name
# %<action>n is used where the <action> name is truncated on the right where necessary to ensure that the total
# length of the chain name does not exceed 30 characters.
#
# The second phase (process_actions2) occurs after the rules file is scanned. The transitive closure of
# %usedactions is generated; again, as new actions are merged into the hash, their action chains are created.
#
# The final phase (process_actions3) is to traverse the keys of %usedactions populating each chain appropriately
# by reading the action definition files and creating rules. Note that a given action definition file is
# processed once for each unique [:level[:tag]] applied to an invocation of the action.
#    
sub process_actions1() {

    for my $act ( grep $all_actions{$_} & ACTION , keys %all_actions ) {
	new_action $act;
    }

    for my $file qw/actions.std actions/ {
	open F, "$ENV{TMP_DIR}/$file" or fatal_error "Unable to open stripped $file file: $!";
	
	while ( $line = <F> ) {
	    chomp $line;
	    my ( $action , $extra ) = split /\s+/, $line;
	    fatal_error "Invalid Action: $line" if $extra;
	    
	    if ( $action =~ /:/ ) {
		warning_message 'Default Actions are now specified in /etc/shorewall/shorewall.conf';
		$action =~ s/:.*$//;
	    }

	    next unless $action;

	    if ( $all_actions{$action} ) {
		next if $all_actions{$action} & ACTION;
		fatal_error "Invalid Action Name: $action";
	    }

	    $all_actions{$action} = ACTION;

	    fatal_error "Invalid Action Name: $action" unless "\L$action" =~ /^[a-z]\w*$/;

	    new_action $action;

	    my $actionfile = find_file "action.$action";

	    fatal_error "Missing Action File: $actionfile" unless -f $actionfile;

	    progress_message2 "   Pre-processing $actionfile...";

	    open A, $actionfile or fatal_error "Unable to open $actionfile: $!";

	    while ( $line = <A> ) {
		chomp $line;
		next if $line =~ /^\s*#/;
		next if $line =~ /^\s*$/;
		$line =~ s/\s+/ /g;
		$line =~ s/#.*$//;
		
		( my ($wholetarget, $source, $dest, $proto, $ports, $sports, $rate, $users ) , $extra ) = split /\s+/, $line;
		
		fatal_error "Invalid action rule \"$line\"\n" if $extra;

		my ( $target, $level ) = split_action $wholetarget;
		
		$level = 'none' unless $level;

		my $targettype = $all_actions{$target};

		if ( defined $targettype ) {
		    next if ( $targettype == STANDARD ) || ( $targettype == MACRO ) || ( $target eq 'LOG' );
		  
		    fatal_error "Invalid TARGET ($target) in action rule \"$line\"" if $targettype & STANDARD;

		    add_requiredby $wholetarget, $action if $targettype & ACTION;
		} else {
		    $target =~ s!/.*$!!;

		    if ( find_macro $target ) {
			my $macrofile = $macros{$target};

			progress_message "   ..Expanding Macro $macrofile...";
			
			open M, $macrofile or fatal_error "Unable to open $macrofile: $!";

			while ( $line = <M> ) {
			    next if $line =~ /^\s*#/;
			    $line =~ s/\s+/ /g;
			    $line =~ s/#.*$//;
			    next if $line =~ /^\s*$/;
			    
			    my ( $mtarget, $msource,  $mdest,  $mproto,  $mports,  $msports, $ mrate, $muser, $mextra ) = split /\s+/, $line;

			    fatal_error "Invalid macro rule \"$line\"" if $mextra;

			    $mtarget =~ s/:.*$//;

			    $targettype = $all_actions{$mtarget};

			    $targettype = 0 unless defined $targettype;

			    fatal_error "Invalid target ($mtarget) in rule \"$line\"" 
				unless ( $targettype == STANDARD ) || ( $mtarget eq 'PARAM' ) || ( $mtarget eq 'LOG' );
			}

			progress_message "   ..End Macro";
			
			close M;
		    } else {
			fatal_error "Invalid TARGET ($target) in rule \"$line\"";
		    }
		}
	    }
	    close A;
	}
	close F;
    }
}

sub process_actions2 () {  
    progress_message2 'Generating Transitive Closure of Used-action List...'; 

    my $changed = 1;

    while ( $changed ) {
	$changed = 0;
	for my $target (keys %usedactions) {
	    my ($action, $level) = split_action $target;
	    my $actionref = $actions{$action};
	    die "Null Action Reference in process_actions2" unless $actionref;
	    for my $action1 ( keys %{$actionref->{requires}} ) {
		my $action2 = merge_levels $target, $action1;
		unless ( $usedactions{ $action2 } ) {
		    $usedactions{ $action2 } = 1;
		    createactionchain $action2;
		    $changed = 1;
		}
	    }
	}
    }
}
		
sub process_actions3 () {
    my %builtinops = ( 'dropBcast'    => \&dropBcast,
		       'allowBcast'   => \&allowBcast,
		       'dropNotSyn'   => \&dropNotSyn,
		       'rejNotSyn'    => \&rejNotSyn,
		       'dropInvalid'  => \&dropInvalid,
		       'allowInvalid' => \&allowInvalid,
		       'allowinUPnP'  => \&allowinUPnP,
		       'forwardUPnP'  => \&forwardUPnP,
		       'Limit'        => \&Limit,
		       );

    for my $wholeaction ( keys %usedactions ) {
	my $chainref = find_logactionchain $wholeaction;
	my ( $action, $level, $tag ) = split /:/, $wholeaction;

	$level = '' unless defined $level;
	$tag   = '' unless defined $tag;
	
	if ( $all_actions{$action} & BUILTIN ) {
	    $level = '' if $level =~ /none!?/;
	    $builtinops{$action}->($chainref, $level, $tag);
	} else {
	    process_action3 $chainref, $wholeaction, $action, $level, $tag;
	}
    }   
}

sub dump_action_table() {
    my $action;

    print "\n";

    for $action ( sort keys %actions ) {
	print "Action $action\n";
	my $already = 0;
	for my $requires ( keys %{$actions{$action}{requires}} ) {
	    print "   Requires:\n" unless $already;
	    print "      $requires\n";
	    $already = 1;
	}
    }

    print "\nAction Chains:\n";

    for $action ( sort keys %usedactions ) {
	$action .= ':none' unless $action =~ /:/;
	print "   $action = $logactionchains{$action}{name}\n";
    }
}

#
# Accounting
#
sub accounting_error() {
    warning_message "Invalid Accounting rule \"$line\"";
}

my $jumpchainref;

sub jump_to_chain( $ ) {
    my $jumpchain = $_[0];
    $jumpchainref = ensure_chain( 'filter', $jumpchain );
    "-j $jumpchain";
}

sub process_accounting_rule( $$$$$$$$ ) {
    my ($action, $chain, $source, $dest, $proto, $ports, $sports, $user ) = @_;

    $chain = 'accounting' unless $chain and $chain ne '-';
    
    my $chainref = ensure_filter_chain $chain , 0;

    my $target = '';

    my $rule = do_proto( $proto, $ports, $sports ) . do_user ( $user );
    my $rule2 = 0;

    unless ( $action eq 'COUNT' ) {
	if ( $action eq 'DONE' ) {
	    $target = '-j RETURN';
	} else {
	    ( $action, my $cmd ) = split /:/, $action;
	    if ( $cmd ) {
		if ( $cmd eq 'COUNT' ) {
		    $rule2=1;
		    $target = jump_to_chain $action;
		} elsif ( $cmd ne 'JUMP' ) {
		    accounting_error;
		}
	    } else {
		$target = jump_to_chain $action;
	    }
	}
    }

    finish_rule
	$chainref ,
	$rule ,
	$source ,
	$dest ,
	'' ,
	$target ,
	'' ,
	'' ,
	'' ;

    if ( $rule2 ) {
	finish_rule 
	    $jumpchainref ,
	    $rule ,
	    $source ,
	    $dest ,
	    '' ,
	    '' ,
	    '' ,
	    '' ,
	    '' ;
    }
}

sub setup_accounting() {

    open ACC, "$ENV{TMP_DIR}/accounting" or fatal_error "Unable to open stripped accounting file: $!";

    while ( $line = <ACC> ) {

	chomp $line;
	$line =~ s/\s+/ /g;

	my ( $action, $chain, $source, $dest, $proto, $ports, $sports, $user, $extra ) = split /\s+/, $line;

	accounting_error if $extra;
	process_accounting_rule $action, $chain, $source, $dest, $proto, $ports, $sports, $user;
    }
	
    close ACC;

    if ( $filter_table->{accounting} ) {
	for my $chain qw/INPUT FORWARD OUTPUT/ {
	    insert_rule $filter_table->{$chain}, 1, '-j accounting';
	}
    }
}

#
# Helper functions for generate_matrix()
#-----------------------------------------
#
# If the destination chain exists, then at the end of the source chain add a jump to the destination.
#
sub addnatjump( $$$ ) {
    my ( $source , $dest, $predicates ) = @_;

    my $destref   = $nat_table->{$dest} || {};

    if ( $destref->{referenced} ) {
	add_rule $nat_table->{$source} , $predicates . "-j $dest";
    } else {
	$iprangematch = $ipsetmatch = 0;
    }
}

#
# If the destination chain exists, then at the position in the source chain given by $$countref, add a jump to the destination.
#
sub insertnatjump( $$$$ ) {
    my ( $source, $dest, $countref, $predicates ) = @_;

    my $destref   = $nat_table->{$dest} || {};

    if ( $destref->{referenced} ) {
	insert_rule $nat_table->{$source} , ($$countref)++, $predicates . "-j $dest";
    } else {
	$iprangematch = $ipsetmatch = 0;
    }
}

#
# Return the target for rules from the $zone to $zone1.
#
sub rules_target( $$ ) {
    my ( $zone, $zone1 ) = @_;
    my $chain = "${zone}2${zone1}";
    my $chainref = $filter_table->{$chain};

    return $chain   if $chainref && $chainref->{referenced};
    return 'ACCEPT' if $zone eq $zone1;
    
    if ( $chainref->{policy} ne 'CONTINUE' ) {
	my $policyref = $chainref->{policychain};
	return $policyref->{name} if $policyref;
	fatal_error "No policy defined for zone $zone to zone $zone1";
    }

    '';
}

#
# Add a jump to the passed chain ($chainref) to the dynamic zone chain for the passed zone.
#
sub create_zone_dyn_chain( $$ ) {
    my ( $zone , $chainref ) = @_;
    my $name = "${zone}_dyn";
    new_standard_chain $name;
    add_rule $chainref, "-j $name";
}

#
# Insert the passed exclusions at the front of the passed chain.
#
sub insert_exclusions( $$ ) {
    my ( $chainref, $exclusionsref ) = @_;

    my $num = 1;

    for my $host ( @{$exclusionsref} ) {
	my ( $interface, $net ) = split /:/, $host;
	insert_rule $chainref , $num++, "-i $interface " . match_source_net( $host ) . '-j RETURN';
    }
}

#
# Add the passed exclusions at the end of the passed chain.
#
sub add_exclusions ( $$ ) {
    my ( $chainref, $exclusionsref ) = @_;

    for my $host ( @{$exclusionsref} ) {
	my ( $interface, $net ) = split /:/, $host;
	add_rule $chainref , "-i $interface " . match_source_net( $host ) . '-j RETURN';
    }
}    

#
# To quote an old comment, generate_matrix makes a sows ear out of a silk purse.
#
# The biggest disadvantage of the zone-policy-rule model used by Shorewall is that it doesn't scale well as the number of zones increases (Order N**2 where N = number of zones).
#-----------------------------------------------------------
# The goal of the rewrite of the compiler in Perl was to restrict those scaling effects to this functions and the rules that it generates.
#
# The function traverses the full "source-zone X destination-zone" matrix and generates the rules necessary to direct traffic through the right set of rules.
# 
sub generate_matrix() {
    my $prerouting_rule  = 1;
    my $postrouting_rule = 1;
    my $exclusion_seq    = 1;
    my %chain_exclusions;
    my %policy_exclusions;

    for my $interface ( @interfaces ) {
	addnatjump 'POSTROUTING' , snat_chain( $interface ), "-o $interface ";
    }

    if ( $config{DYNAMIC_ZONES} ) {
	for my $interface ( @interfaces ) {
	    addnatjump 'PREROUTING' , dynamic_in( $interface ), "-i $interface ";
	}
    }

    addnatjump 'PREROUTING'  , 'nat_in'  , '';
    addnatjump 'POSTROUTING' , 'nat_out' , '';
	
    for my $interface ( @interfaces ) {
	addnatjump 'PREROUTING'  , input_chain( $interface )  , "-i $interface ";
	addnatjump 'POSTROUTING' , output_chain( $interface ) , "-o $interface ";
    }

    for my $zone ( grep $zone_options{$_}{complex} , @zones ) {
	my $frwd_ref = new_standard_chain "${zone}_frwd";
	my $exclusions = $zone_exclusions{$zone};

	if ( @$exclusions ) {
	    my $num = 1;
	    my $in_ref  = new_standard_chain "${zone}_input";
	    my $out_ref = new_standard_chain "${zone}_output";
	    
	    add_rule ensure_filter_chain( "${zone}2${zone}", 1 ) , '-j ACCEPT' if rules_target $zone, $zone eq 'ACCEPT';

	    for my $host ( @$exclusions ) {
		my ( $interface, $net ) = split /:/, $host;
		add_rule $frwd_ref , "-i $interface -s $net -j RETURN";
		add_rule $in_ref   , "-i $interface -s $net -j RETURN";
		add_rule $out_ref  , "-i $interface -s $net -j RETURN";
	    }
	    
	    if ( $capabilities{POLICY_MATCH} ) {
		my $type       = $zones{$zone};
		my $source_ref = $zone_hosts{ipsec} || [];

		create_zone_dyn_chain $zone, $frwd_ref && $config{DYNAMIC_ZONES} && (@$source_ref || $type ne 'ipsec4' );
		
		while ( my ( $interface, $arrayref ) = each %$source_ref ) {
		    for my $hostref ( @{$arrayref} ) {
			my $ipsec_match = match_ipsec_in $zone , $hostref;
			for my $net ( @{$hostref->{hosts}} ) {
			    add_rule
				find_chainref( 'filter' , forward_chain $interface ) , 
				match_source_net $net . $ipsec_match . "-j $frwd_ref->n{name}";
			}
		    }
		}
	    }   
	}
    }
    #
    # Main source-zone matrix-generation loop
    #
    for my $zone ( grep ( $zones{$_} ne 'firewall'  ,  @zones ) ) {
	my $source_hosts_ref = $zone_hosts{$zone};
	my $chain1         = rules_target $firewall_zone , $zone;
	my $chain2         = rules_target $zone, $firewall_zone;
	my $complex        = $zone_options{$zone}{complex} || 0; 
	my $type           = $zones{$zone};
	my $exclusions     = $zone_exclusions{$zone};
	my $need_broadcast = {}; ### Fixme ###
	my $frwd_ref       = 0; 
	my $chain          = 0;

	if ( $complex ) {
	    $frwd_ref = $filter_table->{"${zone}_frwd"};
	    my $dnat_ref = ensure_chain 'nat' , dnat_chain( $zone );
	    if ( @$exclusions ) {
		insert_exclusions $dnat_ref, $exclusions if $dnat_ref->{referenced};
	    }
	}
	#
	# Take care of PREROUTING, INPUT and OUTPUT jumps
	#
	for my $typeref ( values %$source_hosts_ref ) {
	    while ( my ( $interface, $arrayref ) = each %$typeref ) {
		for my $hostref ( @$arrayref ) {
		    my $ipsec_in_match  = match_ipsec_in  $zone , $hostref;
		    my $ipsec_out_match = match_ipsec_out $zone , $hostref; 
		    for my $net ( @{$hostref->{hosts}} ) {
			my $source = match_source_net $net;
			my $dest   = match_dest_net   $net;

			if ( $chain1 ) {
			    if ( @$exclusions ) {
				add_rule $filter_table->{output_chain $interface} , $dest . $ipsec_out_match . "-j ${zone}_output";
				add_rule $filter_table->{"${zone}_output"} , "-j $chain1";
			    } else {
				add_rule $filter_table->{output_chain $interface} , $dest . $ipsec_out_match . "-j $chain1";
			    }
			}
			
			insertnatjump 'PREROUTING' , dnat_chain $zone, \$prerouting_rule, ( "-i $interface " . $source . $ipsec_in_match );

			if ( $chain2 ) {
			    if ( @$exclusions ) {
				add_rule $filter_table->{input_chain $interface}, $source . $ipsec_in_match . "-j ${zone}_input";
				add_rule $filter_table->{"${zone}_input"} , "-j $chain2";
			    } else {
				add_rule $filter_table->{input_chain $interface}, $source . $ipsec_in_match . "-j $chain2";
			    }
			}

			add_rule $filter_table->{forward_chain $interface} , $source . $ipsec_in_match . "-j $frwd_ref->{name}"
			    if $complex && $hostref->{ipsec} ne 'ipsec';
		    }
		}
	    }
	}
	#
	#                           F O R W A R D I N G
	#
	my @dest_zones;
	my $last_chain = '';

	if ( $config{OPTIMIZE} > 0 ) {
	    my @temp_zones;

	  ZONE1:
	    for my $zone1 ( grep $zones{$_} ne 'firewall' , @zones )  {
		my $policy = $filter_table->{"${zone}2${zone1}"}->{policy};
		
		next if $policy  eq 'NONE';
		
		my $chain = rules_target $zone, $zone1;
		
		next unless $chain;

		if ( $zone eq $zone1 ) {
		    #
		    # One thing that the Llama fails to mention is that evaluating a hash in a numeric context produces a warning.
		    #
		    no warnings;
		    next if (  %{ $zone_interfaces{$zone}} < 2 ) && ! ( $zone_options{$zone}{routeback} || @$exclusions );
		}
		
		if ( $chain =~ /2all$/ ) {
		    if ( $chain ne $last_chain ) {
			$last_chain = $chain;
			push @dest_zones, @temp_zones;
			@temp_zones = ( $zone1 );
		    } elsif ( $policy eq 'ACCEPT' ) {
			push @temp_zones , $zone1;
		    } else {
			$last_chain = $chain;
			@temp_zones = ( $zone1 );
		    }
		} else {
		    push @dest_zones, @temp_zones, $zone1;
		    @temp_zones = ();
		    $last_chain = '';
		}
	    }
	    
	    if ( $last_chain && @temp_zones == 1 ) {
		push @dest_zones, @temp_zones;
		$last_chain = '';
	    }
	} else {
	    @dest_zones =  grep $zones{$_} ne 'firewall' , @zones ;
	}
	#
	# Here it is -- THE BIG UGLY!!!!!!!!!!!!
	#
	# We now loop through the destination zones creating jumps to the rules chain for each source/dest combination.
	# @dest_zones is the list of destination zones that we need to handle from this source zone
	#
      ZONE1:
	for my $zone1 ( @dest_zones ) {
	    my $policy = $filter_table->{"${zone}2${zone1}"}->{policy};

	    next if $policy  eq 'NONE';

	    my $chain = rules_target $zone, $zone1;

	    next unless $chain;
	    
	    my $num_ifaces = 0;
	    
	    if ( $zone eq $zone1 ) {
		#
		# One thing that the Llama fails to mention is that evaluating a hash in a numeric context produces a warning.
		#
		no warnings;
		next ZONE1 if ( $num_ifaces = %{$zone_interfaces{$zone}} ) < 2 && ! ( $zone_options{$zone}{routeback} || @$exclusions );
	    }

	    my $chainref    = $filter_table->{$chain};
	    my $exclusions1 = $zone_exclusions{$zone1};
	    
	    my $dest_hosts_ref = $zone_hosts{$zone1};
	    
	    if ( @$exclusions1 ) {
		if ( $chain eq "all2$zone1" ) {
		    unless ( $chain_exclusions{$chain} ) {
			$chain_exclusions{$chain} = 1;
			insert_exclusions $chainref , $exclusions1;
		    }
		} elsif ( $chain =~ /2all$/ ) {
		    my $chain1 = $policy_exclusions{"${chain}_${zone1}"};
		    
		    unless ( $chain ) {
			$chain1="excl_$exclseq";
			$exclseq++;
			$policy_exclusions{"${chain}_${zone1}"} = $chain1;
			my $chain1ref = ensure_filter_chain $chain1, 0;
			add_exclusions $chain1ref, $exclusions1;
			add_rule $chain1ref, "-j $chain";
		    }
		    
		    $chain = $chain1;
		} else {
		    insert_exclusions $chainref , $exclusions1;
		}
	    }
	    
	    if ( $complex ) {
		for my $typeref ( values %$dest_hosts_ref ) {
		    while ( my ( $interface , $arrayref ) = each %$typeref ) {
			for my $hostref ( @$arrayref ) {
			    if ( $zone ne $zone1 || $num_ifaces > 1 || $hostref->{options}{routeback} ) {
				my $ipsec_out_match = match_ipsec_out $zone1 , $hostref; 
				for my $net ( @{$hostref->{hosts}} ) {
				    add_rule $frwd_ref, "-o $interface " . match_dest_net($net) . $ipsec_out_match . "-j $chain";
				}
			    }
			}
		    }
		}
	    } else {
		for my $typeref ( values %$source_hosts_ref ) {
		    while ( my ( $interface , $arrayref ) = each %$typeref ) {
			my $chain3ref = $filter_table->{forward_chain $interface};
			for my $hostref ( @$arrayref ) {
			    for my $net ( @{$hostref->{hosts}} ) {
				my $source_match = match_source_net $net;
				for my $type1ref ( values %$dest_hosts_ref ) {
				    while ( my ( $interface1, $array1ref ) = each %$type1ref ) {
					for my $host1ref ( @$array1ref ) {
					    my $ipsec_out_match = match_ipsec_out $zone1 , $host1ref; 
					    for my $net1 ( @{$host1ref->{hosts}} ) {
						unless ( $interface eq $interface1 && $net eq $net1 && ! $host1ref->{options}{routeback} ) {
						    add_rule $chain3ref, "-o $interface1 " . $source_match . match_dest_net($net1) . $ipsec_out_match . "-j $chain";
						}
					    }
					}
				    }
				}
			    }
			}
		    }
		}
	    }
	    #
	    #                                      E N D   F O R W A R D I N G
	    #
	    # Now add (an) unconditional jump(s) to the last unique policy-only chain determined above, if any
	    #
	    if ( $last_chain ) {
		if ( $complex ) {
		    add_rule $frwd_ref , "-j $last_chain";
		} else {
		    for my $typeref ( values %$source_hosts_ref ) {
			while ( my ( $interface , $arrayref ) = each %$typeref ) {
			    my $chain2ref = $filter_table->{forward_chain $interface};
			    for my $hostref ( @$arrayref ) {
				for my $net ( @{$hostref->{hosts}} ) {
				    add_rule $chain2ref, match_source_net($net) .  "-j $last_chain";
				}
			    }
			}
		    }
		}
	    }
	}
    }
    #
    # Now add the jumps to the interface chains from FORWARD, INPUT, OUTPUT and POSTROUTING
    #
    for my $interface ( @interfaces ) {
	add_rule $filter_table->{FORWARD} , "-i $interface -j " . forward_chain $interface;
	add_rule $filter_table->{INPUT}   , "-i $interface -j " . input_chain $interface;
	add_rule $filter_table->{OUTPUT}  , "-o $interface -j " . output_chain $interface;
	addnatjump 'POSTROUTING' , masq_chain( $interface ) , "-o $interface ";
    }

    my $chainref = $filter_table->{"${firewall_zone}2${firewall_zone}"};

    add_rule $filter_table->{OUTPUT} , "-o lo -j " . ($chainref->{referenced} ? "$chainref->{name}" : 'ACCEPT' );
    add_rule $filter_table->{INPUT} , '-i lo -j ACCEPT';

    complete_standard_chain $filter_table->{INPUT}   , 'all' , $firewall_zone;
    complete_standard_chain $filter_table->{OUTPUT}  , $firewall_zone , 'all';
    complete_standard_chain $filter_table->{FORWARD} , 'all' , 'all';

    my %builtins = ( mangle => [ qw/PREROUTING INPUT FORWARD POSTROUTING/ ] ,
		     nat=>     [ qw/PREROUTING OUTPUT POSTROUTING/ ] ,
		     filter=>  [ qw/INPUT FORWARD OUTPUT/ ] );

    if ( $config{LOGALLNEW} ) {
	for my $table qw/mangle nat filter/ {
	    for my $chain ( @{$builtins{$table}} ) {
		log_rule_limit 
		    $config{LOGALLNEW} , 
		    $chain_table{$table}{$chain} ,
		    $table ,
		    $chain ,
		    '' ,
		    '' ,
		    'insert' ,
		    '-m state --state NEW';
	    }
	}
    }
}

sub create_iptables_restore_file() {
    print "#Generated by Shorewall $env{VERSION} - " . ( localtime ) . "\n";

    for my $table qw/raw nat mangle filter/ {
	print "*$table\n";
	my @chains;
	for my $chain ( grep $chain_table{$table}{$_}->{referenced} , ( sort keys %{$chain_table{$table}} ) ) {
	    my $chainref =  $chain_table{$table}{$chain};
	    if ( $chainref->{builtin} ) {
		print ":$chainref->{name} $chainref->{policy} [0:0]\n";
	    } else {
		print ":$chainref->{name} - [0:0]\n";
	    }

	    push @chains, $chainref;
	}

	for my $chainref ( @chains ) {
	    my $name = $chainref->{name};
	    for my $rule ( @{$chainref->{rules}} ) {
		print "-A $name $rule\n";
	    }
	}
	print "COMMIT\n";
    }
}
       
#
# Read the shorewall.conf file and establish global hashes %config and %env.
#
sub do_initialize() {
    ensure_config_path;

    my $file = find_file 'shorewall.conf';

    if ( -f $file ) {
	if ( -r _ ) {
	    open CONFIG , $file or fatal_error "Unable to open $file: $!";

	    while ( $line = <CONFIG> ) {
		chomp $line;
		next if $line =~ /^\s*#/;
		next if $line =~ /^\s*$/;

		if ( $line =~ /^([a-zA-Z]\w*)\s*=\s*(.*)$/ ) {
		    my ($var, $val) = ($1, $2);
		    unless ( exists $config{$var} ) {
			warning_message "Unknown configuration option \"$var\" ignored";
			next;
		    }

		    $config{$var} = $val =~ /\"([^\"]*)\"$/ ? $1 : $val;
		} else {
		    fatal_error "Unrecognized entry in $file: $line";
		}
	    }

	    close CONFIG;
	} else {
	    fatal_error "Cannot read $file (Hint: Are you root?)";
	}
    } else {
	fatal_error "$file does not exist!";
    }

    ensure_config_path;

    $file = find_file 'capabilities';

    if ( -f $file ) {
	if ( -r _ ) {
	    open CAPS , $file or fatal_error "Unable to open $file: $!";

	    while ( $line = <CAPS> ) {
		chomp $line;
		next if $line =~ /^\s*#/;
		next if $line =~ /^\s*$/;

		if ( $line =~ /^([a-zA-Z]\w*)\s*=\s*(.*)$/ ) {
		    my ($var, $val) = ($1, $2);
		    unless ( exists $capabilities{$var} ) {
			warning_message "Unknown capability \"$var\" ignored";
			next;
		    }

		    $capabilities{$var} = $val =~ /^\"([^\"]*)\"$/ ? $1 : $val;
		} else {
		    fatal_error "Unrecognized entry in $file: $line";
		}
	    }

	    close CAPS;

	} else {
	    fatal_error "Cannot read $file (Hint: Are you root?)";
	}
    } else {
	fatal_error "$file does not exist!";
    }

    if ( $ENV{DEBUG} ) {
	print "\n";
	print "Capabilities:\n";
	for my $var (sort keys %capabilities) {
	    print "   $var=$capabilities{$var}\n";
	}
    }

    $env{ORIGINAL_POLICY_MATCH} = $capabilities{POLICY_MATCH};

    default 'MODULE_PREFIX', 'o gz ko o.gz ko.gz';

    if ( $config{LOGRATE} || $config{LOGBURST} ) {
	$env{LOGLIMIT} = '-m limit';
	$env{LOGLIMIT} .= " --limit $config{LOGRATE}"        if $config{LOGRATE};
	$env{LOGLIMIT} .= " --limit-burst $config{LOGBURST}" if $config{LOGBURST};
    } else {
	$env{LOGLIMIT} = '';
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

    unless ( $config{IP_ADD_ALIASES} || $config{ADD_SNAT_ALIASES} ) {
	$config{RETAIN_ALIASES} = '';
    } else {
	default_yes_no 'RETAIN_ALIASES'             , '';
    }

    default_yes_no 'ADMINISABSENTMINDED'        , '';
    default_yes_no 'BLACKLISTNEWONLY'           , '';
    default_yes_no 'DISABLE_IPV6'               , '';
    default_yes_no 'DYNAMIC_ZONES'              , '';

    fatal_error "DYNAMIC_ZONES=Yes is incompatible with the -e option" if $config{DYNAMIC_ZONES} and $ENV{EXPORT};
    
    default_yes_no 'STARTUP_ENABLED'            , 'Yes';
    default_yes_no 'DELAYBLACKLISTLOAD'         , '';
    default_yes_no 'LOGTAGONLY'                 , '';
    default_yes_no 'RFC1918_STRICT'             , '';
    default_yes_no 'SAVE_IPSETS'                , '';
    default_yes_no 'MAPOLDACTIONS'              , '';
    default_yes_no 'FASTACCEPT'                 , '';
    default_yes_no 'IMPLICIT_CONTINUE'          , '';
    default_yes_no 'HIGH_ROUTE_MARKS'           , '';
    default_yes_no 'TC_EXPERT'                  , '';
    default_yes_no 'USE_ACTIONS'                , 'Yes';
    default_yes_no 'EXPORTPARAMS'               , '';

    $capabilities{XCONNMARK} = '' unless $capabilities{XCONNMARK_MATCH} and $capabilities{XMARK};

    fatal_error 'HIGH_ROUTE_MARKS=Yes requires extended MARK support' if $config{HIGH_ROUTE_MARKS} and ! $capabilities{XCONNMARK};

    default 'BLACKLIST_DISPOSITION'             , 'DROP';
    
    my $val;

    $env{MACLIST_TARGET} = 'reject';

    if ( $val = $config{MACLIST_DISPOSITION} ) {
	unless ( $val eq 'REJECT' ) {
	    if ( $val eq 'DROP' ) {
		$env{MACLIST_TARGET} = 'DROP';
	    } elsif ( $val eq 'ACCEPT' ) {
		$env{MACLIST_TARGET} = 'RETURN';
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
	
    $env{TC_SCRIPT} = '';

    if ( $val = "\L$config{TC_ENABLED}" ) {
	if ( $val eq 'yes' ) {
	    $file = find_file 'tcstart';
	    fatal_error "Unable to find tcstart file" unless -f $file;
	} elsif ( $val ne 'internal' ) {
	    fatal_error "Invalid value ($config{TC_ENABLED}) for TC_ENABLED" unless $val eq 'no';
	    $config{TC_ENABLED} = '';
	}
    }

    if ( $config{MANGLE_ENABLED} ) {
	fatal_error 'Traffic Shaping requires mangle support in your kernel and iptables' unless $capabilities{MANGLE_ENABLED};
    }

    default 'MARK_IN_FORWARD_CHAIN' , '';
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

    $env{MARKING_CHAIN} = $config{MARK_IN_FORWARD_CHAIN} ? 'tcfor' : 'tcpre';

    if ( $val = $config{LOGFORMAT} ) {
	my $result;

	eval {
	    if ( $val =~ /%d/ ) {
		$env{LOGRULENUMBERS} = 'Yes';
		$result = sprintf "$val", 'fooxx2barxx', 1, 'ACCEPT';
	    } else {
		$result = sprintf "$val", 'fooxx2barxx', 'ACCEPT';
	    }
	};

	fatal_error "Invalid LOGFORMAT ($val)" if $@;
	    
	fatal_error "LOGFORMAT string is longer than 29 characters: \"$val\"" 
	    if length $result > 29;

	$env{MAXZONENAMELENGTH} = int ( 5 + ( ( 29 - (length $result ) ) / 2) );
    } else {
	$env{LOGFORMAT}='Shorewall:%s:%s:';
	$env{MAXZONENAMELENGTH} = 5;
    }

    fatal_error "Shorewall $env{VERSION} requires Conntrack Match Support" unless $capabilities{CONNTRACK_MATCH};
    fatal_error "Shorewall $env{VERSION} requires Extended Multi-port Match Support" unless $capabilities{XMULTIPORT};
    fatal_error "Shorewall $env{VERSION} requires Address Type Match Support" unless $capabilities{ADDRTYPE};

    if ( $ENV{DEBUG} ) {
	print "\n";
	print "Configuration:\n";

	for my $var (sort keys %config) {
	    if ( defined $config{$var} ) {
		print "   $var=$config{$var}\n";
	    } else {
		print "   $var=\n";
	    }
	}

	print "\n";
	print "Environment:\n";

	for my $var (sort keys %env) {
	    print "   $var=$env{$var}\n" if $env{$var};
	}
    }

    initialize_chain_table;
}

sub compile_firewall() {
    #
    # Process the zones file.
    #
    progress_message2 "Determining Zones...";                    determine_zones;
    #
    # Process the interfaces file.
    #
    progress_message2 "Validating interfaces file...";           validate_interfaces_file;             dump_interface_info if $ENV{DEBUG};
    #
    # Process the hosts file.
    #
    progress_message2 "Validating hosts file...";                validate_hosts_file;

    if ( $ENV{DEBUG} ) {
	dump_zone_info;
    } else {
	progress_message "Determining Hosts in Zones...";        zone_report;
    }
    #
    # Do action pre-processing.
    #
    progress_message2 "Preprocessing Action Files...";           process_actions1;
    #
    # Process the Policy File.
    #
    progress_message2 "Validating Policy file...";               validate_policy;
    #
    # Do all of the zone-independent stuff
    #
    progress_message2 "Setting up Common Rules...";              add_common_rules;
    #
    # Setup Masquerading/SNAT
    #
    progress_message2 "Compiling Masq file...";                  setup_masq;
    #
    # MACLIST Filtration
    #
    progress_message2 "Setting up MAC Filtration -- Phase 1..."; setup_mac_lists 1;
    #
    # Process the rules file.
    #
    progress_message2 "Compiling Rules...";                      process_rules;
    #
    # Add Tunnel rules.
    #
    progress_message2 "Adding Tunnels...";                       setup_tunnels;
    #
    # Post-rules action processing.
    #
    process_actions2;
    process_actions3;
    #
    # MACLIST Filtration again
    #
    progress_message2 "Setting up MAC Filtration -- Phase 2..."; setup_mac_lists 2;
    #
    # Apply Policies
    #
    progress_message 'Applying Policies...';                     apply_policy_rules;                    dump_action_table if $ENV{DEBUG};
    #
    # Setup Nat
    #
    progress_message2 "Compiling one-to-one NAT...";             setup_nat;
    #
    # TCRules
    #
    progress_message2 "Processing TC Rules...";                  process_tcrules;
    #
    # Accounting.
    #
    progress_message2 "Setting UP Accounting...";                setup_accounting;
    #
    # Do the BIG UGLY...
    #
    progress_message2 "Generating Rule Matrix...";               generate_matrix;                       dump_chain_table if $ENV{DEBUG};
    #
    # Create the script.
    #
    progress_message2 "Creating iptables-restore file...";       create_iptables_restore_file;
}

#
#                                               E x e c u t i o n   S t a r t s   H e r e
#

$ENV{VERBOSE} = 2 if $ENV{DEBUG};
#
# Get shorewall.conf and capabilities.
#
do_initialize;

compile_firewall;
