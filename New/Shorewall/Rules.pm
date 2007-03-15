package Shorewall::Rules;
require Exporter;

use strict;

use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Chains;
use Shorewall::Zones;
use Shorewall::Interfaces;

our @ISA = qw(Exporter);
our @EXPORT = qw( STANDARD
		  NATRULE
		  BUILTIN
		  NONAT
		  NATONLY
		  REDIRECT
		  ACTION
		  MACRO
		  LOGRULE

		  do_proto
		  mac_match
		  numeric_value
		  verify_mark
		  verify_small_mark
		  validate_mark
		  do_test
		  do_ratelimit
		  do_user
		  iprange_match
		  match_source_net
		  match_dest_net
		  match_orig_dest
		  match_ipsec_in
		  match_ipsec_out
		  log_rule_limit
		  log_rule
		  expand_rule
		  addnatjump
		  insertnatjump

		  %targets
		  );
our @EXPORT_OK = ();
our @VERSION = 1.00;

#

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
# Convert value to decimal number
#
sub numeric_value ( $ ) {
    my $mark = $_[0];
    $mark =~ /^0x/ ? hex $mark : $mark =~ /^0/ ? oct $mark : $mark;
}

#
# Mark validatation functions
#
sub verify_mark( $ ) {
    my $mark  = $_[0];
    my $limit = $config{HIGH_ROUTE_MARKS} ? 0xFFFF : 0xFF;

    fatal_error "Invalid Mark or Mask value: $mark" 
	unless "\L$mark" =~ /^(0x[a-f0-9]+|0[0-7]*|[0-9]*)$/ && numeric_value( $mark ) <= $limit;
}

sub verify_small_mark( $ ) {
    verify_mark ( (my $mark) = $_[0] );
    fatal_error "Mark value ($mark) too large" if numeric_value( $mark ) > 0xFF;
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
    my $zoneref    = $zones{$zone};
    my $optionsref = $zoneref->{options};

    if ( $zoneref->{type} eq 'ipsec4' ) {
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
    my $zoneref    = $zones{$zone};
    my $optionsref = $zoneref->{options};

    if ( $zoneref->{type} eq 'ipsec4' ) {
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
sub expand_rule( $$$$$$$$$ )
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
	my $echain = newexclusionchain;
	
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

#
# If the destination chain exists, then at the end of the source chain add a jump to the destination.
#
sub addnatjump( $$$ ) {
    my ( $source , $dest, $predicates ) = @_;

    my $destref   = $nat_table->{$dest} || {};
    
    if ( $destref->{referenced} ) {
	add_rule $nat_table->{$source} , $predicates . "-j $dest";
    } else {
	clearrule;
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
	clearrule;
    }
}

1;
