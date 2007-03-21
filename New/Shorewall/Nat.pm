#
# Shorewall 3.9 -- /usr/share/shorewall/Shorewall/Nat.pm
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
package Shorewall::Nat;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Chains;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_masq setup_nat );
our @EXPORT_OK = ();
our @VERSION = 1.00;

my @addresses_to_add;
my %addresses_to_add;

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
	$add_snat_aliases = 0;
	$destnets = $2;
	$fullinterface = $1;
    } elsif ( $fullinterface =~ /^([^:]+:[^:]+):([^:]+)$/ ) {
	$destnets = $2;
	$fullinterface = $1;
    } elsif ( $fullinterface =~ /^([^:]+):$/ ) {
	$add_snat_aliases = 0;
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

    fatal_error "Unknown interface $interface, rule \"$line\"" unless $interfaces{$interface}{root};

    my $chainref = ensure_chain('nat', $pre_nat ? snat_chain $interface : masq_chain $interface);
    #
    # If there is no source or destination then allow all addresses
    #
    $networks = ALLIPv4 unless $networks;
    $destnets = ALLIPv4 unless $destnets;

    #
    # Handle Protocol and Ports
    #
    $rule .= do_proto $proto, $ports, '';
	
    my $detectaddress = 0;
    #
    # Parse the ADDRESSES column
    #
    if ( $addresses ) {
	if ( $addresses =~ /^SAME:nodst:/ ) {
	    $target = '-j SAME --nodst';
	    $addresses =~ s/.*://;
	    for my $addr ( split /,/, $addresses ) {
		$target .= "--to $addr ";
	    }
	} elsif ( $addresses =~ /^SAME:nodst:/ ) {
	    $target = '-j SAME ';
	    $addresses =~ s/.*://;
	    for my $addr ( split /,/, $addresses ) {
		$target .= "--to $addr ";
	    }
	} elsif ( $addresses eq 'detect' ) {
	    $target = '-j SNAT $addrlist';
	    add_command( $chainref , "addresses=\$(find_interface_addresses $interface); \\" );
	    add_command( $chainref , qq([ -z "\$addresses" ] && fatal_error "Unable to determine the IP address(es) of $interface"; \\) );
	    add_command( $chainref , 'addrlist=; \\' );
	    add_command( $chainref , 'for address in $addresses; do \\' );
	    add_command( $chainref , '    addrlist="$addrlist --to-source $address \\";' );
	    add_command( $chainref , 'done' );
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
    } else {
	$add_snat_aliases = 0;
    }
    #
    # And Generate the Rule(s)
    #
    expand_rule $chainref , POSTROUTE_RESTRICT , $rule, $networks, $destnets, '', $target, '', '' , '';


    progress_message "   Masq record \"$line\" $done";
    
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

#
# Process a record from the NAT file
#
sub do_one_nat( $$$$$ )
{
    my ( $external, $interface, $internal, $allints, $localnat ) = @_;

    sub add_nat_rule( $$ ) {
	add_rule ensure_chain( 'nat', $_[0] ) , $_[1];
    }
    
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
    progress_message "   NAT entry \"$line\" $done";
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
