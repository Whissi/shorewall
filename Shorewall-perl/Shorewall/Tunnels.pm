#
# Shorewall-perl 3.9 -- /usr/share/shorewall-perl/Shorewall/Tunnels.pm
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
#   This module handles the /etc/shorewall/tunnels file.
#
package Shorewall::Tunnels;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Chains;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_tunnels );
our @EXPORT_OK = ( );
our @VERSION = 1.00;

#
# Here starts the tunnel stuff -- we really should get rid of this crap...
#
sub setup_tunnels() {

    sub setup_one_ipsec {
	my ($inchainref, $outchainref, $kind, $source, $dest, $gatewayzones) = @_;

	( $kind, my $qualifier ) = split /:/, $kind;

	fatal_error "Invalid IPSEC modifier ($qualifier)" if $qualifier && ( $qualifier ne 'noah' );

	my $noah = $qualifier || ($kind ne 'ipsec' );

	my $options = '-m state --state NEW -j ACCEPT';

	add_rule $inchainref,  "-p 50 $source -j ACCEPT";
	add_rule $outchainref, "-p 50 $dest   -j ACCEPT";

	unless ( $noah ) {
	    add_rule $inchainref,  "-p 51 $source -j ACCEPT";
	    add_rule $outchainref, "-p 51 $dest   -j ACCEPT";
	}

	add_rule $outchainref,  "-p udp $dest --dport 500 $options";

	if ( $kind eq 'ipsec' ) {
	    add_rule $inchainref, "-p udp $source --dport 500 $options";
	} else {
	    add_rule $inchainref,  "-p udp $source -m multiport --dports 500,4500 $options";
	    add_rule $outchainref, "-p udp $dest   -m multiport --dports 500,4500 $options";
	}

	unless ( $gatewayzones eq '-' ) {
	    for my $zone ( split /,/, $gatewayzones ) {
		fatal_error "Unknown zone ($zone)" unless $zones{$zone};
		fatal_error "Invalid zone ($zone)" unless $zones{$zone}{type} eq 'ipv4';
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
    }

    sub setup_one_other {
	my ($inchainref, $outchainref, $source, $dest , $protocol) = @_;

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

	if ( defined $p && $p ne '' ) {
	    $port = $p;
	    $protocol = $proto;
	} elsif ( defined $proto && $proto ne '' ) {
	    if ( "\L$proto" =~ /udp|tcp/ ) {
		$protocol = $proto;
	    } else {
		$port = $proto;
	    }
	}

	add_rule $inchainref,  "-p $protocol $source --dport $port -j ACCEPT";
	add_rule $outchainref, "-p $protocol $dest --dport $port -j ACCEPT";
    }

    sub setup_one_openvpn_client {
	my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

	my $protocol = 'udp';
	my $port     = 1194;

	( $kind, my ( $proto, $p ) ) = split /:/, $kind;

	if ( defined $p && $p ne '' ) {
	    $port = $p;
	    $protocol = $proto;
	} elsif ( defined $proto && $proto ne '' ) {
	    if ( "\L$proto" =~ /udp|tcp/ ) {
		$protocol = $proto;
	    } else {
		$port = $proto;
	    }
	}

	add_rule $inchainref,  "-p $protocol $source --sport $port -j ACCEPT";
	add_rule $outchainref, "-p $protocol $dest --dport $port -j ACCEPT";
    }

    sub setup_one_openvpn_server {
	my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

	my $protocol = 'udp';
	my $port     = 1194;

	( $kind, my ( $proto, $p ) ) = split /:/, $kind;

	if ( defined $p && $p ne '' ) {
	    $port = $p;
	    $protocol = $proto;
	} elsif ( defined $proto && $proto ne '' ) {
	    if ( "\L$proto" =~ /udp|tcp/ ) {
		$protocol = $proto;
	    } else {
		$port = $proto;
	    }
	}

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

	fatal_error "Unknown zone ($zone)" unless $zones{$zone};

	fatal_error "Invalid zone ($zone)" unless $zones{$zone}{type} eq 'ipv4';

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

	fatal_error "Tunnels of type $type are not supported" unless $tunnelref;

	$tunnelref->{function}->( $inchainref, $outchainref, @{$tunnelref->{params}} );

	progress_message "   Tunnel \"$line\" $done";
    }

    my $first_entry = 1;

    #
    # Setup_Tunnels() Starts Here
    #
    my $fn = open_file 'tunnels';

    while ( read_a_line ) {

	if ( $first_entry ) {
	    progress_message2 "$doing $fn...";
	    $first_entry = 0;
	}

	my ( $kind, $zone, $gateway, $gatewayzones ) = split_line 2, 4, 'tunnels file';

	if ( $kind eq 'COMMENT' ) {
	    process_comment;
	} else {
	    setup_one_tunnel $kind, $zone, $gateway, $gatewayzones;
	}
    }

    $comment = '';
}

1;
