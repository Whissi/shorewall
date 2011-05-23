#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Tunnels.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009,2010,2011 - Tom Eastep (teastep@shorewall.net)
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
#   This module handles the /etc/shorewall/tunnels file.
#
package Shorewall::Tunnels;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;
use Shorewall::IPAddrs;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::Rules;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( setup_tunnels );
our @EXPORT_OK = ( );
our $VERSION = '4.4_18';

#
# Here starts the tunnel stuff -- we really should get rid of this crap...
#
sub setup_tunnels() {

    our $fw = firewall_zone;

    sub setup_one_ipsec {
	my ($inchainref, $outchainref, $kind, $source, $dest, $gatewayzones) = @_;

	( $kind, my ( $qualifier , $remainder ) ) = split( /:/, $kind, 3 );

	my $noah = 1;

	fatal_error "Invalid IPSEC modifier ($qualifier:$remainder)" if defined $remainder;

	if ( defined $qualifier ) {
	    if ( $qualifier eq 'ah' ) {
		fatal_error ":ah not allowed with ipsecnat tunnels" if $kind eq 'ipsecnat';
		$noah = 0;
	    } else {
		fatal_error "Invalid IPSEC modifier ($qualifier)" if $qualifier ne 'noah';
	    }
	}

	my $options = $globals{UNTRACKED} ? "-m state --state NEW,UNTRACKED -j ACCEPT" : "$globals{STATEMATCH} NEW -j ACCEPT";

	add_tunnel_rule $inchainref,  "-p 50 $source -j ACCEPT";
	add_tunnel_rule $outchainref, "-p 50 $dest   -j ACCEPT";

	unless ( $noah ) {
	    add_tunnel_rule $inchainref,  "-p 51 $source -j ACCEPT";
	    add_tunnel_rule $outchainref, "-p 51 $dest   -j ACCEPT";
	}

	if ( $kind eq 'ipsec' ) {
	    add_tunnel_rule $inchainref,  "-p udp $source --dport 500 $options";
	    add_tunnel_rule $outchainref, "-p udp $dest   --dport 500 $options";
	} else {
	    add_tunnel_rule $inchainref,  "-p udp $source -m multiport --dports 500,4500 $options";
	    add_tunnel_rule $outchainref, "-p udp $dest   -m multiport --dports 500,4500 $options";
	}

	unless ( $gatewayzones eq '-' ) {
	    for my $zone ( split_list $gatewayzones, 'zone' ) {
		my $type = zone_type( $zone );
		fatal_error "Invalid zone ($zone) for GATEWAY ZONE" if $type == FIREWALL || $type == BPORT;
		$inchainref  = ensure_rules_chain( rules_chain( ${zone}, ${fw} ) );
		$outchainref = ensure_rules_chain( rules_chain( ${fw}, ${zone} ) );

		unless ( have_ipsec ) {
		    add_tunnel_rule $inchainref,  "-p 50 $source -j ACCEPT";
		    add_tunnel_rule $outchainref, "-p 50 $dest -j ACCEPT";

		    unless ( $noah ) {
			add_tunnel_rule $inchainref,  "-p 51 $source -j ACCEPT";
			add_tunnel_rule $outchainref, "-p 51 $dest -j ACCEPT";
		    }
		}

		if ( $kind eq 'ipsec' ) {
		    add_tunnel_rule $inchainref,  "-p udp $source --dport 500 $options";
		    add_tunnel_rule $outchainref, "-p udp $dest --dport 500 $options";
		} else {
		    add_tunnel_rule $inchainref,  "-p udp $source -m multiport --dports 500,4500 $options";
		    add_tunnel_rule $outchainref, "-p udp $dest -m multiport --dports 500,4500 $options";
		}
	    }
	}
    }

    sub setup_one_other {
	my ($inchainref, $outchainref, $source, $dest , $protocol) = @_;

	add_tunnel_rule $inchainref ,  "-p $protocol $source -j ACCEPT";
	add_tunnel_rule $outchainref , "-p $protocol $dest -j ACCEPT";
    }

    sub setup_pptp_client {
	my ($inchainref, $outchainref, $kind, $source, $dest ) = @_;

	add_tunnel_rule $outchainref,  "-p 47 $dest -j ACCEPT";
	add_tunnel_rule $inchainref,   "-p 47 $source -j ACCEPT";
	add_tunnel_rule $outchainref,  "-p tcp --dport 1723 $dest -j ACCEPT"
	}

    sub setup_pptp_server {
	my ($inchainref, $outchainref, $kind, $source, $dest ) = @_;

	add_tunnel_rule $inchainref,  "-p 47 $dest -j ACCEPT";
	add_tunnel_rule $outchainref, "-p 47 $source -j ACCEPT";
	add_tunnel_rule $inchainref,  "-p tcp --dport 1723 $dest -j ACCEPT"
	}

    sub setup_one_openvpn {
	my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

	my $protocol = 'udp';
	my $port     = 1194;

	( $kind, my ( $proto, $p, $remainder ) ) = split( /:/, $kind, 4 );

	fatal_error "Invalid port ($p:$remainder)" if defined $remainder;

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

	add_tunnel_rule $inchainref,  "-p $protocol $source --dport $port -j ACCEPT";
	add_tunnel_rule $outchainref, "-p $protocol $dest --dport $port -j ACCEPT";
    }

    sub setup_one_openvpn_client {
	my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

	my $protocol = 'udp';
	my $port     = 1194;

	( $kind, my ( $proto, $p , $remainder ) ) = split( /:/, $kind, 4 );

	fatal_error "Invalid port ($p:$remainder)" if defined $remainder;

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

	add_tunnel_rule $inchainref,  "-p $protocol $source --sport $port -j ACCEPT";
	add_tunnel_rule $outchainref, "-p $protocol $dest --dport $port -j ACCEPT";
    }

    sub setup_one_openvpn_server {
	my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

	my $protocol = 'udp';
	my $port     = 1194;

	( $kind, my ( $proto, $p , $remainder ) ) = split( /:/, $kind, 4 );

	fatal_error "Invalid port ($p:$remainder)" if defined $remainder;

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

	add_tunnel_rule $inchainref,  "-p $protocol $source --dport $port -j ACCEPT";
	add_tunnel_rule $outchainref, "-p $protocol $dest --sport $port -j ACCEPT";
    }

    sub setup_one_l2tp {
	my ($inchainref, $outchainref, $kind, $source, $dest) = @_;

	fatal_error "Unknown option ($1)" if $kind =~ /^.*?:(.*)$/;

	add_tunnel_rule $inchainref,  "-p udp $source --sport 1701 --dport 1701 -j ACCEPT";
	add_tunnel_rule $outchainref, "-p udp $dest   --sport 1701 --dport 1701 -j ACCEPT";
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

	add_tunnel_rule $inchainref,  "-p $protocol $source $port -j ACCEPT";
	add_tunnel_rule $outchainref, "-p $protocol $dest $port -j ACCEPT";
    }

    sub setup_one_tunnel($$$$) {
	my ( $kind , $zone, $gateway, $gatewayzones ) = @_;

	my $zonetype = zone_type( $zone );

	fatal_error "Invalid tunnel ZONE ($zone)" if $zonetype == FIREWALL || $zonetype == BPORT;

	my $inchainref  = ensure_rules_chain( rules_chain( ${zone}, ${fw} ) );
	my $outchainref = ensure_rules_chain( rules_chain( ${fw}, ${zone} ) );

	$gateway = ALLIP if $gateway eq '-';

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
			    'l2tp'          => { function => \&setup_one_l2tp ,          params   => [ $kind, $source, $dest ] } ,
			    'generic'       => { function => \&setup_one_generic ,       params   => [ $kind, $source, $dest ] } ,
			  );

	$kind = "\L$kind";

	(my $type) = split /:/, $kind;

	my $tunnelref = $tunneltypes{ $type };

	fatal_error "Tunnels of type $type are not supported" unless $tunnelref;

	$tunnelref->{function}->( $inchainref, $outchainref, @{$tunnelref->{params}} );

	progress_message "   Tunnel \"$currentline\" $done";
    }

    #
    # Setup_Tunnels() Starts Here
    #
    if ( my $fn = open_file 'tunnels' ) {

	first_entry "$doing $fn...";

	while ( read_a_line ) {

	    my ( $kind, $zone, $gateway, $gatewayzones ) = split_line1 2, 4, 'tunnels file';

	    if ( $kind eq 'COMMENT' ) {
		process_comment;
	    } else {
		setup_one_tunnel $kind, $zone, $gateway, $gatewayzones;
	    }
	}

	clear_comment;
    }
}

1;
