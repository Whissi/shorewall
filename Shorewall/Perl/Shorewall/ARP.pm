#
# Shorewall 4.5 -- /usr/share/shorewall/Shorewall/ARP.pm
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2013 - Tom Eastep (teastep@shorewall.net)
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
#  This file is responsible for Shorewall's arptables support
#
package Shorewall::ARP;
require Exporter;

use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;
use Shorewall::IPAddrs;
use strict;

our @ISA = qw(Exporter);
our @EXPORT = ( qw( process_arprules create_arptables_load preview_arptables_load ) );

our %arp_table;
our $arp_input;
our $arp_output;
our $arp_forward;
our $sourcemac;
our $destmac;
our $addrlen;
our $hw;
our @builtins;
our $arptablesjf;
our @map = ( qw( 0 Request Reply Request_Reverse Reply_Reverse DRARP_Request DRARP_Reply DRARP_Error InARP_Request ARP_NAK ) );


#
# Handles the network and mac parts of the SOURCE ($source == 1 ) and DEST ($source == 0) columns in the arprules file.
# Returns any match(es) specified.
#
sub match_arp_net( $$$ ) {
    my ( $net, $mac, $source ) = @_;

    my $return = '';

    if ( supplied $net ) {
	my $invert = ( $net =~ s/^!// ) ? '! ' : '';
	validate_net $net, 0;
	$return = $source ? "-s ${invert}$net " : "-d ${invert}$net ";
    }

    if ( supplied $mac ) {
	my ( $addr , $mask ) = split( '/', $mac, 2 );

	my $invert = ( $addr =~ s/^!// ) ? '! ' : '';

	fatal_error "Invalid MAC address ($addr)" unless $addr =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
	if ( supplied $mask ) {
	    fatal_error "Invalid MAC Mask ($mask)" unless $mask =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
	    $return .= $source ? "$sourcemac $invert$addr/$mask " : "$destmac $invert$addr/mask ";
	} else {
	    $return .= $source ? "$sourcemac $invert$addr " : "$destmac $invert$addr ";
	}
    }

    $return;
}

#
# Process a rule in the arprules file
#
sub process_arprule() {
    my ( $originalaction, $source, $dest, $opcode ) = split_line( 'arprules file entry', {action => 0, source => 1, dest => 2, opcode => 3 } );

    my $chainref;
    my $iifaceref;
    my $iiface;
    my $difaceref;
    my $diface;
    my $saddr;
    my $smac;
    my $daddr;
    my $dmac;
    my $rule = '';

    fatal_error "ACTION must be specified" if $originalaction eq '-';

    my ( $action, $newaddr ) = split( ':', $originalaction, 2 );

    my %functions = ( DROP   => sub() { $rule .= "-j DROP" },
		      ACCEPT => sub() { $rule .= "-j ACCEPT" },
		      SNAT   => sub() { validate_address $newaddr, 0;
					$rule .= "-j mangle --mangle-ip-s $newaddr"; },
		      DNAT   => sub() { validate_address $newaddr, 0;
					$rule .= "-j mangle --mangle-ip-d $newaddr"; },
		      SMAT   => sub() { fatal_error "Invalid MAC address ($newaddr)" unless $newaddr =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
					$rule .= "$addrlen 6 -j mangle --mangle-$hw-s $newaddr"; },
		      DMAT   => sub() { fatal_error "Invalid MAC address ($newaddr)" unless $newaddr =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
					$rule .= "$addrlen 6 -j mangle --mangle-$hw-d $newaddr"; },
		      SNATC  => sub() { validate_address $newaddr, 0;
					$rule .= "-j mangle --mangle-ip-s $newaddr --mangle-target CONTINUE"; },
		      DNATC  => sub() { validate_address $newaddr, 0;
					$rule .= "-j mangle --mangle-ip-d $newaddr --mangle-target CONTINUE"; },
		      SMATC  => sub() { fatal_error "Invalid MAC address ($newaddr)" unless $newaddr =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
					$rule .= "$addrlen 6 -j mangle --mangle-$hw-s $newaddr --mangle-target CONTINUE"; },
		      DMATC  => sub() { fatal_error "Invalid MAC address ($newaddr)" unless $newaddr =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
					$rule .= "$addrlen 6 -j mangle --mangle-$hw-d $newaddr --mangle-target CONTINUE"; },
		    );

    if ( supplied $newaddr ) {
	fatal_error "The $action ACTION does not allow a new address" unless $action =~ /^(?:SNAT|DNAT|SMAT|DMAT)C?$/;
    } else {
	fatal_error "The $action ACTION requires a new address" if $action =~ /^SNAT|DNAT|SMAT|DMAT$/;
    }

    my $function = $functions{$action};

    fatal_error "Unknown ACTION ($action)" unless $function;

    if ( $source ne '-' ) {
	( $iiface, $saddr, $smac ) = split /:/, $source, 3;

	fatal_error "SOURCE interface missing" unless supplied $iiface; 

	$iiface = ( $iifaceref = find_interface( $iiface ) )->{physical};

	fatal_error "Wildcard Interfaces ( $iiface )may not be used in this context" if $iiface =~ /\+$/;

	$rule .= "-i $iiface ";
	$rule .= match_arp_net( $saddr , $smac, 1 ) if supplied( $saddr );
	$chainref = $arp_input;
    }

    if ( $dest ne '-' ) {
	( $diface, $daddr, $dmac ) = split /:/, $dest, 3;

	fatal_error "DEST interface missing" unless supplied $diface; 

	$diface = ( $difaceref = find_interface( $diface ) )->{physical};

	fatal_error "A wildcard interfaces ( $diface) may not be used in this context" if $diface =~ /\+$/;

	if ( $iiface ) {
	    fatal_error "When both SOURCE and DEST are given, the interfaces must be ports on the same bridge"
		if $iifaceref->{bridge} ne $difaceref->{bridge};
	    $chainref = $arp_forward;
	} else {
	    $chainref = $arp_output;
	}

	$rule .= "-o $diface ";
	$rule .= match_arp_net( $daddr , $dmac, 0 ) if supplied( $daddr );

    }

    if ( $opcode ne '-' ) {
	my $invert = ( $opcode =~ s/^!// ) ? '! ' : '';
	warning_message q(arptables versions through 0.3.4 ignore '!' after '--opcode') if $invert && ! $arptablesjf;
	fatal_error "Invalid ARP OPCODE ($opcode)" unless $opcode =~ /^\d$/ && $opcode;
	$rule .= $arptablesjf ? " --arpop ${invert}$map[$opcode] " : "--opcode ${invert}$opcode ";
    }

    $function ->();

    fatal_error "Either SOURCE or DEST must be specified" unless $chainref;

    push @$chainref, $rule;

}

#
# Process the arprules file -- returns true if there were any arp rules
#
sub process_arprules() {
    my $result = 0;

    if ( $arptablesjf = have_capability 'ARPTABLESJF' ) {
	$arp_input  = $arp_table{IN}       = [];
	$arp_output = $arp_table{OUT}      = [];
	$arp_forward = $arp_table{FORWARD} = [];
	@builtins = qw( IN OUT FORWARD );
	$sourcemac = '-z';
	$destmac   = '-y';
	$addrlen   = '--arhln';
	$hw        = 'hw';
    } else {
	$arp_input   = $arp_table{INPUT}   = [];
	$arp_output  = $arp_table{OUTPUT}  = [];
	$arp_forward = $arp_table{FORWARD} = [];
	@builtins = qw( INPUT OUTPUT FORWARD );
	$sourcemac = '--source-mac';
	$destmac   = '--destination-mac';
	$addrlen   = '--h-length';
	$hw        = 'mac';
    }

    my $fn = open_file 'arprules';

    if ( $fn ) {
	first_entry( sub() {
			 $result = 1;
			 progress_message2 "$doing $fn..."; }
		   );
	process_arprule while read_a_line( NORMAL_READ );
    }

    $result;
}

#
# Generate the arptables_load() function
#
sub create_arptables_load( $ ) {
    my $test = shift;

    emit ( '#',
	   '# Create the input to arptables-restore and pass that input to the utility',
	   '#',
	   'setup_arptables()',
	   '{'
	   );

    push_indent;

    save_progress_message "Preparing arptables-restore input...";

    emit '';

    emit "exec 3>\${VARDIR}/.arptables-input";

    my $date = localtime;

    unless ( $test ) {
	emit_unindented '#';
	emit_unindented "# Generated by Shorewall $globals{VERSION} - $date";
	emit_unindented '#';
    }

    emit '';
    emit 'cat >&3 << __EOF__';

    emit_unindented "*filter";

    emit_unindented ":$_ ACCEPT" for @builtins;

    for ( @builtins ) {
	my $rules = $arp_table{$_};

	while ( my $rule = shift @$rules ) {
	    emit_unindented "-A $_ $rule";
	}
    }

    emit_unindented "COMMIT\n" if $arptablesjf;

    emit_unindented "__EOF__";

    #
    # Now generate the actual ip[6]tables-restore command
    #
    emit(  'exec 3>&-',
	   '',
	   'progress_message2 "Running $ARPTABLES_RESTORE..."',
	   '',
	   'cat ${VARDIR}/.arptables-input | $ARPTABLES_RESTORE # Use this nonsensical form to appease SELinux',
	   'if [ $? != 0 ]; then',
	   qq(    fatal_error "arptables-restore Failed. Input is in \${VARDIR}/.arptables-input"),
	   "fi\n",
	   "run_ip neigh flush nud noarp nud stale nud reachable\n",
	   );    

    pop_indent;
    emit "}\n";
}	  

#
# Preview the generated ARP rules
#
sub preview_arptables_load() {

    my $date = localtime;

    print "#\n# Generated by Shorewall $globals{VERSION} - $date\n#\n";

    print "*filter\n";

    print ":$_ ACCEPT\n" for qw( INPUT OUTPUT FORWARD );

    for ( @builtins ) {
	my $rules = $arp_table{$_};

	while ( my $rule = shift @$rules ) {
	    print "-A $rule\n";
	}
    }

    print "COMMIT\n" if $arptablesjf;

    print "\n";
}	  

1;
