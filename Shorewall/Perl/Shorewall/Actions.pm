#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Actions.pm
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
#  This module contains the action variables and routines needed by both the Policy 
#  and rules modules.
#
package Shorewall::Actions;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Scalar::Util 'reftype';

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		  split_action
		  get_target_param
		  normalize_action
		  normalize_action_name
		  createactionchain
		  %actions   
		  %usedactions
		  %logactionchains
		  %default_actions
		  );
our @EXPORT_OK = qw( initialize );
our $VERSION = '4.4_16';

#
#  Used Actions. Each action that is actually used has an entry with value 1.
#
our %usedactions;
#
# Default actions for each policy.
#
our %default_actions;

#  Action Table
#
#     %actions{ <action1> =>  { requires => { <requisite1> = 1,
#                                             <requisite2> = 1,
#                                             ...
#                                           } ,
#                               actchain => <action chain number> # Used for generating unique chain names for each <level>:<tag> pair.
#
our %actions;
#
# Contains an entry for each used <action>:<level>[:<tag>] that maps to the associated chain.
#
our %logactionchains;

our $family;

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

    $family           = shift;
    %usedactions      = ();
    %default_actions  = ( DROP     => 'none' ,
		 	  REJECT   => 'none' ,
			  ACCEPT   => 'none' ,
			  QUEUE    => 'none' );
    %actions          = ();
    %logactionchains  = ();
}

#
# Return ( action, level[:tag] ) from passed full action
#
sub split_action ( $ ) {
    my $action = $_[0];

    my $target = '';
    my $max    = 3;
    #
    # The following rather grim RE, when matched, breaks the action into two parts:
    #
    #    basicaction(param)
    #    logging part (may be empty)
    #
    # The param may contain one or more ':' characters
    #
    if ( $action =~ /^([^(:]+\(.*?\))(:(.*))?$/ ) {
	$target = $1;
	$action = $2 ? $3 : '';
	$max    = 2;
    }

    my @a = split( /:/ , $action, 4 );
    fatal_error "Invalid ACTION ($action)" if ( $action =~ /::/ ) || ( @a > $max );
    $target = shift @a unless $target;
    ( $target, join ":", @a );
}

# Split the passed target into the basic target and parameter
#
sub get_target_param( $ ) {
    my ( $target, $param ) = split '/', $_[0];

    unless ( defined $param ) {
	( $target, $param ) = ( $1, $2 ) if $target =~ /^(.*?)[(](.*)[)]$/;
    }

    ( $target, $param );
}

#
# Create a normalized action name from the passed pieces
#
sub normalize_action( $$ ) {
    my $target = shift;
    my $param  = shift;

    my ($action, $level, $tag ) = split /:/, $target;

    $level = 'none' unless defined $level && $level ne '';
    $tag   = ''     unless defined $tag;
    $param = ''     unless defined $param;

    ( $action, $level, $tag, $param );
}

sub normalize_action_name( $$ ) {
    join (':', &normalize_action( @_ ) );
} 

#
# Create and record a log action chain -- Log action chains have names
# that are formed from the action name by prepending a "%" and appending
# a 1- or 2-digit sequence number. In the functions that follow,
# the $chain, $level and $tag variable serves as arguments to the user's
# exit. We call the exit corresponding to the name of the action but we
# set $chain to the name of the iptables chain where rules are to be added.
# Similarly, $level and $tag contain the log level and log tag respectively.
#
# The maximum length of a chain name is 30 characters -- since the log
# action chain name is 2-3 characters longer than the base chain name,
# this function truncates the original chain name where necessary before
# it adds the leading "%" and trailing sequence number.
#
sub createlogactionchain( $$ ) {
    my ( $action, $level ) = @_;
    my $chain = $action;
    my $actionref = $actions{$action};
    my $chainref;

    my ($lev, $tag) = split ':', $level;

    validate_level $lev;

    $actionref = new_action $action unless $actionref;

    $chain = substr $chain, 0, 28 if ( length $chain ) > 28;

  CHECKDUP:
    {
	$actionref->{actchain}++ while $chain_table{filter}{'%' . $chain . $actionref->{actchain}};
	$chain = substr( $chain, 0, 27 ), redo CHECKDUP if ( $actionref->{actchain} || 0 ) >= 10 and length $chain == 28;
    }

    $logactionchains{"$action:$level"} = $chainref = new_standard_chain '%' . $chain . $actionref->{actchain}++;

    fatal_error "Too many invocations of Action $action" if $actionref->{actchain} > 99;

    unless ( $targets{$action} & BUILTIN ) {

	dont_optimize $chainref;

	my $file = find_file $chain;

	if ( -f $file ) {
	    progress_message "Processing $file...";

	    ( $level, my $tag ) = split /:/, $level;

	    $tag = $tag || '';

	    unless ( my $return = eval `cat $file` ) {
		fatal_error "Couldn't parse $file: $@" if $@;
		fatal_error "Couldn't do $file: $!"    unless defined $return;
		fatal_error "Couldn't run $file"       unless $return;
	    }
	}
    }

    $chainref;
}

sub createsimpleactionchain( $ ) {
    my $action  = shift;
    my $chainref = new_standard_chain $action;

    $logactionchains{"$action:none"} = $chainref;

    unless ( $targets{$action} & BUILTIN ) {

	dont_optimize $chainref;

	my $file = find_file $action;

	if ( -f $file ) {
	    progress_message "Processing $file...";

	    my ( $level, $tag ) = ( '', '' );

	    unless ( my $return = eval `cat $file` ) {
		fatal_error "Couldn't parse $file: $@" if $@;
		fatal_error "Couldn't do $file: $!"    unless defined $return;
		fatal_error "Couldn't run $file"       unless $return;
	    }
	}
    }

    $chainref;
}

#
# Create an action chain and run its associated user exit
#
sub createactionchain( $ ) {
    my ( $action , $level ) = split_action $_[0];

    my $chainref;

    if ( defined $level && $level ne '' ) {
	if ( $level eq 'none' ) {
	    createsimpleactionchain $action;
	} else {
	    createlogactionchain $action , $level;
	}
    } else {
	createsimpleactionchain $action;
    }
}

1;
