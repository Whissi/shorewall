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
#   This module contains the code for dealing with actions (built-in,
#   standard and user-defined) and Macros. It also contains process_rule_common() which
#   performs low-level rule processing.
#
package Shorewall::Actions;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::IPAddrs;
use Shorewall::Policy;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( merge_levels
		  isolate_basic_target
		  get_target_param
		  add_requiredby
		  createactionchain
		  find_logactionchain
		  process_actions1
		  process_actions2
		  process_actions3
		  process_rule_common

		  find_macro
		  split_action
		  substitute_param
		  merge_macro_source_dest
		  merge_macro_column
		  map_old_actions

		  %usedactions
		  %default_actions
		  %actions

		  %macros
		  $macro_commands
		  );
our @EXPORT_OK = qw( initialize );
our $VERSION = '4.4_13';

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

our %macros;

our $family;

our @builtins;

#
# Commands that can be embedded in a macro file and how many total tokens on the line (0 => unlimited).
#
our $macro_commands = { COMMENT => 0, FORMAT => 2 };

use constant { MAX_MACRO_NEST_LEVEL => 5 };

our $macro_nest_level;

#
# When splitting a line in the rules file, don't pad out the columns with '-' if the first column contains one of these
#

my %rules_commands = ( COMMENT => 0,
		       SECTION => 2 );


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
    %macros           = ();
    $macro_nest_level = 0;

    if ( $family == F_IPV4 ) {
	@builtins = qw/dropBcast allowBcast dropNotSyn rejNotSyn dropInvalid allowInvalid allowinUPnP forwardUPnP Limit/;
    } else {
	@builtins = qw/dropBcast allowBcast dropNotSyn rejNotSyn dropInvalid allowInvalid/;
    }
}

#
# This function determines the logging for a subordinate action or a rule within a superior action
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
	return "$target:$level:$tag";
    }

    if ( @supparts == 2 ) {
	return "$target:none!"        if $level eq 'none!';
	return "$target:$level"       if ($level =~ /!$/) || ($subparts < 2);
    }

    $subordinate;
}

#
# Try to find a macro file -- RETURNS false if the file doesn't exist or MACRO if it does.
# If the file exists, the macro is entered into the 'targets' table and the fully-qualified
# name of the file is stored in the 'macro' table.
#
sub find_macro( $ )
{
    my $macro = $_[0];
    my $macrofile = find_file "macro.$macro";

    if ( -f $macrofile ) {
	$macros{$macro} = $macrofile;
	$targets{$macro} = MACRO;
    } else {
	0;
    }
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

#
# This function substitutes the second argument for the first part of the first argument up to the first colon (":")
#
# Example:
#
#         substitute_param DNAT PARAM:info:FTP
#
#         produces "DNAT:info:FTP"
#
sub substitute_param( $$ ) {
    my ( $param, $action ) = @_;

    if ( $action =~ /:/ ) {
	my $logpart = (split_action $action)[1];
	$logpart =~ s!/$!!;
	return "$param:$logpart";
    }

    $param;
}

#
# Combine fields from a macro body with one from the macro invocation
#
sub merge_macro_source_dest( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( $invocation ) {
	if ( $body ) {
	    return $body if $invocation eq '-';
	    return "$body:$invocation" if $invocation =~ /.*?\.*?\.|^\+|^!+|^~|^!~|~<|~\[/;
	    return "$invocation:$body";
	}

	return $invocation;
    }

    $body || '';
}

sub merge_macro_column( $$ ) {
    my ( $body, $invocation ) = @_;

    if ( defined $invocation && $invocation ne '' && $invocation ne '-' ) {
	$invocation;
    } else {
	$body;
    }
}

#
# Get Macro Name -- strips away trailing /*, :* and (*) from the first column in a rule, macro or action.
#
sub isolate_basic_target( $ ) {
    my $target = ( split '[/:]', $_[0])[0];

    $target =~ /^(\w+)[(].*[)]$/ ? $1 : $target;
}

#
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
# Define an Action
#
sub new_action( $ ) {

    my $action = $_[0];

    $actions{$action} = { actchain => '', requires => {} };
}

#
# Record a 'requires' relationship between a pair of actions.
#
sub add_requiredby ( $$ ) {
    my ($requiredby , $requires ) = @_;
    $actions{$requires}{requires}{$requiredby} = 1;
}

#
# Map pre-3.0 actions to the corresponding Macro invocation
#

sub find_old_action ( $$$ ) {
    my ( $target, $macro, $param ) = @_;

    if ( my $actiontype = find_macro( $macro ) ) {
	( $macro, $actiontype , $param );
    } else {
	( $target, 0, '' );
    }
}

sub map_old_actions( $ ) {
    my $target = shift;

    if ( $target =~ /^Allow(.*)$/ ) {
	find_old_action( $target, $1, 'ACCEPT' );
    } elsif ( $target =~ /^Drop(.*)$/ ) {
	find_old_action( $target, $1, 'DROP' );
    } elsif ( $target = /^Reject(.*)$/ ) {
	find_old_action( $target, $1, 'REJECT' );
    } else {
	( $target, 0, '' );
    }
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
# Scans a macro file invoked from an action file ensuring that all targets mentioned in the file are known and that none are actions.
#
sub process_macro1 ( $$ ) {
    my ( $action, $macrofile ) = @_;

    my $nat;

    progress_message "   ..Expanding Macro $macrofile...";

    push_open( $macrofile );

    while ( read_a_line ) {
	my ( $mtarget, $msource,  $mdest,  $mproto,  $mports,  $msports, $morigdest, $mrate, $muser ) = split_line1 1, 9, 'macro file', $macro_commands;

	next if $mtarget eq 'COMMENT' || $mtarget eq 'FORMAT';

	$mtarget =~ s/:.*$//;

	$mtarget = (split '/' , $mtarget)[0];

	my $targettype = $targets{$mtarget};

	$targettype = 0 unless defined $targettype;

	fatal_error "Invalid target ($mtarget)"
	    unless ( $targettype == STANDARD ) || ( $mtarget eq 'PARAM' ) || ( $targettype & ( LOGRULE | NFQ | CHAIN | NATRULE ) );

	$nat ||= ( $targettype & NATRULE );
    }

    progress_message "   ..End Macro $macrofile";

    pop_open;

    $nat;
}

#
# The functions process_actions1-3() implement the three phases of action processing.
#
# The first phase (process_actions1) occurs before the rules file is processed. The builtin-actions are added
# to the target table (%Shorewall::Chains::targets) and actions table, then ${SHAREDIR}/actions.std and
# ${CONFDIR}/actions are scanned (in that order). For each action:
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
# The final phase (process_actions3) traverses the keys of %usedactions populating each chain appropriately
# by reading the related action definition file and creating rules. Note that a given action definition file is
# processed once for each unique [:level[:tag]] applied to an invocation of the action.
#

sub process_action1 ( $$ ) {
    my ( $action, $wholetarget ) = @_;

    my ( $target, $level ) = split_action $wholetarget;

    $level = 'none' unless $level;

    my $targettype = $targets{$target};

    if ( defined $targettype ) {
	return if ( $targettype == STANDARD ) || ( $targettype & ( MACRO | LOGRULE |  NFQ | CHAIN ) );

	fatal_error "Invalid TARGET ($target)" if $targettype & STANDARD;

	fatal_error "An action may not invoke itself" if $target eq $action;

	add_requiredby $wholetarget, $action if $targettype & ACTION;
    } elsif ( $target eq 'COMMENT' ) {
	fatal_error "Invalid TARGET ($wholetarget)" unless $wholetarget eq $target;
    } else {
	( $target, my $param ) = get_target_param $target;

	return if $target eq 'NFQUEUE';

	if ( defined $param ) {
	    my $paramtype = $targets{$param} || 0;

	    fatal_error "Parameter value not allowed in action files ($param)" if $paramtype & NATRULE;
	}

	fatal_error "Invalid or missing ACTION ($wholetarget)" unless defined $target;

	if ( find_macro $target ) {
	    process_macro1( $action, $macros{$target} );
	} else {
	    fatal_error "Invalid TARGET ($target)";
	}
    }
}

sub process_actions1() {

    progress_message2 "Preprocessing Action Files...";
    #
    # Add built-in actions to the target table and create those actions
    #
    $targets{$_} = ACTION + BUILTIN, new_action( $_ ) for @builtins;

    for my $file ( qw/actions.std actions/ ) {
	open_file $file;

	while ( read_a_line ) {
	    my ( $action ) = split_line 1, 1, 'action file';

	    if ( $action =~ /:/ ) {
		warning_message 'Default Actions are now specified in /etc/shorewall/shorewall.conf';
		$action =~ s/:.*$//;
	    }

	    next unless $action;

	    if ( $targets{$action} ) {
		warning_message "Duplicate Action Name ($action) Ignored" unless $targets{$action} & ACTION;
		next;
	    }

	    $targets{$action} = ACTION;

	    fatal_error "Invalid Action Name ($action)" unless "\L$action" =~ /^[a-z]\w*$/;

	    new_action $action;

	    my $actionfile = find_file "action.$action";

	    fatal_error "Missing Action File ($actionfile)" unless -f $actionfile;

	    progress_message2 "   Pre-processing $actionfile...";

	    push_open( $actionfile );

	    while ( read_a_line ) {

		my ($wholetarget, $source, $dest, $proto, $ports, $sports, $rate, $users, $mark ) = split_line 1, 9, 'action file';

		process_action1( $action, $wholetarget );

	    }

	    pop_open;
	}
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
	    assert( $actionref );
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

#
# This function is called to process each rule generated from an action file.
#
sub process_action( $$$$$$$$$$$ ) {
    my ($chainref, $actionname, $target, $source, $dest, $proto, $ports, $sports, $rate, $user, $mark ) = @_;

    my ( $action , $level ) = split_action $target;

    if ( $action eq 'REJECT' ) {
	$action = 'reject';
    } elsif ( $action eq 'CONTINUE' ) {
	$action = 'RETURN';
    } elsif ( $action =~ /^NFQUEUE/ ) {
	( $action, my $param ) = get_target_param $action;
	$param = 1 unless defined $param;
	$action = "NFQUEUE --queue-num $param";
    } elsif ( $action eq 'COUNT' ) {
	$action = '';
    }

    expand_rule ( $chainref ,
		  NO_RESTRICT ,
		  do_proto( $proto, $ports, $sports ) . do_ratelimit( $rate, $action ) . do_user $user . do_test( $mark, $globals{TC_MASK} ) ,
		  $source ,
		  $dest ,
		  '', #Original Dest
		  $action ,
		  $level ,
		  $action ,
		  '' );
}

#
# Expand Macro in action files.
#
sub process_macro3( $$$$$$$$$$$$ ) {
    my ( $macro, $param, $chainref, $action, $source, $dest, $proto, $ports, $sports, $rate, $user, $mark ) = @_;

    my $nocomment = no_comment;

    my $format = 1;

    macro_comment $macro;

    my $fn = $macros{$macro};

    progress_message "..Expanding Macro $fn...";

    push_open $fn;

    while ( read_a_line ) {

	my ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $morigdest, $mrate, $muser, $mmark );

	if ( $format == 1 ) {
	    ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split_line1 1, 8, 'macro file', $macro_commands;
	    $morigdest = '-';
	    $mmark     = '-';
	} else {
	    ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $morigdest, $mrate, $muser, $mmark ) = split_line1 1, 10, 'macro file', $macro_commands;
	}

	if ( $mtarget eq 'COMMENT' ) {
	    process_comment unless $nocomment;
	    next;
	}

	if ( $mtarget eq 'FORMAT' ) {
	    fatal_error "Invalid FORMAT ($msource)" unless $msource =~ /^[12]$/;
	    $format = $msource;
	    next;
	}

	if ( $mtarget =~ /^PARAM:?/ ) {
	    fatal_error 'PARAM requires that a parameter be supplied in macro invocation' unless $param;
	    $mtarget = substitute_param $param,  $mtarget;
	}

	fatal_error "Macros used within Actions may not specify an ORIGINAL DEST " if $morigdest ne '-';

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

	$mdest   = '' if $mdest eq '-';

	$mproto  = merge_macro_column $mproto,  $proto;
	$mports  = merge_macro_column $mports,  $ports;
	$msports = merge_macro_column $msports, $sports;
	$mrate   = merge_macro_column $mrate,   $rate;
	$muser   = merge_macro_column $muser,   $user;
	$mmark   = merge_macro_column $mmark,   $mark;

	process_action $chainref, $action, $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser, $mark;
    }

    pop_open;

    progress_message '..End Macro';

    clear_comment unless $nocomment;
}

#
# Generate chain for non-builtin action invocation
#
sub process_action3( $$$$$ ) {
    my ( $chainref, $wholeaction, $action, $level, $tag ) = @_;
    my $actionfile = find_file "action.$action";

    fatal_error "Missing Action File ($actionfile)" unless -f $actionfile;

    progress_message2 "Processing $actionfile for chain $chainref->{name}...";

    open_file $actionfile;

    while ( read_a_line ) {

	my ($target, $source, $dest, $proto, $ports, $sports, $rate, $user, $mark ) = split_line1 1, 9, 'action file';

	if ( $target eq 'COMMENT' ) {
	    process_comment;
	    next;
	}

	my $target2 = merge_levels $wholeaction, $target;

	my ( $action2 , $level2 ) = split_action $target2;

	( $action2 , my $param ) = get_target_param $action2;

	my $action2type = $targets{$action2} || 0;

	unless ( $action2type == STANDARD ) {
	    if ( $action2type & ACTION ) {
		$target2 = (find_logactionchain ( $target = $target2 ))->{name};
	    } else {
		assert( $action2type & ( MACRO | LOGRULE | NFQ | CHAIN ) );
	    }
	}

	if ( $action2type == MACRO ) {
	    process_macro3( $action2, $param, $chainref, $action, $source, $dest, $proto, $ports, $sports, $rate, $user, $mark );
	} else {
	    process_action $chainref, $action, $target2, $source, $dest, $proto, $ports, $sports, $rate, $user, $mark;
	}
    }

    clear_comment;
}

#
# The following small functions generate rules for the builtin actions of the same name
#
sub dropBcast( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    if ( have_capability( 'ADDRTYPE' ) ) {
	if ( $level ne '' ) {
	    log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -m addrtype --dst-type BROADCAST ';
	    if ( $family == F_IPV4 ) {
		log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -d 224.0.0.0/4 ';
	    } else {
		log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', join( ' ', ' -d' , IPv6_MULTICAST , '-j DROP ' );
	    }
	}

	add_rule $chainref, '-m addrtype --dst-type BROADCAST -j DROP';
    } else {
	if ( $family == F_IPV4 ) {
	    add_commands $chainref, 'for address in $ALL_BCASTS; do';
	} else {
	    add_commands $chainref, 'for address in $ALL_ACASTS; do';
	}

	incr_cmd_level $chainref;
	log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -d $address ' if $level ne '';
	add_rule $chainref, '-d $address -j DROP';
	decr_cmd_level $chainref;
	add_commands $chainref, 'done';

	log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -d 224.0.0.0/4 ' if $level ne '';
    }


    if ( $family == F_IPV4 ) {
	add_rule $chainref, '-d 224.0.0.0/4 -j DROP';
    } else {
	add_rule $chainref, join( ' ', '-d', IPv6_MULTICAST, '-j DROP' );
    }
}

sub allowBcast( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    if ( $family == F_IPV4 && have_capability( 'ADDRTYPE' ) ) {
	if ( $level ne '' ) {
	    log_rule_limit $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add', ' -m addrtype --dst-type BROADCAST ';
	    log_rule_limit $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add', ' -d 224.0.0.0/4 ';
	}

	add_rule $chainref, '-m addrtype --dst-type BROADCAST -j ACCEPT';
	add_rule $chainref, '-d 224.0.0.0/4 -j ACCEPT';
    } else {
	if ( $family == F_IPV4 ) {
	    add_commands $chainref, 'for address in $ALL_BCASTS; do';
	} else {
	    add_commands $chainref, 'for address in $ALL_MACASTS; do';
	}

	incr_cmd_level $chainref;
	log_rule_limit $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add', ' -d $address ' if $level ne '';
	add_rule $chainref, '-d $address -j ACCEPT';
	decr_cmd_level $chainref;
	add_commands $chainref, 'done';

	if ( $family == F_IPV4 ) {
	    log_rule_limit $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add', ' -d 224.0.0.0/4 ' if $level ne '';
	    add_rule $chainref, '-d 224.0.0.0/4 -j ACCEPT';
	} else {
	    log_rule_limit $level, $chainref, 'allowBcast' , 'ACCEPT', '', $tag, 'add', ' -d ' . IPv6_MULTICAST . ' ' if $level ne '';
	    add_rule $chainref, join ( ' ', '-d', IPv6_MULTICAST, '-j ACCEPT' );
	}
    }
}

sub dropNotSyn ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    log_rule_limit $level, $chainref, 'dropNotSyn' , 'DROP', '', $tag, 'add', '-p 6 ! --syn ' if $level ne '';
    add_rule $chainref , '-p 6 ! --syn -j DROP';
}

sub rejNotSyn ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    log_rule_limit $level, $chainref, 'rejNotSyn' , 'REJECT', '', $tag, 'add', '-p 6 ! --syn ' if $level ne '';
    add_rule $chainref , '-p 6 ! --syn -j REJECT --reject-with tcp-reset';
}

sub dropInvalid ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    log_rule_limit $level, $chainref, 'dropInvalid' , 'DROP', '', $tag, 'add', "$globals{STATEMATCH} INVALID " if $level ne '';
    add_rule $chainref , "$globals{STATEMATCH} INVALID -j DROP";
}

sub allowInvalid ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    log_rule_limit $level, $chainref, 'allowInvalid' , 'ACCEPT', '', $tag, 'add', "$globals{STATEMATCH} INVALID " if $level ne '';
    add_rule $chainref , "$globals{STATEMATCH} INVALID -j ACCEPT";
}

sub forwardUPnP ( $$$ ) {
    my $chainref = dont_optimize 'forwardUPnP';
    add_commands( $chainref , '[ -f ${VARDIR}/.forwardUPnP ] && cat ${VARDIR}/.forwardUPnP >&3' );
}

sub allowinUPnP ( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    if ( $level ne '' ) {
	log_rule_limit $level, $chainref, 'allowinUPnP' , 'ACCEPT', '', $tag, 'add', '-p 17 --dport 1900 ';
	log_rule_limit $level, $chainref, 'allowinUPnP' , 'ACCEPT', '', $tag, 'add', '-p 6 --dport 49152 ';
    }

    add_rule $chainref, '-p 17 --dport 1900 -j ACCEPT';
    add_rule $chainref, '-p 6 --dport 49152 -j ACCEPT';
}

sub Limit( $$$ ) {
    my ($chainref, $level, $tag) = @_;

    my @tag = split /,/, $tag;

    fatal_error 'Limit rules must include <set name>,<max connections>,<interval> as the log tag (' . join( ':', 'Limit', $level eq '' ? 'none' : $level , $tag ) . ')' unless @tag == 3;

    my $set   = $tag[0];

    for ( @tag[1,2] ) {
	fatal_error 'Max connections and interval in Limit rules must be numeric (' . join( ':', 'Limit', $level eq '' ? 'none' : $level, $tag ) . ')' unless /^\d+$/
    }

    my $count = $tag[1] + 1;

    require_capability( 'RECENT_MATCH' , 'Limit rules' , '' );

    add_rule $chainref, "-m recent --name $set --set";

    if ( $level ne '' ) {
	my $xchainref = new_chain 'filter' , "$chainref->{name}%";
	log_rule_limit $level, $xchainref, $tag[0], 'DROP', '', '', 'add', '';
	add_rule $xchainref, '-j DROP';
	add_jump $chainref,  $xchainref, 0, "-m recent --name $set --update --seconds $tag[2] --hitcount $count ";
    } else {
	add_rule $chainref, "-m recent --update --name $set --seconds $tag[2] --hitcount $count -j DROP";
    }

    add_rule $chainref, '-j ACCEPT';
}

sub process_actions3 () {
    my %builtinops = ( 'dropBcast'      => \&dropBcast,
		       'allowBcast'     => \&allowBcast,
		       'dropNotSyn'     => \&dropNotSyn,
		       'rejNotSyn'      => \&rejNotSyn,
		       'dropInvalid'    => \&dropInvalid,
		       'allowInvalid'   => \&allowInvalid,
		       'allowinUPnP'    => \&allowinUPnP,
		       'forwardUPnP'    => \&forwardUPnP,
		       'Limit'          => \&Limit, );

    for my $wholeaction ( keys %usedactions ) {
	my $chainref = find_logactionchain $wholeaction;
	my ( $action, $level, $tag ) = split /:/, $wholeaction;

	$level = '' unless defined $level;
	$tag   = '' unless defined $tag;

	if ( $targets{$action} & BUILTIN ) {
	    $level = '' if $level =~ /none!?/;
	    $builtinops{$action}->($chainref, $level, $tag);
	} else {
	    process_action3 $chainref, $wholeaction, $action, $level, $tag;
	}
    }
}

sub process_rule_common ( $$$$$$$$$$$$$$$ );

#
# Expand a macro rule from the rules file
#
sub process_macro ( $$$$$$$$$$$$$$$$ ) {
    my ($macro, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers, $wildcard ) = @_;

    my $nocomment = no_comment;

    my $format = 1;

    my $generated = 0;

    macro_comment $macro;

    my $macrofile = $macros{$macro};

    progress_message "..Expanding Macro $macrofile...";

    push_open $macrofile;

    while ( read_a_line ) {

	my ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $morigdest, $mrate, $muser, $mmark, $mconnlimit, $mtime, $mheaders );

	if ( $format == 1 ) {
	    ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split_line1 1, 8, 'macro file', $macro_commands;
	    ( $morigdest, $mmark, $mconnlimit, $mtime, $mheaders ) = qw/- - - - -/;
	} else {
	    ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $morigdest, $mrate, $muser, $mmark, $mconnlimit, $mtime, $mheaders ) = split_line1 1, 13, 'macro file', $macro_commands;
	}

	if ( $mtarget eq 'COMMENT' ) {
	    process_comment unless $nocomment;
	    next;
	}

	if ( $mtarget eq 'FORMAT' ) {
	    fatal_error "Invalid FORMAT ($msource)" unless $msource =~ /^[12]$/;
	    $format = $msource;
	    next;
	}

	$mtarget = merge_levels $target, $mtarget;

	if ( $mtarget =~ /^PARAM(:.*)?$/ ) {
	    fatal_error 'PARAM requires a parameter to be supplied in macro invocation' unless $param ne '';
	    $mtarget = substitute_param $param,  $mtarget;
	}

	my $action = isolate_basic_target $mtarget;

	fatal_error "Invalid or missing ACTION ($mtarget)" unless defined $action;

	my $actiontype = $targets{$action} || find_macro( $action );

	fatal_error "Invalid Action ($mtarget) in macro" unless $actiontype & ( ACTION +  STANDARD + NATRULE + MACRO );

	if ( $msource ) {
	    if ( $msource eq '-' ) {
		$msource = $source || '';
	    } elsif ( $msource =~ s/^DEST:?// ) {
		$msource = merge_macro_source_dest $msource, $dest;
	    } else {
		$msource =~ s/^SOURCE:?//;
		$msource = merge_macro_source_dest $msource, $source;
	    }
	} else {
	    $msource = '';
	}

	if ( $mdest ) {
	    if ( $mdest eq '-' ) {
		$mdest = $dest || '';
	    } elsif ( $mdest =~ s/^SOURCE:?// ) {
		$mdest = merge_macro_source_dest $mdest , $source;
	    } else {
		$mdest =~ s/DEST:?//;
		$mdest = merge_macro_source_dest $mdest, $dest;
	    }
	} else {
	    $mdest = '';
	}

	$generated |= process_rule_common(
				    $mtarget,
				    $param,
				    $msource,
				    $mdest,
				    merge_macro_column( $mproto,     $proto ) ,
				    merge_macro_column( $mports,     $ports ) ,
				    merge_macro_column( $msports,    $sports ) ,
				    merge_macro_column( $morigdest,  $origdest ) ,
				    merge_macro_column( $mrate,      $rate ) ,
				    merge_macro_column( $muser,      $user ) ,
				    merge_macro_column( $mmark,      $mark ) ,
				    merge_macro_column( $mconnlimit, $connlimit) ,
				    merge_macro_column( $mtime,      $time ),
				    merge_macro_column( $mheaders,   $headers ),
				    $wildcard
				   );

	progress_message "   Rule \"$currentline\" $done";
    }

    pop_open;

    progress_message "..End Macro $macrofile";

    clear_comment unless $nocomment;

    return $generated;

}
#
# Once a rule has been expanded via wildcards (source and/or dest zone eq 'all'), it is processed by this function. If
# the target is a macro, the macro is expanded and this function is called recursively for each rule in the expansion.
#
sub process_rule_common ( $$$$$$$$$$$$$$$ ) {
    my ( $target, $current_param, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time, $headers, $wildcard ) = @_;
    my ( $action, $loglevel) = split_action $target;
    my ( $basictarget, $param ) = get_target_param $action;
    my $rule = '';
    my $actionchainref;
    my $optimize = $wildcard ? ( $basictarget =~ /!$/ ? 0 : $config{OPTIMIZE} & 1 ) : 0;

    $param = '' unless defined $param;

    #
    # Determine the validity of the action
    #
    my $actiontype = $targets{$basictarget} || find_macro( $basictarget );

    if ( $config{ MAPOLDACTIONS } ) {
	( $basictarget, $actiontype , $param ) = map_old_actions( $basictarget ) unless $actiontype || $param;
    }

    fatal_error "Unknown action ($action)" unless $actiontype;

    if ( $actiontype == MACRO ) {
	#
	# process_macro() will call process_rule_common() recursively for each rule in the macro body
	#
	fatal_error "Macro invocations nested too deeply" if ++$macro_nest_level > MAX_MACRO_NEST_LEVEL;

	if ( $param ne '' ) {
	    $current_param = $param unless $param eq 'PARAM';
	}

	my $generated = process_macro( $basictarget,
				       $target,
				       $current_param,
				       $source,
				       $dest,
				       $proto,
				       $ports,
				       $sports,
				       $origdest,
				       $ratelimit,
				       $user,
				       $mark,
				       $connlimit,
				       $time,
				       $headers,
				       $wildcard );

	$macro_nest_level--;

	return $generated;

    } elsif ( $actiontype & NFQ ) {
	require_capability( 'NFQUEUE_TARGET', 'NFQUEUE Rules', '' );
	my $paramval = $param eq '' ? 0 : numeric_value( $param );
	fatal_error "Invalid value ($param) for NFQUEUE queue number" unless defined($paramval) && $paramval <= 65535;
	$action = "NFQUEUE --queue-num $paramval";
    } elsif ( $actiontype & SET ) {
	require_capability( 'IPSET_MATCH', 'SET and UNSET rules', '' );
	fatal_error "$action rules require a set name parameter" unless $param;
    } else {
	fatal_error "The $basictarget TARGET does not accept a parameter" unless $param eq '';
    }
    #
    # We can now dispense with the postfix character
    #
    $action =~ s/[\+\-!]$//;
    #
    # Mark target as used
    #
    if ( $actiontype & ACTION ) {
	unless ( $usedactions{$target} ) {
	    $usedactions{$target} = 1;
	    createactionchain $target;
	}
    }
    #
    # Take care of irregular syntax and targets
    #
    my $log_action = $action;

    if ( $actiontype & REDIRECT ) {
	my $z = $actiontype & NATONLY ? '' : firewall_zone;
	if ( $dest eq '-' ) {
	    $dest = join( '', $z, '::' , $ports =~ /[:,]/ ? '' : $ports );
	} else {
	    $dest = join( '', $z, '::', $dest ) unless $dest =~ /^[^\d].*:/;
	}
    } elsif ( $action eq 'REJECT' ) {
	$action = 'reject';
    } elsif ( $action eq 'CONTINUE' ) {
	$action = 'RETURN';
    } elsif ( $action eq 'COUNT' ) {
	$action = '';
    } elsif ( $actiontype & LOGRULE ) {
	fatal_error 'LOG requires a log level' unless defined $loglevel and $loglevel ne '';
    } elsif ( $actiontype & SET ) {
	my %xlate = ( ADD => 'add-set' , DEL => 'del-set' );

	my ( $setname, $flags, $rest ) = split ':', $param, 3;
	fatal_error "Invalid ADD/DEL parameter ($param)" if $rest;
	fatal_error "Expected ipset name ($setname)" unless $setname =~ s/^\+// && $setname =~ /^[a-zA-Z]\w*$/;
	fatal_error "Invalid flags ($flags)" unless defined $flags && $flags =~ /^(dst|src)(,(dst|src)){0,5}$/;
	$action = join( ' ', 'SET --' . $xlate{$basictarget} , $setname , $flags );
    }
    #
    # Isolate and validate source and destination zones
    #
    my $sourcezone;
    my $destzone;
    my $sourceref;
    my $destref;
    my $origdstports;

    if ( $source =~ /^(.+?):(.*)/ ) {
	fatal_error "Missing SOURCE Qualifier ($source)" if $2 eq '';
	$sourcezone = $1;
	$source = $2;
    } else {
	$sourcezone = $source;
	$source = ALLIP;
    }

    if ( $dest =~ /^(.*?):(.*)/ ) {
	fatal_error "Missing DEST Qualifier ($dest)" if $2 eq '';
	$destzone = $1;
	$dest = $2;
    } elsif ( $dest =~ /.*\..*\./ ) {
	#
	# Appears to be an IPv4 address (no NAT in IPv6)
	#
	$destzone = '-';
    } else {
	$destzone = $dest;
	$dest = ALLIP;
    }

    fatal_error "Missing source zone" if $sourcezone eq '-' || $sourcezone =~ /^:/;
    fatal_error "Unknown source zone ($sourcezone)" unless $sourceref = defined_zone( $sourcezone );

    if ( $actiontype & NATONLY ) {
	unless ( $destzone eq '-' || $destzone eq '' ) {
	    $destref = defined_zone( $destzone );

	    if ( $destref ) {
		warning_message "The destination zone ($destzone) is ignored in $log_action rules";
	    } else {
		$dest = join ':', $destzone, $dest;
		$destzone = '';
	    }
	}
    } else {
	fatal_error "Missing destination zone" if $destzone eq '-' || $destzone eq '';
	fatal_error "Unknown destination zone ($destzone)" unless $destref = defined_zone( $destzone );
    }

    my $restriction = NO_RESTRICT;

    if ( $sourceref && ( $sourceref->{type} == FIREWALL || $sourceref->{type} == VSERVER ) ) {
	$restriction = $destref && ( $destref->{type} == FIREWALL || $destref->{type} == VSERVER ) ? ALL_RESTRICT : OUTPUT_RESTRICT;
    } else {
	$restriction = INPUT_RESTRICT if $destref && ( $destref->{type} == FIREWALL || $destref->{type} == VSERVER );
    }

    my ( $chain, $chainref, $policy );
    #
    # For compatibility with older Shorewall versions
    #
    $origdest = ALLIP if $origdest eq 'all';

    #
    # Take care of chain
    #

    unless ( $actiontype & NATONLY ) {
	#
	# Check for illegal bridge port rule
	#
	if ( $destref->{type} == BPORT ) {
	    unless ( $sourceref->{bridge} eq $destref->{bridge} || single_interface( $sourcezone ) eq $destref->{bridge} ) {
		return 0 if $wildcard;
		fatal_error "Rules with a DESTINATION Bridge Port zone must have a SOURCE zone on the same bridge";
	    }
	}

	$chain = rules_chain( ${sourcezone}, ${destzone} );
	#
	# Ensure that the chain exists but don't mark it as referenced until after optimization is checked
	#
	$chainref = ensure_chain 'filter', $chain;
	$policy   = $chainref->{policy};

	if ( $policy eq 'NONE' ) {
	    return 0 if $wildcard;
	    fatal_error "Rules may not override a NONE policy";
	}
	#
	# Handle Optimization
	#
	if ( $optimize > 0 ) {
	    my $loglevel = $filter_table->{$chainref->{policychain}}{loglevel};
	    if ( $loglevel ne '' ) {
		return 0 if $target eq "${policy}:$loglevel}";
	    } else {
		return 0 if $basictarget eq $policy;
	    }
	}
	#
	# Mark the chain as referenced and add appropriate rules from earlier sections.
	#
	$chainref = ensure_filter_chain $chain, 1;
	#
	# Don't let the rules in this chain be moved elsewhere
	#
	dont_move $chainref;
    }

    #
    # Generate Fixed part of the rule
    #
    if ( $actiontype & ( NATRULE | NONAT ) && ! ( $actiontype & NATONLY ) ) {
	#
	# Either a DNAT, REDIRECT or ACCEPT+ rule; don't apply rate limiting twice
	#
	$rule = join( '',
		      do_proto($proto, $ports, $sports),
		      do_user( $user ) ,
		      do_test( $mark , $globals{TC_MASK} ) ,
		      do_connlimit( $connlimit ),
		      do_time( $time ) );
    } else {
	$rule = join( '',
		      do_proto($proto, $ports, $sports),
		      do_ratelimit( $ratelimit, $basictarget ) ,
		      do_user( $user ) ,
		      do_test( $mark , $globals{TC_MASK} ) ,
		      do_connlimit( $connlimit ),
		      do_time( $time ) ,
		      do_headers( $headers )
		    );
    }

    unless ( $section eq 'NEW' ) {
	fatal_error "Entries in the $section SECTION of the rules file not permitted with FASTACCEPT=Yes" if $config{FASTACCEPT};
	fatal_error "$basictarget rules are not allowed in the $section SECTION" if $actiontype & ( NATRULE | NONAT );
	$rule .= "$globals{STATEMATCH} $section "
    }

    #
    # Generate NAT rule(s), if any
    #
    if ( $actiontype & NATRULE ) {
	my ( $server, $serverport );
	my $randomize = $dest =~ s/:random$// ? ' --random' : '';

	require_capability( 'NAT_ENABLED' , "$basictarget rules", '' );
	#
	# Isolate server port
	#
	if ( $dest =~ /^(.*)(:(.+))$/ ) {
	    #
	    # Server IP and Port
	    #
	    $server = $1;      # May be empty
	    $serverport = $3;  # Not Empty due to RE
	    $origdstports = $ports;

	    if ( $origdstports && $origdstports ne '-' && port_count( $origdstports ) == 1 ) {
		$origdstports = validate_port( $proto, $origdstports );
	    } else {
		$origdstports = '';
	    }

	    if ( $serverport =~ /^(\d+)-(\d+)$/ ) {
		#
		# Server Port Range
		#
		fatal_error "Invalid port range ($serverport)" unless $1 < $2;
		my @ports = ( $1, $2 );
		$_ = validate_port( proto_name( $proto ), $_) for ( @ports );
		( $ports = $serverport ) =~ tr/-/:/;
	    } else {
		$serverport = $ports = validate_port( proto_name( $proto ), $serverport );
	    }
	} elsif ( $dest eq ':' ) {
	    #
	    # Rule with no server IP or port ( zone:: )
	    #
	    $server = $serverport = '';
	} else {
	    #
	    # Simple server IP address (may be empty or "-")
	    #
	    $server = $dest;
	    $serverport = '';
	}

	#
	# Generate the target
	#
	my $target = '';

	if ( $actiontype  & REDIRECT ) {
	    fatal_error "A server IP address may not be specified in a REDIRECT rule" if $server;
	    $target  = 'REDIRECT';
	    $target .= " --to-port $serverport" if $serverport;
	    if ( $origdest eq '' || $origdest eq '-' ) {
		$origdest = ALLIP;
	    } elsif ( $origdest eq 'detect' ) {
		if ( $config{DETECT_DNAT_IPADDRS} && $sourcezone ne firewall_zone ) {
		    my $interfacesref = $sourceref->{interfaces};
		    my @interfaces = keys %$interfacesref;
		    $origdest = @interfaces ? "detect:@interfaces" : ALLIP;
 		} else {
		    $origdest = ALLIP;
		}
	    }
	} else {
	    if ( $server eq '' ) {
		fatal_error "A server and/or port must be specified in the DEST column in $action rules" unless $serverport;
	    } elsif ( $server =~ /^(.+)-(.+)$/ ) {
		validate_range( $1, $2 );
	    } else {
		my @servers = validate_address $server, 1;
		$server = join ',', @servers;
	    }

	    if ( $action eq 'DNAT' ) {
		$target = 'DNAT';
		if ( $server ) {
		    $serverport = ":$serverport" if $serverport;
		    for my $serv ( split /,/, $server ) {
			$target .= " --to-destination ${serv}${serverport}";
		    }
		} else {
		    $target .= " --to-destination :$serverport";
		}
	    }

	    unless ( $origdest && $origdest ne '-' && $origdest ne 'detect' ) {
		if ( $config{DETECT_DNAT_IPADDRS} && $sourcezone ne firewall_zone ) {
		    my $interfacesref = $sourceref->{interfaces};
		    my @interfaces = keys %$interfacesref;
		    $origdest = @interfaces ? "detect:@interfaces" : ALLIP;
		} else {
		    $origdest = ALLIP;
		}
	    }
	}

	$target .= $randomize;

	#
	# And generate the nat table rule(s)
	#
	expand_rule ( ensure_chain ('nat' , $sourceref->{type} == FIREWALL ? 'OUTPUT' : dnat_chain $sourcezone ),
		      PREROUTE_RESTRICT ,
		      $rule ,
		      $source ,
		      $origdest ,
		      '' ,
		      $target ,
		      $loglevel ,
		      $log_action ,
		      $serverport ? do_proto( $proto, '', '' ) : '' );
	#
	# After NAT:
	#   - the destination port will be the server port ($ports) -- we did that above
	#   - the destination IP   will be the server IP   ($dest)
	#   - there will be no log level (we log NAT rules in the nat table rather than in the filter table).
	#   - the target will be ACCEPT.
	#
	unless ( $actiontype & NATONLY ) {
	    $rule = join( '',
			  do_proto( $proto, $ports, $sports ),
			  do_ratelimit( $ratelimit, 'ACCEPT' ),
			  do_user $user ,
			  do_test( $mark , $globals{TC_MASK} ) );
	    $loglevel = '';
	    $dest     = $server;
	    $action   = 'ACCEPT';
	}
    } elsif ( $actiontype & NONAT ) {
	#
	# NONAT or ACCEPT+ -- May not specify a destination interface
	#
	fatal_error "Invalid DEST ($dest) in $action rule" if $dest =~ /:/;

	$origdest = '' unless $origdest and $origdest ne '-';

	if ( $origdest eq 'detect' ) {
	    my $interfacesref = $sourceref->{interfaces};
	    my $interfaces = [ ( keys %$interfacesref ) ];
	    $origdest = $interfaces ? "detect:@$interfaces" : ALLIP;
	}

	my $tgt = 'RETURN';

	my $nonat_chain;

	my $chn;

	if ( $sourceref->{type} == FIREWALL ) {
	    $nonat_chain = $nat_table->{OUTPUT};
	} else {
	    $nonat_chain = ensure_chain 'nat', dnat_chain $sourcezone;

	    my @interfaces = keys %{zone_interfaces $sourcezone};

	    for ( @interfaces ) {
		my $ichain = input_chain $_;

		if ( $nat_table->{$ichain} ) {
		    #
		    # Static NAT is defined on this interface
		    #
		    $chn = new_chain( 'nat', newnonatchain ) unless $chn;
		    add_jump $chn, $nat_table->{$ichain}, 0, @interfaces > 1 ? match_source_dev( $_ )  : '';
		}
	    }

	    if ( $chn ) {
		#
		# Call expand_rule() to correctly handle logging. Because
		# the 'logname' argument is passed, expand_rule() will
		# not create a separate logging chain but will rather emit
		# any logging rule in-line.
		#
		expand_rule( $chn,
			     PREROUTE_RESTRICT,
			     '', # Rule
			     '', # Source
			     '', # Dest
			     '', # Original dest
			     'ACCEPT',
			     $loglevel,
			     $log_action,
			     '',
			     dnat_chain( $sourcezone  ) );
		$loglevel = '';
		$tgt = $chn->{name};
	    } else {
		$tgt = 'ACCEPT';
	    }
	}

	expand_rule( $nonat_chain ,
		     PREROUTE_RESTRICT ,
		     $rule ,
		     $source ,
		     $dest ,
		     $origdest ,
		     $tgt,
		     $loglevel ,
		     $log_action ,
		     '' ,
		   );
	#
	# Possible optimization if the rule just generated was a simple jump to the nonat chain
	#
	if ( $chn && ${$nonat_chain->{rules}}[-1] eq "-A -j $tgt" ) {
	    #
	    # It was -- delete that rule
	    #
	    pop @{$nonat_chain->{rules}};
	    #
	    # And move the rules from the nonat chain to the zone dnat chain
	    #
	    move_rules ( $chn, $nonat_chain );
	}
    }

    #
    # Add filter table rule, unless this is a NATONLY rule type
    #
    unless ( $actiontype & NATONLY ) {

	if ( $actiontype & ACTION ) {
	    $action = (find_logactionchain $target)->{name};
	    $loglevel = '';
	}

	if ( $origdest ) {
	    unless ( $origdest eq '-' ) {
		require_capability( 'CONNTRACK_MATCH', 'ORIGINAL DEST in a non-NAT rule', 's' ) unless $actiontype & NATRULE;
	    } else {
		$origdest = '';
	    }
	}

	$rule .= "-m conntrack --ctorigdstport $origdstports " if have_capability( 'NEW_CONNTRACK_MATCH' ) && $origdstports;

	expand_rule( ensure_chain( 'filter', $chain ) ,
		     $restriction ,
		     $rule ,
		     $source ,
		     $dest ,
		     $origdest ,
		     $action ,
		     $loglevel ,
		     $log_action ,
		     '' );
    }

    return 1;
}

1;
