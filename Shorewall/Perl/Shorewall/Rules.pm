#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Rules.pm
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
#   This module contains process_rule() and it's associated helpers for handling 
#   Actions and Macros.
#
package Shorewall::Rules;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Zones;
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::Actions;
use Shorewall::IPAddrs;
use Shorewall::Policy;
use Scalar::Util 'reftype';

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		  process_actions1
		  process_actions2
		  process_actions3

		  process_rules
	       );

our @EXPORT_OK = qw( initialize );
our $VERSION = '4.4_16';

our %macros;

our $family;

our @builtins;

#
# Commands that can be embedded in a basic rule and how many total tokens on the line (0 => unlimited).
#
our $rule_commands = { COMMENT => 0, FORMAT => 2 };

use constant { MAX_MACRO_NEST_LEVEL => 5 , MAX_ACTION_NEST_LEVEL => 5 };

our $macro_nest_level;
our $action_nest_level;

our @actions;

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
    $family            = shift;
    %macros            = ();
    @actions           = ();
    $macro_nest_level  = 0;
    $action_nest_level = 0;

    if ( $family == F_IPV4 ) {
	@builtins = qw/dropBcast allowBcast dropNotSyn rejNotSyn dropInvalid allowInvalid allowinUPnP forwardUPnP Limit/;
    } else {
	@builtins = qw/dropBcast allowBcast dropNotSyn rejNotSyn dropInvalid allowInvalid/;
    }
}

#
# This function determines the logging and params for a subordinate action or a rule within a superior action
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
# Define an Action
#
sub new_action( $ ) {

    my $action = $_[0];

    $actions{$action} = { actchain => '', active => 0 };
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
# The functions process_actions1-3() implement the three phases of action processing.
#
# The first phase (process_actions1) occurs before the rules file is processed. The builtin-actions are added
# to the target table (%Shorewall::Chains::targets) and actions table, then ${SHAREDIR}/actions.std and
# ${CONFDIR}/actions are scanned (in that order). For each action:
#
#      a) The related action definition file is located.
#      a) The action is added to the target table
#
# The second phase (process_actions2) occurs after the policy file is scanned. Each default action's file
# is processed by process_action2(). That function recursively processes action files up the action 
# invocation tree, adding to the %usedactions hash as each new action is discovered.
#
# During rules file processing, process_action2() is called when a new action:level:tag:params is encountered.
# Again, each new such tupple is entered into the %usedactions hash.
#
# The final phase (process_actions3) traverses the keys of %usedactions populating each chain appropriately
# by reading the related action definition file and creating rules. Note that a given action definition file is
# processed once for each unique [:level[:tag]][:param] applied to an invocation of the action.
#

sub process_rule_common ( $$$$$$$$$$$$$$$$ );

sub process_actions1() {

    progress_message2 "Locating Action Files...";
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

	    fatal_error "Invalid Action Name ($action)" unless "\L$action" =~ /^[a-z]\w*$/;

	    new_action $action;

	    $targets{$action} = ACTION;

	    my $actionfile = find_file "action.$action";

	    fatal_error "Missing Action File ($actionfile)" unless -f $actionfile;
	}
    }
}

sub merge_action_levels( $$ ) {
    my $superior    = shift;
    my $subordinate = shift;

    my ( $unused, $suplevel, $suptag, $supparam ) = split /:/, $superior;
    my ( $action, $sublevel, $subtag, $subparam ) = split /:/, $subordinate;

    assert defined $supparam;

    if ( $suplevel =~ /!$/ ) {
	( $sublevel, $subtag ) = ( $suplevel, $subtag );
    } else {
	$sublevel = 'none' unless defined $sublevel && $sublevel ne '';
	if ( $sublevel =~ /^none~/ ) {
	    $subtag = '';
	} else {
	    $subtag = '' unless defined $subtag;
	}
    }

    $subparam = $supparam unless defined $subparam && $subparam ne '';

    join ':', $action, $sublevel, $subtag, $subparam;
}

sub process_action2( $ ) {
    my $wholeaction = shift;
    my ( $action , $level, $tag, $param ) = split /:/, $wholeaction;
    my $actionfile  = find_file "action.$action";

    push @actions, $action;

    $actions{$action}{active}++;

    fatal_error "Missing Action File ($actionfile)" unless -f $actionfile;

    progress_message2 "   Pre-processing $actionfile...";

    fatal_error "Actions nested too deeply" if ++$action_nest_level > MAX_ACTION_NEST_LEVEL;

    push_open( $actionfile );

    my $oldparms = push_params( $param );
 
    while ( read_a_line ) {

	my ($wholetarget, @rest ) = split_line1 1, 13, 'action file' , $rule_commands;
	#
	# When passed an action name in the first argument, process_rule_common() only
	# deals with the target and the parameter. We pass undef for the rest so we'll
	# know if we try to use one of them.
	#
	process_rule_common( $wholeaction ,
			     $wholetarget ,
			     '' ,   # Current Param
			     undef, # source
			     undef, # dest
			     undef, # proto
			     undef, # ports
			     undef, # sports
			     undef, # origdest
			     undef, # ratelimit
			     undef, # user
			     undef, # mark
			     undef, # connlimit
			     undef, # time
			     undef, # headers
			     undef  # wildcard	     
			   ) unless $wholetarget eq 'FORMAT' || $wholetarget eq 'COMMENT';
    }

    pop_open;

    --$action_nest_level;

    pop_params( $oldparms );

    $actions{$action}{active}--;

    pop @actions;
}

sub process_actions2 () {
    progress_message2 "Pre-processing default actions...";

    for my $action ( keys %usedactions ) {
	my ( $basic_action, undef, undef, undef ) = split /:/, $action;
	process_action2( $action ) unless $targets{$basic_action} & BUILTIN;
    }
}

#
# Generate chain for non-builtin action invocation
#
sub process_action3( $$$$$$ ) {
    my ( $chainref, $wholeaction, $action, $level, $tag, $param ) = @_;
    my $actionfile = find_file "action.$action";
    my $format = 1;

    fatal_error "Missing Action File ($actionfile)" unless -f $actionfile;

    progress_message2 "Processing $actionfile for chain $chainref->{name}...";

    open_file $actionfile;

    my $oldparms = push_params( $param );

    while ( read_a_line ) {

	my ($target, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers );

	if ( $format == 1 ) {
	    ($target, $source, $dest, $proto, $ports, $sports, $rate, $user, $mark ) = split_line1 1, 9, 'action file', $rule_commands;
	    $origdest = $connlimit = $time = $headers = '-';
	} else {
	    ($target, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers ) = split_line1 1, 13, 'action file', $rule_commands;
	}

	if ( $target eq 'COMMENT' ) {
	    process_comment;
	    next;
	}

	if ( $target eq 'FORMAT' ) {
	    fatal_error "FORMAT must be 1 or 2" unless $source =~ /^[12]$/;
	    $format = $source;
	    next;
	}

	process_rule_common( $chainref, $target, '', $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers, 0 );
    }

    clear_comment;

    pop_params( $oldparms );
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
    my ($chainref, $level, $tag, $param ) = @_;

    my @param = split /,/, $param ? $param : $tag;

    fatal_error 'Limit rules must include <set name>,<max connections>,<interval> as the log tag or as parameters' unless @param == 3;

    my $set   = $param[0];

    for ( @param[1,2] ) {
	fatal_error 'Max connections and interval in Limit rules must be numeric (' . join( ':', 'Limit', $level eq '' ? 'none' : $level, $tag ) . ')' unless /^\d+$/
    }

    my $count = $param[1] + 1;

    require_capability( 'RECENT_MATCH' , 'Limit rules' , '' );

    add_rule $chainref, "-m recent --name $set --set";

    if ( $level ne '' ) {
	my $xchainref = new_chain 'filter' , "$chainref->{name}%";
	log_rule_limit $level, $xchainref, $param[0], 'DROP', '', '', 'add', '';
	add_rule $xchainref, '-j DROP';
	add_jump $chainref,  $xchainref, 0, "-m recent --name $set --update --seconds $param[2] --hitcount $count ";
    } else {
	add_rule $chainref, "-m recent --update --name $set --seconds $param[2] --hitcount $count -j DROP";
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

    while ( my ( $wholeaction, $chainref ) = each %usedactions ) {
	my ( $action, $level, $tag, $param ) = split /:/, $wholeaction;

	if ( $targets{$action} & BUILTIN ) {
	    $level = '' if $level =~ /none!?/;
	    $builtinops{$action}->($chainref, $level, $tag, $param );
	} else {
	    process_action3 $chainref, $wholeaction, $action, $level, $tag, $param;
	}
    }
}

#
# Expand a macro rule from the rules file
#
sub process_macro ( $$$$$$$$$$$$$$$$$ ) {
    my ($macro, $chainref, $target, $param, $source, $dest, $proto, $ports, $sports, $origdest, $rate, $user, $mark, $connlimit, $time, $headers, $wildcard ) = @_;

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
	    ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $mrate, $muser ) = split_line1 1, 8, 'macro file', $rule_commands;
	    ( $morigdest, $mmark, $mconnlimit, $mtime, $mheaders ) = qw/- - - - -/;
	} else {
	    ( $mtarget, $msource, $mdest, $mproto, $mports, $msports, $morigdest, $mrate, $muser, $mmark, $mconnlimit, $mtime, $mheaders ) = split_line1 1, 13, 'macro file', $rule_commands;
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

	fatal_error "Invalid Action ($mtarget) in macro" unless $actiontype & ( ACTION +  STANDARD + NATRULE +  MACRO );

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
				    $chainref,
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
# Rules in both the rules file and in action bodies are processed here.
#
# This function may be called in three different ways:
#
#  1) $chainref undefined -- Being called to process a record in the rules file. All arguments are passed.
#  2) $chainref is a chain name -- Pre-proessing the records in an action file. Only $target is passed.
#  3) $chainref is a chain reference -- Processing the records in an action file. The chain is where the generated
#     rules are added.
#
sub process_rule_common ( $$$$$$$$$$$$$$$$ ) {
    my ( $chainref,   #reference to Action Chain if we are being called from process_action3()
                      # if defined, we are being called from process_action2() and this is the name of the action
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
	 $wildcard ) = @_;

    my ( $action, $loglevel) = split_action $target;
    my ( $basictarget, $param ) = get_target_param $action;
    my $rule = '';
    my $optimize = $wildcard ? ( $basictarget =~ /!$/ ? 0 : $config{OPTIMIZE} & 1 ) : 0;
    my $inaction1 = '';
    my $inaction3;
    my $normalized_target;
    my $normalized_action;
 
    if ( defined $chainref ) {
	if ( reftype $chainref ) {
	    $inaction3 = 1;
	} else {
	    ( $inaction1, undef, undef, undef ) = split /:/, $normalized_action = $chainref;
	}
    }	

    $param = '' unless defined $param;

    #
    # Determine the validity of the action
    #
    my $actiontype = $targets{$basictarget} || find_macro( $basictarget );

    if ( $config{ MAPOLDACTIONS } ) {
	( $basictarget, $actiontype , $param ) = map_old_actions( $basictarget ) unless $actiontype || $param;
    }

    fatal_error "Unknown ACTION ($action)" unless $actiontype;

    if ( $actiontype == MACRO ) {
	#
	# process_macro() will call process_rule_common() recursively for each rule in the macro body
	#
	fatal_error "Macro invocations nested too deeply" if ++$macro_nest_level > MAX_MACRO_NEST_LEVEL;

	if ( $param ne '' ) {
	    $current_param = $param unless $param eq 'PARAM';
	}

	my $generated = process_macro( $basictarget,
				       $chainref,
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
    } elsif ( $actiontype & ACTION ) {
	split_list $param, 'Action parameter';
    } else {
	fatal_error "The $basictarget TARGET does not accept a parameter" unless $param eq '';
    }

    #
    # We can now dispense with the postfix character
    #
    $action =~ s/[\+\-!]$//;
    #
    # Handle actions
    #
    if ( $actiontype & ACTION ) {
	#
	# Create the action:level:tag:param tupple.
	#
	$normalized_target = normalize_action( $basictarget, $loglevel, $param );

	unless (  $inaction3 ) {
	    fatal_error( "Action $basictarget invoked Recursively:" . join( '->', @actions, $basictarget ) ) if $actions{$basictarget}{active};
	    if ( my $ref = use_action( $normalized_target ) ) {
		#
		# First reference to this tupple
		#
		unless ( $actiontype & BUILTIN ) {
		    #
		    # Not a built-in - do preprocessing
		    #
		    process_action2( $normalized_target );
		    #
		    # Preprocessing may determine that the chain or one of it's dependents does NAT. If so:
		    #
		    #    - Refresh $actiontype
		    #    - Create the associate nat table chain if appropriate.
		    #
		    ensure_chain( 'nat', $ref->{name} ) if ( $actiontype = $targets{$basictarget} ) & NATRULE;
		}
	    }
	}

	$action = $basictarget; # Remove params, if any, from $action.
    }

    if ( $inaction1 ) {
	$targets{$inaction1} |= NATRULE if $actiontype & (NATRULE | NONAT | NATONLY );
	return 1;
    } 
    #
    # Take care of irregular syntax and targets
    #
    my $log_action = $action;

    if ( $actiontype & REDIRECT ) {
	my $z = $actiontype & NATONLY ? '' : firewall_zone;
	if ( $dest eq '-' ) {
	    $dest = $inaction3 ? '' : join( '', $z, '::' , $ports =~ /[:,]/ ? '' : $ports );
	} elsif ( $inaction3 ) {
	    $dest = ":$dest";
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
    my $sourcezone = '-';
    my $destzone = '-';
    my $sourceref;
    my $destref;
    my $origdstports;

    unless ( $inaction3 ) {
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
    }

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
	unless ( $inaction3 ) {
	    fatal_error "Missing destination zone" if $destzone eq '-' || $destzone eq '';
	    fatal_error "Unknown destination zone ($destzone)" unless $destref = defined_zone( $destzone );
	}
    }

    my $restriction = NO_RESTRICT;

    unless ( $inaction3 ) {
	if ( $sourceref && ( $sourceref->{type} == FIREWALL || $sourceref->{type} == VSERVER ) ) {
	    $restriction = $destref && ( $destref->{type} == FIREWALL || $destref->{type} == VSERVER ) ? ALL_RESTRICT : OUTPUT_RESTRICT;
	} else {
	    $restriction = INPUT_RESTRICT if $destref && ( $destref->{type} == FIREWALL || $destref->{type} == VSERVER );
	}
    }

    #
    # For compatibility with older Shorewall versions
    #
    $origdest = ALLIP if $origdest eq 'all';

    #
    # Take care of chain
    #
    my ( $chain, $policy );

    if ( $inaction3 ) {
	$chain = $chainref->{name};
    } else { 
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
    }
    #
    # Generate Fixed part of the rule
    #
    if ( $actiontype & ( NATRULE | NONAT ) && ! ( $actiontype & NATONLY ) ) {
	#
	# Either a DNAT, REDIRECT or ACCEPT+ rule or an Action with NAT;
	# don't apply rate limiting twice
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

    unless ( $section eq 'NEW' || $inaction3 ) {
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
		fatal_error 'ORIGINAL DEST "detect" is invalid in an action' if $inaction3;

		if ( $config{DETECT_DNAT_IPADDRS} && $sourcezone ne firewall_zone ) {
		    my $interfacesref = $sourceref->{interfaces};
		    my @interfaces = keys %$interfacesref;
		    $origdest = @interfaces ? "detect:@interfaces" : ALLIP;
 		} else {
		    $origdest = ALLIP;
		}
	    }
	} elsif ( $actiontype & ACTION ) {
	    $target = $usedactions{$normalized_target}->{name};
	} else {
	    if ( $server eq '' ) {
		fatal_error "A server and/or port must be specified in the DEST column in $action rules" unless $serverport;
	    } elsif ( $server =~ /^(.+)-(.+)$/ ) {
		validate_range( $1, $2 );
	    } else {
		unless ( ( $actiontype & ACTION ) && $server eq ALLIP ) {
		    my @servers = validate_address $server, 1;
		    $server = join ',', @servers;
		}
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
		if ( ! $inaction3 && $config{DETECT_DNAT_IPADDRS} && $sourcezone ne firewall_zone ) {
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
	expand_rule ( ensure_chain ('nat' , $inaction3 ? $chain : $sourceref->{type} == FIREWALL ? 'OUTPUT' : dnat_chain $sourcezone ),
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

	if ( $inaction3 ) {
	    $nonat_chain = ensure_chain 'nat', $chain;
	} elsif ( $sourceref->{type} == FIREWALL ) {
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
	    $action = $usedactions{$normalized_target}{name};
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

#
# Helper functions for process_rule(). That function deals with the ugliness of wildcard zones ('all' and 'any') and zone lists.
#
# Process a SECTION header
#
sub process_section ($) {
    my $sect = shift;
    #
    # read_a_line has already verified that there are exactly two tokens on the line
    #
    fatal_error "Invalid SECTION ($sect)" unless defined $sections{$sect};
    fatal_error "Duplicate or out of order SECTION $sect" if $sections{$sect};
    $sections{$sect} = 1;

    if ( $sect eq 'RELATED' ) {
	$sections{ESTABLISHED} = 1;
	finish_section 'ESTABLISHED';
    } elsif ( $sect eq 'NEW' ) {
	@sections{'ESTABLISHED','RELATED'} = ( 1, 1 );
	finish_section ( ( $section eq 'RELATED' ) ? 'RELATED' : 'ESTABLISHED,RELATED' );
    }

    $section = $sect;
}

#
# Build a source or destination zone list
#
sub build_zone_list( $$$\$\$ ) {
    my ($fw, $input, $which, $intrazoneref, $wildref ) = @_;
    my $any = ( $input =~ s/^any/all/ );
    my $exclude;
    my $rest;
    my %exclude;
    my @result;
    #
    # Handle Wildcards
    #
    if ( $input =~ /^(all[-+]*)(![^:]+)?(:.*)?/ ) {
	$input   = $1;
	$exclude = $2;
	$rest    = $3;

	$$wildref = 1;

	if ( defined $exclude ) {
	    $exclude =~ s/!//;
	    fatal_error "Invalid exclusion list (!$exclude)" if $exclude =~ /^,|!|,,|,$/;
	    for ( split /,/, $exclude ) {
		fatal_error "Unknown zone ($_)" unless defined_zone $_;
		$exclude{$_} = 1;
	    }
	}

	unless ( $input eq 'all' ) {
	    if ( $input eq 'all+' ) {
		$$intrazoneref = 1;
	    } elsif ( ( $input eq 'all+-' ) || ( $input eq 'all-+' ) ) {
		$$intrazoneref = 1;
		$exclude{$fw} = 1;
	    } elsif ( $input eq 'all-' ) {
		$exclude{$fw} = 1;
	    } else {
		fatal_error "Invalid $which ($input)";
	    }
	}

	@result = grep ! $exclude{$_}, $any ? all_parent_zones : non_firewall_zones;

	unshift @result, $fw unless $exclude{$fw};

    } elsif ( $input =~ /^([^:]+,[^:]+)(:.*)?$/ ) {
	$input    = $1;
	$rest     = $2;
	$$wildref = 1;

	$$intrazoneref = ( $input =~ s/\+$// );

	@result = split_list $input, 'zone';
    } else {
	@result = ( $input );
    }

    if ( defined $rest ) {
	$_ .= $rest for @result;
    }

    @result;
}

#
# Process a Record in the rules file
#
sub process_rule ( ) {
    my ( $target, $source, $dest, $proto, $ports, $sports, $origdest, $ratelimit, $user, $mark, $connlimit, $time, $headers ) = split_line1 1, 13, 'rules file', $rule_commands;

    process_comment,            return 1 if $target eq 'COMMENT';
    process_section( $source ), return 1 if $target eq 'SECTION';
    #
    # Section Names are optional so once we get to an actual rule, we need to be sure that
    # we close off any missing sections.
    #
    process_section( 'NEW' ) unless $section;

    if ( $source =~ /^none(:.*)?$/i || $dest =~ /^none(:.*)?$/i ) {
	progress_message "Rule \"$currentline\" ignored.";
	return 1;
    }

    my $intrazone = 0;
    my $wild      = 0;
    my $thisline  = $currentline; #We must save $currentline because it is overwritten by macro expansion
    my $action    = isolate_basic_target $target;
    my $fw        = firewall_zone;
    my @source    = build_zone_list ( $fw, $source, 'SOURCE', $intrazone, $wild );
    my @dest      = build_zone_list ( $fw, $dest,   'DEST'  , $intrazone, $wild );
    my $generated = 0;

    fatal_error "Invalid or missing ACTION ($target)" unless defined $action;

    for $source ( @source ) {
	for $dest ( @dest ) {
	    my $sourcezone = (split( /:/, $source, 2 ) )[0];
	    my $destzone   = (split( /:/, $dest,   2 ) )[0];
	    $destzone = $action =~ /^REDIRECT/ ? $fw : '' unless defined_zone $destzone;
	    if ( ! $wild || $intrazone || ( $sourcezone ne $destzone ) ) {
		$generated |= process_rule_common( undef,
						   $target,
						   '',
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
						   $wild );
	    }
	}
    }

    warning_message  qq(Entry generated no $toolname rules) unless $generated;

    progress_message qq(   Rule "$thisline" $done);
}

#
# Process the Rules File
#
sub process_rules() {

    my $fn = open_file 'rules';

    if ( $fn ) {

	first_entry "$doing $fn...";

	process_rule while read_a_line;

	clear_comment;
    }

    $section = 'DONE';
}

1;
