package Shorewall::Actions;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Chains;
use Shorewall::Macros;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( merge_levels 
		  split_action 
		  isolate_basic_target
		  add_requiredby 
		  createlogactionchain 
		  createactionchain 
		  find_logactionchain
		  process_actions1
		  process_actions2
		  process_actions3
		  dump_action_table
		  
		  %usedactions 
		  %default_actions 
		  %actions
		  );
our @EXPORT_OK = qw( );
our @VERSION = 1.00;

#
#  Used Actions. Each action that is actually used has an entry with value 1.
#
our %usedactions;
#
# Default actions for each policy.
#
our %default_actions = ( DROP     => 'none' ,
			 REJECT   => 'none' ,
			 ACCEPT   => 'none' ,
			 QUEUE    => 'none' );

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
my %logactionchains;
#
# Maps each used macro to it's 'macro. ...' file.
#
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
# Get Macro Name
#
sub isolate_basic_target( $ ) {
    ( split '/' , $_[0] )[0];
}

#
# Define an Action
#
sub new_action( $ ) {

    my $action = $_[0];

    my %h;

    $h{actchain}   = '';
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
	$chain = substr $chain, 0, 27 if $actionref->{actchain} == 10 and length $chain == 28;
    }

    $actionref = new_action $action unless $actionref;

    $level = 'none' unless $level;

    $logactionchains{"$action:$level"} = new_chain 'filter', '%' . $chain . $actionref->{actchain}++;

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

    for my $act ( grep $targets{$_} & ACTION , keys %targets ) {
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

	    if ( $targets{$action} ) {
		next if $targets{$action} & ACTION;
		fatal_error "Invalid Action Name: $action";
	    }

	    $targets{$action} = ACTION;

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

		my $targettype = $targets{$target};

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

			    $targettype = $targets{$mtarget};

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
		
#
# Generate chain for non-builtin action invocation
#	
sub process_action3( $$$$$ ) {
    #
    # This function is called to process each rule generated from an action file.
    #
    sub process_action( $$$$$$$$$$ ) {
	my ($chainref, $actionname, $target, $source, $dest, $proto, $ports, $sports, $rate, $user ) = @_;
	
	my ( $action , $level ) = split_action $target;
	
	expand_rule ( $chainref ,
		      do_proto( $proto, $ports, $sports ) . do_ratelimit( $rate ) . do_user $user , 
		      $source ,
		      $dest ,
		      '', #Original Dest
		      '-j ' . ($action eq 'REJECT' ? 'reject' : $action eq 'CONTINUE' ? 'RETURN' : $action),
		      $level ,
		      $action ,
		      '' );
    }

    my ( $chainref, $wholeaction, $action, $level, $tag ) = @_;
    my $actionfile = find_file "action.$action";
    my $standard = ( $actionfile =~ /^($env{SHAREDIR})/ );

    fatal_error "Missing Action File: $actionfile" unless -f $actionfile;

    progress_message2 "Processing $actionfile for chain $chainref->{name}...";

    open A, $actionfile or fatal_error "Unable to open $actionfile: $!";

    while ( $line = <A> ) {
	chomp $line;
	next if $line =~ /^\s*#/;
	next if $line =~ /^\s*$/;
	$line =~ s/\s+/ /g;
	$line =~ s/#.*$//;	
	$line = expand_shell_variables $line unless $standard;
		
	my ($target, $source, $dest, $proto, $ports, $sports, $rate, $user , $extra ) = split /\s+/, $line;

	my $target2 = merge_levels $wholeaction, $target;

	my ( $action2 , $level2 ) = split_action $target2;

	my $action2type = $targets{isolate_basic_target $action2};

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
	    
	    my $standard = ( $fn =~ /^($env{SHAREDIR})/ );
	    
	    while ( $line = <M> ) {
		next if $line =~ /^\s*#/;
		next if $line =~ /^\s*$/;
		$line =~ s/\s+/ /g;
		$line =~ s/#.*$//;
		$line = expand_shell_variables $line unless $standard;

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

sub process_actions3 () {
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
	
	my @tag = split /,/, $tag;
	
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
	
	if ( $targets{$action} & BUILTIN ) {
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

1;
