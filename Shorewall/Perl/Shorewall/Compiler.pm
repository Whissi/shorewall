#! /usr/bin/perl -w
#
#     The Shoreline Firewall4 (Shorewall-perl) Packet Filtering Firewall Compiler - V4.4
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2007,2008,2009 - Tom Eastep (teastep@shorewall.net)
#
#	Complete documentation is available at http://shorewall.net
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of Version 2 of the GNU General Public License
#	as published by the Free Software Foundation.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

package Shorewall::Compiler;
require Exporter;
use Shorewall::Config qw(:DEFAULT :internal);
use Shorewall::Chains qw(:DEFAULT :internal);
use Shorewall::Zones;
use Shorewall::Policy;
use Shorewall::Nat;
use Shorewall::Providers;
use Shorewall::Tc;
use Shorewall::Tunnels;
use Shorewall::Actions;
use Shorewall::Accounting;
use Shorewall::Rules;
use Shorewall::Proc;
use Shorewall::Proxyarp;
use Shorewall::IPAddrs;
use Shorewall::Raw;

our @ISA = qw(Exporter);
our @EXPORT = qw( compiler EXPORT TIMESTAMP DEBUG );
our @EXPORT_OK = qw( $export );
our $VERSION = '4.3_7';

our $export;

our $test;

our $reused = 0;

our $family = F_IPV4;

#
# Reinitilize the package-globals in the other modules
#
sub reinitialize() {
    Shorewall::Config::initialize($family);
    Shorewall::Chains::initialize ($family);
    Shorewall::Zones::initialize ($family);
    Shorewall::Policy::initialize;
    Shorewall::Nat::initialize;
    Shorewall::Providers::initialize($family);
    Shorewall::Tc::initialize($family);
    Shorewall::Actions::initialize( $family );
    Shorewall::Accounting::initialize;
    Shorewall::Rules::initialize($family);
    Shorewall::Proxyarp::initialize($family);
    Shorewall::IPAddrs::initialize($family);
}

#
# First stage of script generation.
#
#    Copy prog.header to the generated script.
#    Generate the various user-exit jacket functions.
#
sub generate_script_1() {

    my $date = localtime;

    if ( $test ) {
	emit "#!/bin/sh\n#\n# Compiled firewall script generated by Shorewall-perl\n#";
    } else {
	emit "#!/bin/sh\n#\n# Compiled firewall script generated by Shorewall-perl $globals{VERSION} - $date\n#";
	if ( $family == F_IPV4 ) {
	    copy $globals{SHAREDIRPL} . 'prog.header';
	} else {
	    copy $globals{SHAREDIRPL} . 'prog.header6';
	}
    }

    emit <<'EOF';
################################################################################
# Functions to execute the various user exits (extension scripts)
################################################################################
EOF

    for my $exit qw/init isusable start tcclear started stop stopped clear refresh refreshed restored/ {
	emit "\nrun_${exit}_exit() {";
	push_indent;
	append_file $exit or emit 'true';
	pop_indent;
	emit '}';
    }

    emit <<'EOF';
################################################################################
# End user exit functions
################################################################################
EOF

}

#
# Second stage of script generation.
#
#    Generate the 'initialize()' function.
#
#    Note: This function is not called when $command eq 'check'. So it must have no side effects other
#          than those related to writing to the object file.

sub generate_script_2() {

    emit ( '',
	   '#',
	   '# This function initializes the global variables used by the program',
	   '#',
	   'initialize()',
	   '{',
	   '    #',
	   '    # Be sure that umask is sane',
	   '    #',
	   '    umask 077',
	   '    #',
	   '    # These variables are required by the library functions called in this script',
	   '    #'
	   );

    push_indent;

    if ( $family == F_IPV4 ) {
	if ( $export ) {
	    emit ( 'SHAREDIR=/usr/share/shorewall-lite',
		   'CONFDIR=/etc/shorewall-lite',
		   'PRODUCT="Shorewall Lite"'
		 );
	} else {
	    emit ( 'SHAREDIR=/usr/share/shorewall',
		   'CONFDIR=/etc/shorewall',
		   'PRODUCT=\'Shorewall\'',
		 );
	}
    } else {
	if ( $export ) {
	    emit ( 'SHAREDIR=/usr/share/shorewall6-lite',
		   'CONFDIR=/etc/shorewall6-lite',
		   'PRODUCT="Shorewall6 Lite"'
		 );
	} else {
	    emit ( 'SHAREDIR=/usr/share/shorewall6',
		   'CONFDIR=/etc/shorewall6',
		   'PRODUCT=\'Shorewall6\'',
		 );
	}
    }

    emit( '[ -f ${CONFDIR}/vardir ] && . ${CONFDIR}/vardir' );

    if ( $family == F_IPV4 ) {
	if ( $export ) {
	    emit ( 'CONFIG_PATH="/etc/shorewall-lite:/usr/share/shorewall-lite"' ,
		   '[ -n "${VARDIR:=/var/lib/shorewall-lite}" ]' );
	} else {
	    emit ( qq(CONFIG_PATH="$config{CONFIG_PATH}") ,
		   '[ -n "${VARDIR:=/var/lib/shorewall}" ]' );
	}
    } else {
	if ( $export ) {
	    emit ( 'CONFIG_PATH="/etc/shorewall6-lite:/usr/share/shorewall6-lite"' ,
		   '[ -n "${VARDIR:=/var/lib/shorewall6-lite}" ]' );
	} else {
	    emit ( qq(CONFIG_PATH="$config{CONFIG_PATH}") ,
		   '[ -n "${VARDIR:=/var/lib/shorewall6}" ]' );
	}
    }

    emit 'TEMPFILE=';

    propagateconfig;

    my @dont_load = split_list $config{DONT_LOAD}, 'module';

    emit ( '[ -n "${COMMAND:=restart}" ]',
	   '[ -n "${VERBOSE:=0}" ]',
	   qq([ -n "\${RESTOREFILE:=$config{RESTOREFILE}}" ]),
	   '[ -n "$LOGFORMAT" ] || LOGFORMAT="Shorewall:%s:%s:"' );

    emit ( qq(VERSION="$globals{VERSION}") ) unless $test;

    emit ( qq(PATH="$config{PATH}") ,
	   'TERMINATOR=fatal_error' ,
	   qq(DONT_LOAD="@dont_load") ,
	   qq(STARTUP_LOG="$config{STARTUP_LOG}") ,
	   "LOG_VERBOSE=$config{LOG_VERBOSITY}" ,
	   ''
	   );

    set_chain_variables;

    append_file 'params' if $config{EXPORTPARAMS};

    emit ( '',
	   "STOPPING=",
	   '',
	   '#',
	   '# The library requires that ${VARDIR} exist',
	   '#',
	   '[ -d ${VARDIR} ] || mkdir -p ${VARDIR}'
	   );

    my $global_variables = have_global_variables;

    if ( $global_variables ) {
	emit( '' ,
	      '#' ,
	      '# Set global variables holding detected IP information' ,
	      '#' ,
	      'case $COMMAND in' );

	push_indent;

	if ( $global_variables & NOT_RESTORE ) {
	    emit( 'start|restart|refresh)' );
	} else {
	    emit( 'start|restart|refresh|restore)' );
	}
	 
	push_indent;

	set_global_variables(1);

	emit ';;';
    
	if ( $global_variables == ( ALL_COMMANDS | NOT_RESTORE ) ) {
	    pop_indent;
	
	    emit 'restore)';

	    push_indent;

	    set_global_variables(0);

	    emit ';;';
	}

	pop_indent;
	pop_indent;

	emit ( 'esac' ) ,
    }

    pop_indent;

    emit "\n}\n"; # End of initialize()

}

#
# Final stage of script generation.
#
#    Copy prog.functions to the object file.
#    Generate code for loading the various files in /var/lib/shorewall[6][-lite]
#    Generate code to add IP addresses under ADD_IP_ALIASES and ADD_SNAT_ALIASES
#
#    Generate the 'setup_netfilter()' function that runs iptables-restore.
#    Generate the 'define_firewall()' function.
#
#    Note: This function is not called when $command eq 'check'. So it must have no side effects other
#          than those related to writing to the object file.
#
sub generate_script_3($) {

    unless ( $test ) {
	if ( $family == F_IPV4 ) {
	    copy $globals{SHAREDIRPL} . 'prog.functions';
	} else {
	    copy $globals{SHAREDIRPL} . 'prog.functions6';
	}
    }

    if ( $family == F_IPV4 ) {
	progress_message2 "Creating iptables-restore input...";
    } else {
	progress_message2 "Creating ip6tables-restore input...";
    }

    create_netfilter_load( $test );
    create_chainlist_reload( $_[0] );

    emit "#\n# Start/Restart the Firewall\n#";

    emit 'define_firewall() {';

    push_indent;

    save_progress_message 'Initializing...';

    if ( $export ) {
	my $fn = find_file 'modules';

	if ( $fn ne "$globals{SHAREDIR}/modules" && -f $fn ) {
	    emit 'echo MODULESDIR="$MODULESDIR" > ${VARDIR}/.modulesdir';
	    emit 'cat > ${VARDIR}/.modules << EOF';
	    open_file $fn;
	    while ( read_a_line ) {
		emit_unindented $currentline;
	    }
	    emit_unindented 'EOF';
	    emit 'reload_kernel_modules < ${VARDIR}/.modules';
	} else {
	    emit 'load_kernel_modules Yes';
	}
    } else {
	emit 'load_kernel_modules Yes';
    }

    if ( $family == F_IPV4 ) {
	for my $interface ( @{find_interfaces_by_option 'norfc1918'} ) {
	    emit ( "addr=\$(ip -f inet addr show $interface 2> /dev/null | grep 'inet\ ' | head -n1)",
		   'if [ -n "$addr" ]; then',
		   '    addr=$(echo $addr | sed \'s/inet //;s/\/.*//;s/ peer.*//\')',
		   '    for network in 10.0.0.0/8 176.16.0.0/12 192.168.0.0/16; do',
		   '        if in_network $addr $network; then',
		   "            error_message \"WARNING: The 'norfc1918' option has been specified on an interface with an RFC 1918 address. Interface:$interface\"",
		   '        fi',
		   '    done',
		   "fi\n" );
	}

	my @ipsets = all_ipsets;

	if ( @ipsets ) {
	    emit ( '[ -n "$(mywhich ipset)" ] || fatal_error "The ipset utility cannot be located"' ,    
		   '',
		   'if [ "$COMMAND" = start ]; then' ,
		   '    if [ -f ${VARDIR}/ipsets.save ]; then' ,
		   '        ipset -U :all: :all:' ,
		   '        ipset -U :all: :default:' ,
		   '        ipset -F' ,
		   '        ipset -X' ,
		   '        ipset -R < ${VARDIR}/ipsets.save' ,
		   '    fi' ,
		   '' );

	    emit ( "    qt ipset -L $_ -n || ipset -N $_ iphash" ) for @ipsets;

	    emit ( '' ,
		   'elif [ "$COMMAND" = restart ]; then' ,
		   '' );

	    emit ( "    qt ipset -L $_ -n || ipset -N $_ iphash" ) for @ipsets;

	    emit ( '' , 
		   '    if ipset -S > ${VARDIR}/ipsets.tmp; then' ,
		   '        grep -q "^-N" ${VARDIR}/ipsets.tmp && mv -f ${VARDIR}/ipsets.tmp ${VARDIR}/ipsets.save' ,
		   '    fi' );
	    emit ( 'fi',
		   '' );
	}

	emit ( 'if [ "$COMMAND" = refresh ]; then' ,
	       '   run_refresh_exit' );

	emit ( "   qt ipset -L $_ -n || ipset -N $_ iphash" ) for @ipsets;

	emit ( 'else' ,
	       '    run_init_exit',
	       'fi',
	       '' );

	mark_firewall_not_started;
		       	       
	emit ('',
	       'delete_proxyarp',
	       ''
	     );

	if ( $capabilities{NAT_ENABLED} ) {
	    emit(  'if [ -f ${VARDIR}/nat ]; then',
		   '    while read external interface; do',
		   '        del_ip_addr $external $interface',
		   '    done < ${VARDIR}/nat',
		   '',
		   '    rm -f ${VARDIR}/nat',
		   "fi\n" );
	}

	emit "disable_ipv6\n" if $config{DISABLE_IPV6};

    } else {
	emit ( '#',
	       '# Recent kernels are difficult to configure -- we see state match omitted a lot so we check for it here',
	       '#',
	       'qt1 $IP6TABLES -N foox1234',
	       'qt1 $IP6TABLES -A foox1234 -m state --state ESTABLISHED,RELATED -j ACCEPT',
	       'result=$?',
	       'qt1 $IP6TABLES -F foox1234',
	       'qt1 $IP6TABLES -X foox1234',
	       '[ $result = 0 ] || startup_error "Your kernel/ip6tables do not include state match support. No version of Shorewall6 will run on this system"',
	       '' );

	emit ( '[ "$COMMAND" = refresh ] && run_refresh_exit || run_init_exit',
		   '',
	       'qt1 $IP6TABLES -L shorewall -n && qt1 $IP6TABLES -F shorewall && qt1 $IP6TABLES -X shorewall',
	       ''
	     );

    }

    emit qq(delete_tc1\n) if $config{CLEAR_TC};

    emit( 'setup_common_rules', '' );

    emit( 'setup_routing_and_traffic_shaping', '' );

    emit 'cat > ${VARDIR}/proxyarp << __EOF__';
    dump_proxy_arp;
    emit_unindented '__EOF__';

    emit( '',
	  'if [ "$COMMAND" != refresh ]; then' );

    push_indent;

    emit 'cat > ${VARDIR}/zones << __EOF__';
    dump_zone_contents;
    emit_unindented '__EOF__';

    pop_indent;

    emit "fi\n";

    emit '> ${VARDIR}/nat';

    add_addresses;

    emit( '',
	  'if [ $COMMAND = restore ]; then',
	  '    iptables_save_file=${VARDIR}/$(basename $0)-iptables',
	  '    if [ -f $iptables_save_file ]; then' );

    if ( $family == F_IPV4 ) {
	emit '        cat $iptables_save_file | $IPTABLES_RESTORE # Use this nonsensical form to appease SELinux'
    } else {
	emit '        cat $iptables_save_file | $IP6TABLES_RESTORE # Use this nonsensical form to appease SELinux'
    }

    emit<<'EOF';
    else
        fatal_error "$iptables_save_file does not exist"
    fi
EOF
    pop_indent;
    setup_forwarding( $family );
    push_indent;
    emit<<'EOF';
    set_state "Started"
    run_restored_exit
else
    if [ $COMMAND = refresh ]; then
        chainlist_reload
EOF
    setup_forwarding( $family );
    emit<<'EOF';
        run_refreshed_exit
        do_iptables -N shorewall
        set_state "Started"
    else
        setup_netfilter
        restore_dynamic_rules
        conditionally_flush_conntrack
EOF
    setup_forwarding( $family );
    emit<<'EOF';
        run_start_exit
        do_iptables -N shorewall
        set_state "Started"
        run_started_exit
    fi

    [ $0 = ${VARDIR}/firewall ] || cp -f $(my_pathname) ${VARDIR}/firewall
fi

date > ${VARDIR}/restarted

case $COMMAND in
    start)
        logger -p kern.info "$PRODUCT started"
        ;;
    restart)
        logger -p kern.info "$PRODUCT restarted"
        ;;
    refresh)
        logger -p kern.info "$PRODUCT refreshed"
        ;;
    restore)
        logger -p kern.info "$PRODUCT restored"
        ;;
esac
EOF

    pop_indent;

    emit "}\n";

}

#
#  The Compiler.
#
#     Arguments are named -- see %parms below.
#
sub compiler {

    my ( $objectfile, $directory, $verbosity, $timestamp , $debug, $chains , $log , $log_verbosity ) = 
       ( '',          '',         -1,          '',          0,      '',       '',   -1 );

    $export = 0;
    $test   = 0;

    sub edit_boolean( $ ) {
	 my $val = numeric_value( shift ); 
	 defined($val) && ($val >= 0) && ($val < 2);
     }

    sub edit_verbosity( $ ) {
	 my $val = numeric_value( shift );
	 defined($val) && ($val >= MIN_VERBOSITY) && ($val <= MAX_VERBOSITY);
     }

    sub edit_family( $ ) {
	my $val = numeric_value( shift );
	defined($val) && ($val == F_IPV4 || $val == F_IPV6);
    }

    my %parms = ( object        => { store => \$objectfile },
		  directory     => { store => \$directory  },
		  family        => { store => \$family    ,    edit => \&edit_family    } ,
		  verbosity     => { store => \$verbosity ,    edit => \&edit_verbosity } ,
		  timestamp     => { store => \$timestamp,     edit => \&edit_boolean   } ,
		  debug         => { store => \$debug,         edit => \&edit_boolean   } ,
		  export        => { store => \$export ,       edit => \&edit_boolean   } ,
		  chains        => { store => \$chains },
		  log           => { store => \$log },
		  log_verbosity => { store => \$log_verbosity, edit => \&edit_verbosity } ,
		  test          => { store => \$test },
		);
    #
    #                               P A R A M E T E R    P R O C E S S I N G
    #
    while ( defined ( my $name = shift ) ) {
	fatal_error "Unknown parameter ($name)" unless my $ref = $parms{$name};
	fatal_error "Undefined value supplied for parameter $name" unless defined ( my $val = shift ) ;
	if ( $ref->{edit} ) {
	    fatal_error "Invalid value ( $val ) supplied for parameter $name" unless $ref->{edit}->($val);
	}

	${$ref->{store}} = $val;
    }

    reinitialize if $reused++ || $family == F_IPV6;

    if ( $directory ne '' ) {
	fatal_error "$directory is not an existing directory" unless -d $directory;
	set_shorewall_dir( $directory );
    }

    set_verbose( $verbosity );
    set_log($log, $log_verbosity) if $log;
    set_timestamp( $timestamp );
    set_debug( $debug );
    #
    #                      S H O R E W A L L . C O N F  A N D  C A P A B I L I T I E S
    #
    get_configuration( $export );

    report_capabilities;

    require_capability( 'MULTIPORT'       , "Shorewall-perl $globals{VERSION}" , 's' );
    require_capability( 'RECENT_MATCH'    , 'MACLIST_TTL' , 's' )           if $config{MACLIST_TTL};
    require_capability( 'XCONNMARK'       , 'HIGH_ROUTE_MARKS=Yes' , 's' )  if $config{HIGH_ROUTE_MARKS};
    require_capability( 'MANGLE_ENABLED'  , 'Traffic Shaping' , 's'      )  if $config{TC_ENABLED};
    require_capability( 'CONNTRACK_MATCH' , 'RFC1918_STRICT=Yes' , 's'   )  if $config{RFC1918_STRICT};

    set_command( 'check', 'Checking', 'Checked' ) unless $objectfile;

    initialize_chain_table;

    unless ( $command eq 'check' ) {
	create_temp_object( $objectfile , $export );
    }

    #
    # Allow user to load Perl modules
    #
    run_user_exit1 'compile';
    #
    #                                     Z O N E   D E F I N I T I O N
    #                              (Produces no output to the compiled script)
    #
    determine_zones;
    #
    # Process the interfaces file.
    #
    validate_interfaces_file ( $export );
    #
    # Process the hosts file.
    #
    validate_hosts_file;
    #
    # Report zone contents
    #
    zone_report;
    #
    # Do action pre-processing.
    #
    process_actions1;
    #
    #                                        P O L I C Y
    #                           (Produces no output to the compiled script)
    #
    validate_policy;
    #
    #                                       N O T R A C K
    #                           (Produces no output to the compiled script)
    #
    setup_notrack;

    enable_object;

    unless ( $command eq 'check' ) {
	#
	# Place Header in the object
	#
	generate_script_1;
	#
	#                               C O M M O N _ R U L E S
	#           (Writes the setup_common_rules() function to the compiled script)
	#
	emit(  "\n#",
	       '# Setup Common Rules (/proc)',
	       '#',
	       'setup_common_rules() {'
	    );

	push_indent;
    } 
    #
    # Do all of the zone-independent stuff
    #
    add_common_rules;
    #
    # /proc stuff
    #
    if ( $family == F_IPV4 ) {
	setup_arp_filtering;
	setup_route_filtering;
	setup_martian_logging;
    }

    setup_source_routing($family);
    #
    # Proxy Arp/Ndp
    #
    setup_proxy_arp;
    #
    # Handle MSS setings in the zones file
    #
    setup_zone_mss;

    unless ( $command eq 'check' ) {
	pop_indent;
	emit '}';
    }

    #
    #                      R O U T I N G _ A N D _ T R A F F I C _ S H A P I N G
    #         (Writes the setup_routing_and_traffic_shaping() function to the compiled script)
    #
    unless ( $command eq 'check' ) {
	emit(  "\n#",
	       '# Setup routing and traffic shaping',
	       '#',
	       'setup_routing_and_traffic_shaping() {'
	    );

	push_indent;
    }
    #
    # [Re-]establish Routing
    #
    setup_providers;
    #
    # TCRules and Traffic Shaping
    #
    setup_tc;

    unless ( $command eq 'check' ) {
	pop_indent;
	emit "}\n";
    }

    disable_object;
    #
    #                                       N E T F I L T E R
    #       (Produces no output to the compiled script -- rules are stored in the chain table)
    #
    process_tos;

    if ( $family == F_IPV4 ) {
	#
	# ECN
	#
	setup_ecn if $capabilities{MANGLE_ENABLED} && $config{MANGLE_ENABLED};
	#
	# Setup Masquerading/SNAT
	#
	setup_masq; 
    }

    #
    # MACLIST Filtration
    #
    setup_mac_lists 1;
    #
    # Process the rules file.
    #
    process_rules;
    #
    # Add Tunnel rules.
    #
    setup_tunnels;
    #
    # Post-rules action processing.
    #
    process_actions2;
    process_actions3;
    #
    # MACLIST Filtration again
    #
    setup_mac_lists 2;
    #
    # Apply Policies
    #
    apply_policy_rules;

    if ( $family == F_IPV4 ) {
	#
	# Setup Nat
	#
	setup_nat;
	#
	# Setup NETMAP
	#
	setup_netmap;
    }
    #
    # Accounting.
    #
    setup_accounting;
    #
    # We generate the matrix even though we don't write out the rules. That way, we insure that
    # a compile of the script won't blow up during that step.
    #
    generate_matrix;

    if ( $command eq 'check' ) {
	if ( $family == F_IPV4 ) {
	    progress_message3 "Shorewall configuration verified";
	} else {
	    progress_message3 "Shorewall6 configuration verified";
	}
    } else {
	enable_object;
	#
	#                                    I N I T I A L I Z E
	#                  (Writes the initialize() function to the compiled script)
	#
	generate_script_2;
	#
	#                          N E T F I L T E R   L O A D
	#    (Produces setup_netfilter(), chainlist_reload() and define_firewall() )
	#
	generate_script_3( $chains );
	#                               S T O P _ F I R E W A L L
	#             (Writes the stop_firewall() function to the compiled script)
	#
	compile_stop_firewall( $test );
	#
	# Copy the footer to the object
	#
	unless ( $test ) {
	    if ( $family == F_IPV4 ) {
		copy $globals{SHAREDIRPL} . 'prog.footer';
	    } else {
		copy $globals{SHAREDIRPL} . 'prog.footer6';
	    }
	}
	#
	# Close, rename and secure the object
	#
	finalize_object ( $export );
	#
	# And generate the auxilary config file
	#
	generate_aux_config if $export;
    }

    close_log if $log;

    1;
}

1;
