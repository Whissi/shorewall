package Shorewall::Rules;
require Exporter;

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
		  
		  %targets
		  );
our @EXPORT_OK = ();
our @VERSION = 1.00;

#
#  Target Table. Each entry maps a target to a set of flags defined as follows.
#
use constant { STANDARD => 1,              #defined by Netfilter
	       NATRULE  => 2,              #Involved NAT
	       BUILTIN  => 4,              #A built-in action
	       NONAT    => 8,              #'NONAT' or 'ACCEPT+'
	       NATONLY  => 16,             #'DNAT-' or 'REDIRECT-'
	       REDIRECT => 32,             #'REDIRECT'
	       ACTION   => 64,             #An action
	       MACRO    => 128,            #A Macro
	       LOGRULE  => 256,            #'LOG'
	   };
#
#   As new targets (Actions and Macros) are discovered, they are added to the table
#
our %targets = ('ACCEPT'       => STANDARD,
		'ACCEPT+'      => STANDARD  + NONAT,
		'ACCEPT!'      => STANDARD,
		'NONAT'        => STANDARD  + NONAT,
		'DROP'         => STANDARD,
		'DROP!'        => STANDARD,
		'REJECT'       => STANDARD,
		'REJECT!'      => STANDARD,
		'DNAT'         => NATRULE,
		'DNAT-'        => NATRULE  + NATONLY,
		'REDIRECT'     => NATRULE  + REDIRECT,
		'REDIRECT-'    => NATRULE  + REDIRECT + NATONLY,
		'LOG'          => STANDARD + LOGRULE,
		'CONTINUE'     => STANDARD,
		'QUEUE'        => STANDARD,
		'SAME'         => NATRULE,
		'SAME-'        => NATRULE  + NATONLY,
		'dropBcast'    => BUILTIN  + ACTION,
		'allowBcast'   => BUILTIN  + ACTION,
		'dropNotSyn'   => BUILTIN  + ACTION,
		'rejNotSyn'    => BUILTIN  + ACTION,
		'dropInvalid'  => BUILTIN  + ACTION,
		'allowInvalid' => BUILTIN  + ACTION,
		'allowinUPnP'  => BUILTIN  + ACTION,
		'forwardUPnP'  => BUILTIN  + ACTION,
		'Limit'        => BUILTIN  + ACTION,
		);

1;
