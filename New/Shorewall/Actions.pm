package Shorewall::Actions;
require Exporter;
use Shorewall::Common;
use Shorewall::Config;
use Shorewall::Zones;
use Shorewall::Chains;

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw( %usedactions %default_actions );
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

1;
