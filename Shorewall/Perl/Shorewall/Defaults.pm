#
# Shorewall 4.4 -- /usr/share/shorewall/Shorewall/Defaults.pm
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
#  This module exists solely to allow flexibility in the location of files

package Shorewall::Defaults;
require Exporter;

use strict;

our @ISA = qw(Exporter);

our @EXPORT = qw( %defaults );

# %defaults => {product}  => { sbin   => <directory> ,
#                              share  => <directory> ,
#                              config => <directory> ,
#                              var    => <directory> }
# 
######################################################################################
# These are set by the installer. Capitalized variable names ease the installer's work
########################b##############################################################
my $ETC   = '/etc/';
my $SBIN  = '/sbin/';
my $SHARE = '/usr/share/';
my $VAR   = '/var/lib/';
#######################################################################################
our %defaults = ( 'shorewall'       => { sbin   => $SBIN ,
					 share  => $SHARE ,
					 config => $ETC ,
					 var    => $VAR ,
					 name   => 'Shorewall' } ,
		  'shorewall-lite'  => { sbin   => '/sbin/' ,
					 share  => '/usr/share/' ,
					 config => '/etc/' ,
					 var    => '/var/lib/' ,
					 name   => 'Shorewall Lite' } ,
		  'shorewall6'      => { sbin   => $SBIN ,
					 share  => $SHARE ,
					 config => $ETC ,
					 var    => $VAR ,
					 name   => 'Shorewall6' } ,
		  'shorewall6-lite' => { sbin   => '/sbin/' ,
					 share  => '/usr/share/' ,
					 config => '/etc/' ,
					 var    => '/var/lib/' ,
					 name   => 'Shorewall6 Lite' } ,
		);
