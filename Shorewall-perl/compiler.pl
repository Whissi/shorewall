#! /usr/bin/perl -w
#
#     The Shoreline Firewall4 (Shorewall-perl) Packet Filtering Firewall Compiler - V3.9
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2007 - Tom Eastep (teastep@shorewall.net)
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
#	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#
#	Commands are:
#
#          compiler.pl                          Verify the configuration files.
#	   compile <path name>                  Compile into <path name>
#
#	Environmental Variables are set up by the Compiler wrapper ('compiler' program).
#
#	    EXPORT=Yes                          -e option specified to /sbin/shorewall
#	    SHOREWALL_DIR                       A directory name was passed to /sbin/shorewall
#	    VERBOSE                             Standard Shorewall verbosity control.
#           TIMESTAMP=Yes                       -t option specified to /sbin/shorewall
#
#       This program performs rudimentary shell variable expansion on action and macro files.

use strict;
use lib '/usr/share/shorewall-perl';
use Shorewall::Compiler;
#
# Compile/Check the configuration.
#
compiler $ARGV[0];
