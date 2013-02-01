#
# Shorewall 4 - RST Action
#
#    /usr/share/shorewall/action.RST
#
#     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
#
#     (c) 2012 - Tom Eastep (teastep@shorewall.net)
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
#   RST[([<action>])]
#
#       Default action is DROP
#
##########################################################################################
?FORMAT 2

DEFAULTS DROP,-

?BEGIN PERL;

use Shorewall::Config;
use Shorewall::Chains;
use Shorewall::Rules;

my ( $action, $audit ) = get_action_params( 2 );

if ( supplied $audit ) {
     fatal_error "Invalid parameter ($audit) to action Invalid" if $audit ne 'audit';
     $action = "A_$action";
}    

perl_action_tcp_helper( $action, '-p 6 --tcp-flags RST RST' );

1;

?END PERL;
