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

DEFAULTS DROP,-

?if @2 ne '' && @2 ne '-'
    ?if @2 eq 'audit'
DEFAULTS A_DROP,-
    ?else
	?error The second parameter to NotSyn must be 'audit' or '-'
    ?endif
?else
DEFAULTS DROP,-
?endif

@1	-	-	-	;;+ -p 6 --tcp-flags RST RST
