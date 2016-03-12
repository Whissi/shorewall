#
# Shorewall 4 - RST Action
#
#    /usr/share/shorewall/action.RST
#
#   RST[([<action>])]
#
#       Default action is DROP
#
##########################################################################################

DEFAULTS DROP

@1	 -	-	tcp	;; --tcp-flags RST RST
