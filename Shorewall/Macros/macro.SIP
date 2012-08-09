#
# Shorewall version 4 - SIP Macro
#
# /usr/share/shorewall/macro.SIP
#
#	This macro handles SIP traffic.
#
###############################################################################
FORMAT 2
#ACTION	SOURCE	DEST	PROTO	DEST	SOURCE	RATE	USER/
#				PORT(S)	PORT(S)	LIMIT	GROUP

?IF ( __CT_TARGET && $HELPERS && __SIP_HELPER  )
 PARAM	-	-	udp	5060 ; helper=sip
?ELSE
 PARAM	-	-	udp	5060
?ENDIF
