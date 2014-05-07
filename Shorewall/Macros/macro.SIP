#
# Shorewall version 4 - SIP Macro
#
# /usr/share/shorewall/macro.SIP
#
#	This macro handles SIP traffic.
#
###############################################################################
?FORMAT 2
###############################################################################
#ACTION	SOURCE	DEST	PROTO	DEST	SOURCE	ORIGIN	RATE	USER/
#				PORT(S)	PORT(S)	DEST	LIMIT	GROUP

?if ( __CT_TARGET && ! $AUTOHELPERS && __SIP_HELPER  )
 PARAM	-	-	udp	5060 ; helper=sip
?else
 PARAM	-	-	udp	5060
?endif
