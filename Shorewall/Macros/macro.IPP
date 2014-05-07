#
# Shorewall version 3.2 - IPP Macro
#
# /usr/share/shorewall/macro.IPP
#
#	This macro handles Internet Printing Protocol (IPP).
#
###############################################################################
?FORMAT 2
###############################################################################
#ACTION	SOURCE	DEST	PROTO	DEST	SOURCE	ORIGIN	RATE	USER/
#				PORT(S)	PORT(S)	DEST	LIMIT	GROUP
PARAM	-	-	tcp	631
