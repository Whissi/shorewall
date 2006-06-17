# Shorewall Lite Makefile to restart if firewall script is newer than last restart
VARDIR=/var/lib/shorewall-lite
SHAREDIR=/usr/share/shorewall-lite
RESTOREFILE?=.restore
include $(SHAREDIR)/configpath

all: $(VARDIR)/${RESTOREFILE}

$(VARDIR)/${RESTOREFILE}: $(LITEDIR)/firewall
	@/sbin/shorewall-lite -q save >/dev/null; \
	if \
	    /sbin/shorewall-lite -q restart >/dev/null 2>&1; \
	then \
	    /sbin/shorewall-lite -q save >/dev/null; \
	else \
	    /sbin/shorewall-lite -q restart 2>&1 | tail >&2; \
	fi

# EOF
