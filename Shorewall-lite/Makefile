# Shorewall Lite Makefile to restart if firewall script is newer than last restart
VARDIR=/var/lib/shorewall-lite
SHAREDIR=/usr/share/shorewall-lite
RESTOREFILE?=.restore
all: $(VARDIR)/${RESTOREFILE}

$(VARDIR)/${RESTOREFILE}: $(SHAREDIR)/firewall
	@/usr/share/shorewall-lite/shorewall -q save >/dev/null; \
	if \
	    /usr/share/shorewall-lite/shorewall -q restart >/dev/null 2>&1; \
	then \
	    /usr/share/shorewall-lite/shorewall -q save >/dev/null; \
	else \
	    /usr/share/shorewall-lite/shorewall -q restart 2>&1 | tail >&2; \
	fi

# EOF
