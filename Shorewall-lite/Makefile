# Shorewall Lite Makefile to restart if firewall script is newer than last restart
VARDIR=$(shell /sbin/shorewall-lite show vardir)
SHAREDIR=/usr/share/shorewall-lite
RESTOREFILE?=.restore

all: $(VARDIR)/$(RESTOREFILE)

$(VARDIR)/$(RESTOREFILE): $(VARDIR)/firewall
	@/sbin/shorewall-lite -q save >/dev/null; \
	if \
	    /sbin/shorewall-lite -q restart >/dev/null 2>&1; \
	then \
	    /sbin/shorewall-lite -q save >/dev/null; \
	else \
	    /sbin/shorewall-lite -q restart 2>&1 | tail >&2; exit 1; \
	fi

# EOF
