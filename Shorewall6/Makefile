#
# Shorewall6 -- /etc/shorewall6/Makefile
#
# Reload Shorewall6 if config files are updated.

SWBIN	?= /sbin/shorewall6 -q
CONFDIR	?= /etc/shorewall6
SWSTATE	?= $(shell $(SWBIN) show vardir)/firewall

.PHONY: clean

$(SWSTATE): $(CONFDIR)/*
	@$(SWBIN) save >/dev/null; \
	RESULT=$$($(SWBIN) reload 2>&1); \
	if [ $$? -eq 0 ]; then \
	    $(SWBIN) save >/dev/null; \
	else \
	    echo "$${RESULT}" >&2; \
	    false; \
	fi

clean:
	@rm -f $(CONFDIR)/*~ $(CONFDIR)/.*~
