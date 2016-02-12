#
# Shorewall -- /etc/shorewall/Makefile
#
# Reload Shorewall if config files are updated.
# If reloading fails, restore old settings.

SWBIN	?= /sbin/shorewall -q
CONFDIR	?= /etc/shorewall
SWSTATE	?= $(shell $(SWBIN) show vardir)/firewall

.PHONY: clean

$(SWSTATE): $(CONFDIR)/*
	@$(SWBIN) save >/dev/null; \
	RESULT=$$($(SWBIN) reload 2>&1); \
	if [ $$? -eq 0 ]; then \
	    $(SWBIN) save >/dev/null; \
	else \
	    $(SWBIN) restore >/dev/null 2>&1; \
	    echo "$${RESULT}" >&2; \
	    false; \
	fi

clean:
	@rm -f $(CONFDIR)/*~ $(CONFDIR)/.*~
