FLAGS=-c -r
HOSTS=ig proxy mail og

default:	$(HOSTS)

$(HOSTS):
	shoregen $@

install:	$(HOSTS)
	install_shoregen -c -r $(HOSTS)
