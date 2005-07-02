all:	bogons

wget:
	wget --timestamping http://www.iana.org/assignments/ipv4-address-space

bogons:	bogons.head bogons.body bogons.tail
	cat $^ > $@

bogons.body:	wget ipv4-address-space getreserved.py Makefile
	./getreserved.py < ipv4-address-space > $@
