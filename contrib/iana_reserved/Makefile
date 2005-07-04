all:	bogons.body

wget:
	wget --timestamping http://www.iana.org/assignments/ipv4-address-space

bogons.body:	wget ipv4-address-space getreserved.py Makefile
	./getreserved.py < ipv4-address-space | grep -v '^10\.0\.0\.0/8' > $@
