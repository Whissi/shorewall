%define name shorewall
%define version 3.3.3
%define release 1
%define prefix /usr

Summary: Shoreline Firewall is an iptables-based firewall for Linux systems.
Name: %{name}
Version: %{version}
Release: %{release}
Prefix: %{prefix}
License: GPL
Packager: Tom Eastep <teastep@shorewall.net>
Group: Networking/Utilities
Source: %{name}-%{version}.tgz
URL: http://www.shorewall.net/
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Requires: iptables iproute

%description

The Shoreline Firewall, more commonly known as "Shorewall", is a Netfilter
(iptables) based firewall that can be used on a dedicated firewall system,
a multi-function gateway/ router/server or on a standalone GNU/Linux system.

%prep

%setup

%build

%install
export PREFIX=$RPM_BUILD_ROOT ; \
export OWNER=`id -n -u` ; \
export GROUP=`id -n -g` ;\
./install.sh

%clean
rm -rf $RPM_BUILD_ROOT

%post

if [ $1 -eq 1 ]; then
	if [ -x /sbin/insserv ]; then
		/sbin/insserv /etc/rc.d/shorewall
	elif [ -x /sbin/chkconfig ]; then
		/sbin/chkconfig --add shorewall;
	fi
fi

%preun

if [ $1 = 0 ]; then
	if [ -x /sbin/insserv ]; then
		/sbin/insserv -r /etc/init.d/shorewall
	elif [ -x /sbin/chkconfig ]; then
		/sbin/chkconfig --del shorewall
	fi

	rm -f /etc/shorewall/startup_disabled

fi

%files
%defattr(0644,root,root,0755)
%attr(0544,root,root) /etc/init.d/shorewall
%attr(0755,root,root) %dir /etc/shorewall
%attr(0755,root,root) %dir /usr/share/shorewall
%attr(0755,root,root) %dir /usr/share/shorewall/configfiles
%attr(0700,root,root) %dir /var/lib/shorewall
%attr(0644,root,root) %config(noreplace) /etc/shorewall/shorewall.conf
%attr(0600,root,root) %config(noreplace) /etc/shorewall/zones
%attr(0600,root,root) %config(noreplace) /etc/shorewall/policy
%attr(0600,root,root) %config(noreplace) /etc/shorewall/interfaces
%attr(0600,root,root) %config(noreplace) /etc/shorewall/ipsec
%attr(0600,root,root) %config(noreplace) /etc/shorewall/rules
%attr(0600,root,root) %config(noreplace) /etc/shorewall/nat
%attr(0600,root,root) %config(noreplace) /etc/shorewall/netmap
%attr(0644,root,root) %config(noreplace) /etc/shorewall/params
%attr(0600,root,root) %config(noreplace) /etc/shorewall/proxyarp
%attr(0600,root,root) %config(noreplace) /etc/shorewall/routestopped
%attr(0600,root,root) %config(noreplace) /etc/shorewall/maclist
%attr(0600,root,root) %config(noreplace) /etc/shorewall/masq
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tcrules
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tos
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tunnels
%attr(0600,root,root) %config(noreplace) /etc/shorewall/hosts
%attr(0600,root,root) %config(noreplace) /etc/shorewall/blacklist
%attr(0600,root,root) %config(noreplace) /etc/shorewall/init
%attr(0600,root,root) %config(noreplace) /etc/shorewall/initdone
%attr(0600,root,root) %config(noreplace) /etc/shorewall/start
%attr(0600,root,root) %config(noreplace) /etc/shorewall/stop
%attr(0600,root,root) %config(noreplace) /etc/shorewall/stopped
%attr(0600,root,root) %config(noreplace) /etc/shorewall/ecn
%attr(0600,root,root) %config(noreplace) /etc/shorewall/accounting
%attr(0600,root,root) %config(noreplace) /etc/shorewall/actions
%attr(0600,root,root) %config(noreplace) /etc/shorewall/continue
%attr(0600,root,root) %config(noreplace) /etc/shorewall/started
%attr(0600,root,root) %config(noreplace) /etc/shorewall/providers
%attr(0600,root,root) %config(noreplace) /etc/shorewall/route_rules
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tcclasses
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tcdevices
%attr(0600,root,root) /etc/shorewall/Makefile

%attr(0555,root,root) /sbin/shorewall

%attr(0644,root,root) /usr/share/shorewall/version
%attr(0644,root,root) /usr/share/shorewall/actions.std
%attr(0644,root,root) /usr/share/shorewall/action.Drop
%attr(0644,root,root) /usr/share/shorewall/action.Reject
%attr(0644,root,root) /usr/share/shorewall/action.template
%attr(0555,root,root) /usr/share/shorewall/compiler
%attr(0555,root,root) /usr/share/shorewall/firewall
%attr(0777,root,root) /usr/share/shorewall/functions
%attr(0555,root,root) /usr/share/shorewall/help
%attr(0444,root,root) /usr/share/shorewall/lib.accounting
%attr(0444,root,root) /usr/share/shorewall/lib.actions
%attr(0444,root,root) /usr/share/shorewall/lib.base
%attr(0444,root,root) /usr/share/shorewall/lib.config
%attr(0444,root,root) /usr/share/shorewall/lib.dynamiczones
%attr(0444,root,root) /usr/share/shorewall/lib.maclist
%attr(0444,root,root) /usr/share/shorewall/lib.nat
%attr(0444,root,root) /usr/share/shorewall/lib.providers
%attr(0444,root,root) /usr/share/shorewall/lib.proxyarp
%attr(0444,root,root) /usr/share/shorewall/lib.tc
%attr(0444,root,root) /usr/share/shorewall/lib.tcrules
%attr(0444,root,root) /usr/share/shorewall/lib.tunnels
%attr(0644,root,root) /usr/share/shorewall/macro.AllowICMPs
%attr(0644,root,root) /usr/share/shorewall/macro.Amanda
%attr(0644,root,root) /usr/share/shorewall/macro.Auth
%attr(0644,root,root) /usr/share/shorewall/macro.BitTorrent
%attr(0644,root,root) /usr/share/shorewall/macro.CVS
%attr(0644,root,root) /usr/share/shorewall/macro.Distcc
%attr(0644,root,root) /usr/share/shorewall/macro.DNS
%attr(0644,root,root) /usr/share/shorewall/macro.Drop
%attr(0644,root,root) /usr/share/shorewall/macro.DropDNSrep
%attr(0644,root,root) /usr/share/shorewall/macro.DropUPnP
%attr(0644,root,root) /usr/share/shorewall/macro.Edonkey
%attr(0644,root,root) /usr/share/shorewall/macro.Finger
%attr(0644,root,root) /usr/share/shorewall/macro.FTP
%attr(0644,root,root) /usr/share/shorewall/macro.Gnutella
%attr(0644,root,root) /usr/share/shorewall/macro.HTTP
%attr(0644,root,root) /usr/share/shorewall/macro.HTTPS
%attr(0644,root,root) /usr/share/shorewall/macro.ICQ
%attr(0644,root,root) /usr/share/shorewall/macro.IMAP
%attr(0644,root,root) /usr/share/shorewall/macro.IMAPS
%attr(0644,root,root) /usr/share/shorewall/macro.LDAP
%attr(0644,root,root) /usr/share/shorewall/macro.LDAPS
%attr(0644,root,root) /usr/share/shorewall/macro.MySQL
%attr(0644,root,root) /usr/share/shorewall/macro.NNTP
%attr(0644,root,root) /usr/share/shorewall/macro.NNTPS
%attr(0644,root,root) /usr/share/shorewall/macro.NTP
%attr(0644,root,root) /usr/share/shorewall/macro.NTPbrd
%attr(0644,root,root) /usr/share/shorewall/macro.PCA
%attr(0644,root,root) /usr/share/shorewall/macro.Ping
%attr(0644,root,root) /usr/share/shorewall/macro.POP3
%attr(0644,root,root) /usr/share/shorewall/macro.POP3S
%attr(0644,root,root) /usr/share/shorewall/macro.PostgreSQL
%attr(0644,root,root) /usr/share/shorewall/macro.RDP
%attr(0644,root,root) /usr/share/shorewall/macro.Rdate
%attr(0644,root,root) /usr/share/shorewall/macro.Reject
%attr(0644,root,root) /usr/share/shorewall/macro.Rsync
%attr(0644,root,root) /usr/share/shorewall/macro.SMB
%attr(0644,root,root) /usr/share/shorewall/macro.SMBBI
%attr(0644,root,root) /usr/share/shorewall/macro.SMBswat
%attr(0644,root,root) /usr/share/shorewall/macro.SMTP
%attr(0644,root,root) /usr/share/shorewall/macro.SMTPS
%attr(0644,root,root) /usr/share/shorewall/macro.SNMP
%attr(0644,root,root) /usr/share/shorewall/macro.SPAMD
%attr(0644,root,root) /usr/share/shorewall/macro.SSH
%attr(0644,root,root) /usr/share/shorewall/macro.Submission
%attr(0644,root,root) /usr/share/shorewall/macro.SVN
%attr(0644,root,root) /usr/share/shorewall/macro.Syslog
%attr(0644,root,root) /usr/share/shorewall/macro.Telnet
%attr(0644,root,root) /usr/share/shorewall/macro.Telnets
%attr(0644,root,root) /usr/share/shorewall/macro.Time
%attr(0644,root,root) /usr/share/shorewall/macro.template
%attr(0644,root,root) /usr/share/shorewall/macro.Trcrt
%attr(0644,root,root) /usr/share/shorewall/macro.VNC
%attr(0644,root,root) /usr/share/shorewall/macro.VNCL
%attr(0644,root,root) /usr/share/shorewall/macro.Web
%attr(0644,root,root) /usr/share/shorewall/macro.Webmin
%attr(0644,root,root) /usr/share/shorewall/macro.Whois
%attr(0644,root,root) /usr/share/shorewall/modules
%attr(0644,root,root) /usr/share/shorewall/prog.footer
%attr(0644,root,root) /usr/share/shorewall/prog.header
%attr(0644,root,root) /usr/share/shorewall/rfc1918
%attr(0644,root,root) /usr/share/shorewall/configpath

%attr(0644,root,root) /usr/share/shorewall/configfiles/shorewall.conf
%attr(0644,root,root) /usr/share/shorewall/configfiles/zones
%attr(0644,root,root) /usr/share/shorewall/configfiles/policy
%attr(0644,root,root) /usr/share/shorewall/configfiles/interfaces
%attr(0644,root,root) /usr/share/shorewall/configfiles/ipsec
%attr(0644,root,root) /usr/share/shorewall/configfiles/rules
%attr(0644,root,root) /usr/share/shorewall/configfiles/nat
%attr(0644,root,root) /usr/share/shorewall/configfiles/netmap
%attr(0644,root,root) /usr/share/shorewall/configfiles/params
%attr(0644,root,root) /usr/share/shorewall/configfiles/proxyarp
%attr(0644,root,root) /usr/share/shorewall/configfiles/routestopped
%attr(0644,root,root) /usr/share/shorewall/configfiles/maclist
%attr(0644,root,root) /usr/share/shorewall/configfiles/masq
%attr(0644,root,root) /usr/share/shorewall/configfiles/tcrules
%attr(0644,root,root) /usr/share/shorewall/configfiles/tos
%attr(0644,root,root) /usr/share/shorewall/configfiles/tunnels
%attr(0644,root,root) /usr/share/shorewall/configfiles/hosts
%attr(0644,root,root) /usr/share/shorewall/configfiles/blacklist
%attr(0644,root,root) /usr/share/shorewall/configfiles/init
%attr(0644,root,root) /usr/share/shorewall/configfiles/initdone
%attr(0644,root,root) /usr/share/shorewall/configfiles/start
%attr(0644,root,root) /usr/share/shorewall/configfiles/stop
%attr(0644,root,root) /usr/share/shorewall/configfiles/stopped
%attr(0644,root,root) /usr/share/shorewall/configfiles/ecn
%attr(0644,root,root) /usr/share/shorewall/configfiles/accounting
%attr(0644,root,root) /usr/share/shorewall/configfiles/actions
%attr(0644,root,root) /usr/share/shorewall/configfiles/continue
%attr(0644,root,root) /usr/share/shorewall/configfiles/started
%attr(0644,root,root) /usr/share/shorewall/configfiles/providers
%attr(0644,root,root) /usr/share/shorewall/configfiles/route_rules
%attr(0644,root,root) /usr/share/shorewall/configfiles/tcclasses
%attr(0644,root,root) /usr/share/shorewall/configfiles/tcdevices
%attr(0644,root,root) /usr/share/shorewall/configfiles/Makefile

%doc COPYING INSTALL changelog.txt releasenotes.txt tunnel ipsecvpn Samples

%changelog
* Mon Oct 16 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.3-1
* Sat Sep 30 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.2-1
* Wed Aug 30 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.1-1
* Sun Aug 27 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.0-1
* Fri Aug 25 2006 Tom Eastep tom@shorewall.net
- Updated to 3.2.3-1


