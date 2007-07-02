%define name shorewall-common
%define version 4.0.0
%define release 0RC1
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
Requires: iptables iproute shorewall_compiler

%description

The Shoreline Firewall, more commonly known as "Shorewall", is a Netfilter
(iptables) based firewall that can be used on a dedicated firewall system,
a multi-function gateway/ router/server or on a standalone GNU/Linux system.

Shorewall offers two alternative firewall compilers, shorewall-perl and
shorewall-shell. The shorewall-perl compilers is suggested for new installed
systems and shorewall-shell is provided for backwards compability and smooth
system upgrades because shorewall perl is not fully compatible with all legacy
configurations.

%prep

%setup

%build

%install
export PREFIX=$RPM_BUILD_ROOT ; \
export OWNER=`id -n -u` ; \
export GROUP=`id -n -g` ;\
./install.sh -n

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

%attr(0755,root,root) /sbin/shorewall

%attr(0644,root,root) /usr/share/shorewall/version
%attr(0644,root,root) /usr/share/shorewall/actions.std
%attr(0644,root,root) /usr/share/shorewall/action.Drop
%attr(0644,root,root) /usr/share/shorewall/action.Reject
%attr(0644,root,root) /usr/share/shorewall/action.template
%attr(0755,root,root) /usr/share/shorewall/firewall
%attr(0777,root,root) /usr/share/shorewall/functions
%attr(0644,root,root) /usr/share/shorewall/lib.base
%attr(0644,root,root) /usr/share/shorewall/lib.cli
%attr(0644,root,root) /usr/share/shorewall/lib.config
%attr(0644,root,root) /usr/share/shorewall/lib.dynamiczones
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
%attr(0644,root,root) /usr/share/shorewall/macro.IPP
%attr(0644,root,root) /usr/share/shorewall/macro.IPPserver
%attr(0644,root,root) /usr/share/shorewall/macro.Jetdirect
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
%attr(0644,root,root) /usr/share/shorewall/macro.Printer
%attr(0644,root,root) /usr/share/shorewall/macro.RDP
%attr(0644,root,root) /usr/share/shorewall/macro.Rdate
%attr(0644,root,root) /usr/share/shorewall/macro.Reject
%attr(0644,root,root) /usr/share/shorewall/macro.Rsync
%attr(0644,root,root) /usr/share/shorewall/macro.SixXS
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
%attr(0644,root,root) /usr/share/shorewall/macro.TFTP
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
%attr(0644,root,root) /usr/share/shorewall/rfc1918
%attr(0644,root,root) /usr/share/shorewall/configpath
%attr(0755,root,root) /usr/share/shorewall/wait4ifup

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

%attr(0644,root,root) %{_mandir}/man5/shorewall-accounting.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-actions.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-blacklist.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall.conf.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-ecn.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-exclusion.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-hosts.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-interfaces.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-maclist.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-masq.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-nat.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-nesting.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-netmap.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-params.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-policy.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-providers.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-proxyarp.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-rfc1918.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-route_rules.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-routestopped.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-rules.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-tcclasses.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-tcdevices.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-tcrules.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-tos.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-tunnels.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-zones.5.gz

%attr(0644,root,root) %{_mandir}/man8/shorewall.8.gz

%doc COPYING INSTALL changelog.txt releasenotes.txt tunnel ipsecvpn Samples

%changelog
* Fri Jun 29 2007 Tom EAstep tom@shorewall.net
- Updated to 4.0.0-0RC1
* Sun Jun 24 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta7
* Wed Jun 20 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta6
* Thu Jun 14 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta5
* Fri Jun 08 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta4
* Tue Jun 05 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta3
* Tue May 15 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta1
* Fri May 11 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.7-1
* Sat May 05 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.6-1
* Mon Apr 30 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.5-1
* Mon Apr 23 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.4-1
* Wed Apr 18 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.3-1
* Mon Apr 16 2007 Tom Eastep tom@shorewall.net
- Moved lib.dynamiczones from Shorewall-shell
* Sat Apr 14 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.2-1
* Tue Apr 03 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.1-1
* Thu Mar 24 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.2-1
* Thu Mar 15 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.1-1
* Sat Mar 10 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-1
* Sun Feb 25 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0RC3
* Sun Feb 04 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0RC2
* Wed Jan 24 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0RC1
* Mon Jan 22 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0Beta3
* Wed Jan 03 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0Beta2
* Thu Dec 14 2006 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0Beta1
* Sat Nov 25 2006 Tom Eastep tom@shorewall.net
- Added shorewall-exclusion(5)
- Updated to 3.3.6-1
* Sun Nov 19 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.5-1
* Sat Nov 18 2006 Tom Eastep tom@shorewall.net
- Add Man Pages.
* Sun Oct 29 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.4-1
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


