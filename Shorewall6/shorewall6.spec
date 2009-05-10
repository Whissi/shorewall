%define name shorewall6
%define version 4.3.11
%define release 0base

Summary: Shoreline Firewall 6 is an ip6tables-based firewall for Linux systems.
Name: %{name}
Version: %{version}
Release: %{release}
License: GPLv2
Packager: Tom Eastep <teastep@shorewall.net>
Group: Networking/Utilities
Source: %{name}-%{version}.tgz
URL: http://www.shorewall.net/
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Requires: iptables iproute shorewall >= 4.3.5

%description

The Shoreline Firewall 6, more commonly known as "Shorewall6", is a Netfilter
(ip6tables) based IPv6 firewall that can be used on a dedicated firewall system,
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
		/sbin/insserv /etc/rc.d/shorewall6
	elif [ -x /sbin/chkconfig ]; then
		/sbin/chkconfig --add shorewall6;
	fi
fi

%preun

if [ $1 = 0 ]; then
	if [ -x /sbin/insserv ]; then
		/sbin/insserv -r /etc/init.d/shorewall6
	elif [ -x /sbin/chkconfig ]; then
		/sbin/chkconfig --del shorewall6
	fi

	rm -f /etc/shorewall/startup_disabled

fi

%files
%defattr(0644,root,root,0755)
%attr(0544,root,root) /etc/init.d/shorewall6
%attr(0755,root,root) %dir /etc/shorewall6
%attr(0755,root,root) %dir /usr/share/shorewall6
%attr(0755,root,root) %dir /usr/share/shorewall6/configfiles
%attr(0700,root,root) %dir /var/lib/shorewall6
%attr(0644,root,root) %config(noreplace) /etc/shorewall6/shorewall6.conf
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/zones
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/policy
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/interfaces
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/rules
%attr(0644,root,root) %config(noreplace) /etc/shorewall6/params
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/routestopped
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/maclist
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/tcrules
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/tos
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/tunnels
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/hosts
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/blacklist
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/init
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/start
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/stop
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/stopped
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/accounting
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/actions
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/started
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/restored
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/providers
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/route_rules
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/tcclasses
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/tcdevices
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/notrack
%attr(0600,root,root) /etc/shorewall6/Makefile

%attr(0755,root,root) /sbin/shorewall6

%attr(0644,root,root) /usr/share/shorewall6/version
%attr(0644,root,root) /usr/share/shorewall6/actions.std
%attr(0644,root,root) /usr/share/shorewall6/action.AllowICMPs
%attr(0644,root,root) /usr/share/shorewall6/action.Drop
%attr(0644,root,root) /usr/share/shorewall6/action.Reject
%attr(0644,root,root) /usr/share/shorewall6/action.template
%attr(-   ,root,root) /usr/share/shorewall6/functions
%attr(0644,root,root) /usr/share/shorewall6/lib.base
%attr(0644,root,root) /usr/share/shorewall6/lib.cli
%attr(0644,root,root) /usr/share/shorewall6/macro.*
%attr(0644,root,root) /usr/share/shorewall6/modules
%attr(0644,root,root) /usr/share/shorewall6/configpath
%attr(0755,root,root) /usr/share/shorewall6/wait4ifup

%attr(0644,root,root) /usr/share/shorewall6/configfiles/shorewall6.conf
%attr(0644,root,root) /usr/share/shorewall6/configfiles/zones
%attr(0644,root,root) /usr/share/shorewall6/configfiles/policy
%attr(0644,root,root) /usr/share/shorewall6/configfiles/interfaces
%attr(0644,root,root) /usr/share/shorewall6/configfiles/rules
%attr(0644,root,root) /usr/share/shorewall6/configfiles/params
%attr(0644,root,root) /usr/share/shorewall6/configfiles/routestopped
%attr(0644,root,root) /usr/share/shorewall6/configfiles/maclist
%attr(0644,root,root) /usr/share/shorewall6/configfiles/tcrules
%attr(0644,root,root) /usr/share/shorewall6/configfiles/tos
%attr(0644,root,root) /usr/share/shorewall6/configfiles/tunnels
%attr(0644,root,root) /usr/share/shorewall6/configfiles/hosts
%attr(0644,root,root) /usr/share/shorewall6/configfiles/blacklist
%attr(0644,root,root) /usr/share/shorewall6/configfiles/init
%attr(0644,root,root) /usr/share/shorewall6/configfiles/start
%attr(0644,root,root) /usr/share/shorewall6/configfiles/stop
%attr(0644,root,root) /usr/share/shorewall6/configfiles/stopped
%attr(0644,root,root) /usr/share/shorewall6/configfiles/accounting
%attr(0644,root,root) /usr/share/shorewall6/configfiles/actions
%attr(0644,root,root) /usr/share/shorewall6/configfiles/started
%attr(0644,root,root) /usr/share/shorewall6/configfiles/restored
%attr(0644,root,root) /usr/share/shorewall6/configfiles/providers
%attr(0644,root,root) /usr/share/shorewall6/configfiles/route_rules
%attr(0644,root,root) /usr/share/shorewall6/configfiles/tcclasses
%attr(0644,root,root) /usr/share/shorewall6/configfiles/tcdevices
%attr(0644,root,root) /usr/share/shorewall6/configfiles/notrack
%attr(0644,root,root) /usr/share/shorewall6/configfiles/Makefile

%attr(0644,root,root) %{_mandir}/man5/*
%attr(0644,root,root) %{_mandir}/man8/shorewall6.8.gz

%doc COPYING INSTALL changelog.txt releasenotes.txt tunnel ipsecvpn ipv6 Samples6

%changelog
* Sun May 10 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.11-0base
* Sun Apr 19 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.10-0base
* Sat Apr 11 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.9-0base
* Tue Mar 17 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.8-0base
* Sun Mar 01 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.7-0base
* Fri Feb 27 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.6-0base
* Sun Feb 22 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.5-0base
* Sat Feb 21 2009 Tom Eastep tom@shorewall.net
- Updated to 4.2.7-0base
* Wed Feb 05 2009 Tom Eastep tom@shorewall.net
- Added 'restored' script
* Wed Feb 04 2009 Tom Eastep tom@shorewall.net
- Updated to 4.2.6-0base
* Thu Jan 29 2009 Tom Eastep tom@shorewall.net
- Updated to 4.2.6-0base
* Tue Jan 06 2009 Tom Eastep tom@shorewall.net
- Updated to 4.2.5-0base
* Thu Dec 25 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.4-0base
* Sun Dec 21 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.4-0RC2
* Wed Dec 17 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.4-0RC1
* Tue Dec 16 2008 Tom Eastep tom@shorewall.net
- Updated to 4.3.4-0base
* Sat Dec 13 2008 Tom Eastep tom@shorewall.net
- Updated to 4.3.3-0base
* Fri Dec 12 2008 Tom Eastep tom@shorewall.net
- Updated to 4.3.2-0base
* Thu Dec 11 2008 Tom Eastep tom@shorewall.net
- Updated to 4.3.1-0base
* Wed Dec 10 2008 Tom Eastep tom@shorewall.net
- Updated to 4.3.0-0base
* Wed Dec 10 2008 Tom Eastep tom@shorewall.net
- Updated to 2.3.0-0base
* Tue Dec 09 2008 Tom Eastep tom@shorewall6.net
- Initial Version
