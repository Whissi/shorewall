%define name shorewall6
%define version 4.3.0
%define release 0base

Summary: Shoreline Firewall 6 is an ip6tables-based firewall for Linux systems.
Name: %{name}
Version: %{version}
Release: %{release}
License: GPL
Packager: Tom Eastep <teastep@shorewall.net>
Group: Networking/Utilities
Source: %{name}-%{version}.tgz
URL: http://www.shorewall.net/
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Requires: iptables iproute shorewall-perl

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
./install.sh -n

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

%triggerpostun  -- shorewall < 4.0.0

if [ -x /sbin/insserv ]; then
    /sbin/insserv /etc/rc.d/shorewall6
elif [ -x /sbin/chkconfig ]; then
    /sbin/chkconfig --add shorewall6;
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
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/initdone
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/start
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/stop
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/stopped
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/ecn
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/accounting
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/actions
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/started
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/providers
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/route_rules
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/tcclasses
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/tcdevices
%attr(0600,root,root) %config(noreplace) /etc/shorewall6/tcfilters
%attr(0600,root,root) /etc/shorewall6/Makefile

%attr(0755,root,root) /sbin/shorewall6

%attr(0644,root,root) /usr/share/shorewall6/version
%attr(0644,root,root) /usr/share/shorewall6/actions.std
%attr(0644,root,root) /usr/share/shorewall6/action.Drop
%attr(0644,root,root) /usr/share/shorewall6/action.Reject
%attr(0644,root,root) /usr/share/shorewall6/action.template
%attr(0755,root,root) /usr/share/shorewall6/firewall
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
%attr(0644,root,root) /usr/share/shorewall6/configfiles/initdone
%attr(0644,root,root) /usr/share/shorewall6/configfiles/start
%attr(0644,root,root) /usr/share/shorewall6/configfiles/stop
%attr(0644,root,root) /usr/share/shorewall6/configfiles/stopped
%attr(0644,root,root) /usr/share/shorewall6/configfiles/ecn
%attr(0644,root,root) /usr/share/shorewall6/configfiles/accounting
%attr(0644,root,root) /usr/share/shorewall6/configfiles/actions
%attr(0644,root,root) /usr/share/shorewall6/configfiles/started
%attr(0644,root,root) /usr/share/shorewall6/configfiles/providers
%attr(0644,root,root) /usr/share/shorewall6/configfiles/route_rules
%attr(0644,root,root) /usr/share/shorewall6/configfiles/tcclasses
%attr(0644,root,root) /usr/share/shorewall6/configfiles/tcdevices
%attr(0644,root,root) /usr/share/shorewall6/configfiles/tcfilters
%attr(0644,root,root) /usr/share/shorewall6/configfiles/Makefile

%doc COPYING INSTALL changelog.txt releasenotes.txt tunnel ipsecvpn Samples6

%changelog
* Wed Dec 10 2008 Tom Eastep tom@shorewall.net
- Updated to 4.3.0-0base
* Wed Dec 10 2008 Tom Eastep tom@shorewall.net
- Updated to 2.3.0-0base
* Tue Dec 09 2008 Tom Eastep tom@shorewall6.net
- Initial Version
