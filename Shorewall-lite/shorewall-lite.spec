%define name shorewall-lite
%define version 3.3.5
%define release 1
%define prefix /usr

Summary: Shoreline Firewall Lite is an iptables-based firewall for Linux systems.
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

Shorewall Lite is a companion product to Shorewall that allows network
administrators to centralize the configuration of Shorewall-based firewalls.

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
		/sbin/insserv /etc/rc.d/shorewall-lite
	elif [ -x /sbin/chkconfig ]; then
		/sbin/chkconfig --add shorewall-lite;
	fi
fi

%preun

if [ $1 = 0 ]; then
	if [ -x /sbin/insserv ]; then
		/sbin/insserv -r /etc/init.d/shorewall-lite
	elif [ -x /sbin/chkconfig ]; then
		/sbin/chkconfig --del shorewall-lite
	fi

fi

%files
%defattr(0644,root,root,0755)
%attr(0755,root,root) %dir /etc/shorewall-lite
%attr(0644,root,root) %config(noreplace) /etc/shorewall-lite/shorewall.conf
%attr(0644,root,root) /etc/shorewall-lite/Makefile
%attr(0544,root,root) /etc/init.d/shorewall-lite
%attr(0755,root,root) %dir /usr/share/shorewall-lite
%attr(0700,root,root) %dir /var/lib/shorewall-lite

%attr(0555,root,root) /sbin/shorewall-lite

%attr(0644,root,root) /usr/share/shorewall-lite/version
%attr(0644,root,root) /usr/share/shorewall-lite/configpath
%attr(0777,root,root) /usr/share/shorewall-lite/functions
%attr(0444,root,root) /usr/share/shorewall-lite/lib.base
%attr(0444,root,root) /usr/share/shorewall-lite/lib.cli
%attr(0444,root,root) /usr/share/shorewall-lite/modules
%attr(0544,root,root) /usr/share/shorewall-lite/shorecap

%attr(0444,root,root) %{_mandir}/man5/shorewall-accounting.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-actions.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-blacklist.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall.conf.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-ecn.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-hosts.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-interfaces.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-maclist.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-masq.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-nat.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-netmap.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-params.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-policy.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-providers.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-proxyarp.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-route_rules.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-routestopped.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-rules.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-tcclasses.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-tcdevices.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-tcrules.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-tos.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-tunnels.5.gz
%attr(0444,root,root) %{_mandir}/man5/shorewall-zones.5.gz

%attr(0444,root,root) %{_mandir}/man8/shorewall-lite.8.gz

%doc COPYING changelog.txt releasenotes.txt

%changelog
* Sun Nov 19 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.5-1
* Sun Oct 29 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.4-1
* Mon Oct 16 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.3-1
* Sat Sep 30 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.2-1
* Wed Aug 30 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.1-1
* Wed Aug 09 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.0-1
* Wed Aug 09 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.0-1


