%define name shorewall6-lite
%define version 4.3.0
%define release 0base

Summary: Shoreline Firewall 6 Lite is an ip6tables-based firewall for Linux systems.
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
Requires: iptables iproute

%description

The Shoreline Firewall 6, more commonly known as "Shorewall6", is a Netfilter
(ip6tables) based firewall that can be used on a dedicated firewall system,
a multi-function gateway/ router/server or on a standalone GNU/Linux system.

Shorewall6 Lite is a companion product to Shorewall6 that allows network
administrators to centralize the configuration of Shorewall6-based firewalls.

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

%pre

%post

if [ $1 -eq 1 ]; then
    if [ -x /sbin/insserv ]; then
	/sbin/insserv /etc/rc.d/shorewall6-lite
    elif [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --add shorewall6-lite;
    fi
fi

%preun

if [ $1 -eq 0 ]; then
    if [ -x /sbin/insserv ]; then
	/sbin/insserv -r /etc/init.d/shorewall6-lite
    elif [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --del shorewall6-lite
    fi
fi

%files
%defattr(0644,root,root,0755)
%attr(0755,root,root) %dir /etc/shorewall6-lite
%attr(0644,root,root) %config(noreplace) /etc/shorewall6-lite/shorewall6-lite.conf
%attr(0644,root,root) /etc/shorewall6-lite/Makefile
%attr(0544,root,root) /etc/init.d/shorewall6-lite
%attr(0755,root,root) %dir /usr/share/shorewall6-lite
%attr(0700,root,root) %dir /var/lib/shorewall6-lite

%attr(0755,root,root) /sbin/shorewall6-lite

%attr(0644,root,root) /usr/share/shorewall6-lite/version
%attr(0644,root,root) /usr/share/shorewall6-lite/configpath
%attr(-   ,root,root) /usr/share/shorewall6-lite/functions
%attr(0644,root,root) /usr/share/shorewall6-lite/lib.base
%attr(0644,root,root) /usr/share/shorewall6-lite/lib.cli
%attr(0644,root,root) /usr/share/shorewall6-lite/modules
%attr(0544,root,root) /usr/share/shorewall6-lite/shorecap
%attr(0755,root,root) /usr/share/shorewall6-lite/wait4ifup

%doc COPYING changelog.txt releasenotes.txt

%changelog
* Wed Dec 10 2008 Tom Eastep tom@shorewall.net
- Updated to 4.3.0-0base
* Wed Dec 10 2008 Tom Eastep tom@shorewall.net
- Updated to 2.3.0-0base
* Tue Dec 09 2008 Tom Eastep tom@shorewall.net
- Initial Version


