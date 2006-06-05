%define name shorewall-lite
%define version 3.2.0
%define release 0RC1
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

fi

%files
%defattr(0644,root,root,0755)
%attr(0755,root,root) %dir /etc/shorewall
%attr(0644,root,root) %config(noreplace) /etc/shorewall/shorewall.conf
%attr(0644,root,root) /etc/shorewall/Makefile
%attr(0544,root,root) /etc/init.d/shorewall
%attr(0755,root,root) %dir /usr/share/shorewall
%attr(0700,root,root) %dir /var/lib/shorewall

%attr(0555,root,root) /sbin/shorewall

%attr(0644,root,root) /usr/share/shorewall/version
%attr(0644,root,root) /usr/share/shorewall/configpath
%attr(0444,root,root) /usr/share/shorewall/functions
%attr(0444,root,root) /usr/share/shorewall/modules
%attr(0444,root,root) /usr/share/shorewall/xmodules
%attr(0544,root,root) /usr/share/shorewall/shorecap
%attr(0544,root,root) /usr/share/shorewall/help

%doc COPYING INSTALL changelog.txt releasenotes.txt

%changelog
* Tue Apr 18 2006 Tom Eastep tom@shorewall.net
- Initial Version


