%define name shorewall-pl
%define version 3.9.0
%define release 1
%define prefix /usr

Summary: Shoreline Firewall Perl-based compiler.
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
Requires: perl

%description

The Shoreline Firewall, more commonly known as "Shorewall", is a Netfilter
(iptables) based firewall that can be used on a dedicated firewall system,
a multi-function gateway/ router/server or on a standalone GNU/Linux system.

Shorewall-pl is a companion product to Shorewall that allows faster
compilation and execution.

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

%preun

%files
%defattr(0644,root,root,0755)

%attr(0755,root,root) %dir /usr/share/shorewall-pl
%attr(0755,root,root) %dir /usr/share/shorewall-pl/Shorewall

%attr(555,root,root) /usr/share/shorewall-pl/compiler.pl
%attr(0644,root,root) /usr/share/shorewall-pl/prog.header
%attr(0644,root,root) /usr/share/shorewall-pl/prog.functions
%attr(0644,root,root) /usr/share/shorewall-pl/prog.footer
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Accounting.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Actions.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Chains.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Common.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Config.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Hosts.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Interfaces.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/IPAddrs.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Macros.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Nat.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Policy.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Proc.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Providers.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Proxyarp.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Rules.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Tc.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Tunnels.pm
%attr(0555,root,root) /usr/share/shorewall-pl/Shorewall/Zones.pm

%doc COPYING releasenotes.txt

%changelog

* Sat Mar 24 2007 Tom Eastep tom@shorewall.net
- Initial version 3.9.0-1


