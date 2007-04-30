%define name shorewall-perl
%define version 3.9.5
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
Provides: shorewall_compiler

%description

The Shoreline Firewall, more commonly known as "Shorewall", is a Netfilter
(iptables) based firewall that can be used on a dedicated firewall system,
a multi-function gateway/ router/server or on a standalone GNU/Linux system.

Shorewall-perl is a companion product to Shorewall that allows faster
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

%attr(0755,root,root) %dir /usr/share/shorewall-perl
%attr(0755,root,root) %dir /usr/share/shorewall-perl/Shorewall

%attr(555,root,root) /usr/share/shorewall-perl/compiler.pl
%attr(0644,root,root) /usr/share/shorewall-perl/prog.header
%attr(0644,root,root) /usr/share/shorewall-perl/prog.functions
%attr(0644,root,root) /usr/share/shorewall-perl/prog.footer
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Accounting.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Actions.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Chains.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Common.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Config.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Hosts.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Interfaces.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/IPAddrs.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Macros.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Nat.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Policy.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Proc.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Providers.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Proxyarp.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Rules.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Tc.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Tunnels.pm
%attr(0555,root,root) /usr/share/shorewall-perl/Shorewall/Zones.pm

%doc COPYING releasenotes.txt

%changelog
* Mon Apr 30 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.5-1
* Mon Apr 23 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.4-1
* Wed Apr 18 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.3-1
* Sat Apr 14 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.2-1
* Sat Apr 07 2007 Tom Eastep tom@shorewall.net
- Initial version 3.9.1-1
* Sat Mar 24 2007 Tom Eastep tom@shorewall.net
- Initial version 3.9.0-1


