%define name shorewall
%define version 2.5.0
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
%attr(0544,root,root) /etc/init.d/shorewall
%attr(0700,root,root) %dir /etc/shorewall
%attr(0700,root,root) %dir /usr/share/shorewall
%attr(0700,root,root) %dir /var/lib/shorewall
%attr(0600,root,root) %config(noreplace) /etc/shorewall/shorewall.conf
%attr(0600,root,root) %config(noreplace) /etc/shorewall/zones
%attr(0600,root,root) %config(noreplace) /etc/shorewall/policy
%attr(0600,root,root) %config(noreplace) /etc/shorewall/interfaces
%attr(0600,root,root) %config(noreplace) /etc/shorewall/ipsec
%attr(0600,root,root) %config(noreplace) /etc/shorewall/rules
%attr(0600,root,root) %config(noreplace) /etc/shorewall/nat
%attr(0600,root,root) %config(noreplace) /etc/shorewall/netmap
%attr(0600,root,root) %config(noreplace) /etc/shorewall/params
%attr(0600,root,root) %config(noreplace) /etc/shorewall/proxyarp
%attr(0600,root,root) %config(noreplace) /etc/shorewall/routestopped
%attr(0600,root,root) %config(noreplace) /etc/shorewall/maclist
%attr(0600,root,root) %config(noreplace) /etc/shorewall/masq
%attr(0600,root,root) %config(noreplace) /etc/shorewall/modules
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

%attr(0544,root,root) /sbin/shorewall

%attr(0600,root,root) /usr/share/shorewall/version
%attr(0600,root,root) /usr/share/shorewall/actions.std
%attr(0600,root,root) /usr/share/shorewall/action.Drop
%attr(0600,root,root) /usr/share/shorewall/action.Reject
%attr(0600,root,root) /usr/share/shorewall/action.template
%attr(0444,root,root) /usr/share/shorewall/functions
%attr(0544,root,root) /usr/share/shorewall/firewall
%attr(0544,root,root) /usr/share/shorewall/help
%attr(0600,root,root) /usr/share/shorewall/macro.AllowAuth
%attr(0600,root,root) /usr/share/shorewall/macro.AllowDNS
%attr(0600,root,root) /usr/share/shorewall/macro.AllowFTP
%attr(0600,root,root) /usr/share/shorewall/macro.AllowICMPs
%attr(0600,root,root) /usr/share/shorewall/macro.AllowIMAP
%attr(0600,root,root) /usr/share/shorewall/macro.AllowNNTP
%attr(0600,root,root) /usr/share/shorewall/macro.AllowNTP
%attr(0600,root,root) /usr/share/shorewall/macro.AllowPCA
%attr(0600,root,root) /usr/share/shorewall/macro.AllowPing
%attr(0600,root,root) /usr/share/shorewall/macro.AllowPOP3
%attr(0600,root,root) /usr/share/shorewall/macro.AllowRdate
%attr(0600,root,root) /usr/share/shorewall/macro.AllowSMTP
%attr(0600,root,root) /usr/share/shorewall/macro.AllowSNMP
%attr(0600,root,root) /usr/share/shorewall/macro.AllowSMB
%attr(0600,root,root) /usr/share/shorewall/macro.AllowSSH
%attr(0600,root,root) /usr/share/shorewall/macro.AllowTelnet
%attr(0600,root,root) /usr/share/shorewall/macro.AllowTrcrt
%attr(0600,root,root) /usr/share/shorewall/macro.AllowVNC
%attr(0600,root,root) /usr/share/shorewall/macro.AllowVNCL
%attr(0600,root,root) /usr/share/shorewall/macro.AllowWeb
%attr(0600,root,root) /usr/share/shorewall/macro.DropDNSrep
%attr(0600,root,root) /usr/share/shorewall/macro.DropPing
%attr(0600,root,root) /usr/share/shorewall/macro.DropSMB
%attr(0600,root,root) /usr/share/shorewall/macro.RejectSMB
%attr(0600,root,root) /usr/share/shorewall/macro.DropUPnP
%attr(0600,root,root) /usr/share/shorewall/macro.FwdAuth
%attr(0600,root,root) /usr/share/shorewall/macro.FwdDNS
%attr(0600,root,root) /usr/share/shorewall/macro.FwdFTP
%attr(0600,root,root) /usr/share/shorewall/macro.FwdIMAP
%attr(0600,root,root) /usr/share/shorewall/macro.FwdNNTP
%attr(0600,root,root) /usr/share/shorewall/macro.FwdPCA
%attr(0600,root,root) /usr/share/shorewall/macro.FwdPing
%attr(0600,root,root) /usr/share/shorewall/macro.FwdPOP3
%attr(0600,root,root) /usr/share/shorewall/macro.FwdRdate
%attr(0600,root,root) /usr/share/shorewall/macro.FwdSMTP
%attr(0600,root,root) /usr/share/shorewall/macro.FwdSNMP
%attr(0600,root,root) /usr/share/shorewall/macro.FwdSSH
%attr(0600,root,root) /usr/share/shorewall/macro.FwdTelnet
%attr(0600,root,root) /usr/share/shorewall/macro.FwdVNC
%attr(0600,root,root) /usr/share/shorewall/macro.FwdVNCL
%attr(0600,root,root) /usr/share/shorewall/macro.FwdWeb
%attr(0600,root,root) /usr/share/shorewall/macro.RejectAuth
%attr(0600,root,root) /usr/share/shorewall/macro.template
%attr(0600,root,root) /usr/share/shorewall/rfc1918
%attr(0600,root,root) /usr/share/shorewall/configpath

%doc COPYING INSTALL changelog.txt releasenotes.txt tunnel ipsecvpn

%changelog
* Mon Jul 25 2005 Tom Eastep tom@shorewall.net
- Updated to 2.5.0-1
- Add macros and convert most actions to macros
* Thu Jun 02 2005 Tom Eastep tom@shorewall.net
- Updated to 2.4.0-1
* Sun May 30 2005 Tom Eastep tom@shorewall.net
- Updated to 2.4.0-0RC2
* Thu May 19 2005 Tom Eastep tom@shorewall.net
- Updated to 2.4.0-0RC1
* Thu May 19 2005 Tom Eastep tom@shorewall.net
- Updated to 2.3.2-1
* Sun May 15 2005 Tom Eastep tom@shorewall.net
- Updated to 2.3.1-1
* Mon Apr 11 2005 Tom Eastep tom@shorewall.net
- Updated to 2.2.4-1
* Fri Apr 08 2005 Tom Eastep tom@shorewall.net
- Added /etc/shorewall/started
* Tue Apr 05 2005 Tom Eastep tom@shorewall.net
- Updated to 2.2.3-1
* Mon Mar 07 2005 Tom Eastep tom@shorewall.net
- Updated to 2.2.2-1
* Mon Jan 24 2005 Tom Eastep tom@shorewall.net
- Updated to 2.2.1-1
* Mon Jan 24 2005 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-1
* Mon Jan 17 2005 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0RC5
* Thu Jan 06 2005 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0RC4
* Thu Dec 30 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0RC3
* Fri Dec 24 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0RC2
* Sun Dec 19 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0RC1
- Added ipsecvpn file
* Sat Dec 11 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0Beta8
* Mon Nov 29 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0Beta7
* Fri Nov 26 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0Beta6
* Fri Nov 26 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0Beta5
* Fri Nov 19 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0Beta4
* Tue Nov 09 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0Beta3
* Tue Nov 02 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0Beta2
* Fri Oct 22 2004 Tom Eastep tom@shorewall.net
- Updated to 2.2.0-0Beta1


