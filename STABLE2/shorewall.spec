%define name shorewall
%define version 2.0.5
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
    	echo \
"########################################################################
#      REMOVE THIS FILE AFTER YOU HAVE CONFIGURED SHOREWALL            #
########################################################################" \
	> /etc/shorewall/startup_disabled

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

%attr(0544,root,root) /sbin/shorewall

%attr(0600,root,root) /usr/share/shorewall/version
%attr(0600,root,root) /usr/share/shorewall/actions.std
%attr(0600,root,root) /usr/share/shorewall/action.AllowAuth
%attr(0600,root,root) /usr/share/shorewall/action.AllowDNS
%attr(0600,root,root) /usr/share/shorewall/action.AllowFTP
%attr(0600,root,root) /usr/share/shorewall/action.AllowIMAP
%attr(0600,root,root) /usr/share/shorewall/action.AllowNNTP
%attr(0600,root,root) /usr/share/shorewall/action.AllowNTP
%attr(0600,root,root) /usr/share/shorewall/action.AllowPCA
%attr(0600,root,root) /usr/share/shorewall/action.AllowPing
%attr(0600,root,root) /usr/share/shorewall/action.AllowPOP3
%attr(0600,root,root) /usr/share/shorewall/action.AllowRdate
%attr(0600,root,root) /usr/share/shorewall/action.AllowSMB
%attr(0600,root,root) /usr/share/shorewall/action.AllowSMTP
%attr(0600,root,root) /usr/share/shorewall/action.AllowSNMP
%attr(0600,root,root) /usr/share/shorewall/action.AllowSSH
%attr(0600,root,root) /usr/share/shorewall/action.AllowTelnet
%attr(0600,root,root) /usr/share/shorewall/action.AllowTrcrt
%attr(0600,root,root) /usr/share/shorewall/action.AllowVNC
%attr(0600,root,root) /usr/share/shorewall/action.AllowVNCL
%attr(0600,root,root) /usr/share/shorewall/action.AllowWeb
%attr(0600,root,root) /usr/share/shorewall/action.Drop
%attr(0600,root,root) /usr/share/shorewall/action.DropDNSrep
%attr(0600,root,root) /usr/share/shorewall/action.DropPing
%attr(0600,root,root) /usr/share/shorewall/action.DropSMB
%attr(0600,root,root) /usr/share/shorewall/action.DropUPnP
%attr(0600,root,root) /usr/share/shorewall/action.Reject
%attr(0600,root,root) /usr/share/shorewall/action.RejectAuth
%attr(0600,root,root) /usr/share/shorewall/action.RejectSMB
%attr(0600,root,root) /usr/share/shorewall/action.template
%attr(0444,root,root) /usr/share/shorewall/functions
%attr(0544,root,root) /usr/share/shorewall/firewall
%attr(0544,root,root) /usr/share/shorewall/help
%attr(0600,root,root) /usr/share/shorewall/rfc1918
%attr(0600,root,root) /usr/share/shorewall/bogons
%attr(0600,root,root) /usr/share/shorewall/configpath

%doc COPYING INSTALL changelog.txt releasenotes.txt tunnel

%changelog
* Fri Jul 09 2004 Tom Eastep tom@shorewall.net
- Updated to 2.0.5-1
* Tue Jul 06 2004 Tom Eastep tom@shorewall.net
- Updated to 2.0.4-1
* Fri Jul 02 2004 Tom Eastep tom@shorewall.net
- Updated to 2.0.3c-1
* Wed Jun 30 2004 Tom Eastep tom@shorewall.net
- Updated to 2.0.3b-1
* Mon Jun 28 2004 Tom Eastep tom@shorewall.net
- Updated to 2.0.3a-1
* Wed Jun 23 2004 Tom Eastep tom@shorewall.net
- Updated to 2.0.3-1
* Sat Jun 19 2004 Tom Eastep tom@shorewall.net
- Updated to 2.0.2-0RC2
* Tue Jun 15 2004 Tom Eastep tom@shorewall.net
- Updated to 2.0.2-0RC1
* Mon Jun 14 2004 Tom Eastep tom@shorewall.net
- Added %attr spec for /etc/init.d/shorewall
* Sat May 15 2004 Tom Eastep tom@shorewall.net
- Updated for 2.0.2a-1
* Thu May 13 2004 Tom Eastep tom@shorewall.net
- Updated for 2.0.2-1
* Mon May 10 2004 Tom Eastep tom@shorewall.net
- Add /etc/shorewall/initdone
* Fri May 07 2004 Tom Eastep tom@shorewall.net
- Shorewall 2.0.2-RC1
* Tue May 04 2004 Tom Eastep tom@shorewall.net
- Shorewall 2.0.2-Beta2
* Tue Apr 13 2004 Tom Eastep tom@shorewall.net
- Add /usr/share/shorewall/configpath
* Mon Apr 05 2004 Tom Eastep tom@shorewall.net
- Updated for 2.0.1-1
* Thu Apr 02 2004 Tom Eastep tom@shorewall.net
- Updated for 2.0.1 RC5
* Thu Apr 01 2004 Tom Eastep tom@shorewall.net
- Updated for 2.0.1 RC4
* Sun Mar 28 2004 Tom Eastep tom@shorewall.net
- Updated for 2.0.1 RC3
* Thu Mar 25 2004 Tom Eastep tom@shorewall.net
- Updated for 2.0.1 RC2
* Wed Mar 24 2004 Tom Eastep tom@shorewall.net
- Updated for 2.0.1 RC1
* Fri Mar 19 2004 Tom Eastep tom@shorewall.net
- Updated for 2.0.1 Beta 2
* Thu Mar 18 2004 Tom Eastep tom@shorewall.net
- Added netmap file
* Wed Mar 17 2004 Tom Eastep <tom@shorewall.net>
- Update for 2.0.1 Beta 1
* Wed Mar 17 2004 Tom Eastep <tom@shorewall.net>
- Add bogons file
* Sat Mar 13 2004 Tom Eastep <tom@shorewall.net>
- Update for 2.0.0 Final
* Sat Mar 06 2004 Tom Eastep <tom@shorewall.net>
- Update for RC2
* Fri Feb 27 2004 Tom Eastep <tom@shorewall.net>
- Update for RC1
* Mon Feb 16 2004 Tom Eastep <tom@shorewall.net>
- Moved rfc1918 to /usr/share/shorewall
- Update for Beta 3
* Sat Feb 14 2004 Tom Eastep <tom@shorewall.net>
- Removed common.def
- Unconditionally replace actions.std
- Update for Beta 2
* Thu Feb 12 2004 Tom Eastep <tom@shorewall.net>
- Added action.AllowPCA
* Sun Feb 08 2004 Tom Eastep <tom@shorewall.net>
- Updates for Shorewall 2.0.0.
* Mon Dec 29 2003 Tom Eastep <tom@shorewall.net>
- Remove Documentation from this RPM
* Sun Dec 28 2003 Tom Eastep <tom@shorewall.net>
- Updated for Beta 2
* Sun Dec 07 2003 Tom Eastep <tom@shorewall.net>
- Added User Defined Actions Files
* Wed Dec 03 2003 Tom Eastep <tom@shorewall.net>
- Added User Defined Actions Files
* Fri Nov 07 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.8
* Sat Nov 01 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.8-0RC2
* Thu Oct 30 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.8-0RC1
* Sat Oct 04 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.7-1
- Removed conflict with 2.2 Kernels
* Mon Sep 22 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.7-0RC2
* Thu Sep 18 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.7-0RC1
* Mon Sep 15 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.7-0Beta2
* Mon Aug 25 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.7-0Beta1
* Sat Aug 23 2003 Tom Eastep <tom@shorewall.net>
- Added /etc/shorewall/users
- Changed version to 1.4.6_20030823-1
* Thu Aug 21 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.6_20030821-1
- Added /etc/shorewall/usersets
* Wed Aug 13 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.6_20030813-1
* Sat Aug 09 2003 Tom Eastep <tom@shorewall.net>
- Added /etc/shorewall/accounting
* Sat Aug 09 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.6_20030809-1
* Thu Jul 31 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.6_20030731-1
* Sun Jul 27 2003 Tom Eastep <tom@shorewall.net>
- Added /usr/share/shorewall/help
- Changed version to 1.4.6_20030727-1
* Sat Jul 26 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.6_20030726-1
* Sat Jul 19 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.6-1
* Mon Jul 14 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.6-0RC1
* Mon Jul 07 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.6-0Beta2
* Fri Jul 04 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.6-0Beta1
* Tue Jun 17 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.5-1
* Thu May 29 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.4b-1
* Tue May 27 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.4a-1
* Thu May 22 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.4-1
* Mon May 19 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.3a-1
* Sun May 18 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.3-1
* Mon Apr 07 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.2-1
* Fri Mar 21 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.1-1
* Mon Mar 17 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.0-1
* Fri Mar 07 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.0-0RC2
* Wed Mar 05 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.0-0RC1
* Mon Feb 24 2003 Tom Eastep <tom@shorewall.net>
- Changed version to 1.4.0-0Beta2
* Sun Feb 23 2003 Tom Eastep <tom@shorewall.net>
- Add ecn file
* Fri Feb 21 2003 Tom Eastep <tom@shorewall.net>
- Changes version to 1.4.0-0Beta1
* Thu Feb 06 2003 Tom Eastep <tom@shorewall.net>
- Changes version to 1.4.0Alpha1
- Delete icmp.def
- Move firewall and version to /usr/share/shorewall
* Tue Feb 04 2003 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.14-0RC1
* Tue Jan 28 2003 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.14-0Beta2
* Sat Jan 25 2003 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.14-0Beta1
* Mon Jan 13 2003 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.13
* Fri Dec 27 2002 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.12
* Sun Dec 22 2002 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.12-0Beta3
* Fri Dec 20 2002 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.12-0Beta2
* Wed Dec 18 2002 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.12-0Beta1
- Add init, start, stop and stopped files.
* Tue Dec 03 2002 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.11a
* Sun Nov 24 2002 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.11
* Sat Nov 09 2002 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.10
* Wed Oct 23 2002 Tom Eastep <tom@shorewall.net>
- Changes version to 1.3.10b1
* Tue Oct 22 2002 Tom Eastep <tom@shorewall.net>
- Added maclist file
* Tue Oct 15 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.10
- Replaced symlink with real file
* Wed Oct 09 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.9b
* Mon Sep 30 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.9a
* Thu Sep 18 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.8
* Mon Sep 16 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.8
* Mon Sep 02 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.7c
* Mon Aug 26 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.7b
* Thu Aug 22 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.7a
* Thu Aug 22 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.7
* Sun Aug 04 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.6
* Mon Jul 29 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.5b
* Sat Jul 13 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.4
* Wed Jul 10 2002 Tom Eastep <tom@shorewall.net>
- Added 'routestopped' configuration file.
* Fri Jul 05 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.3
* Sat Jun 15 2002 Tom Eastep <tom@shorewall.net>
- Changed version and release for new convention
- Moved version,firewall and functions to /var/lib/shorewall
* Sun Jun 02 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.2
* Fri May 31 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.1
- Added the rfc1918 file
* Wed May 29 2002 Tom Eastep <tom@shorewall.net>
- Changed version to 1.3.0
* Mon May 20 2002 Tom Eastep <tom@shorewall.net>
- Removed whitelist file
* Sat May 18 2002 Tom Eastep <tom@shorewall.net>
- changed version to 91
* Wed May 8 2002 Tom Eastep <tom@shorewall.net>
- changed version to 90
- removed 'provides' tag.
* Tue Apr 23 2002 Tom Eastep <tom@shorewall.net>
- changed version to 13
- Added whitelist file.
* Thu Apr 18 2002 Tom Eastep <tom@shorewall.net>
- changed version to 12
* Tue Apr 16 2002 Tom Eastep <tom@shorewall.net>
- Merged Stefan's changes to create single RPM
* Mon Apr 15 2002 Stefan Mohr <stefan@familie-mohr.com>
- changed to SuSE Linux 7.3
* Wed Apr 10 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 11
* Tue Mar 19 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 10
* Sat Mar 09 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 9
* Sat Feb 23 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 8
* Thu Feb 21 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 7
* Tue Feb 05 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 6
* Wed Jan 30 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 5
* Sat Jan 26 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 4
- Merged Ajay's change to allow build by non-root
* Sun Jan 12 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 3
* Tue Jan 01 2002 Tom Eastep <tom@shorewall.net>
- changed Version to 2
- Updated URL
- Added blacklist file
* Mon Dec 31 2001 Tom Eastep <tom@shorewall.net>
- changed Version to 1
* Wed Dec 19 2001 Tom Eastep <tom@shorewall.net>
- changed Version to 0
* Tue Dec 18 2001 Tom Eastep <tom@shorewall.net>
- changed Version to Rc1
* Sat Dec 15 2001 Tom Eastep <tom@shorewall.net>
- changed Version to Beta2
* Thu Nov 08 2001 Tom Eastep <tom@shorewall.net>
- changed Version to 1.2
- added tcrules file
* Sun Oct 21 2001 Tom Eastep <tom@shorewall.net>
- changed release to 17
* Sun Oct 21 2001 Tom Eastep <tom@shorewall.net>
- changed release to 16
* Sun Oct 14 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- changed release to 15
* Thu Oct 11 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- changed release to 14
* Tue Sep 11 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- changed release to 13
- added params file
* Tue Aug 28 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 12
* Fri Jul 27 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 11
* Sun Jul 08 2001 Ajay Ramaswamy <ajayr@bigfoot.com>
- reorganized spec file
- s/Copyright/License/
- now will build fron rpm -tb
* Fri Jul 06 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 10
* Tue Jun 19 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 9
- Added tunnel file
- Readded tunnels file
* Mon Jun 18 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 8
* Sat Jun 02 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 7
- Changed iptables dependency.
* Tue May 22 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 6
- Added tunnels file
* Sat May 19 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 5
- Added modules and tos files
* Sat May 12 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 4
- Added changelog.txt and releasenotes.txt
* Sat Apr 28 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed release to 3
* Mon Apr 9 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Added files common.def and icmpdef.def
- Changed release to 2
* Wed Apr 4 2001 Tom Eastep <tom@seattlefirewall.dyndns.org>
- Changed the release to 1.
* Mon Mar 26 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Changed the version to 1.1
- Added hosts file
* Sun Mar 18 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Changed the release to 4
- Added Zones and Functions files
* Mon Mar 12 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Change ipchains dependency to an iptables dependency and
  changed the release to 3
* Fri Mar 9 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Add additional files.
* Thu Mar 8 2001 Tom EAstep <teastep@seattlefirewall.dyndns.org>
- Change version to 1.0.2
* Tue Mar 6 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Change version to 1.0.1
* Sun Mar 4 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Changes for Shorewall
* Thu Feb 22 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Change version to 4.1.0
* Fri Feb 2 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Change version to 4.0.4
* Mon Jan 22 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Change version to 4.0.2
* Sat Jan 20 2001 Tom Eastep <teastep@seattlefirewall.dyndns.org>
- Changed version to 4.0
* Fri Jan 5 2001 Tom Eastep <teastep@evergo.net>
- Added dmzclients file
* Sun Dec 24 2000 Tom Eastep <teastep@evergo.net>
- Added ftpserver file
* Sat Aug 12 2000 Tom Eastep <teastep@evergo.net>
- Added "nat" and "proxyarp" files for 4.0
* Mon May 20 2000 Tom Eastep <teastep@evergo.net>
- added updown file
* Sat May 20 2000 Simon Piette <spiette@generation.net>
- Corrected the group - Networking/Utilities
- Added "noreplace" attributes to config files, so current confis is not
  changed.
- Added the version file.
* Sat May 20 2000 Tom Eastep <teastep@evergo.net>
- Converted Simon's patch to version 3.1
* Sat May 20 2000 Simon Piette <spiette@generation.net>
- 3.0.2 Initial RPM
  Patched the install script so it can take a PREFIX variable


