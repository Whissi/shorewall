%define name shorewall
%define version 1.3.9b
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
Requires: iptables
Conflicts: kernel <= 2.2

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
./install.sh /etc/init.d

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
/etc/init.d/shorewall
%attr(0700,root,root) %dir /etc/shorewall
%attr(0700,root,root) %dir /usr/lib/shorewall
%attr(0700,root,root) %dir /var/lib/shorewall
%attr(0600,root,root) /usr/lib/shorewall/version
%attr(0600,root,root) /etc/shorewall/common.def
%attr(0600,root,root) /etc/shorewall/icmp.def
%attr(0600,root,root) %config(noreplace) /etc/shorewall/shorewall.conf
%attr(0600,root,root) %config(noreplace) /etc/shorewall/zones
%attr(0600,root,root) %config(noreplace) /etc/shorewall/policy
%attr(0600,root,root) %config(noreplace) /etc/shorewall/interfaces
%attr(0600,root,root) %config(noreplace) /etc/shorewall/rules
%attr(0600,root,root) %config(noreplace) /etc/shorewall/nat
%attr(0600,root,root) %config(noreplace) /etc/shorewall/params
%attr(0600,root,root) %config(noreplace) /etc/shorewall/proxyarp
%attr(0600,root,root) %config(noreplace) /etc/shorewall/routestopped
%attr(0600,root,root) %config(noreplace) /etc/shorewall/masq
%attr(0600,root,root) %config(noreplace) /etc/shorewall/modules
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tcrules
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tos
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tunnels
%attr(0600,root,root) %config(noreplace) /etc/shorewall/hosts
%attr(0600,root,root) %config(noreplace) /etc/shorewall/blacklist
%attr(0600,root,root) %config(noreplace) /etc/shorewall/rfc1918
%attr(0544,root,root) /sbin/shorewall
%attr(0444,root,root) /usr/lib/shorewall/functions
/usr/lib/shorewall/firewall
%doc documentation
%doc COPYING INSTALL changelog.txt releasenotes.txt tunnel

%changelog
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


