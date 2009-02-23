%define name shorewall
%define version 4.3.5
%define release 0base

Summary: Shoreline Firewall is an iptables-based firewall for Linux systems.
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
Requires: iptables iproute
Obsoletes: shorewall-common shorewall-perl shorewall-shell

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

%triggerpostun  -- shorewall < 4.0.0

if [ -x /sbin/insserv ]; then
    /sbin/insserv /etc/rc.d/shorewall
elif [ -x /sbin/chkconfig ]; then
    /sbin/chkconfig --add shorewall;
fi

%files
%defattr(0644,root,root,0755)
%attr(0544,root,root) /etc/init.d/shorewall
%attr(0755,root,root) %dir /etc/shorewall
%attr(0755,root,root) %dir /usr/share/shorewall
%attr(0755,root,root) %dir /usr/share/shorewall/configfiles
%attr(0700,root,root) %dir /var/lib/shorewall
%attr(0644,root,root) %config(noreplace) /etc/shorewall/shorewall.conf
%attr(0600,root,root) %config(noreplace) /etc/shorewall/zones
%attr(0600,root,root) %config(noreplace) /etc/shorewall/policy
%attr(0600,root,root) %config(noreplace) /etc/shorewall/interfaces
%attr(0600,root,root) %config(noreplace) /etc/shorewall/ipsec
%attr(0600,root,root) %config(noreplace) /etc/shorewall/rules
%attr(0600,root,root) %config(noreplace) /etc/shorewall/nat
%attr(0600,root,root) %config(noreplace) /etc/shorewall/netmap
%attr(0644,root,root) %config(noreplace) /etc/shorewall/params
%attr(0600,root,root) %config(noreplace) /etc/shorewall/proxyarp
%attr(0600,root,root) %config(noreplace) /etc/shorewall/routestopped
%attr(0600,root,root) %config(noreplace) /etc/shorewall/maclist
%attr(0600,root,root) %config(noreplace) /etc/shorewall/masq
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
%attr(0600,root,root) %config(noreplace) /etc/shorewall/restored
%attr(0600,root,root) %config(noreplace) /etc/shorewall/providers
%attr(0600,root,root) %config(noreplace) /etc/shorewall/route_rules
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tcclasses
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tcdevices
%attr(0600,root,root) %config(noreplace) /etc/shorewall/tcfilters
%attr(0600,root,root) %config(noreplace) /etc/shorewall/notrack
%attr(0600,root,root) /etc/shorewall/Makefile

%attr(0755,root,root) /sbin/shorewall

%attr(0644,root,root) /usr/share/shorewall/version
%attr(0644,root,root) /usr/share/shorewall/actions.std
%attr(0644,root,root) /usr/share/shorewall/action.Drop
%attr(0644,root,root) /usr/share/shorewall/action.Reject
%attr(0644,root,root) /usr/share/shorewall/action.template
%attr(-   ,root,root) /usr/share/shorewall/functions
%attr(0644,root,root) /usr/share/shorewall/lib.base
%attr(0644,root,root) /usr/share/shorewall/lib.cli
%attr(0644,root,root) /usr/share/shorewall/macro.*
%attr(0644,root,root) /usr/share/shorewall/modules
%attr(0644,root,root) /usr/share/shorewall/rfc1918
%attr(0644,root,root) /usr/share/shorewall/configpath
%attr(0755,root,root) /usr/share/shorewall/wait4ifup

%attr(755,root,root) /usr/share/shorewall/compiler.pl
%attr(0644,root,root) /usr/share/shorewall/prog.*
%attr(0644,root,root) /usr/share/shorewall/Shorewall/*.pm

%attr(0644,root,root) /usr/share/shorewall/configfiles/shorewall.conf
%attr(0644,root,root) /usr/share/shorewall/configfiles/zones
%attr(0644,root,root) /usr/share/shorewall/configfiles/policy
%attr(0644,root,root) /usr/share/shorewall/configfiles/interfaces
%attr(0644,root,root) /usr/share/shorewall/configfiles/ipsec
%attr(0644,root,root) /usr/share/shorewall/configfiles/rules
%attr(0644,root,root) /usr/share/shorewall/configfiles/nat
%attr(0644,root,root) /usr/share/shorewall/configfiles/netmap
%attr(0644,root,root) /usr/share/shorewall/configfiles/params
%attr(0644,root,root) /usr/share/shorewall/configfiles/proxyarp
%attr(0644,root,root) /usr/share/shorewall/configfiles/routestopped
%attr(0644,root,root) /usr/share/shorewall/configfiles/maclist
%attr(0644,root,root) /usr/share/shorewall/configfiles/masq
%attr(0644,root,root) /usr/share/shorewall/configfiles/tcrules
%attr(0644,root,root) /usr/share/shorewall/configfiles/tos
%attr(0644,root,root) /usr/share/shorewall/configfiles/tunnels
%attr(0644,root,root) /usr/share/shorewall/configfiles/hosts
%attr(0644,root,root) /usr/share/shorewall/configfiles/blacklist
%attr(0644,root,root) /usr/share/shorewall/configfiles/init
%attr(0644,root,root) /usr/share/shorewall/configfiles/initdone
%attr(0644,root,root) /usr/share/shorewall/configfiles/start
%attr(0644,root,root) /usr/share/shorewall/configfiles/stop
%attr(0644,root,root) /usr/share/shorewall/configfiles/stopped
%attr(0644,root,root) /usr/share/shorewall/configfiles/ecn
%attr(0644,root,root) /usr/share/shorewall/configfiles/accounting
%attr(0644,root,root) /usr/share/shorewall/configfiles/actions
%attr(0644,root,root) /usr/share/shorewall/configfiles/continue
%attr(0644,root,root) /usr/share/shorewall/configfiles/started
%attr(0644,root,root) /usr/share/shorewall/configfiles/restored
%attr(0644,root,root) /usr/share/shorewall/configfiles/providers
%attr(0644,root,root) /usr/share/shorewall/configfiles/route_rules
%attr(0644,root,root) /usr/share/shorewall/configfiles/tcclasses
%attr(0644,root,root) /usr/share/shorewall/configfiles/tcdevices
%attr(0644,root,root) /usr/share/shorewall/configfiles/tcfilters
%attr(0644,root,root) /usr/share/shorewall/configfiles/notrack
%attr(0644,root,root) /usr/share/shorewall/configfiles/Makefile

%attr(0644,root,root) %{_mandir}/man5/*
%attr(0644,root,root) %{_mandir}/man8/shorewall.8.gz

%doc COPYING INSTALL changelog.txt releasenotes.txt tunnel ipsecvpn Samples swping swping.init isusable

%changelog
* Sun Feb 22 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.5-0base
* Sat Feb 21 2009 Tom Eastep tom@shorewall.net
- Updated to 4.2.7-0base
* Thu Feb 05 2009 Tom Eastep tom@shorewall.net
- Add 'restored' script
* Wed Feb 04 2009 Tom Eastep tom@shorewall.net
- Updated to 4.2.6-0base
* Fri Jan 30 2009 Tom Eastep tom@shorewall.net
- Added swping files to the doc directory
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
* Thu Dec 11 2008 Tom Eastep tom@shorewall.net
- Updated to 4.3.1-0base
* Wed Dec 10 2008 Tom Eastep tom@shorewall.net
- Updated to 4.3.0-0base
* Wed Dec 10 2008 Tom Eastep tom@shorewall.net
- Updated to 2.3.0-0base
* Fri Dec 05 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.3-0base
* Wed Nov 05 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.2-0base
* Wed Oct 08 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.1-0base
* Fri Oct 03 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.0-0base
* Tue Sep 23 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.0-0RC4
* Mon Sep 15 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.0-0RC3
* Mon Sep 08 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.0-0RC2
* Tue Aug 19 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.0-0RC1
* Thu Jul 03 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.0-0Beta3
* Mon Jun 02 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.0-0Beta2
* Wed May 07 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.0-0Beta1
* Mon Apr 28 2008 Tom Eastep tom@shorewall.net
- Updated to 4.1.8-0base
* Mon Mar 24 2008 Tom Eastep tom@shorewall.net
- Updated to 4.1.7-0base
* Thu Mar 13 2008 Tom Eastep tom@shorewall.net
- Updated to 4.1.6-0base
* Tue Feb 05 2008 Tom Eastep tom@shorewall.net
- Updated to 4.1.5-0base
* Fri Jan 04 2008 Tom Eastep tom@shorewall.net
- Updated to 4.1.4-0base
* Wed Dec 12 2007 Tom Eastep tom@shorewall.net
- Updated to 4.1.3-0base
* Fri Dec 07 2007 Tom Eastep tom@shorewall.net
- Updated to 4.1.3-1
* Tue Nov 27 2007 Tom Eastep tom@shorewall.net
- Updated to 4.1.2-1
* Wed Nov 21 2007 Tom Eastep tom@shorewall.net
- Updated to 4.1.1-1
* Mon Nov 19 2007 Tom Eastep tom@shorewall.net
- Updated to 4.1.0-1
* Thu Nov 15 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.6-1
* Sat Nov 10 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.6-0RC3
* Wed Nov 07 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.6-0RC2
* Thu Oct 25 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.6-0RC1
* Tue Oct 03 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.5-1
* Wed Sep 05 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.4-1
* Mon Aug 13 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.3-1
* Thu Aug 09 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.2-1
* Sat Jul 21 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.1-1
* Wed Jul 11 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-1
* Sun Jul 08 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0RC2
* Fri Jun 29 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0RC1
* Sun Jun 24 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta7
* Wed Jun 20 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta6
* Thu Jun 14 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta5
* Fri Jun 08 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta4
* Tue Jun 05 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta3
* Tue May 15 2007 Tom Eastep tom@shorewall.net
- Updated to 4.0.0-0Beta1
* Fri May 11 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.7-1
* Sat May 05 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.6-1
* Mon Apr 30 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.5-1
* Mon Apr 23 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.4-1
* Wed Apr 18 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.3-1
* Mon Apr 16 2007 Tom Eastep tom@shorewall.net
- Moved lib.dynamiczones from Shorewall-shell
* Sat Apr 14 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.2-1
* Tue Apr 03 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.1-1
* Thu Mar 24 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.2-1
* Thu Mar 15 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.1-1
* Sat Mar 10 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-1
* Sun Feb 25 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0RC3
* Sun Feb 04 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0RC2
* Wed Jan 24 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0RC1
* Mon Jan 22 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0Beta3
* Wed Jan 03 2007 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0Beta2
* Thu Dec 14 2006 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0Beta1
* Sat Nov 25 2006 Tom Eastep tom@shorewall.net
- Added shorewall-exclusion(5)
- Updated to 3.3.6-1
* Sun Nov 19 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.5-1
* Sat Nov 18 2006 Tom Eastep tom@shorewall.net
- Add Man Pages.
* Sun Oct 29 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.4-1
* Mon Oct 16 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.3-1
* Sat Sep 30 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.2-1
* Wed Aug 30 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.1-1
* Sun Aug 27 2006 Tom Eastep tom@shorewall.net
- Updated to 3.3.0-1
* Fri Aug 25 2006 Tom Eastep tom@shorewall.net
- Updated to 3.2.3-1


