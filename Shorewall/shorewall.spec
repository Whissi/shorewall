%define name shorewall
%define version 4.4.20
%define release 0Beta4

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
BuildRoot: %{_tmppath}/%{name}-%{version}-root1
Requires: iptables iproute perl
Provides: shoreline_firewall = %{version}-%{release}
Obsoletes: shorewall-common shorewall-perl shorewall-shell

%description

The Shoreline Firewall, more commonly known as "Shorewall", is a Netfilter
(iptables) based firewall that can be used on a dedicated firewall system,
a multi-function gateway/ router/server or on a standalone GNU/Linux system.
%prep

%setup

%build

%install
export DESTDIR=$RPM_BUILD_ROOT ; \
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

%triggerpostun  -- shorewall-common < 4.4.0

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
%attr(0644,root,root) %config(noreplace) /etc/shorewall/*

%attr(0644,root,root) /etc/logrotate.d/shorewall

%attr(0755,root,root) /sbin/shorewall

%attr(0644,root,root) /usr/share/shorewall/version
%attr(0644,root,root) /usr/share/shorewall/actions.std
%attr(0644,root,root) /usr/share/shorewall/action.Drop
%attr(0644,root,root) /usr/share/shorewall/action.Reject
%attr(0644,root,root) /usr/share/shorewall/action.template
%attr(-   ,root,root) /usr/share/shorewall/functions
%attr(0644,root,root) /usr/share/shorewall/lib.base
%attr(0644,root,root) /usr/share/shorewall/lib.cli
%attr(0644,root,root) /usr/share/shorewall/lib.common
%attr(0644,root,root) /usr/share/shorewall/macro.*
%attr(0644,root,root) /usr/share/shorewall/modules*
%attr(0644,root,root) /usr/share/shorewall/helpers
%attr(0644,root,root) /usr/share/shorewall/configpath
%attr(0755,root,root) /usr/share/shorewall/wait4ifup

%attr(755,root,root) /usr/share/shorewall/compiler.pl
%attr(755,root,root) /usr/share/shorewall/getparams
%attr(0644,root,root) /usr/share/shorewall/prog.*
%attr(0644,root,root) /usr/share/shorewall/Shorewall/*.pm

%attr(0644,root,root) /usr/share/shorewall/configfiles/*

%attr(0644,root,root) %{_mandir}/man5/*
%attr(0644,root,root) %{_mandir}/man8/*

%doc COPYING INSTALL changelog.txt releasenotes.txt Contrib/* Samples

%changelog
* Sun May 22 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.20-0Beta4
* Thu May 19 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.20-0Beta3
* Wed May 18 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.20-0Beta2
* Fri Apr 15 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.20-0Beta1
* Wed Apr 13 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.19-1
* Sat Apr 09 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.19-0base
* Sun Apr 03 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.19-0RC1
* Sun Apr 03 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.19-0Beta5
* Sat Apr 02 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.19-0Beta4
* Sat Mar 26 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.19-0Beta3
* Sat Mar 05 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.19-0Beta1
* Wed Mar 02 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.18-0base
* Mon Feb 28 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.18-0RC1
* Sun Feb 20 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.18-0Beta4
* Sat Feb 19 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.18-0Beta3
* Sun Feb 13 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.18-0Beta2
* Sat Feb 05 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.18-0Beta1
* Fri Feb 04 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.17-0base
* Sun Jan 30 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.17-0RC1
* Fri Jan 28 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.17-0Beta3
* Wed Jan 19 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.17-0Beta2
* Sat Jan 08 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.17-0Beta1
* Mon Jan 03 2011 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0base
* Thu Dec 30 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0RC1
* Thu Dec 30 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0Beta8
* Sun Dec 26 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0Beta7
* Mon Dec 20 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0Beta6
* Fri Dec 10 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0Beta5
* Sat Dec 04 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0Beta4
* Fri Dec 03 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0Beta3
* Fri Dec 03 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0Beta2
* Tue Nov 30 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.16-0Beta1
* Fri Nov 26 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.15-0base
* Mon Nov 22 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.15-0RC1
* Mon Nov 15 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.15-0Beta2
* Sun Nov 14 2010 Tom Eastep tom@shorewall.net
- Added getparams to installed files
* Sat Oct 30 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.15-0Beta1
* Sat Oct 23 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.14-0base
* Wed Oct 06 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.14-0RC1
* Fri Oct 01 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.14-0Beta4
* Sun Sep 26 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.14-0Beta3
* Thu Sep 23 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.14-0Beta2
* Tue Sep 21 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.14-0Beta1
* Fri Sep 17 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.13-0RC1
* Fri Sep 17 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.13-0Beta6
* Mon Sep 13 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.13-0Beta5
* Sat Sep 04 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.13-0Beta4
* Mon Aug 30 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.13-0Beta3
* Wed Aug 25 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.13-0Beta2
* Wed Aug 18 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.13-0Beta1
* Sun Aug 15 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.12-0base
* Fri Aug 06 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.12-0RC1
* Sun Aug 01 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.12-0Beta4
* Sat Jul 31 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.12-0Beta3
* Sun Jul 25 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.12-0Beta2
* Wed Jul 21 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.12-0Beta1
* Fri Jul 09 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-0base
* Mon Jul 05 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-0RC1
* Sat Jul 03 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-0Beta3
* Thu Jul 01 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-0Beta2
* Sun Jun 06 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-0Beta1
* Sat Jun 05 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.10-0base
* Fri Jun 04 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.10-0RC2
* Thu May 27 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.10-0RC1
* Wed May 26 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.10-0Beta4
* Tue May 25 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.10-0Beta3
* Thu May 20 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.10-0Beta2
* Thu May 20 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.10-0Beta2
* Thu May 13 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.10-0Beta1
* Mon May 03 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.9-0base
* Sun May 02 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.9-0RC2
* Sun Apr 25 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.9-0RC1
* Sat Apr 24 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.9-0Beta5
* Fri Apr 16 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.9-0Beta4
* Fri Apr 09 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.9-0Beta3
* Thu Apr 08 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.9-0Beta2
* Sat Mar 20 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.9-0Beta1
* Fri Mar 19 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.8-0base
* Tue Mar 16 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.8-0RC2
* Mon Mar 08 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.8-0RC1
* Sun Feb 28 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.8-0Beta2
* Thu Feb 11 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.8-0Beta1
* Fri Feb 05 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.7-0base
* Tue Feb 02 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.7-0RC2
* Wed Jan 27 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.7-0RC1
* Mon Jan 25 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.7-0Beta4
* Fri Jan 22 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.7-0Beta3
* Fri Jan 22 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.7-0Beta2
* Thu Jan 21 2010 Tom Eastep tom@shorewall.net
- Add /usr/share/shorewall/helpers
* Sun Jan 17 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.7-0Beta1
* Wed Jan 13 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.6-0base
* Wed Jan 13 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.6-0Beta1
* Thu Dec 24 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.5-0base
* Sat Nov 21 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.4-0base
* Fri Nov 13 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.4-0Beta2
* Wed Nov 11 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.4-0Beta1
* Tue Nov 03 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.3-0base
* Sun Sep 06 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.2-0base
* Fri Sep 04 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.2-0base
* Fri Aug 14 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.1-0base
* Sun Aug 09 2009 Tom Eastep tom@shorewall.net
- Made Perl a dependency
* Mon Aug 03 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.0-0base
* Tue Jul 28 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.0-0RC2
* Sun Jul 12 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.0-0RC1
* Thu Jul 09 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.0-0Beta4
* Sat Jun 27 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.0-0Beta3
* Mon Jun 15 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.0-0Beta2
* Fri Jun 12 2009 Tom Eastep tom@shorewall.net
- Updated to 4.4.0-0Beta1
* Sun Jun 07 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.13-0base
* Fri Jun 05 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.12-0base
* Fri Jun 05 2009 Tom Eastep tom@shorewall.net
- Remove 'rfc1918' file
* Sun May 10 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.11-0base
* Sun Apr 19 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.10-0base
* Sat Apr 11 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.9-0base
* Tue Mar 17 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.8-0base
* Sun Mar 01 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.7-0base
* Fri Feb 27 2009 Tom Eastep tom@shorewall.net
- Updated to 4.3.6-0base
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


