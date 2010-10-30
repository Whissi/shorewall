%define name shorewall-lite
%define version 4.4.15
%define release 0Beta1

Summary: Shoreline Firewall Lite is an iptables-based firewall for Linux systems.
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
Provides: shoreline_firewall = %{version}-%{release}

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
export DESTDIR=$RPM_BUILD_ROOT ; \
export OWNER=`id -n -u` ; \
export GROUP=`id -n -g` ;\
./install.sh

%clean
rm -rf $RPM_BUILD_ROOT

%pre

if [ -f /etc/shorewall-lite/shorewall.conf ]; then
    cp -fa /etc/shorewall-lite/shorewall.conf /etc/shorewall-lite/shorewall.conf.rpmsave
fi

%post

if [ $1 -eq 1 ]; then
    if [ -x /sbin/insserv ]; then
	/sbin/insserv /etc/rc.d/shorewall-lite
    elif [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --add shorewall-lite;
    fi
elif [ -f /etc/shorewall-lite/shorewall.conf.rpmsave ]; then
    mv -f /etc/shorewall-lite/shorewall-lite.conf /etc/shorewall-lite/shorewall-lite.conf.rpmnew
    mv -f /etc/shorewall-lite/shorewall.conf.rpmsave /etc/shorewall-lite/shorewall-lite.conf
    echo "/etc/shorewall-lite/shorewall.conf retained as /etc/shorewall-lite/shorewall-lite.conf"
    echo "/etc/shorewall-lite/shorewall-lite.conf installed as /etc/shorewall-lite/shorewall-lite.conf.rpmnew"
fi

%preun

if [ $1 -eq 0 ]; then
    if [ -x /sbin/insserv ]; then
	/sbin/insserv -r /etc/init.d/shorewall-lite
    elif [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --del shorewall-lite
    fi
fi

%files
%defattr(0644,root,root,0755)
%attr(0755,root,root) %dir /etc/shorewall-lite
%attr(0644,root,root) %config(noreplace) /etc/shorewall-lite/shorewall-lite.conf
%attr(0644,root,root) /etc/shorewall-lite/Makefile
%attr(0544,root,root) /etc/init.d/shorewall-lite
%attr(0755,root,root) %dir /usr/share/shorewall-lite
%attr(0700,root,root) %dir /var/lib/shorewall-lite

%attr(0644,root,root) /etc/logrotate.d/shorewall-lite

%attr(0755,root,root) /sbin/shorewall-lite

%attr(0644,root,root) /usr/share/shorewall-lite/version
%attr(0644,root,root) /usr/share/shorewall-lite/configpath
%attr(-   ,root,root) /usr/share/shorewall-lite/functions
%attr(0644,root,root) /usr/share/shorewall-lite/lib.base
%attr(0644,root,root) /usr/share/shorewall-lite/lib.cli
%attr(0644,root,root) /usr/share/shorewall-lite/lib.common
%attr(0644,root,root) /usr/share/shorewall-lite/modules
%attr(0544,root,root) /usr/share/shorewall-lite/shorecap
%attr(0755,root,root) /usr/share/shorewall-lite/wait4ifup

%attr(0644,root,root) %{_mandir}/man5/shorewall-lite.conf.5.gz
%attr(0644,root,root) %{_mandir}/man5/shorewall-lite-vardir.5.gz

%attr(0644,root,root) %{_mandir}/man8/shorewall-lite.8.gz

%doc COPYING changelog.txt releasenotes.txt

%changelog
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
* Sun Jan 17 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.7-0Beta1
* Wed Jan 13 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.6-0base
* Tue Jan 12 2010 Tom Eastep tom@shorewall.net
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
* Wed Feb 04 2009 Tom Eastep tom@shorewall.net
- Updated to 4.2.6-0base
* Thu Jan 29 2009 Tom Eastep tom@shorewall.net
- Updated to 4.2.6-0base
* Tue Jan 06 2009 Tom Eastep tom@shorewall.net
- Updated to 4.2.5-0base
* Thu Dec 25 2008 Tom Eastep tom@shorewall.net
- Updated to 4.2.4-0base
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
* Mon Jul 02 2007 Tom Eastep tom@shorewall.net
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
* Sat Apr 14 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.2-1
* Sat Apr 07 2007 Tom Eastep tom@shorewall.net
- Updated to 3.9.1-1
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
- Handle rename of shorewall.conf
* Thu Dec 14 2006 Tom Eastep tom@shorewall.net
- Updated to 3.4.0-0Beta1
* Sat Nov 25 2006 Tom Eastep tom@shorewall.net
- Added shorewall-exclusion(5)
- Updated to 3.3.6-1
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


