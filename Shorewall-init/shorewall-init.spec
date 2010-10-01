%define name shorewall-init
%define version 4.4.11
%define release 6

Summary: Shorewall-init adds functionality to Shoreline Firewall (Shorewall).
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
Requires: shoreline_firewall >= 4.4.10

%description

The Shoreline Firewall, more commonly known as "Shorewall", is a Netfilter
(iptables) based firewall that can be used on a dedicated firewall system,
a multi-function gateway/ router/server or on a standalone GNU/Linux system.

Shorewall Init is a companion product to Shorewall that allows for tigher
control of connections during boot and that integrates Shorewall with
ifup/ifdown and NetworkManager.

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
	/sbin/insserv /etc/rc.d/shorewall-init
    elif [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --add shorewall-init;
    fi
fi

if [ -f /etc/SuSE-release ]; then
    cp -pf /usr/share/shorewall-init/ifupdown /etc/sysconfig/network/if-up.d/shorewall
    cp -pf /usr/share/shorewall-init/ifupdown /etc/sysconfig/network/if-down.d/shorewall
else
    if [ -f /sbin/ifup-local -o -f /sbin/ifdown-local ]; then
	if ! grep -q Shorewall /sbin/ifup-local || ! grep -q Shorewall /sbin/ifdown-local; then
	    echo "WARNING: /sbin/ifup-local and/or /sbin/ifdown-local already exist; ifup/ifdown events will not be handled" >&2
	else
	    cp -pf /usr/share/shorewall-init/ifupdown /sbin/ifup-local
	    cp -pf /usr/share/shorewall-init/ifupdown /sbin/ifdown-local
	fi
    else
	cp -pf /usr/share/shorewall-init/ifupdown /sbin/ifup-local
	cp -pf /usr/share/shorewall-init/ifupdown /sbin/ifdown-local
    fi

    if [ -d /etc/NetworkManager/dispatcher.d/ ]; then
	cp -pf /usr/share/shorewall-init/ifupdown /etc/NetworkManager/dispatcher.d/01-shorewall
    fi
fi

%preun

if [ $1 -eq 0 ]; then
    if [ -x /sbin/insserv ]; then
	/sbin/insserv -r /etc/init.d/shorewall-init
    elif [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --del shorewall-init
    fi

    [ -f /sbin/ifup-local ]   && grep -q Shorewall /sbin/ifup-local   && rm -f /sbin/ifup-local
    [ -f /sbin/ifdown-local ] && grep -q Shorewall /sbin/ifdown-local && rm -f /sbin/ifdown-local

    rm -f /etc/NetworkManager/dispatcher.d/01-shorewall
fi

%files
%defattr(0644,root,root,0755)
%attr(0644,root,root) %config(noreplace) /etc/sysconfig/shorewall-init

%attr(0544,root,root) /etc/init.d/shorewall-init
%attr(0755,root,root) %dir /usr/share/shorewall-init

%attr(0644,root,root) /usr/share/shorewall-init/version
%attr(0544,root,root) /usr/share/shorewall-init/ifupdown

%doc COPYING changelog.txt releasenotes.txt

%changelog
* Fri Oct 01 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-6
* Sun Sep 12 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-5
* Sat Aug 28 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-4
* Thu Aug 12 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-3
* Sat Jul 31 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-2
* Wed Jul 14 2010 Tom Eastep tom@shorewall.net
- Updated to 4.4.11-1
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
* Tue May 18 2010 Tom Eastep tom@shorewall.net
- Initial version



