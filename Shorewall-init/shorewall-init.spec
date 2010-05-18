%define name shorewall-init
%define version 4.4.10
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

%description

The Shoreline Firewall, more commonly known as "Shorewall", is a Netfilter
(iptables) based firewall that can be used on a dedicated firewall system,
a multi-function gateway/ router/server or on a standalone GNU/Linux system.

Shorewall Init is a companion product to Shorewall that allows for tigher
control of connections during boot and to integrate Shorewall with ifup/ifdown
and NetworkManager.

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

%pre

if [ -f /etc/sysconfig/shorewall-init ]; then
    cp -fa /etc/sysconfig/shorewall-init /etc/sysconfig/shorewall-init.rpmsave
fi

%post

if [ $1 -eq 1 ]; then
    if [ -x /sbin/insserv ]; then
	/sbin/insserv /etc/rc.d/shorewall-init
    elif [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --add shorewall-init;
    fi

    if [ -f /etc/SuSE-release ]; then
	ln -sf /usr/share/shorewall-init/ifupdown /etc/sysconfig/network/if-up.d/shorewall
	ln -sf /usr/share/shorewall-init/ifupdown /etc/sysconfig/network/if-down.d/shorewall
    else
	if [ -f /sbin/ifup-local -o -f /sbin/ifdown-local ]; then
	    echo "WARNING: /sbin/ifup-local and/or /sbin/ifdown-local already exist; up/down events will not be handled" >&2
	else
	    ln -s /usr/share/shorewall-init/ifupdown /sbin/ifup-local
	    ln -s /usr/share/shorewall-init/ifupdown /sbin/ifdown-local
	fi

	if [ -d /etc/NetworkManager/dispatcher.d ]; then
	    #
      	    # RedHat doesn't integrate ifup-local/ifdown-local with NetworkManager
	    #
	    ln -s /usr/share/shorewall-init/ifupdown /etc/NetworkManager/dispatcher.d/01-shorewall
	fi
    fi	    
fi

%preun

if [ $1 -eq 0 ]; then
    if [ -x /sbin/insserv ]; then
	/sbin/insserv -r /etc/init.d/shorewall-init
    elif [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --del shorewall-init
    fi
fi

%files
%defattr(0644,root,root,0755)
%attr(0644,root,root) %config(noreplace) /etc/sysconfig/shorewall-init
%attr(0544,root,root) /etc/init.d/shorewall-init
%attr(0755,root,root) %dir /usr/share/shorewall-init

%attr(0644,root,root) /usr/share/shorewall-init/version
%attr(0644,root,root) /usr/share/shorewall-init/ifupdown

%doc COPYING changelog.txt releasenotes.txt

%changelog
* Tue May 18 2010 Tom Eastep tom@shorewall.net
- Initial version



