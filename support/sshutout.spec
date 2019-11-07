Name:           sshutout
Version:        1.0.6
Release:        1
Summary:        Daemon to Stop SSH Dictionary Attacks
License:        GPL
Group:          System/Servers
URL:            https://github.com/ConsulTent/sshutout
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}.init
Source2:        %{name}.sysconfig
Source3:        %{name}.logrotate
Patch0:         sshutout-1.0.6-centos_conf.patch
Requires:       openssh-server, iptables, sed
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root
Packager:	Alexey Zilber <azilber@consultent.ltd>

%description
This is a Linux daemon, that periodically monitors log
files looking for multiple failed login attempts via the Secure Shell
daemon (sshd, or optionally, sshd2). The daemon is meant to mitigate
what are commonly known as "dictionary attacks," i.e. scripted brute
force attacks that use lists of user ID's and passwords to effect
unauthorized intrusions. Typically such attacks fill the system logs
with hundreds or even thousands of log entries for the failed login
attempts. Aside from the nuisance of wasted space, wasted bandwidth,
and reduced signal to noise ratio in the logs, the attacks can pose a
real danger to systems with weak ID and password combinations.

The sshutout daemon blunts such attacks by creating firewall rules to
block individual offenders from accessing the system. These rules are
created when an attack signature is detected, and after a configurable
expiry interval has elapsed, the rules are deleted.

While sshutout can help reduce the severity and impact of dictionary
attacks, it is by no means a substitute for a good password policy. A
password policy is the front line of defense against intrusion and
should be given careful consideration. The sshutout daemon is merely
one small tool intended to help reduce log clutter and diminish the
incentive to mount dictionary attacks.

%prep
%setup -q
%patch0 -p1

%build
make

%install
%{__rm} -rf %{buildroot}

%{__mkdir_p} %{buildroot}%{_initrddir}
%{__mkdir_p} %{buildroot}%{_sbindir}
%{__mkdir_p} %{buildroot}%{_sysconfdir}/sysconfig
%{__mkdir_p} %{buildroot}%{_sysconfdir}/logrotate.d
%{__mkdir_p} %{buildroot}%{_mandir}/man8
%{__mkdir_p} %{buildroot}%{_logdir}

%{__install} -p -m 0755 %{name} %{buildroot}%{_sbindir}/
%{__install} -p -m 0644 %{name}.conf %{buildroot}%{_sysconfdir}/
%{__install} -p -m 0644 %{name}.8 %{buildroot}%{_mandir}/man8/

%{__install} -p -m 0755 %{SOURCE1} %{buildroot}%{_initrddir}/%{name}
%{__install} -p -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/sysconfig/%{name}
%{__install} -p -m 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/logrotate.d/%{name}

%post
if [ -n "$WHITELIST" ]; then
echo "\$WHITELIST exists as '$WHITELIST'"
sed -i -e "s/XXWHITELISTXX/$WHITELIST/g" %{_sysconfdir}/%{name}.conf
else
echo "\$WHITELIST doesnt exist, using localhost"
sed -i -e "s/XXWHITELISTXX/localhost/g" %{_sysconfdir}/%{name}.conf
fi
/sbin/chkconfig --add %{name}


%preun
if [ $1 = 0 ]; then # package is being erased, not upgraded
     /sbin/service %{name} stop > /dev/null 2>&1
     /sbin/chkconfig --del %{name}
fi

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(0644,root,root,0755)
%doc License README TODO FILES sshutout.html
%attr(0755,root,root) %{_initrddir}/%{name}
%attr(0640,root,root) %config(noreplace) %{_sysconfdir}/%{name}.conf
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%attr(0755,root,root) %{_sbindir}/*
%attr(0644,root,root) %{_mandir}/man8/*


%changelog
* Tue Mar 16 2011 Alexey Zilber <alex@kfactormedia.com> 1.0.6-1
- Packaged new version for CentOs

* Mon Dec 31 2007 David Walluck <walluck@mandriva.org> 1.0.5-2mdv2008.1
+ Revision: 139762
- fix install calls
- 1.0.5
- macros
- convert remaining tabs in spec to spaces

  + Thierry Vignaud <tvignaud@mandriva.com>
    - kill re-definition of %%buildroot on Pixel's request
    - fix descriptions

* Sat Nov 17 2007 David Walluck <walluck@mandriva.org> 1.0.4-1mdv2008.1
+ Revision: 109681
- add sources and patches
- 1.0.4
- rediff mdv_conf patch

* Fri May 11 2007 David Walluck <walluck@mandriva.org> 1.0.3-2mdv2008.0
+ Revision: 26284
-LSB initscript
- bunzip2 sources
- Import sshutout



* Sat Jul 01 2006 Oden Eriksson <oeriksson@mandriva.com> 1.0.3-1mdv2007.0
- 1.0.3
- rediffed P0

* Tue Jun 20 2006 Oden Eriksson <oeriksson@mandriva.com> 1.0.2-1mdv2007.0
- initial Mandriva package
