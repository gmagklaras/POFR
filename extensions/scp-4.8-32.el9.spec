%define _hardened_build 1
Summary: Restricted shell for ssh based file services
Name: scponly
Version: 4.8
Release: 32%{?dist}
License: BSD
URL: http://sublimation.org/scponly/
Source: http://downloads.sf.net/scponly/scponly-%{version}.tgz
Patch0: scponly-install.patch
Patch1: scponly-4.8-elif-gcc44.patch
Patch2: scponly-configure-c99.patch

# Checks only for location of binaries
BuildRequires: make
BuildRequires:  gcc
BuildRequires: openssh-clients >= 3.4
BuildRequires: openssh-server
BuildRequires: rsync

%description
scponly is an alternative 'shell' for system administrators 
who would like to provide access to remote users to both 
read and write local files without providing any remote 
execution priviledges. Functionally, it is best described 
as a wrapper to the "tried and true" ssh suite of applications. 

%prep
%setup -q
%patch0 -p1
%patch1 -p1
%patch2 -p1

%build
# config.guess in tarball lacks ppc64
cp -p /usr/lib/rpm/redhat/config.{guess,sub} .
%configure --enable-scp-compat --enable-winscp-compat --enable-chrooted-binary

%{__make} %{?_smp_mflags} \
	CFLAGS="%{optflags} -specs=/usr/lib/rpm/redhat/redhat-hardened-ld"

# Remove executable bit so the debuginfo does not hae executable source files
chmod 0644 scponly.c scponly.h helper.c

%install
%{__rm} -rf %{buildroot}

# 
sed -i "s|%{_prefix}/local/|%{_prefix}/|g" scponly.8* INSTALL README
make install DESTDIR=%{buildroot}

%files 
%doc AUTHOR CHANGELOG CONTRIB COPYING INSTALL README TODO BUILDING-JAILS.TXT
%doc SECURITY
%defattr(-, root, root, 0755)
%doc %{_mandir}/man8/scponly.8*
%{_bindir}/scponly
%{_sbindir}/scponlyc
%dir %{_sysconfdir}/scponly/
%config(noreplace) %{_sysconfdir}/scponly/*

%changelog
* Sat Dec 16 2023 Steelcyber Scientific Georgios Magklaras <georgios@mail.steelcyber.com> - 4.8-32-rhel9
- Rebuilt for POFR Release v.1.3.2  https://github.com/gmagklaras/POFR/releases/tag/v1.3.2 

* Sat Jan 21 2023 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-32
- Rebuilt for https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild

* Tue Jan 10 2023 Florian Weimer <fweimer@redhat.com> - 4.8-31
- Port configure script to C99

* Sat Jul 23 2022 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-30
- Rebuilt for https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild

* Steelcyber Scientific Georgios Magklaras <georgios@mail.steelcyber.com> - 4.8-29-rhel9
- Rebuilt for POFR Release v.1.3.1 https://github.com/gmagklaras/POFR/releases/tag/v1.3.1

* Sat Jan 22 2022 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-29
- Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild

* Fri Jul 23 2021 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-28
- Rebuilt for https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild

* Wed Jan 27 2021 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-27
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Sat Aug 01 2020 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-26
- Second attempt - Rebuilt for
  https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

* Wed Jul 29 2020 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-25
- Rebuilt for https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

* Thu Jan 30 2020 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-24
- Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild

* Fri Jul 26 2019 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-23
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Sat Feb 02 2019 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-22
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Sat Jul 14 2018 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-21
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Fri Feb 09 2018 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-20
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Thu Aug 03 2017 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-19
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Thu Jul 27 2017 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-18
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Sat Feb 11 2017 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-17
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Thu Feb 04 2016 Fedora Release Engineering <releng@fedoraproject.org> - 4.8-16
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Fri Jun 19 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-15
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Mon Aug 18 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-14
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Sun Jun 08 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-13
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Sun Aug 04 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-12
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Fri Apr 13 2013 Jon Ciesla <limburgher@gmail.com> - 4.8-11
- Fix hardened build, BZ 965483.

* Thu Feb 14 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-10
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Sat Jul 21 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-9
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Fri Apr 13 2012 Jon Ciesla <limburgher@gmail.com> - 4.8-8
- Add hardened build.

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Fri Feb 27 2009 Warren Togami <wtogami@redhat.com> - 4.8-4
- Fix gcc-4.4 build due to broken #elif
- copy config.guess from /usr/lib/rpm so it builds on ppc64

* Wed Feb 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Mon May 5 2008 Toshio Kuratomi <toshio@fedoraproject.org> - 4.8-1
- Update to 4.8 which has its own version of.  scponly-4.6-CVE-2007-6415.

* Wed Feb 13 2008 Tomas Hoger <thoger@redhat.com> - 4.6-10
- Add patch to prevent restriction bypass using OpenSSH's scp options -F
  and -o (CVE-2007-6415, #426072)

* Mon Feb 11 2008 Warren Togami <wtogami@redhat.com> - 4.6-9
- rebuild with gcc-4.3

* Tue Dec 11 2007 Toshio Kuratomi <a.badger@gmail.com> - 4.6-8
- Disable rsync support due to security concerns: RH BZ#418201

* Tue Aug 21 2007 Warren Togami <wtogami@redhat.com> - 4.6-7
- rebuild

* Fri Sep 15 2006 Warren Togami <wtogami@redhat.com> - 4.6-6
- rebuild for FC6

* Tue Jun 27 2006 Toshio Kuratomi <toshio@tiki-lounge.com> - 4.6-5
- Add BR: openssh-server so sftp-server is present.
- Make source files nonexecutable so they are nonexecutable in debuginfo.
- Mark the scponly configuration files as %%config.

* Sun Jun 25 2006 Toshio Kuratomi <toshio@tiki-lounge.com> - 4.6-4
- --enable-chrooted-binary creates a binary that will operate in a chroot
  environment.  It does not manage creation and updating of a chroot jail.
  This is the user's responsibility.
- Patch the Makefile.in to support install as a non-root user.

* Sun Mar 19 2006 Warren Togami <wtogami@redhat.com> - 4.6-3
- --enable-winscp-compat seems necessary
- --enable-rsync-compat seems useful too 

* Fri Feb 17 2006 Warren Togami <wtogami@redhat.com> - 4.6-1
- 4.6
- --enable-scp-compat so scp works
  upstream seems broken and no longer enables by default
  WinSCP 2.0 compatibilty is not enabled in this build

* Mon Jan 02 2006 Warren Togami <wtogami@redhat.com> - 4.3-1
- security fixes
- Gentoo's patch for optreset which is not supplied by glibc

* Thu Nov 03 2005 Warren Togami <wtogami@redhat.com> - 4.1-6
- use macro in substitution

* Tue Nov 01 2005 Warren Togami <wtogami@redhat.com> - 4.1-5
- BSD license
- fix path to scponly binary in man and docs

* Mon Oct 31 2005 Warren Togami <wtogami@redhat.com> - 4.1-4
- fix doc permissions

* Fri Oct 28 2005 Warren Togami <wtogami@redhat.com> - 4.1-2
- various spec fixes (#171987)

* Fri Oct 28 2005 Warren Togami <wtogami@redhat.com> - 4.1-1
- Fedora

* Tue May 10 2005 Dag Wieers <dag@wwieers.com> - 4.1-1 - 3051+/dag
- Updated to release 4.1.

* Thu Mar 03 2005 Dag Wieers <dag@wwieers.com> - 4.0-1
- Initial package. (using DAR)
