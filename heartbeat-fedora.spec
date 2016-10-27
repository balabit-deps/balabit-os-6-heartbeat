
# When downloading directly from Mercurial, it will automatically add this prefix
# Invoking 'hg archive' wont but you can add one with:
# hg archive -t tgz -p "Linux-HA-Dev-" -r $upstreamversion $upstreamversion.tar.gz
%global specversion 1
%global upstreamprefix heartbeat
#global upstreamversion 0daab7da36a8

#global alphatag %{upstreamversion}.hg

%global           gname haclient
%global           uname hacluster

%global heartbeat_docdir %{_defaultdocdir}/%{name}-%{version}

Name:             heartbeat
Summary:          Messaging and membership subsystem for High-Availability Linux
Version:          3.0.6
#Release:          %{?alphatag:0.}%{specversion}%{?alphatag:.%{alphatag}}%{?dist}
Release:          1%{?dist}
License:          GPLv2 and LGPLv2+
URL:              http://linux-ha.org/
Group:            System Environment/Daemons
Source0:          heartbeat.tar.bz2
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n) 
BuildRequires:    glib2-devel
BuildRequires:    iputils
%if 0%{?fedora} || 0%{?centos} > 4 || 0%{?rhel} > 4
BuildRequires:    libtool-ltdl-devel
%endif
BuildRequires:    bzip2-devel 
BuildRequires:    ncurses-devel
BuildRequires:    openssl-devel
BuildRequires:    libtool
BuildRequires:    gettext
BuildRequires:    zlib-devel
BuildRequires:    mailx
BuildRequires:    which
BuildRequires:    cluster-glue-libs-devel
BuildRequires:    libxslt docbook-dtds docbook-style-xsl
%if %{defined _unitdir}
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
%else
Requires(post):   /sbin/chkconfig
Requires(preun):  /sbin/chkconfig
%endif
Requires:         heartbeat-libs = %{version}-%{release}
Requires:         resource-agents
Requires:         cluster-glue-libs
Requires(pre):    shadow-utils
Requires(pre):    cluster-glue
Obsoletes:        heartbeat-gui < %{version}-%{release}

%description
Heartbeat is a daemon that provides cluster infrastructure (communication and
membership) services to its clients. This allows clients to know about the
presence (or disappearance!) of peer processes on other machines and to easily
exchange messages with them.

Reference documentation is available online: http://www.linux-ha.org/doc/
Extensive manual pages for system administration commands and configuration
files are included.

In order to be useful to users, the Heartbeat daemon needs to be combined with
a cluster resource manager (CRM) which has the task of starting and stopping
the services (IP addresses, web servers, etc.) that cluster will make highly
available.

Pacemaker is the preferred cluster resource manager for clusters based on
Heartbeat, supporting "n-node" clusters with significant capabilities for
managing resources and dependencies.

In addition Heartbeat continues to support the legacy realease 1 style of
2-node clustering.

It implements the following kinds of heartbeats:
        - Serial ports
        - UDP/IP multicast (ethernet, etc)
        - UDP/IP broadcast (ethernet, etc)
        - UDP/IP unicast heartbeats
        - "ping" heartbeats (for routers, switches, etc.)

%package libs
Summary:          Heartbeat libraries
Group:            System Environment/Daemons

%description libs
Heartbeat library package

%package devel 
Summary:        Heartbeat development package
Group:          System Environment/Daemons
Requires:       heartbeat-libs = %{version}-%{release}

%description devel
Headers and shared libraries for writing programs for Heartbeat

%prep
%setup -q -n %{upstreamprefix}%{?upstreamversion}

%build
./bootstrap
# disable-fatal-warnings flag used to disable gcc4.x warnings of 'difference in signedness'
%if 0%{?fedora} < 11 || 0%{?centos_version} <= 5 || 0%{?rhel} <= 5
export docdir=%{heartbeat_docdir}
%endif
CFLAGS=${RPM_OPT_FLAGS} %configure \
    --disable-fatal-warnings \
    --disable-static \
%if %{defined _initrddir}
    --with-initdir=%{_initrddir} \
%endif
%if %{defined _unitdir}
    --with-systemdunitdir=%{_unitdir} \
%endif
%if %{defined _tmpfilesdir}
    --with-tmpfilesdir=%{_tmpfilesdir} \
%endif
%if 0%{?fedora} >= 11 || 0%{?centos_version} > 5 || 0%{?rhel} > 5
    --docdir=%{heartbeat_docdir}
%endif

# get rid of rpath
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool

make %{?_smp_mflags} docdir=%{heartbeat_docdir}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT docdir=%{heartbeat_docdir} install

# cleanup
[ -d $RPM_BUILD_ROOT/usr/man ] && rm -rf $RPM_BUILD_ROOT/usr/man
[ -d $RPM_BUILD_ROOT/usr/share/libtool ] && rm -rf $RPM_BUILD_ROOT/usr/share/libtool
find $RPM_BUILD_ROOT -type f -name *.la -exec rm -f {} ';'
rm -rf $RPM_BUILD_ROOT/%{_datadir}/heartbeat/cts

# don't package sysv init files on systemd platforms
%if %{defined _unitdir}
rm -f %{buildroot}/%{_initrddir}/heartbeat
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%if %{defined _unitdir}

%post
%systemd_post heartbeat.service
systemd-tmpfiles --create %{_tmpfilesdir}/%{name}.conf

%preun
%systemd_preun heartbeat.service

%postun
%systemd_postun_with_restart heartbeat.service

%else

%post
/sbin/chkconfig --add heartbeat || :

%preun
/sbin/service heartbeat stop || :
if [ $1 = 0 ] ; then
    # package removal, not upgrade
    /sbin/chkconfig --del heartbeat || :
fi

%endif

%post -n %{name}-libs -p /sbin/ldconfig
%postun -n %{name}-libs -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%dir %{_sysconfdir}/ha.d
%{_sysconfdir}/ha.d/harc
%{_sysconfdir}/ha.d/rc.d
%config(noreplace) %{_sysconfdir}/ha.d/README.config
%dir %{_datadir}/heartbeat
%{_datadir}/heartbeat/ResourceManager
%{_datadir}/heartbeat/ha_config
%{_datadir}/heartbeat/ha_propagate
%{_datadir}/heartbeat/hb_addnode
%{_datadir}/heartbeat/hb_delnode
%{_datadir}/heartbeat/hb_setsite
%{_datadir}/heartbeat/hb_setweight
%{_datadir}/heartbeat/hb_standby
%{_datadir}/heartbeat/hb_takeover
%{_datadir}/heartbeat/mach_down
%{_datadir}/heartbeat/req_resource
%{_datadir}/heartbeat/hb_api.py*
%{_datadir}/heartbeat/ha_test.py*
%{_sysconfdir}/ha.d/resource.d/
%if %{defined _unitdir}
%{_unitdir}/heartbeat.service
%{_tmpfilesdir}/%{name}.conf
%else
%{_initrddir}/heartbeat
%endif
%config(noreplace) %{_sysconfdir}/logrotate.d/heartbeat
%dir %{_var}/lib/heartbeat
%dir %attr (0750, %{uname}, %{gname}) %{_var}/run/heartbeat
%dir %attr (0750, %{uname}, %{gname}) %{_var}/run/heartbeat/ccm
%dir %attr (0750, %{uname}, %{gname}) %{_var}/run/heartbeat/dopd
%attr (2555, root, %{gname}) %{_bindir}/cl_status
%{_bindir}/cl_respawn
%{_libexecdir}/heartbeat/apphbd
%{_libexecdir}/heartbeat/ccm
%{_libexecdir}/heartbeat/dopd
%{_libexecdir}/heartbeat/drbd-peer-outdater
%{_libexecdir}/heartbeat/heartbeat
%{_libexecdir}/heartbeat/ipfail

%doc %{_mandir}/man1/cl_status.1*
%doc %{_mandir}/man1/hb_addnode.1*
%doc %{_mandir}/man1/hb_delnode.1*
%doc %{_mandir}/man1/hb_standby.1*
%doc %{_mandir}/man1/hb_takeover.1*
%doc %{_mandir}/man5/ha.cf.5*
%doc %{_mandir}/man5/authkeys.5*
%doc %{_mandir}/man8/heartbeat.8*
%doc %{_mandir}/man8/apphbd.8*
%doc %{_datadir}/doc/%{name}-%{version}

%files libs
%defattr(-,root,root,-)
%{_libdir}/heartbeat
%{_libdir}/libapphb.so.*
%{_libdir}/libccmclient.so.*
%{_libdir}/libclm.so.*
%{_libdir}/libhbclient.so.*

%files devel
%defattr(-,root,root,-)
%doc %{_datadir}/doc/%{name}-%{version}
%{_libexecdir}/heartbeat/api_test
%{_libexecdir}/heartbeat/apphbtest
%{_libexecdir}/heartbeat/ccm_testclient
%{_libexecdir}/heartbeat/clmtest
%{_libexecdir}/heartbeat/mlock
%{_datadir}/heartbeat/BasicSanityCheck
%{_datadir}/heartbeat/TestHeartbeatComm
%{_includedir}/heartbeat/
%{_includedir}/saf/
%{_includedir}/ocf/
%{_libdir}/*.so

%changelog
* Wed Feb 04 2015 Lars Ellenberg <lars.ellenberg@linbit.com> - 3.0.6-1
- fix emergency shutdown due to broken update_ackseq
- fix node dead detection problems
- fix converging of membership (ccm)
- fix init script startup glitch (caused by changes in glue/resource-agents)
- heartbeat.service file for systemd platforms
- new ucast6 UDP IPv6 communication plugin
- package ha_api.py in standard package
- update some man pages, specifically the example ha.cf
- also report ccm membership status for cl_status hbstatus -v
- updated some log messages, or their log levels
- reduce max_delay in broadcast client_status query to one second
- apply various (mostly cosmetic) patches from Debian
- drop HBcompress compression plugins: they are part of cluster glue
- drop "openais" HBcomm plugin
- better support for current pacemaker versions
- try to not miss a SIGTERM (fix problem with very fast respawn/stop cycle)
- dopd: ignore dead ping nodes
- cl_status improvements
- api internals: reduce IPC round-trips to get at status information
- uid=root is sufficient to use heartbeat api (gid=haclient remains sufficient)
- fix /dev/null as log- or debugfile setting
- move daemon binaries into libexecdir
- document movement of compression plugins into cluster-glue
- fix usage of SO_REUSEPORT in ucast sockets
- fix compile issues with recent gcc and -Werror

* Thu Jun 16 2011 Lars Ellenberg <lars.ellenberg@linbit.com> - 3.0.5-1
- do not request retransmission of lost messages from dead members
- fix segfault due to recursion in api_remove_client_pid
- properly cleanup pending delayed rexmit requests before reset of seqtrack
- create HA_RSCTMP on start, if necessary
- improve detection of pacemaker clusters in init script

* Tue Nov 30 2010 Lars Ellenberg <lars.ellenberg@linbit.com> - 3.0.4-1
- better support for Pacemaker >= 1.1
- say Pacemaker support, not "v2", favor "pacemaker on" in ha.cf
- fix message rexmit request logic, it could cause rexmit packet storms
- increase ccm ipc message queue length
- new mcast6 UDP IPv6 communication plugin
- improve some log messages
- drop headers which are now in glue
- fixed/dropped some package dependencies
- fixed/dropped some build dependencies
- new proof-of-concept-only known-to-be-broken RDS communication plugin

* Wed Apr 14 2010 Lars Ellenberg <lars.ellenberg@linbit.com> - 3.0.3-1
- added /var/run/* directory permission paranoia to init script
- added SBD and lrmadmin configuration support to init script
- drop libnet dependency

* Thu Feb 04 2010 Lars Ellenberg <lars.ellenberg@linbit.com> - 3.0.2-2
- changed dopd socket location again to its own subdirectory,
  made sure the init script will create that directory
  with appropriate permissions

* Mon Feb 01 2010 Lars Ellenberg <lars.ellenberg@linbit.com> - 3.0.2-1
- New upstream release

* Sat Dec 19 2009 Florian Haas <florian.haas@linbit.com> - 3.0.2-0rc2
- New upstream RC

* Fri Dec 11 2009 Florian Haas <florian.haas@linbit.com> - 3.0.2-0rc1
- New upstream RC
- Fix docdir for legacy distributions

###########################################################
