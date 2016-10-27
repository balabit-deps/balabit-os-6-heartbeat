#
# heartbeat: Linux-HA heartbeat code
#
# Copyright (C) 2001 Michael Moerz
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
MAINTAINERCLEANFILES    = Makefile.in

AM_CPPFLAGS		= -I$(top_builddir)/include -I$(top_srcdir)/include \
			-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

halibexecdir		= $(libexecdir)/@HB_PKG@

havarlibdir		= $(localstatedir)/lib/@HB_PKG@

dopddir			= $(HA_VARRUNDIR)/$(HB_PKG)/dopd

halibexec_PROGRAMS	= dopd drbd-peer-outdater

## SOURCES
dopd_SOURCES		= dopd.c dopd.h
dopd_LDADD		= \
			-lplumb		\
			$(top_builddir)/lib/hbclient/libhbclient.la $(GLIBLIB)

drbd_peer_outdater_SOURCES	= drbd-peer-outdater.c
drbd_peer_outdater_LDADD	= -lplumb $(GLIBLIB)

## additional Makefile targets
# additional installations not covered normally
install-exec-local:
	$(mkinstalldirs) $(DESTDIR)$(dopddir)
	-chgrp $(HA_APIGROUP) $(DESTDIR)/$(dopddir)
	-chown $(HA_CCMUSER) $(DESTDIR)/$(dopddir)
	chmod 750 $(DESTDIR)/$(dopddir)


uninstall-local:
	rm -fr $(DESTDIR)$(dopddir)
