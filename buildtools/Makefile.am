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

# In the main build, under "--enable-pretty", ccdv is used as a front end
# for the main C compiler.  Bootstrapping this needs the real C compiler.
CC = $(REAL_CC)

MAINTAINERCLEANFILES    = Makefile.in

noinst_PROGRAMS		= ccdv 

ccdv_SOURCES	= ccdv.c

# This seems to break compilation with -Wunused and recent sufficiently "smart"
# compilers, and I'm not going to fix this. It is not relevant for the
# heartbeat code base.
ccdv_CFLAGS = $(AM_CFLAGS) -Wno-unused
