#
# doc: Linux-HA heartbeat code
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

htmlfiles		= heartbeat_api.html

txtfiles                = $(htmlfiles:.html=.txt)

CLEANFILES              = ChangeLog $(txtfiles) $(man_MANS)

SPECSRC 		= $(top_builddir)/heartbeat-fedora.spec

OTHER_DOCS              = AUTHORS COPYING COPYING.LGPL ChangeLog README \
                                authkeys ha.cf haresources \
                                apphbd.cf

doc_DATA		= $(OTHER_DOCS)

man_MANS		= heartbeat.8 apphbd.8 cl_status.1  \
			 hb_standby.1 hb_takeover.1 hb_addnode.1 hb_delnode.1 \
			 ha.cf.5 authkeys.5

STYLESHEET_PREFIX 	?= http://docbook.sourceforge.net/release/xsl/current
MANPAGES_STYLESHEET 	?= $(STYLESHEET_PREFIX)/manpages/docbook.xsl
HTML_STYLESHEET 	?= $(STYLESHEET_PREFIX)/xhtml/docbook.xsl
FO_STYLESHEET 		?= $(STYLESHEET_PREFIX)/fo/docbook.xsl

XSLTPROC_OPTIONS 	?= --xinclude
XSLTPROC_MANPAGES_OPTIONS ?= $(XSLTPROC_OPTIONS)
XSLTPROC_HTML_OPTIONS 	?= $(XSLTPROC_OPTIONS)
XSLTPROC_FO_OPTIONS 	?= $(XSLTPROC_OPTIONS)

EXTRA_DIST = $(txtfiles) $(htmlfiles) $(man_MANS) $(OTHER_DOCS)

ChangeLog: $(SPECSRC)
	rm -fr ChangeLog
	sed -e '1,/^%changelog/d' -e '/^%/,$$d' < $(SPECSRC) > $@

.html.txt:
	if [ "X$(HTML2TXT)" = "X" ]; then echo "Lynx or w3m or user-defined HTML2TXT required to convert $< to $@" >$@ ; else $(HTML2TXT) -dump $< >$@ ; fi

%.5 %.8 %.1: %.xml
	$(XSLTPROC) \
	$(XSLTPROC_MANPAGES_OPTIONS) \
	$(MANPAGES_STYLESHEET) $<
