INCLUDES		= $(GNET_CFLAGS) -I$(top_srcdir)/src

EXTRA_DIST		= $(man_MANS)

bin_PROGRAMS		= gsnmp-get

noinst_PROGRAMS		= gsnmp-ping gsnmp-stub-ping \
			  gsnmp-iftable gsnmp-walk atm

man_MANS                = gsnmp-get.1

gsnmp_ping_SOURCES	= gsnmp-ping.c
gsnmp_ping_LDADD	= $(top_builddir)/src/libgsnmp.la \
			  $(GNET_LIBS)

gsnmp_stub_ping_SOURCES	= gsnmp-stub-ping.c snmpv2-mib.c snmpv2-mib.h
gsnmp_stub_ping_LDADD	= $(top_builddir)/src/libgsnmp.la \
			  $(GNET_LIBS)

gsnmp_iftable_SOURCES	= gsnmp-iftable.c if-mib.c if-mib.h ianaiftype-mib.c ianaiftype-mib.h
gsnmp_iftable_LDADD	= $(top_builddir)/src/libgsnmp.la \
			  $(GNET_LIBS)

gsnmp_walk_SOURCES	= gsnmp-walk.c
gsnmp_walk_LDADD	= $(top_builddir)/src/libgsnmp.la \
			  $(GNET_LIBS)

gsnmp_get_SOURCES	= gsnmp-get.c
gsnmp_get_LDADD		= $(top_builddir)/src/libgsnmp.la \
			  $(GNET_LIBS)

atm_SOURCES		= atm.c atm-mib.c atm-mib.h atm-tc-mib.c atm-tc-mib.h snmpv2-tc.c snmpv2-tc.h
atm_LDADD		= $(top_builddir)/src/libgsnmp.la \
			  $(GNET_LIBS)

