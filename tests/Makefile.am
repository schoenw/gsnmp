AM_CPPFLAGS		= $(GNET_CFLAGS) -I$(top_srcdir)/src

noinst_PROGRAMS		= gsnmp-test

gsnmp_test_SOURCES	= gsnmp-test.c
gsnmp_test_LDADD	= $(top_builddir)/src/libgsnmp.la \
			 $(GNET_LIBS)
