SUBDIRS = src tests examples

EXTRA_DIST		= gsnmp.m4 gsnmp.pc

m4datadir		= $(datadir)/aclocal
m4data_DATA		= gsnmp.m4

pkgconfigdir		= $(libdir)/pkgconfig
pkgconfig_DATA		= gsnmp.pc
$(pkgconfig_DATA):	config.status
