INCLUDES = $(GNET_CFLAGS)

lib_LTLIBRARIES		= libgsnmp.la
libgsnmp_la_SOURCES	= ber.c ber.h			\
			  pdu.c pdu.h			\
			  dispatch.c dispatch.h		\
			  message.c message.h		\
			  security.c security.h		\
			  session.c session.h		\
			  walk.c table.c 		\
			  transport.c transport.h	\
			  utils.c utils.h		\
			  gsnmp.h

gsnmpincludedir=$(includedir)/gsnmp
gsnmpinclude_HEADERS	= ber.h		\
			  pdu.h		\
			  dispatch.h	\
			  message.h	\
			  security.h	\
			  session.h	\
			  transport.h	\
			  utils.h	\
			  gsnmp.h

# libgsnmp_la_LDFLAGS	= -version-info @VERSION_LIBTOOL@
