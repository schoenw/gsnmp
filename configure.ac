dnl Process this file with autoconf to produce a configure script.

AC_INIT(src/gsnmp.h)
dnl Every other copy of the package version number gets its value from here
AM_INIT_AUTOMAKE(gsnmp, 0.2.0)

dnl create a config.h file (Automake will add -DHAVE_CONFIG_H)
AM_CONFIG_HEADER(config.h)

AC_SUBST(VERSION)

ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_CC

AC_PROG_LIBTOOL

dnl Checks for libraries.

AM_PATH_GLIB_2_0(2.0.0)
AM_PATH_GNET_2_0(2.0.4)

dnl Checks for header files.
dnl AC_HEADER_STDC
dnl AC_CHECK_HEADERS(unistd.h sys/param.h sys/time.h time.h sys/mkdev.h sys/sysmacros.h string.h memory.h fcntl.h dirent.h sys/ndir.h ndir.h alloca.h locale.h )

dnl jm_CHECK_TYPE_STRUCT_UTIMBUF
dnl AC_HEADER_MAJOR
dnl AC_FUNC_ALLOCA
dnl AC_STRUCT_TM
dnl AC_STRUCT_ST_BLOCKS
dnl AC_FUNC_CLOSEDIR_VOID
dnl AC_CHECK_FUNCS(mkfifo)
dnl AC_CHECK_FUNC(mknod)

dnl Checks for typedefs, structures, and compiler characteristics.

dnl Checks for library functions.

AC_OUTPUT(Makefile src/Makefile tests/Makefile examples/Makefile gsnmp.lsm gsnmp.spec gsnmp.pc)
