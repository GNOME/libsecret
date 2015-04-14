AC_PREREQ(2.63)

AC_INIT([libsecret],[0.18.2],
        [http://bugzilla.gnome.org/enter_bug.cgi?product=libsecret],
        [libsecret])

dnl ****************************************************************************
dnl Dependency versions

# Required

GLIB_REQ=2.38.0
GLIB_MIN=GLIB_VERSION_2_38
GLIB_MAX=GLIB_VERSION_2_38

INTLTOOL_REQ=0.35.0

# Optional

VALA_WANT=0.17.2.12

GCRYPT_WANT=1.2.2

GTKDOC_WANT=1.9

GIR_WANT=1.29

dnl ****************************************************************************
dnl Library package and libtool versioning
dnl
dnl Updating the libtool versions, follow these instructions sequentially:
dnl  1. If the library source code has changed at all since the last update, then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
dnl  2. If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
dnl  3. If any interfaces have been added since the last public release, then increment age.
dnl  4. If any interfaces have been removed or changed since the last public release, then set age to 0.

SECRET_MAJOR=1
SECRET_MINOR=0
SECRET_MICRO=0

SECRET_CURRENT=0
SECRET_REVISION=0
SECRET_AGE=0

# -----------------------------------------------------------------------------

AC_CONFIG_MACRO_DIR([build/m4])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([1.11 tar-ustar foreign -Wno-portability subdir-objects])
AM_SANITY_CHECK
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_SRCDIR([libsecret/secret-value.c])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_MAINTAINER_MODE([enable])

# -----------------------------------------------------------------------------
# Basic tools

AC_GNU_SOURCE
AC_ISC_POSIX
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL
IT_PROG_INTLTOOL($INTLTOOL_REQ)
AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

GETTEXT_PACKAGE=libsecret
AC_SUBST([GETTEXT_PACKAGE])
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[The gettext domain name])
AM_GLIB_GNU_GETTEXT

# --------------------------------------------------------------------
# Checks for functions

AC_CHECK_FUNCS(mlock)

# --------------------------------------------------------------------
# GLib

PKG_CHECK_MODULES(GLIB,
	glib-2.0 >= $GLIB_REQ
	gio-2.0
	gio-unix-2.0)
LIBS="$LIBS $GLIB_LIBS"
CFLAGS="$CFLAGS $GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=$GLIB_MIN -DGLIB_VERSION_MAX_ALLOWED=$GLIB_MAX"

GTK_DOC_CHECK($GTKDOC_WANT)

GOBJECT_INTROSPECTION_CHECK($GIR_WANT)
AC_PATH_PROG(GLIB_MKENUMS, glib-mkenums)

# --------------------------------------------------------------------
# Manual pages

AC_ARG_ENABLE(manpages,
              AC_HELP_STRING([--disable-manpages], [Build manual pages]))
if test "$enable_manpages" != "no"; then
	enable_manpages="yes"
	AC_PATH_PROG([XSLTPROC], [xsltproc])
	if test x$XSLTPROC = x; then
		AC_MSG_ERROR([xsltproc is required to build manual pages])
	fi
fi
AM_CONDITIONAL(WITH_MANPAGES, test x$enable_manpages = xyes)

# --------------------------------------------------------------------
# Vala

VAPIGEN_CHECK($VALA_WANT)

if test "$enable_vala" != "no"; then
	AC_PATH_PROG([VALAC], [valac], [])
fi
AM_CONDITIONAL(HAVE_VALAC, test "x$VALAC" != "x")

# --------------------------------------------------------------------
# libgcrypt

GCRYPT_LIBVER=1

AC_ARG_ENABLE(gcrypt,
              [AC_HELP_STRING([--disable-gcrypt],
                              [without gcrypt and transport encryption])
              ])

if test "$enable_gcrypt" != "no"; then

	have_gcrypt="no"
	m4_ifdef([AM_PATH_LIBGCRYPT],
	         [AM_PATH_LIBGCRYPT($GCRYPT_LIBVER:$GCRYPT_WANT, have_gcrypt=yes)])

	if test $have_gcrypt != "yes"; then
		AC_MSG_ERROR([[
***
*** libgcrypt was not found. You may want to get it from
*** ftp://ftp.gnupg.org/gcrypt/libgcrypt/
***
		]])
	fi

	AC_DEFINE(WITH_GCRYPT, 1, [Build with libgcypt and transport encryption])
	AC_DEFINE_UNQUOTED(LIBGCRYPT_VERSION, "$GCRYPT_WANT",
	                   [Version of GCRYPT we expect])

	AC_SUBST([LIBGCRYPT_CFLAGS])
	AC_SUBST([LIBGCRYPT_LIBS])

	gcrypt_status="yes"
	enable_gcrypt="yes"
else
	gcrypt_status="no"
fi

AM_CONDITIONAL(WITH_GCRYPT, test "$enable_gcrypt" = "yes")

# --------------------------------------------------------------------
# Compilation options

if test "$GCC" = "yes"; then
	CFLAGS="$CFLAGS \
		-Wall -Wmissing-declarations \
		-Wmissing-prototypes -Wnested-externs -Wpointer-arith \
		-Wdeclaration-after-statement -Wformat=2 -Winit-self \
		-Waggregate-return"

	for option in -Wmissing-include-dirs -Wundef; do
		SAVE_CFLAGS="$CFLAGS"
		CFLAGS="$CFLAGS $option"
		AC_MSG_CHECKING([whether gcc understands $option])
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
				  [has_option=yes],
				  [has_option=no])
		AC_MSG_RESULT($has_option)
		if test $has_option = no; then
			CFLAGS="$SAVE_CFLAGS"
		fi
	done
fi

AC_ARG_ENABLE(strict, [
               AS_HELP_STRING([--enable-strict], [Strict code compilation])
             ])

AC_MSG_CHECKING([build strict])

if test "$enable_strict" = "yes"; then
	CFLAGS="$CFLAGS -Werror -DG_DISABLE_DEPRECATED"
	INTROSPECTION_FLAGS="--warn-error"
	TEST_MODE="thorough"
else
	CFLAGS="$CFLAGS -Wno-error"
	TEST_MODE="quick"
	INTROSPECTION_FLAGS=""
	enable_strict="no"
fi

AC_MSG_RESULT($enable_strict)
AC_SUBST(INTROSPECTION_FLAGS)
AC_SUBST(TEST_MODE)

AC_MSG_CHECKING([for debug mode])
AC_ARG_ENABLE(debug,
              AC_HELP_STRING([--enable-debug=no/default/yes],
                             [Turn on or off debugging])
             )

if test "$enable_debug" != "no"; then
	AC_DEFINE_UNQUOTED(WITH_DEBUG, 1, [Print debug output])
	AC_DEFINE_UNQUOTED(_DEBUG, 1, [In debug mode])
	CFLAGS="$CFLAGS -g"
fi
if test "$enable_debug" = "yes"; then
	debug_status="yes"
	CFLAGS="$CFLAGS -O0"
elif test "$enable_debug" = "no"; then
	debug_status="no"
	CFLAGS="$CFLAGS -O2"
	AC_DEFINE_UNQUOTED(G_DISABLE_ASSERT, 1, [Disable glib assertions])
else
	debug_status="default"
fi

AC_MSG_RESULT($debug_status)

AC_MSG_CHECKING([whether to build with gcov testing])
AC_ARG_ENABLE([coverage],
              AS_HELP_STRING([--enable-coverage],
                             [Whether to enable coverage testing ]),
              [], [enable_coverage=no])
AC_MSG_RESULT([$enable_coverage])

if test "$enable_coverage" = "yes"; then
	if test "$GCC" != "yes"; then
		AC_MSG_ERROR(Coverage testing requires GCC)
	fi

	AC_PATH_PROG(GCOV, gcov, no)
	if test "$GCOV" = "no" ; then
		AC_MSG_ERROR(gcov tool is not available)
	fi

	AC_PATH_PROG(LCOV, lcov, no)
	if test "$LCOV" = "no" ; then
		AC_MSG_ERROR(lcov tool is not installed)
	fi

	AC_PATH_PROG(GENHTML, genhtml, no)
	if test "$GENHTML" = "no" ; then
		AC_MSG_ERROR(lcov's genhtml tool is not installed)
	fi

	CFLAGS="$CFLAGS -O0 -g -fprofile-arcs -ftest-coverage"
	LDFLAGS="$LDFLAGS -lgcov"
fi

AM_CONDITIONAL([WITH_COVERAGE], [test "$enable_coverage" = "yes"])
AC_SUBST(LCOV)
AC_SUBST(GCOV)
AC_SUBST(GENHTML)

# ------------------------------------------------------------------------------
# Results
#

SECRET_LT_RELEASE=$SECRET_CURRENT:$SECRET_REVISION:$SECRET_AGE
AC_SUBST(SECRET_LT_RELEASE)
AC_SUBST(SECRET_MAJOR)
AC_SUBST(SECRET_MINOR)

AC_CONFIG_FILES([
	Makefile
	docs/reference/libsecret/Makefile
	docs/reference/libsecret/version.xml
	docs/reference/libsecret/version-major.xml
	po/Makefile.in
	po/Makefile
	libsecret/libsecret.pc
	libsecret/libsecret-unstable.pc
])
AC_OUTPUT

echo
echo "CFLAGS: $CFLAGS"
echo
echo "OPTIONS:"
echo "  libgcrypt:     $gcrypt_status"
echo "  vala:          $enable_vala"
echo "  Debug:         $debug_status"
echo "  Coverage:      $enable_coverage"
echo "  Manual Page:   $enable_manpages"
echo
