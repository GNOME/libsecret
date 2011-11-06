AC_PREREQ(2.65)
AC_CONFIG_MACRO_DIR([build/m4])

AC_INIT([gsecret],[0.1],[http://bugzilla.gnome.org/enter_bug.cgi?product=gsecret])

AC_CONFIG_SRCDIR([library/gsecret-value.c])
AC_CONFIG_HEADERS([config.h])

dnl Other initialization
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE([enable])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)
LT_INIT

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O

AC_CHECK_FUNCS(mlock)

# --------------------------------------------------------------------
# intltool
#

IT_PROG_INTLTOOL([0.35.0])
GETTEXT_PACKAGE=gsecret

AC_SUBST([GETTEXT_PACKAGE])
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[The gettext domain name])
AM_GLIB_GNU_GETTEXT

# --------------------------------------------------------------------
# GLib
#

PKG_CHECK_MODULES(GLIB,
	glib-2.0 >= 2.31.0
	gio-2.0 >= 2.31.0
	gio-unix-2.0)
LIBS="$LIBS $GLIB_LIBS"
CFLAGS="$CFLAGS $GLIB_CFLAGS"

# --------------------------------------------------------------------
# libgcrypt
#

GCRYPT_VERSION=1.2.2
GCRYPT_LIBVER=1

AC_ARG_ENABLE(gcrypt,
              [AC_HELP_STRING([--disable-gcrypt],
                              [without gcrypt and transport encryption])
              ])

if test "$enable_gcrypt" != "no"; then
	AM_PATH_LIBGCRYPT($GCRYPT_LIBVER:$GCRYPT_VERSION,,
	                  AC_MSG_ERROR([[
***
*** libgcrypt was not found. You may want to get it from
*** ftp://ftp.gnupg.org/gcrypt/libgcrypt/
***
	                  ]]))

	AC_DEFINE(WITH_GCRYPT, 1, [Build with libgcypt and transport encryption])
	AC_DEFINE_UNQUOTED(LIBGCRYPT_VERSION, "$GCRYPT_VERSION",
	                   [Version of GCRYPT we expect])

	AC_SUBST([LIBGCRYPT_CFLAGS])
	AC_SUBST([LIBGCRYPT_LIBS])

	gcrypt_status=$GCRYPT_VERSION
	enable_gcrypt="yes"
else
	gcrypt_status="no"
fi

AM_CONDITIONAL(WITH_GCRYPT, test "$enable_gcrypt" = "yes")

# --------------------------------------------------------------------
# Compilation options
#

AC_ARG_ENABLE(more-warnings,
              AS_HELP_STRING([--disable-more-warnings], [Inhibit compiler warnings]),
              set_more_warnings=no)

if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
	CFLAGS="$CFLAGS \
		-Wall -Wstrict-prototypes -Wmissing-declarations \
		-Wmissing-prototypes -Wnested-externs -Wpointer-arith \
		-Wdeclaration-after-statement -Wformat=2 -Winit-self \
		-Waggregate-return -Wmissing-format-attribute"

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
	CFLAGS="$CFLAGS -Werror \
		-DGTK_DISABLE_DEPRECATED \
		-DGDK_DISABLE_DEPRECATED \
		-DG_DISABLE_DEPRECATED \
		-DGDK_PIXBUF_DISABLE_DEPRECATED"
	TEST_MODE="thorough"
else 
	TEST_MODE="quick"
	$enable_strict="no"
fi

AC_MSG_RESULT($enable_strict)
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

AC_CONFIG_FILES([
	Makefile
	build/Makefile
	egg/Makefile
	egg/tests/Makefile
	po/Makefile.in
	po/Makefile
	library/Makefile
	library/tests/Makefile
])
AC_OUTPUT

echo
echo "CFLAGS: $CFLAGS"
echo
echo "OPTIONS:"
echo "  libgcrypt:            $gcrypt_status"
echo "  Debug:                $debug_status"
echo "  Coverage:             $enable_coverage"
echo
