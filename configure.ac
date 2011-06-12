AC_PREREQ(2.65)
AC_CONFIG_MACRO_DIR([m4])

AC_INIT([gsecret],[0.1],[http://bugzilla.gnome.org/enter_bug.cgi?product=gsecret])

AC_CONFIG_SRCDIR([library/gsecret-data.c])
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

dnl Checks for libraries.

dnl ****************************
dnl *** Checks for intltool

IT_PROG_INTLTOOL([0.35.0])
GETTEXT_PACKAGE=gsecret

AC_SUBST([GETTEXT_PACKAGE])
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[The gettext domain name])
AM_GLIB_GNU_GETTEXT

dnl *****************************
dnl *** Check GLib

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.16.0 gio-2.0 >= 2.16.0 gthread-2.0 >= 2.16.0)
LIBS="$LIBS $GLIB_LIBS"
CFLAGS="$CFLAGS $GLIB_CFLAGS"

AC_CHECK_FUNCS(mlock)

dnl *************************************
dnl *** Warnings to show if using GCC ***
dnl *************************************

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

dnl *****************************
dnl *** done                  ***
dnl *****************************
AC_CONFIG_FILES([Makefile
                 egg/Makefile
                 po/Makefile.in
                 po/Makefile
                 library/Makefile
                ])
AC_OUTPUT
