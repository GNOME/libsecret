## Process this file with automake to produce Makefile.in
NULL =

ACLOCAL_AMFLAGS = -I build/m4 ${ACLOCAL_FLAGS}

SUBDIRS = \
	. \
	po \
	docs/reference/libsecret

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-debug=yes \
	--disable-coverage \
	--disable-strict \
	--disable-silent-rules \
	--enable-gtk-doc \
	--enable-vala

dist-hook:
	@if test -d "$(srcdir)/.git"; \
	then \
		echo Creating ChangeLog && \
		( cd "$(top_srcdir)" && \
		  echo '# Generate automatically. Do not edit.'; echo; \
		  $(top_srcdir)/missing --run git log --stat --date=short ) > ChangeLog.tmp \
		&& mv -f ChangeLog.tmp $(top_distdir)/ChangeLog \
		|| ( rm -f ChangeLog.tmp ; \
		     echo Failed to generate ChangeLog >&2 ); \
	else \
		echo A git clone is required to generate a ChangeLog >&2; \
	fi

upload-release: $(DIST_ARCHIVES)
	scp $(DIST_ARCHIVES) master.gnome.org:
	ssh master.gnome.org ftpadmin install $(DIST_ARCHIVES)

upload-docs:
	rsync -Hvax docs/reference/libsecret/html/./ master.gnome.org:public_html/libsecret-docs/

if HAVE_VALAC
dist-check-valac:

else
dist-check-valac:
	@echo "*** valac must be installed and enabled in order to make dist"
	@false
endif

dist-hook: dist-check-valac

distcleancheck_listfiles =  \
       find . -name '*.gc[dn][oa]' -prune -o -type f -print

TESTS_ENVIRONMENT = LD_LIBRARY_PATH=$(builddir)/.libs GI_TYPELIB_PATH=$(builddir)
TEST_EXTENSIONS = .py .js

# Default executable tests
LOG_DRIVER = $(srcdir)/build/tap-driver
LOG_DRIVER_FLAGS = --format=tap
LOG_COMPILER = $(srcdir)/build/tap-gtester

# Python tests
PY_LOG_DRIVER = $(srcdir)/build/tap-driver
PY_LOG_DRIVER_FLAGS = --format=tap
PY_LOG_COMPILER = $(srcdir)/build/tap-unittest

# Javascript tests
JS_LOG_DRIVER = $(srcdir)/build/tap-driver
JS_LOG_DRIVER_FLAGS = --format=simple
JS_LOG_COMPILER = gjs

VALGRIND_ARGS = --trace-children=no --quiet --error-exitcode=33 \
	--suppressions=valgrind-suppressions --gen-suppressions=all \
	--num-callers=16
VALGRIND_SUPPRESSIONS = \
	build/gcrypt.supp \
	build/glib.supp \
	build/pthread.supp \
	build/unknown.supp \
	$(NULL)

valgrind-suppressions: $(VALGRIND_SUPPRESSIONS)
	$(AM_V_GEN) cat $^ > $@

check-memory: valgrind-suppressions
	$(MAKE) LOG_FLAGS="-- libtool --mode=execute valgrind $(VALGRIND_ARGS)" \
		PY_LOG_DRIVER_FLAGS="--missing=no-python-valgrind" \
		JS_LOG_DRIVER_FLAGS="--missing=no-gjs-valgrind" \
		$(AM_MAKEFLAGS) check
recheck-memory: valgrind-suppressions
	$(MAKE) LOG_FLAGS="-- libtool --mode=execute valgrind $(VALGRIND_ARGS)" \
		PY_LOG_DRIVER_FLAGS="--missing=no-python-valgrind" \
		JS_LOG_DRIVER_FLAGS="--missing=no-gjs-valgrind" \
		$(AM_MAKEFLAGS) recheck

if WITH_COVERAGE
coverage:
	mkdir -p $(top_builddir)/build/coverage
	$(LCOV) --directory . --capture --output-file $(top_builddir)/build/coverage.info
	$(GENHTML) --output-directory $(top_builddir)/build/coverage $(top_builddir)/build/coverage.info
	$(LCOV) --directory . --zerocounters
	@echo "file://$(abs_top_builddir)/build/coverage/index.html"

clear-coverage:
	$(LCOV) --directory . --zerocounters

endif

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/build \
	-DSRCDIR="\"@abs_srcdir@\"" \
	-DLOCALEDIR=\""$(datadir)/locale"\" \
	-DWITH_VALGRIND \
	-DSECRET_COMPILATION \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)

bin_PROGRAMS =
BUILT_SOURCES =
check_PROGRAMS =
DISTCLEANFILES =
lib_LTLIBRARIES =
man_MANS =
nodist_noinst_DATA =
noinst_DATA =
noinst_LTLIBRARIES =
TESTS =

noinst_PROGRAMS =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA =

if HAVE_INTROSPECTION

include $(INTROSPECTION_MAKEFILE)

INTROSPECTION_GIRS = 
INTROSPECTION_SCANNER_ARGS = $(INTROSPECTION_FLAGS) --warn-all \
	--add-include-path=$(srcdir) --add-include-path=$(builddir)
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir) --includedir=$(builddir)

girdir = $(datadir)/gir-1.0
gir_DATA =

typelibsdir = $(libdir)/girepository-1.0
typelibs_DATA = $(gir_DATA:.gir=.typelib)

if ENABLE_VAPIGEN

include $(VAPIGEN_MAKEFILE)

VAPIGEN_VAPIS =

vapidir = $(datadir)/vala/vapi
vapi_DATA =

endif

endif

CLEANFILES = \
	$(pkgconfig_DATA) \
	$(gir_DATA) \
	$(typelibs_DATA) \
	$(BUILT_SOURCES) \
	$(vapi_DATA) \
	$(man_MANS) \
	valgrind-suppressions

EXTRA_DIST = \
	COPYING.TESTS \
	build/valgrind \
	build/tap-gtester \
	build/tap-driver \
	build/tap-unittest \
	$(VALGRIND_SUPPRESSIONS)

include egg/Makefile.am
include libsecret/Makefile.am
include tool/Makefile.am

if WITH_MANPAGES
include docs/man/Makefile.am
endif
