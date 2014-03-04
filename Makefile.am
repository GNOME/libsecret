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
	--enable-strict \
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

check-memory:
	@for subdir in $(SUBDIRS); do \
		test -d $(builddir)/$$subdir/tests && \
			make -C $(builddir)/$$subdir/tests check-memory; \
	done

upload-release: $(DIST_ARCHIVES)
		scp $(DIST_ARCHIVES) master.gnome.org:

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

TEST_SUPPRESSIONS = $(top_builddir)/build/valgrind-suppressions

perform-memcheck: $(TEST_PROGS) $(TEST_SUPPRESSIONS)
	@make -C $(top_builddir)/build all
	@for test in $(TEST_PROGS); do \
		G_SLICE=always-malloc libtool --mode=execute \
			valgrind --trace-children=no --gen-suppressions=all \
			--suppressions=$(TEST_SUPPRESSIONS) \
			--leak-check=full --show-reachable=yes --num-callers=16 \
			--quiet --error-exitcode=33 \
			$(builddir)/$$test; \
	done

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

noinst_PROGRAMS = $(check_PROGRAMS)

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
	$(man_MANS)

EXTRA_DIST = \
	COPYING.TESTS

LOG_DRIVER = $(srcdir)/build/tap-driver
LOG_COMPILER = $(srcdir)/build/tap-compiler

TESTS_ENVIRONMENT = LD_LIBRARY_PATH=$(builddir)/.libs GI_TYPELIB_PATH=$(builddir)
TEST_EXTENSIONS = .py .js
PY_LOG_DRIVER = $(srcdir)/build/tap-driver
PY_LOG_COMPILER = $(srcdir)/build/tap-unittest
JS_LOG_DRIVER = $(srcdir)/build/test-driver
JS_LOG_COMPILER = gjs

include build/Makefile.am
include egg/Makefile.am
include libsecret/Makefile.am
include tool/Makefile.am

if WITH_MANPAGES
include docs/man/Makefile.am
endif
