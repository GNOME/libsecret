include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/library \
	-DSRCDIR="\"@abs_srcdir@\"" \
	-DSECRET_COMPILATION \
	$(NULL)

noinst_LTLIBRARIES = libmock_service.la

libmock_service_la_SOURCES = \
	mock-service.c mock-service.h \
	$(NULL)

libmock_service_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS)

libmock_service_la_LDFLAGS = \
	-rpath /force/shared

libmock_service_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libsecret-@SECRET_MAJOR@.la \
	$(LIBGCRYPT_LIBS)

LDADD =  \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libsecret-@SECRET_MAJOR@.la \
	libmock_service.la \
	$(NULL)

TEST_PROGS = \
	test-value \
	test-prompt \
	test-service \
	test-session \
	test-methods \
	test-password \
	test-item \
	test-collection \
	$(NULL)

check_PROGRAMS = \
	$(TEST_PROGS)

noinst_PROGRAMS =  \
	$(NULL)

JS_TESTS = \
	test-lookup-password.js \
	test-remove-password.js \
	test-store-password.js

JS_ENV = \
	LD_LIBRARY_PATH=$(builddir)/.libs \
	GI_TYPELIB_PATH=$(builddir)/..:$(builddir)

PY_TESTS = \
	test-lookup-password.py \
	test-remove-password.py \
	test-store-password.py

PY_ENV = $(JS_ENV)

test-c: $(TEST_PROGS)
	@gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

test-js:
	@for js in $(JS_TESTS); do echo "TEST: $$js"; $(JS_ENV) gjs $(srcdir)/$$js; done

test-py:
	@for py in $(PY_TESTS); do echo "TEST: $$py"; $(PY_ENV) python $(srcdir)/$$py; done

test: test-c test-py test-js

# ------------------------------------------------------------------
# INTROSPECTION

if HAVE_INTROSPECTION

include $(INTROSPECTION_MAKEFILE)

INTROSPECTION_GIRS = MockService-0.gir
INTROSPECTION_SCANNER_ARGS = $(INTROSPECTION_FLAGS) --warn-all --add-include-path=$(srcdir) --add-include-path=.
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir) --includedir=.

MockService-0.gir: libmock_service.la

MockService_0_gir_PACKAGES = gobject-2.0 gio-2.0
MockService_0_gir_EXPORT_PACKAGES = mock-service-0
MockService_0_gir_INCLUDES = GObject-2.0 Gio-2.0
MockService_0_gir_LIBS = libmock_service.la
MockService_0_gir_CFLAGS = -I$(top_srcdir) -I$(top_builddir)
MockService_0_gir_FILES = $(libmock_service_la_SOURCES)
MockService_0_gir_SCANNERFLAGS = --c-include "mock-service.h"

noinst_DATA = \
	$(INTROSPECTION_GIRS) \
	$(INTROSPECTION_GIRS:.gir=.typelib)

endif

#--------------------------------------------------------------------

EXTRA_DIST = \
	mock \
	mock-service-delete.py \
	mock-service-lock.py \
	mock-service-normal.py \
	mock-service-only-plain.py \
	mock-service-prompt.py \
	$(JS_TESTS) \
	$(PY_TESTS) \
	$(NULL)

CLEANFILES = \
	$(noinst_DATA) \
	$(NULL)

all-local: $(check_PROGRAMS)

check-local: test

check-memory: perform-memcheck

.PHONY: check-memory
