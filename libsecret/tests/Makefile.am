include $(top_srcdir)/Makefile.decl

# test-vala-unstable depends on the mock vapi,
# and I'm not sure how we can add that dependency.
.NOTPARALLEL:

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/libsecret \
	-DSRCDIR="\"@abs_srcdir@\"" \
	-DSECRET_COMPILATION \
	$(NULL)

noinst_LTLIBRARIES = libmock_service.la

libmock_service_la_SOURCES = \
	mock-service.c \
	mock-service.h \
	$(NULL)

libmock_service_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS)

libmock_service_la_LDFLAGS = \
	-rpath /force/shared

libmock_service_la_LIBADD = \
	$(LIBGCRYPT_LIBS)

LDADD =  \
	$(top_builddir)/libsecret/libsecret-testable.la \
	libmock_service.la \
	$(NULL)

C_TESTS = \
	test-attributes \
	test-value \
	test-prompt \
	test-service \
	test-session \
	test-paths \
	test-methods \
	test-password \
	test-item \
	test-collection \
	$(NULL)

TEST_PROGS = \
	$(C_TESTS) \
	$(NULL)

check_PROGRAMS = \
	$(TEST_PROGS)

noinst_PROGRAMS =  \
	$(NULL)

JS_TESTS = \
	test-lookup-password.js \
	test-clear-password.js \
	test-store-password.js \
	test-unstable.js

JS_ENV = \
	LD_LIBRARY_PATH=$(builddir)/../.libs:$(builddir)/.libs \
	GI_TYPELIB_PATH=$(builddir)/..:$(builddir)

PY_TESTS = \
	test-lookup-password.py \
	test-clear-password.py \
	test-store-password.py \
	test-unstable.py

PY_ENV = $(JS_ENV)

# ------------------------------------------------------------------
# VALA

VALA_V = $(VALA_V_$(V))
VALA_V_ = $(VALA_V_$(AM_DEFAULT_VERBOSITY))
VALA_V_0 = @echo "  VALAC " $^;

VALA_TESTS = \
	test-vala-lang \
	test-vala-unstable \
	$(NULL)

VALA_FLAGS = \
	--vapidir=$(builddir)/.. \
	--pkg gio-2.0

VALA_TESTS_VAPIS = \
	$(builddir)/../libsecret-unstable.vapi \
	$(builddir)/../libsecret-@SECRET_MAJOR@.vapi \
	$(builddir)/mock-service-0.vapi

VALA_SRCS = $(VALA_TESTS:=.vala)
VALA_C_SRCS = $(VALA_SRCS:.vala=.c)

if HAVE_VALAC
$(VALA_C_SRCS): %.c: %.vala $(VALA_TESTS_VAPIS)
	$(VALA_V)$(VALAC) $(VALA_FLAGS) $(VALA_TESTS_VAPIS) -C $<
endif

test_vala_lang_CFLAGS = -w
test_vala_unstable_CFLAGS = -DSECRET_WITH_UNSTABLE -w

nodist_test_vala_lang_SOURCES = test-vala-lang.c
nodist_test_vala_unstable_SOURCES = test-vala-unstable.c

DISTCLEANFILES = $(VALA_C_SRCS)

test-vala: $(VALA_TESTS)
	@gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(VALA_TESTS)

VALA_TEST_TARGET =

if HAVE_INTROSPECTION
if ENABLE_VAPIGEN
if HAVE_VALAC

VALA_TEST_TARGET += test-vala

TEST_PROGS += $(VALA_TESTS)

endif # HAVE_VALAC
endif # ENABLE_VAPIGEN
endif # HAVE_INTROSPECTION

test-c: $(C_TESTS)
	@gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(C_TESTS)

test-js:
	@for js in $(JS_TESTS); do echo "TEST: $$js"; $(JS_ENV) gjs $(srcdir)/$$js; done

test-py:
	@for py in $(PY_TESTS); do echo "TEST: $$py"; $(PY_ENV) python $(srcdir)/$$py; done

test: test-c test-py test-js $(VALA_TEST_TARGET)

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
MockService_0_gir_CFLAGS = -I$(top_srcdir) -I$(top_builddir) -I$(srcdir)
MockService_0_gir_FILES = $(libmock_service_la_SOURCES)
MockService_0_gir_SCANNERFLAGS = --c-include "mock-service.h"

noinst_DATA = \
	$(INTROSPECTION_GIRS) \
	$(INTROSPECTION_GIRS:.gir=.typelib)

if ENABLE_VAPIGEN
include $(VAPIGEN_MAKEFILE)

mock-service-0.vapi: MockService-0.gir $(builddir)/../libsecret-@SECRET_MAJOR@.vapi

VAPIGEN_VAPIS = mock-service-0.vapi

mock_service_0_vapi_DEPS = gio-2.0 libsecret-@SECRET_MAJOR@
mock_service_0_vapi_METADATADIRS = $(builddir)
mock_service_0_vapi_VAPIDIRS = $(builddir) $(builddir)/..
mock_service_0_vapi_FILES = MockService-0.gir

vapidir = $(datadir)/vala/vapi
vapi_DATA = mock-service-0.vapi

noinst_DATA += $(VAPIGEN_VAPIS)

endif # ENABLE_VAPIGEN
endif # HAVE_INTROSPECTION

#--------------------------------------------------------------------

EXTRA_DIST = \
	mock \
	mock-service-delete.py \
	mock-service-empty.py \
	mock-service-lock.py \
	mock-service-normal.py \
	mock-service-only-plain.py \
	mock-service-prompt.py \
	$(VALA_SRCS) \
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
