include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/library \
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
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libsecret-@SECRET_MAJOR@.la \
	$(LIBGCRYPT_LIBS)

LDADD =  \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libsecret-@SECRET_MAJOR@.la \
	libmock_service.la \
	$(NULL)

C_TESTS = \
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
	test-remove-password.js \
	test-store-password.js

JS_ENV = \
	LD_LIBRARY_PATH=$(builddir)/../.libs:$(builddir)/.libs \
	GI_TYPELIB_PATH=$(builddir)/..:$(builddir)

PY_TESTS = \
	test-lookup-password.py \
	test-remove-password.py \
	test-store-password.py

PY_ENV = $(JS_ENV)

if HAVE_VALAC

VALA_V = $(VALA_V_$(V))
VALA_V_ = $(VALA_V_$(AM_DEFAULT_VERBOSITY))
VALA_V_0 = @echo "  VALAC " $^;

if HAVE_INTROSPECTION
if ENABLE_VAPIGEN

VALA_TESTS = \
	test-vala-lang \
	$(NULL)

endif
endif

test-vala-lang.c: test-vala-lang.vala libsecret-@SECRET_MAJOR@.vapi mock-service-0.vapi
	$(VALA_V)$(VALAC) -C --pkg gio-2.0 $^

TEST_PROGS += $(VALA_TESTS)

test_vala_lang_CFLAGS = -w

DISTCLEANFILES = test-vala-lang.c

test-vala: $(VALA_TESTS)
	@gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(VALA_TESTS)

else

test-vala:

endif # HAVE_VALAC

test-c: $(C_TESTS)
	@gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(C_TESTS)

test-js:
	@for js in $(JS_TESTS); do echo "TEST: $$js"; $(JS_ENV) gjs $(srcdir)/$$js; done

test-py:
	@for py in $(PY_TESTS); do echo "TEST: $$py"; $(PY_ENV) python $(srcdir)/$$py; done

test: test-c test-py test-js test-vala

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

mock-service-0.vapi: MockService-0.gir libsecret-@SECRET_MAJOR@.vapi

VAPIGEN_VAPIS = mock-service-0.vapi

mock_service_0_vapi_DEPS = gio-2.0 libsecret-@SECRET_MAJOR@
mock_service_0_vapi_METADATADIRS = $(builddir)
mock_service_0_vapi_VAPIDIRS = $(builddir)
mock_service_0_vapi_FILES = MockService-0.gir

vapidir = $(datadir)/vala/vapi
vapi_DATA = mock-service-0.vapi

# We have to make a version of the VAPI which references the
# uninstalled C headers.

VAPIGEN_VAPIS += libsecret-@SECRET_MAJOR@.vapi

Secret-@SECRET_MAJOR@.metadata: $(top_srcdir)/library/Secret-@SECRET_MAJOR@.metadata
	$(AM_V_GEN) echo "* cheader_filename=\"secret-collection.h,secret-item.h,secret-password.h,secret-prompt.h,secret-schema.h,secret-schemas.h,secret-service.h,secret-types.h,secret-value.h\"" > $@ && \
	cat < $^ >> $@

libsecret-@SECRET_MAJOR@.vapi: Secret-@SECRET_MAJOR@.metadata $(top_builddir)/library/Secret-@SECRET_MAJOR@.gir

libsecret_@SECRET_MAJOR@_vapi_DEPS = gio-2.0
libsecret_@SECRET_MAJOR@_vapi_METADATADIRS = $(srcdir)
libsecret_@SECRET_MAJOR@_vapi_FILES = $(top_builddir)/library/Secret-@SECRET_MAJOR@.gir

noinst_DATA += $(VAPIGEN_VAPIS)

endif # ENABLE_VAPIGEN
endif # HAVE_INTROSPECTION

#--------------------------------------------------------------------

EXTRA_DIST = \
	mock \
	mock-service-delete.py \
	mock-service-lock.py \
	mock-service-normal.py \
	mock-service-only-plain.py \
	mock-service-prompt.py \
	Secret-@SECRET_MAJOR@.metadata \
	test-vala-lang.vala \
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
