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

libmock_service_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libsecret-@SECRET_MAJOR@.la \
	$(LIBGCRYPT_LIBS)

LDADD =  \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libsecret-@SECRET_MAJOR@.la \
	$(top_builddir)/library/tests/libmock_service.la \
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

EXTRA_DIST = \
	mock \
	mock-service-delete.py \
	mock-service-lock.py \
	mock-service-normal.py \
	mock-service-only-plain.py \
	mock-service-prompt.py \
	$(NULL)

test: $(TEST_PROGS)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

all-local: $(check_PROGRAMS)

check-local: test

check-memory: perform-memcheck

.PHONY: check-memory