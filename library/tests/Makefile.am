include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir)/library \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(NULL)

noinst_LTLIBRARIES = libmock_service.la

libmock_service_la_SOURCES = \
	mock-service.c mock-service.h \
	$(NULL)

libmock_service_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS)

libmock_service_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libgsecret.la \
	$(LIBGCRYPT_LIBS)

LDADD =  \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libgsecret.la \
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

test: $(TEST_PROGS)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

all-local: $(check_PROGRAMS)

check-local: test

check-memory: perform-memcheck

.PHONY: check-memory