include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir)/library \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(NULL)

LDADD =  \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libgsecret.la \
	$(NULL)

TEST_PROGS = \
	test-service \
	test-session \
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