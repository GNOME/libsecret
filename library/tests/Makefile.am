include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir)/library \
	$(NULL)

LDADD =  \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libgsecret.la \
	$(NULL)

TEST_PROGS = \
	test-initial \
	$(NULL)

check_PROGRAMS = \
	$(TEST_PROGS)

noinst_PROGRAMS =  \
	$(NULL)

test: $(TEST_PROGS)
	gtester -k --verbose $(TEST_PROGS)

all-local: $(check_PROGRAMS)

check-local: test