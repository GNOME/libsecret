include $(top_srcdir)/Makefile.decl

VALGRIND_CONTRIB = \
	valgrind.h \
	memcheck.h \
	$(NULL)

SUPPRESSIONS = \
	$(srcdir)/gcrypt.supp \
	$(srcdir)/glib.supp \
	$(srcdir)/pthread.supp \
	$(srcdir)/unknown.supp \
	$(NULL)

valgrind-suppressions: $(SUPPRESSIONS)
	$(AM_V_GEN) cat $(SUPPRESSIONS) > $@

EXTRA_DIST = \
	valgrind \
	$(SUPPRESSIONS)

CLEANFILES = \
	valgrind-suppressions \
	$(NULL)

all-local: valgrind-suppressions
