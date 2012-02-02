include $(top_srcdir)/Makefile.decl

VALGRIND_CONTRIB = \
	valgrind.h \
	memcheck.h \
	$(NULL)

SUPPRESSIONS = \
	gcrypt.supp \
	glib.supp \
	pthread.supp \
	unknown.supp \
	$(NULL)

valgrind-suppressions: $(SUPPRESSIONS)
	$(AM_V_GEN) cat $(SUPPRESSIONS) > $@

EXTRA_DIST = \
	valgrind \
	$(SUPPRESSIONS)

all-local: valgrind-suppressions
