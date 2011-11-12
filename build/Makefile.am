
VALGRIND_CONTRIB = \
	valgrind.h \
	memcheck.h

SUPPRESSIONS = \
	gcrypt.supp \
	glib.supp \
	pthread.supp \
	unknown.supp

valgrind-suppressions: $(SUPPRESSIONS)
	$(AM_V_GEN) cat $(SUPPRESSIONS) > $@

EXTRA_DIST = \
	$(VALGRIND_CONTRIB) \
	$(SUPPRESSIONS)

all-local: valgrind-suppressions