SUPPRESSIONS = \
	build/gcrypt.supp \
	build/glib.supp \
	build/pthread.supp \
	build/unknown.supp \
	$(NULL)

valgrind-suppressions: $(SUPPRESSIONS)
	$(AM_V_GEN) cat $^ > $@

EXTRA_DIST += \
	build/valgrind \
	build/tap-compiler \
	build/tap-driver \
	build/tap-unittest \
	build/test-driver \
	$(SUPPRESSIONS)

CLEANFILES += \
	valgrind-suppressions \
	$(NULL)

nodist_noinst_DATA += valgrind-suppressions
