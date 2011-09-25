## Process this file with automake to produce Makefile.in
include $(top_srcdir)/Makefile.decl

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = po egg library

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-debug=yes \
	--disable-coverage

dist-hook:
	@if test -d "$(srcdir)/.git"; \
	then \
		echo Creating ChangeLog && \
		( cd "$(top_srcdir)" && \
		  echo '# Generate automatically. Do not edit.'; echo; \
		  $(top_srcdir)/missing --run git log --stat --date=short ) > ChangeLog.tmp \
		&& mv -f ChangeLog.tmp $(top_distdir)/ChangeLog \
		|| ( rm -f ChangeLog.tmp ; \
		     echo Failed to generate ChangeLog >&2 ); \
	else \
		echo A git clone is required to generate a ChangeLog >&2; \
	fi

if WITH_COVERAGE
coverage:
	mkdir -p coverage
	$(LCOV) --directory . --capture --output-file coverage/coverage.info
	$(GENHTML) --output-directory coverage coverage/coverage.info
	$(LCOV) --directory . --zerocounters
	@echo "file://$(abs_top_builddir)/coverage/index.html"

clear-coverage:
	$(LCOV) --directory . --zerocounters

.PHONY: coverage
endif
