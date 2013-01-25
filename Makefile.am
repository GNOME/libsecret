## Process this file with automake to produce Makefile.in
include $(top_srcdir)/Makefile.decl

ACLOCAL_AMFLAGS = -I build/m4 ${ACLOCAL_FLAGS}

SUBDIRS = build egg libsecret tool po docs .

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-debug=yes \
	--disable-coverage \
	--enable-strict \
	--disable-silent-rules \
	--enable-gtk-doc \
	--enable-vala

EXTRA_DIST = \
	COPYING.TESTS

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

check-memory:
	@for subdir in $(SUBDIRS); do \
		test -d $(builddir)/$$subdir/tests && \
			make -C $(builddir)/$$subdir/tests check-memory; \
	done

upload-release: $(DIST_ARCHIVES)
		scp $(DIST_ARCHIVES) master.gnome.org:

upload-docs:
	rsync -Hvax docs/reference/libsecret/html/./ master.gnome.org:public_html/libsecret-docs/

if HAVE_VALAC
dist-check-valac:

else
dist-check-valac:
	@echo "*** valac must be installed and enabled in order to make dist"
	@false
endif

dist-hook: dist-check-valac

distcleancheck_listfiles =  \
       find . -name '*.gc[dn][oa]' -prune -o -type f -print
