include $(top_srcdir)/Makefile.decl

NULL =

module_flags = \
	-export_dynamic \
	-avoid-version \
	-module \
	-no-undefined \
	-export-symbols-regex '^gsecret_'

lib_LTLIBRARIES = libgsecret.la

libgsecret_la_SOURCES = \
	gsecret-data.h gsecret-data.c

libgsecret_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(LIBS)