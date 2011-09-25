include $(top_srcdir)/Makefile.decl

SUBDIRS = . tests

module_flags = \
	-export_dynamic \
	-avoid-version \
	-module \
	-no-undefined \
	-export-symbols-regex '^gsecret_'

lib_LTLIBRARIES = libgsecret.la

libgsecret_la_SOURCES = \
	gsecret-value.h gsecret-value.c \
	gsecret-item.h gsecret-item.c \
	gsecret-service.h gsecret-service.c \
	gsecret-util.c \
	$(NULL)

libgsecret_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS)

libgsecret_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(LIBGCRYPT_LIBS) \
	$(LIBS)