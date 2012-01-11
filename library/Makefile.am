include $(top_srcdir)/Makefile.decl

SUBDIRS = . tests

module_flags = \
	-export_dynamic \
	-avoid-version \
	-module \
	-no-undefined \
	-export-symbols-regex '^gsecret_'

lib_LTLIBRARIES = libgsecret.la

BUILT_SOURCES = \
	gsecret-dbus-generated.c gsecret-dbus-generated.h

libgsecret_la_SOURCES = \
	gsecret-value.h gsecret-value.c \
	gsecret-item.h gsecret-item.c \
	gsecret-service.h gsecret-service.c \
	gsecret-util.c \
	$(BUILT_SOURCES) \
	$(NULL)

libgsecret_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS)

libgsecret_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(LIBGCRYPT_LIBS) \
	$(LIBS)

DBUS_XML_DEFINITIONS = \
	org.freedesktop.Secrets.xml

gsecret-dbus-generated.c: $(DBUS_XML_DEFINITIONS) Makefile.am
	$(AM_V_GEN) gdbus-codegen --interface-prefix org.freedesktop.Secret. \
		--generate-c-code gsecret-dbus-generated --c-namespace GSecretGen \
		$(DBUS_XML_DEFINITIONS)
	$(AM_V_GEN) sed -i -e 's/gsecret_gen_/_gsecret_gen_/g' gsecret-dbus-generated.[ch]
	$(AM_V_GEN) sed -i -e '1i #define GLIB_DISABLE_DEPRECATION_WARNINGS' gsecret-dbus-generated.c
gsecret-dbus-generated.h: gsecret-dbus-generated.c

check-memory:
	make -C tests check-memory