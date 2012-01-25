include $(top_srcdir)/Makefile.decl

SUBDIRS = . tests

module_flags = \
	-export_dynamic \
	-avoid-version \
	-module \
	-no-undefined \
	-export-symbols-regex '^gsecret_'

INCLUDES = \
	-DGSECRET_COMPILATION

lib_LTLIBRARIES = libgsecret.la

HEADER_FILES = \
	gsecret-collection.h \
	gsecret-item.h \
	gsecret-password.h \
	gsecret-prompt.h \
	gsecret-service.h \
	gsecret-value.h

BUILT_SOURCES = \
	gsecret-dbus-generated.c gsecret-dbus-generated.h \
	gsecret-enum-types.c gsecret-enum-types.h

libgsecret_la_SOURCES = \
	gsecret-collection.h gsecret-collection.c \
	gsecret-item.h gsecret-item.c \
	gsecret-password.h gsecret-password.c \
	gsecret-prompt.h gsecret-prompt.c \
	gsecret-service.h gsecret-service.c \
	gsecret-session.h gsecret-session.c \
	gsecret-util.c \
	gsecret-value.h gsecret-value.c \
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

gsecret-enum-types.h: gsecret-enum-types.h.template $(HEADER_FILES)
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $^ > $@

gsecret-enum-types.c: gsecret-enum-types.c.template $(HEADER_FILES)
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $^ > $@

EXTRA_DIST = \
	gsecret-enum-types.h.template \
	gsecret-enum-types.c.template

check-memory:
	make -C tests check-memory