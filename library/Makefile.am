include $(top_srcdir)/Makefile.decl

SUBDIRS = . tests

module_flags = \
	-export_dynamic \
	-avoid-version \
	-module \
	-no-undefined \
	-export-symbols-regex '^secret_'

INCLUDES = \
	-DSECRET_COMPILATION

lib_LTLIBRARIES = libsecret.la

HEADER_FILES = \
	secret-collection.h \
	secret-item.h \
	secret-password.h \
	secret-prompt.h \
	secret-service.h \
	secret-value.h

BUILT_SOURCES = \
	secret-dbus-generated.c secret-dbus-generated.h \
	secret-enum-types.c secret-enum-types.h

libsecret_la_SOURCES = \
	secret-collection.h secret-collection.c \
	secret-item.h secret-item.c \
	secret-methods.c \
	secret-password.h secret-password.c \
	secret-prompt.h secret-prompt.c \
	secret-service.h secret-service.c \
	secret-session.h secret-session.c \
	secret-util.c \
	secret-value.h secret-value.c \
	$(BUILT_SOURCES) \
	$(NULL)

libsecret_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS)

libsecret_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(LIBGCRYPT_LIBS) \
	$(LIBS)

DBUS_XML_DEFINITIONS = \
	org.freedesktop.Secrets.xml

secret-dbus-generated.c: $(DBUS_XML_DEFINITIONS) Makefile.am
	$(AM_V_GEN) gdbus-codegen --interface-prefix org.freedesktop.Secret. \
		--generate-c-code secret-dbus-generated --c-namespace SecretGen \
		$(DBUS_XML_DEFINITIONS)
	$(AM_V_GEN) sed -i -e 's/secret_gen_/_secret_gen_/g' secret-dbus-generated.[ch]
	$(AM_V_GEN) sed -i -e '1i #define GLIB_DISABLE_DEPRECATION_WARNINGS' secret-dbus-generated.c
secret-dbus-generated.h: secret-dbus-generated.c

secret-enum-types.h: secret-enum-types.h.template $(HEADER_FILES)
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $^ > $@

secret-enum-types.c: secret-enum-types.c.template $(HEADER_FILES)
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $^ > $@

EXTRA_DIST = \
	secret-enum-types.h.template \
	secret-enum-types.c.template

check-memory:
	make -C tests check-memory