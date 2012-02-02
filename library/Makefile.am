include $(top_srcdir)/Makefile.decl

SUBDIRS = . tests

module_flags = \
	-version-info $(SECRET_LT_RELEASE) \
	-export_dynamic \
	-avoid-version \
	-module \
	-no-undefined \
	-export-symbols-regex '^secret_'

INCLUDES = \
	-DSECRET_COMPILATION

lib_LTLIBRARIES = libsecret-@SECRET_MAJOR@.la


incdir = $(includedir)/secret-@SECRET_MAJOR@/secret

HEADER_FILES = \
	secret.h \
	secret-collection.h \
	secret-item.h \
	secret-password.h \
	secret-prompt.h \
	secret-service.h \
	secret-types.h \
	secret-value.h \
	$(NULL)

inc_HEADERS = \
	$(HEADER_FILES) \
	secret-enum-types.h \
	$(NULL)

BUILT_SOURCES = \
	secret-dbus-generated.c secret-dbus-generated.h \
	secret-enum-types.c secret-enum-types.h \
	$(NULL)

PUBLIC_FILES = \
	secret-collection.h secret-collection.c \
	secret-item.h secret-item.c \
	secret-methods.c \
	secret-password.h secret-password.c \
	secret-prompt.h secret-prompt.c \
	secret-service.h secret-service.c \
	secret-types.h \
	secret-value.h secret-value.c \
	$(NULL)

INTERNAL_FILES = \
	secret-session.c \
	secret-util.c \
	$(NULL)

libsecret_@SECRET_MAJOR@_la_SOURCES = \
	$(PUBLIC_FILES) \
	$(INTERNAL_FILES) \
	$(BUILT_SOURCES) \
	$(NULL)

libsecret_@SECRET_MAJOR@_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS)

libsecret_@SECRET_MAJOR@_la_LIBADD = \
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

# ------------------------------------------------------------------
# INTROSPECTION

if HAVE_INTROSPECTION

include $(INTROSPECTION_MAKEFILE)

INTROSPECTION_GIRS = Secret-@SECRET_MAJOR@.gir
INTROSPECTION_SCANNER_ARGS = $(INTROSPECTION_FLAGS) --warn-all --add-include-path=$(srcdir) --add-include-path=.
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir) --includedir=.

Secret-@SECRET_MAJOR@.gir: libsecret-@SECRET_MAJOR@.la

Secret_@SECRET_MAJOR@_gir_PACKAGES = gobject-2.0 gio-2.0
Secret_@SECRET_MAJOR@_gir_EXPORT_PACKAGES = libsecret-@SECRET_MAJOR@
Secret_@SECRET_MAJOR@_gir_INCLUDES = GObject-2.0 Gio-2.0
Secret_@SECRET_MAJOR@_gir_LIBS = libsecret-@SECRET_MAJOR@.la
Secret_@SECRET_MAJOR@_gir_CFLAGS = -I$(top_srcdir) -I$(top_builddir) -DSECRET_COMPILATION -DSECRET_API_SUBJECT_TO_CHANGE
Secret_@SECRET_MAJOR@_gir_FILES = $(PUBLIC_FILES)
Secret_@SECRET_MAJOR@_gir_SCANNERFLAGS = --c-include "secret.h"

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibsdir = $(libdir)/girepository-1.0
typelibs_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

endif

# ------------------------------------------------------------------
# PKG CONFIG

libsecret-$(SECRET_MAJOR).pc: libsecret.pc
	cp libsecret.pc libsecret-$(SECRET_MAJOR).pc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsecret-$(SECRET_MAJOR).pc

# ------------------------------------------------------------------


EXTRA_DIST = \
	secret-enum-types.h.template \
	secret-enum-types.c.template \
	org.freedesktop.Secrets.xml \
	$(NULL)

check-memory:
	make -C tests check-memory
