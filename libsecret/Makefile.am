include $(top_srcdir)/Makefile.decl

SUBDIRS = . tests

INCLUDES = \
	-I$(top_srcdir) \
	-DSECRET_COMPILATION \
	$(NULL)

lib_LTLIBRARIES = libsecret-@SECRET_MAJOR@.la


incdir = $(includedir)/libsecret-@SECRET_MAJOR@/libsecret

HEADER_FILES = \
	secret.h \
	secret-attributes.h \
	secret-collection.h \
	secret-item.h \
	secret-password.h \
	secret-paths.h \
	secret-prompt.h \
	secret-schema.h \
	secret-schemas.h \
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

STABLE_FILES = \
	secret-attributes.h secret-attributes.c \
	secret-password.h secret-password.c \
	secret-schema.h secret-schema.c \
	secret-schemas.h secret-schemas.c \
	secret-types.h \
	$(NULL)

UNSTABLE_FILES = \
	secret-collection.h secret-collection.c \
	secret-item.h secret-item.c \
	secret-methods.c \
	secret-paths.h secret-paths.c \
	secret-prompt.h secret-prompt.c \
	secret-service.h secret-service.c \
	secret-value.h secret-value.c \
	$(NULL)

PRIVATE_FILES = \
	secret-private.h \
	secret-session.c \
	secret-util.c \
	$(NULL)

libsecret_@SECRET_MAJOR@_la_SOURCES = \
	$(STABLE_FILES) \
	$(UNSTABLE_FILES) \
	$(PRIVATE_FILES) \
	$(BUILT_SOURCES) \
	$(NULL)

libsecret_@SECRET_MAJOR@_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS)

libsecret_@SECRET_MAJOR@_la_LDFLAGS = \
	-version-info $(SECRET_LT_RELEASE) \
	-no-undefined \
	-export-symbols-regex '^secret_|^SECRET_|^SECMEM_.*'

libsecret_@SECRET_MAJOR@_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(LIBGCRYPT_LIBS) \
	$(LIBS)

noinst_LTLIBRARIES = libsecret-testable.la
libsecret_testable_la_SOURCES =
libsecret_testable_la_LIBADD = $(libsecret_@SECRET_MAJOR@_la_OBJECTS) \
	$(libsecret_@SECRET_MAJOR@_la_LIBADD)
libsecret_testable_la_DEPENDENCIES = $(libsecret_@SECRET_MAJOR@_la_OBJECTS)
libsecret_testable_la_LDFLAGS = -rpath /force/shared

DBUS_XML_DEFINITIONS = \
	$(srcdir)/org.freedesktop.Secrets.xml

secret-dbus-generated.c: $(DBUS_XML_DEFINITIONS) Makefile.am
	$(AM_V_GEN) gdbus-codegen --interface-prefix org.freedesktop.Secret. \
		--generate-c-code secret-dbus-generated --c-namespace SecretGen \
		$(DBUS_XML_DEFINITIONS)
	$(AM_V_GEN) sed -i -e 's/secret_gen_/_secret_gen_/g' -e 's/type-/type/g' secret-dbus-generated.[ch]
	$(AM_V_GEN) sed -i -e '1i #define GLIB_DISABLE_DEPRECATION_WARNINGS' secret-dbus-generated.c
secret-dbus-generated.h: secret-dbus-generated.c

secret-enum-types.h: secret-enum-types.h.template $(HEADER_FILES)
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $^ > $@

secret-enum-types.c: secret-enum-types.c.template $(HEADER_FILES)
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $^ > $@

CLEANFILES =

# ------------------------------------------------------------------
# INTROSPECTION

if HAVE_INTROSPECTION

include $(INTROSPECTION_MAKEFILE)

INTROSPECTION_GIRS = Secret-@SECRET_MAJOR@.gir SecretUnstable-0.gir
INTROSPECTION_SCANNER_ARGS = $(INTROSPECTION_FLAGS) --warn-all --add-include-path=$(srcdir) --add-include-path=.
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir) --includedir=.

Secret-@SECRET_MAJOR@.gir: libsecret-@SECRET_MAJOR@.la

Secret_@SECRET_MAJOR@_gir_NAMESPACE = Secret
Secret_@SECRET_MAJOR@_gir_EXPORT_PACKAGES = libsecret-@SECRET_MAJOR@
Secret_@SECRET_MAJOR@_gir_INCLUDES = GObject-2.0 Gio-2.0
Secret_@SECRET_MAJOR@_gir_LIBS = libsecret-@SECRET_MAJOR@.la
Secret_@SECRET_MAJOR@_gir_CFLAGS = -I$(top_srcdir) -I$(top_builddir) -DSECRET_COMPILATION
Secret_@SECRET_MAJOR@_gir_FILES = $(STABLE_FILES)
Secret_@SECRET_MAJOR@_gir_SCANNERFLAGS = --c-include "libsecret/secret.h"

SecretUnstable-0.gir: Secret-@SECRET_MAJOR@.gir

SecretUnstable_0_gir_NAMESPACE = SecretUnstable
SecretUnstable_0_gir_EXPORT_PACKAGES = libsecret-unstable
SecretUnstable_0_gir_INCLUDES = GObject-2.0 Gio-2.0
SecretUnstable_0_gir_LIBS = libsecret-@SECRET_MAJOR@.la
SecretUnstable_0_gir_CFLAGS = -I$(top_srcdir) -I$(top_builddir) -DSECRET_COMPILATION -DSECRET_API_SUBJECT_TO_CHANGE
SecretUnstable_0_gir_FILES = $(UNSTABLE_FILES)
SecretUnstable_0_gir_SCANNERFLAGS = --c-include "libsecret/secret.h" --identifier-prefix=Secret --symbol-prefix=secret --include-uninstalled=$(builddir)/Secret-@SECRET_MAJOR@.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibsdir = $(libdir)/girepository-1.0
typelibs_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

if ENABLE_VAPIGEN
include $(VAPIGEN_MAKEFILE)

libsecret-@SECRET_MAJOR@.vapi: Secret-@SECRET_MAJOR@.gir Secret-@SECRET_MAJOR@.metadata libsecret-@SECRET_MAJOR@.deps

libsecret-unstable.vapi: SecretUnstable-0.gir SecretUnstable-0.metadata libsecret-unstable.deps

VAPIGEN_VAPIS = \
	libsecret-@SECRET_MAJOR@.vapi \
	libsecret-unstable.vapi

libsecret_@SECRET_MAJOR@_vapi_DEPS = glib-2.0 gio-2.0
libsecret_@SECRET_MAJOR@_vapi_METADATADIRS = $(srcdir)
libsecret_@SECRET_MAJOR@_vapi_FILES = Secret-@SECRET_MAJOR@.gir

libsecret_unstable_vapi_DEPS = gio-2.0 libsecret-@SECRET_MAJOR@
libsecret_unstable_vapi_METADATADIRS = $(srcdir)
libsecret_unstable_vapi_VAPIDIRS = $(builddir)
libsecret_unstable_vapi_GIRDIRS = $(builddir)
# ... because _GIRDIRS above is broken, yes, this is ugly
libsecret_unstable_vapi_FILES = --girdir=$(builddir)
libsecret_unstable_vapi_FILES += SecretUnstable-0.gir

VAPI_DEPS = $(VAPIGEN_VAPIS:.vapi=.deps)

libsecret-$(SECRET_MAJOR).deps: Makefile.am
	$(AM_V_GEN) echo $(libsecret_@SECRET_MAJOR@_vapi_DEPS) | tr ' ' '\n' > $@
libsecret-unstable.deps: Makefile.am
	$(AM_V_GEN) echo $(libsecret_unstable_vapi_DEPS) | tr ' ' '\n' > $@

vapidir = $(datadir)/vala/vapi
vapi_DATA = \
	$(VAPIGEN_VAPIS) \
	$(VAPI_DEPS)

CLEANFILES += \
	$(VAPIGEN_VAPIS) \
	$(VAPI_DEPS)

endif # ENABLE_VAPIGEN
endif # HAVE_INTROSPECTION

# ------------------------------------------------------------------
# PKG CONFIG

libsecret-$(SECRET_MAJOR).pc: libsecret.pc
	cp libsecret.pc libsecret-$(SECRET_MAJOR).pc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = \
	libsecret-$(SECRET_MAJOR).pc \
	libsecret-unstable.pc

# ------------------------------------------------------------------


EXTRA_DIST = \
	secret-enum-types.h.template \
	secret-enum-types.c.template \
	org.freedesktop.Secrets.xml \
	Secret-@SECRET_MAJOR@.metadata \
	SecretUnstable-0.metadata \
	$(NULL)

CLEANFILES += \
	$(pkgconfig_DATA) \
	$(gir_DATA) \
	$(typelibs_DATA) \
	$(NULL)

DISTCLEANFILES = \
	$(NULL)

check-memory:
	make -C tests check-memory
