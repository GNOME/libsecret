libsecret_sources = [
  'secret-attributes.c',
  'secret-collection.c',
  'secret-item.c',
  'secret-methods.c',
  'secret-password.c',
  'secret-prompt.c',
  'secret-schema.c',
  'secret-schemas.c',
  'secret-service.c',
  'secret-value.c',
  'secret-paths.c',
  'secret-session.c',
  'secret-util.c',
]

libsecret_headers = [
  'secret.h',
  'secret-attributes.h',
  'secret-collection.h',
  'secret-item.h',
  'secret-password.h',
  'secret-paths.h',
  'secret-prompt.h',
  'secret-schema.h',
  'secret-schemas.h',
  'secret-service.h',
  'secret-types.h',
  'secret-value.h',
]

_dbus_generated = gnome.gdbus_codegen('secret-dbus-generated',
  sources: 'org.freedesktop.Secrets.xml',
  interface_prefix: 'org.freedesktop.Secret.',
  namespace: '_SecretGen',
)

_enums_generated = gnome.mkenums('secret-enum-types',
  sources: libsecret_headers,
  c_template: 'secret-enum-types.c.template',
  h_template: 'secret-enum-types.h.template',
)

libsecret_dependencies = [
  glib_deps,
]

if with_gcrypt
  libsecret_dependencies += gcrypt_dep
endif

libsecret_cflags = [
  '-DSECRET_COMPILATION',
]

libsecret = library('secret',
  [ libsecret_sources, _dbus_generated, _enums_generated ],
  dependencies: libsecret_dependencies,
  link_with: libegg,
  c_args: libsecret_cflags,
  include_directories: config_h_dir,
  install: true,
)

libsecret_dep = declare_dependency(
  link_with: libsecret,
  dependencies: libsecret_dependencies,
)

# pkg-config
pc_conf = configuration_data()
pc_conf.set_quoted('prefix', libsecret_prefix)
pc_conf.set_quoted('libdir', libdir)
pc_conf.set_quoted('includedir', includedir)
pc_conf.set_quoted('datadir', datadir)
pc_conf.set_quoted('datarootdir', datadir)
pc_conf.set_quoted('sysconfdir', sysconfdir)
pc_conf.set('SECRET_MAJOR', api_version_major)
pc_conf.set('VERSION', meson.project_version())
configure_file(
  input: 'libsecret.pc.in',
  output: 'libsecret-@0@.pc'.format(api_version_major),
  configuration: pc_conf,
)
