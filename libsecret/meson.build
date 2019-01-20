installed_headers_subdir = join_paths('libsecret-@0@'.format(api_version_major), 'libsecret')

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
  install_header: true,
  install_dir: join_paths(includedir, installed_headers_subdir),
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

libsecret = shared_library('secret-@0@'.format(api_version_major),
  [ libsecret_sources, _dbus_generated, _enums_generated ],
  version: libtool_version,
  dependencies: libsecret_dependencies,
  link_with: libegg,
  c_args: libsecret_cflags,
  include_directories: config_h_dir,
  install: true,
)

install_headers(libsecret_headers,
  subdir: installed_headers_subdir,
)

libsecret_dep = declare_dependency(
  link_with: [ libsecret, libegg ],
  dependencies: libsecret_dependencies,
)

# GObject Introspection
libsecret_gir_sources = [
  'secret-attributes.c',
  'secret-attributes.h',
  'secret-collection.c',
  'secret-collection.h',
  'secret-item.c',
  'secret-item.h',
  'secret-methods.c',
  'secret-password.c',
  'secret-password.h',
  'secret-paths.c',
  'secret-paths.h',
  'secret-prompt.c',
  'secret-prompt.h',
  'secret-schema.c',
  'secret-schema.h',
  'secret-schemas.c',
  'secret-schemas.h',
  'secret-service.c',
  'secret-service.h',
  'secret-types.h',
  'secret-value.c',
  'secret-value.h',
]

libsecret_gir = gnome.generate_gir(libsecret,
  sources: libsecret_gir_sources,
  namespace: 'Secret',
  nsversion: api_version_major,
  export_packages: 'libsecret-@0@'.format(api_version_major),
  includes: [ 'GObject-2.0', 'Gio-2.0' ],
  extra_args: [ '-D SECRET_COMPILATION'],
  install: true,
)

# Vapi
if with_vapi
  libsecret_vapi = gnome.generate_vapi('libsecret-@0@'.format(api_version_major),
    sources: libsecret_gir[0],
    metadata_dirs: join_paths(meson.source_root(), 'libsecret'),
    packages: [ 'gobject-2.0', 'gio-2.0' ],
    install: true,
  )
endif

# pkg-config
pc_conf = configuration_data()
pc_conf.set('prefix', libsecret_prefix)
pc_conf.set('exec_prefix', '${prefix}')
pc_conf.set('libdir', join_paths('${prefix}', get_option('libdir')))
pc_conf.set('includedir', join_paths('${prefix}', get_option('includedir')))
pc_conf.set('datarootdir', join_paths('${prefix}', get_option('datadir')))
pc_conf.set('datadir', '${datarootdir}')
pc_conf.set('sysconfdir', join_paths('${prefix}', get_option('sysconfdir')))
pc_conf.set('SECRET_MAJOR', api_version_major)
pc_conf.set('VERSION', meson.project_version())

configure_file(
  input: 'libsecret.pc.in',
  output: 'libsecret-@0@.pc'.format(api_version_major),
  configuration: pc_conf,
  install: true,
  install_dir: join_paths(libdir, 'pkgconfig'),
)
configure_file(
  input: 'libsecret-unstable.pc.in',
  output: 'libsecret-unstable.pc',
  configuration: pc_conf,
  install: true,
  install_dir: join_paths(libdir, 'pkgconfig'),
)

# Tests
mock_cflags = [
  libsecret_cflags,
  '-DSRCDIR="@0@"'.format(meson.source_root()),
]

mock_service_lib = static_library('mock-service',
  'mock-service.c',
  dependencies: glib_deps,
  c_args: mock_cflags,
  include_directories: config_h_dir,
)

test_names = [
  'test-attributes',
  'test-value',
  'test-prompt',
  'test-service',
  'test-session',
  'test-paths',
  'test-methods',
  'test-password',
  'test-item',
  'test-collection',
]

foreach _test : test_names

  test_bin = executable(_test,
    '@0@.c'.format(_test),
    dependencies: libsecret_dep,
    link_with: mock_service_lib,
    include_directories: config_h_dir,
    c_args: libsecret_cflags,
  )

  test(_test, test_bin)
endforeach