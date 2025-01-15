installed_headers_subdir_base = 'libsecret-@0@'.format(api_version_major)
installed_headers_subdir = installed_headers_subdir_base / 'libsecret'

libsecret_sources = [
  'secret-attributes.c',
  'secret-backend.c',
  'secret-collection.c',
  'secret-item.c',
  'secret-methods.c',
  'secret-password.c',
  'secret-prompt.c',
  'secret-retrievable.c',
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
  'secret-backend.h',
  'secret-collection.h',
  'secret-item.h',
  'secret-password.h',
  'secret-paths.h',
  'secret-prompt.h',
  'secret-retrievable.h',
  'secret-schema.h',
  'secret-schemas.h',
  'secret-service.h',
  'secret-types.h',
  'secret-value.h',
]

if with_crypto
  libsecret_sources += [
    'secret-file-backend.c',
    'secret-file-collection.c',
    'secret-file-item.c',
  ]
endif

version_numbers = meson.project_version().split('.')
version_major = version_numbers[0].to_int()
version_minor = version_numbers[1].to_int()
version_micro = version_numbers[2].to_int()
version_h_conf = configuration_data({
  'SECRET_MAJOR_VERSION': version_major,
  'SECRET_MINOR_VERSION': version_minor,
  'SECRET_MICRO_VERSION': version_micro,
})
version_h = configure_file(input: 'secret-version.h.in',
                           output: '@BASENAME@',
                           configuration: version_h_conf)
libsecret_headers += version_h

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
  install_dir: get_option('includedir') / installed_headers_subdir,
)

libsecret_dependencies = [
  glib_deps,
]

if with_crypto
  libsecret_dependencies += crypto_deps
endif

libsecret_cflags = [
  '-DSECRET_COMPILATION',
]

libsecret = library('secret-@0@'.format(api_version_major),
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
if get_option('introspection')
  libsecret_gir_sources = [
    'secret-attributes.c',
    'secret-attributes.h',
    'secret-backend.c',
    'secret-backend.h',
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
    'secret-retrievable.c',
    'secret-retrievable.h',
    'secret-schema.c',
    'secret-schema.h',
    'secret-schemas.c',
    'secret-schemas.h',
    'secret-service.c',
    'secret-service.h',
    'secret-types.h',
    'secret-value.c',
    'secret-value.h',
    'secret-util.c',
  ]
  libsecret_gir_sources += version_h
  libsecret_gir_sources += _enums_generated

  libsecret_gir = gnome.generate_gir(libsecret,
    sources: libsecret_gir_sources,
    namespace: 'Secret',
    nsversion: api_version_major,
    export_packages: 'libsecret-@0@'.format(api_version_major),
    includes: [ 'GObject-2.0', 'Gio-2.0' ],
    header: 'libsecret/secret.h',
    extra_args: [ '-D SECRET_COMPILATION'],
    install: true,
  )

  # Vapi
  if get_option('vapi')
    libsecret_vapi = gnome.generate_vapi('libsecret-@0@'.format(api_version_major),
      sources: libsecret_gir[0],
      metadata_dirs: meson.source_root() / 'libsecret',
      packages: [ 'gobject-2.0', 'gio-2.0' ],
      install: true,
    )
  endif
endif

# pkg-config
libsecret_pc_variables = [
  'exec_prefix=${prefix}',
  'datarootdir=@0@'.format('${prefix}' / get_option('datadir')),
  'datadir=${datarootdir}',
  'sysconfdir=@0@'.format('${prefix}' / get_option('sysconfdir'))
]

pkg.generate(libsecret,
  description: 'GObject bindings for Secret Service API',
  name: 'libsecret-@0@'.format(api_version_major),
  subdirs: installed_headers_subdir_base,
  variables: libsecret_pc_variables,
  requires: glib_deps,
)

pkg.generate(description: 'GObject bindings for Secret Service API (Unstable)',
  name: 'libsecret-unstable',
  variables: libsecret_pc_variables,
  extra_cflags: '-DSECRET_WITH_UNSTABLE',
  requires: libsecret,
)

# Tests
test_cflags = [
  libsecret_cflags,
  '-DSRCDIR="@0@"'.format(meson.source_root()),
]

mock_service_lib = library('mock-service',
  'mock-service.c',
  dependencies: glib_deps,
  c_args: test_cflags,
  include_directories: config_h_dir,
)

if get_option('introspection')
  mock_service_gir = gnome.generate_gir(mock_service_lib,
    sources: files('mock-service.c', 'mock-service.h'),
    namespace: 'MockService',
    nsversion: '0',
    export_packages: 'mock-service-0',
    includes: [ 'GObject-2.0', 'Gio-2.0' ],
    header: 'libsecret/mock-service.h',
  )

  if get_option('vapi')
    mock_service_vapi = gnome.generate_vapi('mock-service-0',
      sources: mock_service_gir[0],
      packages: [
        'gobject-2.0',
        'gio-2.0',
        libsecret_vapi,
      ],
    )
  endif
endif

# C tests
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

if with_crypto
  test_names += [
    'test-file-collection',
  ]
endif

foreach _test : test_names

  test_bin = executable(_test,
    '@0@.c'.format(_test),
    dependencies: libsecret_dep,
    link_with: mock_service_lib,
    include_directories: config_h_dir,
    c_args: test_cflags,
  )

  test(_test, test_bin,
    suite: 'libsecret',
  )
endforeach

# Tests with introspection
if get_option('introspection')
  # env to be used in tests that use the typelib,
  # to make sure they find the one for MockService
  test_typelib_env = environment()
  test_typelib_env.prepend('GI_TYPELIB_PATH', meson.current_build_dir())
  test_typelib_env.prepend('LD_LIBRARY_PATH', meson.current_build_dir())

  # Python Tests
  pytest_names = [
    'test-py-lookup',
    'test-py-clear',
    'test-py-store',
  ]

  pymod = import('python')
  python3 = pymod.find_installation()
  foreach _pytest : pytest_names
    py_test = meson.current_source_dir() / _pytest + '.py'

    test(_pytest, python3,
      args: py_test,
      depends: mock_service_gir[1],
      env: test_typelib_env,
      suite: 'python',
    )
  endforeach

  # JS Tests
  jstest_names = [
    'test-js-lookup',
    'test-js-clear',
    'test-js-store',
  ]

  gjs = find_program('gjs', required: false)
  if gjs.found()
    foreach _jstest : jstest_names
      js_test = meson.current_source_dir() / _jstest + '.js'

      test(_jstest, gjs,
        args: js_test,
        depends: mock_service_gir[1],
        env: test_typelib_env,
        suite: 'javascript',
      )
    endforeach
  else
    message('GJS not found. Not running Javascript tests')
  endif

  # Vala tests
  # FIXME: Don't add Vala tests when generating a coverage build, as this
  # will fail due to https://github.com/mesonbuild/meson/issues/7426
  if get_option('vapi') and not get_option('b_coverage')
    # FIXME: the "native" kwarg should be added once we can require meson ≥0.54
    add_languages('vala')
    valac = meson.get_compiler('vala')

    valatests = [
      {
        'name': 'test-vala-lang',
        'cflags': [ '-Wno-unused-but-set-variable' ],
      },
      {
        'name': 'test-vala-unstable',
        'cflags': [ '-DSECRET_WITH_UNSTABLE', '-DSECRET_API_SUBJECT_TO_CHANGE' ],
      },
    ]

    foreach _valatest: valatests
      name = _valatest['name']
      extra_cflags = _valatest['cflags']

      test_bin = executable(name, '@0@.vala'.format(name),
        dependencies: [
          glib_deps,
          valac.find_library('glib-2.0'),
          valac.find_library('gio-2.0'),
          libsecret_vapi,
          mock_service_vapi,
        ],
        link_with: mock_service_lib,
        include_directories: config_h_dir,
        c_args: test_cflags + extra_cflags,
      )

      test(name, test_bin, suite: 'vala',
      )
    endforeach
  endif

endif
