project('libsecret', 'c',
  version: '0.20.4',
  license: 'GPL2+',
  meson_version: '>= 0.50',
)

gnome = import('gnome')
i18n = import('i18n')
pkg = import('pkgconfig')

# API version
api_version = '1.0.0'
api_version_major = api_version.split('.')[0]
api_version_minor = api_version.split('.')[1]
api_version_micro = api_version.split('.')[2]

libtool_version = '0.0.0'

# Some variables
config_h_dir = include_directories('.')
build_dir = include_directories('build')
libsecret_prefix = get_option('prefix')
po_dir = meson.source_root() / 'po'

# Dependencies
min_glib_version = '2.44'
glib_deps = [
  dependency('glib-2.0', version: '>=' + min_glib_version),
  dependency('gio-2.0', version: '>=' + min_glib_version),
  dependency('gio-unix-2.0', version: '>=' + min_glib_version),
]

min_libgcrypt_version = '1.2.2'
gcrypt_dep = dependency('libgcrypt',
  version: '>=' + min_libgcrypt_version,
  required: get_option('gcrypt'),
)

# Libraries
math = meson.get_compiler('c').find_library('m')

# Configuration
conf = configuration_data()
conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())
conf.set_quoted('G_LOG_DOMAIN', meson.project_name())
conf.set_quoted('LOCALEDIR', libsecret_prefix / get_option('localedir'))
conf.set_quoted('PACKAGE_NAME', meson.project_name())
conf.set_quoted('PACKAGE_STRING', meson.project_name())
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set('WITH_GCRYPT', get_option('gcrypt'))
if get_option('gcrypt')
  conf.set_quoted('LIBGCRYPT_VERSION', min_libgcrypt_version)
endif
conf.set('WITH_DEBUG', get_option('debugging'))
conf.set('_DEBUG', get_option('debugging'))
conf.set('HAVE_MLOCK', meson.get_compiler('c').has_function('mlock'))
configure_file(output: 'config.h', configuration: conf)

# Test environment
test_env = environment()
test_env.set('abs_top_builddir', meson.build_root())

# Subfolders
subdir('po')
subdir('egg')
subdir('libsecret')
subdir('tool')
subdir('docs')
