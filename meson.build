project('libsecret', 'c',
  version: '0.19.1',
  license: 'GPL2+',
  meson_version: '>= 0.50',
)

gnome = import('gnome')
i18n = import('i18n')

# API version
api_version = '1.0.0'
api_version_major = api_version.split('.')[0]
api_version_minor = api_version.split('.')[1]
api_version_micro = api_version.split('.')[2]

libtool_version = '0.0.0'

# Options
with_manpage = get_option('manpage')
with_gcrypt = get_option('gcrypt')
enable_debug = get_option('debugging')
with_vapi = get_option('vapi')
with_gtkdoc = get_option('gtk_doc')

# Some variables
config_h_dir = include_directories('.')
build_dir = include_directories('build')
libsecret_prefix = get_option('prefix')
datadir = get_option('datadir')
includedir = get_option('includedir')
bindir = get_option('bindir')
libdir = get_option('libdir')
libexecdir = get_option('libexecdir')
locale_dir = get_option('localedir')
pkgdatadir = datadir / meson.project_name()
pkglibdir = libdir / meson.project_name()
sysconfdir = get_option('sysconfdir')
po_dir = meson.source_root() / 'po'

# Dependencies
min_glib_version = '2.44'
glib_deps = [
  dependency('glib-2.0', version: '>=' + min_glib_version),
  dependency('gio-2.0', version: '>=' + min_glib_version),
  dependency('gio-unix-2.0', version: '>=' + min_glib_version),
]
if with_gcrypt
  min_libgcrypt_version = '1.2.2'
  gcrypt_dep = dependency('libgcrypt', version: '>=' + min_libgcrypt_version, required: false)
  if not gcrypt_dep.found()
    libgcrypt_config = find_program('libgcrypt-config')
    libgcrypt_version = run_command(libgcrypt_config, '--version').stdout().strip()
    if (libgcrypt_version.version_compare('>' + libgcrypt_version))
      error('@0@ requires at least gcrypt version @1@, but version found is @2@'
              .format(meson.project_name(), min_libgcrypt_version, libgcrypt_version))
    endif
    message('gcrypt version: @0@'.format(libgcrypt_version))
    gcrypt_dep = declare_dependency(
      link_args: run_command(libgcrypt_config, '--libs').stdout().strip().split(),
      compile_args: run_command(libgcrypt_config, '--cflags').stdout().strip().split(),
    )
  endif
endif

# Libraries
math = meson.get_compiler('c').find_library('m')

# Configuration
conf = configuration_data()
conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())
conf.set_quoted('G_LOG_DOMAIN', meson.project_name())
conf.set_quoted('LOCALEDIR', libsecret_prefix / locale_dir)
conf.set_quoted('PACKAGE_NAME', meson.project_name())
conf.set_quoted('PACKAGE_STRING', meson.project_name())
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set('WITH_GCRYPT', with_gcrypt)
if with_gcrypt
  conf.set_quoted('LIBGCRYPT_VERSION', min_libgcrypt_version)
endif
conf.set('WITH_DEBUG', enable_debug)
conf.set('_DEBUG', enable_debug)
conf.set('HAVE_MLOCK', meson.get_compiler('c').has_function('mlock'))
configure_file(output: 'config.h', configuration: conf)

# Subfolders
subdir('po')
subdir('egg')
subdir('libsecret')
subdir('tool')
subdir('docs')
