project('libsecret', 'c',
  version: '0.21.7',
  license: 'LGPL-2.1-or-later AND GPL-2.0-or-later AND Apache-2.0',
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

with_gcrypt = false
with_gnutls = false
with_crypto = false

crypto_deps = []

if get_option('crypto') == 'libgcrypt'
  min_libgcrypt_version = '1.2.2'
  gcrypt_dep = dependency(
    'libgcrypt',
    version: '>=' + min_libgcrypt_version,
  )
  with_gcrypt = true
  with_crypto = true
  crypto_deps += gcrypt_dep
elif get_option('crypto') == 'gnutls'
  min_gnutls_version = '3.8.2'
  gnutls_dep = dependency(
    'gnutls',
    version: '>=' + min_gnutls_version,
  )
  with_gnutls = true
  with_crypto = true
  crypto_deps += gnutls_dep
endif

min_tss2_version = '3.0.3'
tss2_esys = dependency('tss2-esys', version: '>=' + min_tss2_version, required: get_option('tpm2'))
tss2_mu = dependency('tss2-mu', version: '>=' + min_tss2_version, required: get_option('tpm2'))
tss2_rc = dependency('tss2-rc', version: '>=' + min_tss2_version, required: get_option('tpm2'))
tss2_tctildr = dependency('tss2-tctildr', version: '>=' + min_tss2_version, required: get_option('tpm2'))

tss2_deps = []
if tss2_esys.found() and tss2_mu.found() and tss2_rc.found() and tss2_tctildr.found()
  tss2_deps += [tss2_esys, tss2_mu, tss2_rc, tss2_tctildr]
endif

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
conf.set('WITH_GCRYPT', with_gcrypt)
conf.set('WITH_GNUTLS', with_gnutls)
conf.set('WITH_CRYPTO', with_crypto)
conf.set('WITH_TPM', get_option('tpm2'))
if with_gcrypt
  conf.set_quoted('LIBGCRYPT_VERSION', min_libgcrypt_version)
endif
if get_option('tpm2')
  conf.set_quoted('TSS2_VERSION', min_tss2_version)
endif
conf.set('WITH_DEBUG', get_option('debugging'))
conf.set('_DEBUG', get_option('debugging'))
conf.set('HAVE_MLOCK', meson.get_compiler('c').has_function('mlock'))
if get_option('pam')
  conf.set_quoted('GNOME_KEYRING_DAEMON', get_option('prefix') /
    get_option('bindir') / 'gnome-keyring-daemon')
endif
configure_file(output: 'config.h', configuration: conf)

# Test environment
test_env = environment()
test_env.set('abs_top_builddir', meson.build_root())

# Most tests require a D-Bus session, so try to wrap automatically with dbus-run-session
dbus_run_session = find_program('dbus-run-session', required: false)
if dbus_run_session.found()
  add_test_setup('dbus',
    exe_wrapper: dbus_run_session,
    is_default: true,
  )
else
  message('dbus-run-session not found. Please note that tests might fail if you don\'t set up a D-Bus session.')
endif

# Subfolders
subdir('po')
subdir('egg')
subdir('libsecret')
subdir('tool')
subdir('docs')
if get_option('pam')
  subdir('pam')
endif
subdir('bash-completion')
