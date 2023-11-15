# pam source
pam = dependency('pam', required: true)

pam_gnome_keyring = shared_library('pam_gnome_keyring',
  sources: [
    'gkr-pam-module.c',
    'gkr-pam-client.c',
  ],
  dependencies: [
    pam,
    glib_deps,
  ],
  include_directories: config_h_dir,
  link_with: libegg,
  c_args: [
    '-D_GNU_SOURCE',
  ],
  name_prefix: '',
)

# pam tests
pam_wrapper = dependency('pam_wrapper', required: true)
libpamtest = dependency('libpamtest', required: true)

subdir('servicedir')

test_bin = executable('pam_test',
  sources: [
    'test-pam.c',
  ],
  dependencies: [
    libpamtest,
    glib_deps,
  ],
)

test('pam-test',
  test_bin,
  env: {
    'LD_PRELOAD': 'libpam_wrapper.so',
    'PAM_WRAPPER': '1',
    'PAM_WRAPPER_DEBUGLEVEL': '5',
    'PAM_WRAPPER_SERVICE_DIR': meson.current_build_dir() + '/servicedir',
  },
)
