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
