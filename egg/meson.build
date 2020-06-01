libegg_sources = [
  'egg-hex.c',
  'egg-secure-memory.c',
  'egg-testing.c',
]

libegg_deps = [
  glib_deps,
]

if get_option('gcrypt')
  libegg_sources += [
    'egg-dh.c',
    'egg-hkdf.c',
    'egg-libgcrypt.c',
  ]

  libegg_deps += gcrypt_dep
endif

libegg = static_library('egg',
  libegg_sources,
  dependencies: libegg_deps,
  include_directories: [config_h_dir, build_dir],
)
