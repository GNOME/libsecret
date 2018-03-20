libegg_sources = [
  'egg-hex.c',
  'egg-secure-memory.c',
  'egg-testing.c',
]

if with_gcrypt
  libegg_sources += [
    'egg-dh.c',
    'egg-hkdf.c',
    'egg-libgcrypt.c',
  ]
endif

libegg_deps = [
  glib_deps,
  gcrypt_dep,
]

libegg = static_library('egg',
  libegg_sources,
  dependencies: libegg_deps,
  include_directories: config_h_dir,
)
