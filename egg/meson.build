libegg_sources = [
  'egg-hex.c',
  'egg-secure-memory.c',
  'egg-unix-credentials.c',
  'egg-buffer.c',
  'egg-testing.c',
]

libegg_deps = [
  glib_deps,
]

if with_crypto
  libegg_sources += [
    'egg-dh.c',
  ]

  if with_gcrypt
    libegg_sources += [
      'egg-dh-libgcrypt.c',
      'egg-fips-libgcrypt.c',
      'egg-hkdf-libgcrypt.c',
      'egg-keyring1-libgcrypt.c',
      'egg-libgcrypt.c',
    ]
  elif with_gnutls
    libegg_sources += [
      'egg-dh-gnutls.c',
      'egg-fips-gnutls.c',
      'egg-hkdf-gnutls.c',
      'egg-keyring1-gnutls.c',
    ]
  endif

  libegg_deps += crypto_deps
endif

if get_option('tpm2')
  libegg_sources += [
    'egg-tpm2.c',
  ]

  libegg_deps += tss2_deps
endif

libegg = static_library('egg',
  libegg_sources,
  dependencies: libegg_deps,
  c_args: [
    '-D_GNU_SOURCE',
  ],
  include_directories: [config_h_dir, build_dir],
)

# Tests
test_names = [
  'test-hex',
  'test-secmem',
]

if with_crypto
  test_names += [
    'test-dh',
    'test-hkdf',
  ]
endif

if get_option('tpm2')
  test_names += [
    'test-tpm2',
  ]
endif

foreach _test : test_names

  test_bin = executable(_test,
    '@0@.c'.format(_test),
    dependencies: libegg_deps,
    link_with: libegg,
    include_directories: config_h_dir,
  )

  test(_test, test_bin,
    suite: 'libegg',
  )
endforeach
