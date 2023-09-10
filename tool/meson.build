secret_tool_sources = [
  'secret-tool.c',
]

secret_tool = executable('secret-tool',
  secret_tool_sources,
  dependencies: libsecret_dep,
  include_directories: config_h_dir,
  c_args: libsecret_cflags,
  install: true,
)

if with_crypto and host_machine.system() != 'windows'
  test('test-secret-tool.sh',
    find_program('test-secret-tool.sh'),
    env: test_env,
    suite: 'secret-tool',
  )
endif

if get_option('tpm2')
  test('test-secret-tool-tpm2.sh',
    find_program('test-secret-tool-tpm2.sh'),
    env: test_env,
    suite: 'secret-tool',
  )
endif
