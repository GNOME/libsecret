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

if get_option('gcrypt') and host_machine.system() != 'windows'
  test('test-secret-tool.sh',
    find_program('test-secret-tool.sh'),
    env: test_env,
    suite: 'secret-tool',
  )
endif
