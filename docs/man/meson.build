secret_tool_man = custom_target('secret-tool.1',
  input: 'secret-tool.xml',
  output: 'secret-tool.1',
  command: [ find_program('xsltproc'),
    '-o', '@OUTPUT@',
    '--nonet',
    '--stringparam', 'man.output.quietly', '1',
    '--stringparam', 'man.funcsynopsis.style', 'ansi',
    '--stringparam', 'man.th.extra1.suppress', '1',
    '--stringparam', 'man.authors.section.enabled', '0',
    '--stringparam', 'man.copyright.section.enabled', '0',
    'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl',
    '@INPUT@',
  ],
  build_by_default: true,
  install: true,
  install_dir: libsecret_prefix / get_option('mandir') / 'man1',
)
