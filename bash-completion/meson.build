bashcompdir = get_option('bashcompdir')
if bashcompdir == ''
  bashcomp = dependency('bash-completion', version: '>= 2.12', required: get_option('bash_completion'))
  if bashcomp.found()
    bashcompdir = bashcomp.get_pkgconfig_variable('completionsdir')
  else
    message('Won\'t install bash completion due to missing dependencies')
  endif
endif

if bashcompdir != ''
  install_data('secret-tool', install_dir: bashcompdir)
endif
