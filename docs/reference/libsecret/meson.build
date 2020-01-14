reference_content_files = [
  'libsecret-examples.sgml',
  'libsecret-using.sgml',
  'migrating-libgnome-keyring.xml',
]

# SGML files where gtk-doc abbrevations (#GtkWidget) are expanded
reference_expanded_content_files = [
  'migrating-libgnome-keyring.xml',
]

reference_ignore_headers = [
  'mock-service.h',
  'secret-dbus-generated.h',
  'secret-private.h',
]

configure_file(
  input: 'version.xml.in',
  output: '@BASENAME@',
  configuration: {'VERSION': meson.project_version()},
)

gnome.gtkdoc('libsecret',
  main_sgml: 'libsecret-docs.sgml',
  content_files: reference_content_files,
  src_dir: include_directories('../../../libsecret'),
  dependencies: libsecret_dep,
  gobject_typesfile: 'libsecret.types',
  mkdb_args: '--expand-content-files=' + ' '.join(reference_expanded_content_files),
  scan_args: [
    '--deprecated-guards=SECRET_DISABLE_DEPRECATED',
    '--rebuild-types',
    '--ignore-headers=' + ' '.join(reference_ignore_headers),
  ],
  module_version: api_version_major,
  install: true,
)
