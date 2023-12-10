custom_target('pam-test-service',
  command: 'true',
  output: 'null',
  depend_files: configure_file(
    input: 'pam-test-service.in',
    output: 'pam-test-service',
    configuration: configuration_data({
      'KEYRING_PAM': pam_gnome_keyring.full_path(),
    }),
  ),
)
