private static int main (string[] args) {
  GLib.Test.init (ref args);

  var service = SecretUnstable.Service.get_sync(SecretUnstable.ServiceFlags.NONE);
  var path = service.read_alias_dbus_path_sync("default", null);

  /* Just running is enough for us */
  if (GLib.Test.verbose())
    stderr.printf("Vala unstable got default path: %s\n", path);
  return 0;
}
