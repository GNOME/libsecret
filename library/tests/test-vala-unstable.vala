private void test_read_alias () {
	try {
		var service = Secret.Service.get_sync(Secret.ServiceFlags.NONE);
		var path = service.read_alias_dbus_path_sync("default", null);
		GLib.assert (path != null);
	} catch ( GLib.Error e ) {
		GLib.error (e.message);
	}
}

private static int main (string[] args) {
	GLib.Test.init (ref args);

	try {
		MockService.start ("mock-service-normal.py");
	} catch ( GLib.Error e ) {
		GLib.error ("Unable to start mock service: %s", e.message);
	}

	GLib.Test.add_data_func ("/vala/unstable/read-alias", test_read_alias);

	var res = GLib.Test.run ();
	MockService.stop ();
	return res;
}
