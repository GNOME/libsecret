
const Mock = imports.gi.MockService;
const Secret = imports.gi.SecretUnstable;
const GLib = imports.gi.GLib;

const JsUnit = imports.jsUnit;
const assertNotEquals = JsUnit.assertNotEquals;

Mock.start("mock-service-normal.py");

var service = SecretUnstable.Service.get_sync(SecretUnstable.ServiceFlags.NONE);
var path = service.read_alias_dbus_path_sync("default", null);

/* Just running this without error is good enough for us to test the unstable gir */
assertNotEquals(path, null);

Mock.stop();
