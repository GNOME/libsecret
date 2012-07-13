
const Mock = imports.gi.MockService;
const Secret = imports.gi.Secret;
const GLib = imports.gi.GLib;

const JsUnit = imports.jsUnit;
const assertEquals = JsUnit.assertEquals;
const assertRaises = JsUnit.assertRaises;
const assertTrue = JsUnit.assertTrue;

Mock.start("mock-service-normal.py");

const STORE_SCHEMA = new Secret.Schema.new("org.mock.Schema",
	Secret.SchemaFlags.NONE,
	{
		"number": Secret.SchemaAttributeType.INTEGER,
		"string": Secret.SchemaAttributeType.STRING,
		"even": Secret.SchemaAttributeType.BOOLEAN,
	}
);

/* Synchronous */

var attributes = { "number": "1", "string": "one", "even": "false" };

var password = Secret.password_lookup_sync (STORE_SCHEMA, attributes, null);
assertEquals("111", password);

var deleted = Secret.password_remove_sync (STORE_SCHEMA, attributes, null);
assertEquals(true, deleted);

var password = Secret.password_lookup_sync (STORE_SCHEMA, attributes, null);
assertEquals(null, password);

var deleted = Secret.password_remove_sync (STORE_SCHEMA, attributes, null);
assertEquals(false, deleted);

/* Asynchronous */ 

var attributes = { "number": "2", "string": "two", "even": "true" };

var password = Secret.password_lookup_sync (STORE_SCHEMA, attributes, null);
assertEquals("222", password);

var loop = new GLib.MainLoop.new(null, false);

Secret.password_remove (STORE_SCHEMA, attributes,
                        null, function(source, result) {
	loop.quit();
	var deleted = Secret.password_remove_finish(result);
	assertEquals(true, deleted);
});

loop.run();

var password = Secret.password_lookup_sync (STORE_SCHEMA, attributes, null);
assertEquals(null, password);

Secret.password_remove (STORE_SCHEMA, attributes,
        null, function(source, result) {
	loop.quit();
	var deleted = Secret.password_remove_finish(result);
	assertEquals(false, deleted);
});

loop.run();

Mock.stop();
