
const Mock = imports.gi.MockService;
const Secret = imports.gi.Secret;

Mock.start("mock-service-normal.py");

var schema = new Secret.Schema.new("org.test",
                                   Secret.SchemaFlags.NONE,
                                   { "blah": Secret.SchemaAttributeType.STRING });
log(schema.identifier);
log(schema.flags);
/* log(schema.attributes); */

Mock.stop();