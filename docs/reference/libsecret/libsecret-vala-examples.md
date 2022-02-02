Title: Vala Examples
Slug: libsecret-vala-example

# Vala Examples

## Define a password schema

Each stored password has a set of attributes which are later
used to lookup the password. The names and types of the attributes
are defined in a schema. The schema is usually defined once globally.
Here's how to define a schema:

```vala
var example = new Secret.Schema ("org.example.Password", Secret.SchemaFlags.NONE,
                                 "number", Secret.SchemaAttributeType.INTEGER,
                                 "string", Secret.SchemaAttributeType.STRING,
                                 "even", Secret.SchemaAttributeType.BOOLEAN);
```

See the [other examples](#store-a-password) for how
to use the schema.


## Store a password

Here's how to store a password in the running secret service,
like gnome-keyring or ksecretservice.

Each stored password has a set of attributes which are later
used to lookup the password. The attributes should not contain
secrets, as they are not stored in an encrypted fashion.

These examples use the [example schema](#define-a-password-schema).

This first example stores a password asynchronously, and is
appropriate for GUI applications so that the UI does not block.

```vala
var attributes = new GLib.HashTable<string,string> ();
attributes["number"] = "8";
attributes["string"] = "eight";
attributes["even"] = "true";

Secret.password_storev.begin (example_schema, attributes, Secret.COLLECTION_DEFAULT,
                              "The label", "the password", null, (obj, async_res) => {
    bool res = Secret.password_store.end (async_res);
    /* ... do something now that the password has been stored */
});
```

If you are already inside of an async function, you can also
use the yield keyword:

```vala
var attributes = new GLib.HashTable<string,string> ();
attributes["number"] = "8";
attributes["string"] = "eight";
attributes["even"] = "true";

bool res = yield Secret.password_storev (example_schema, attributes,
                                         Secret.COLLECTION_DEFAULT, "The label",
                                         "the password", null);
```

If you would like to avoid creating a hash table for the
attributes you can just use the variadic version:

```vala
bool res = yield Secret.password_store (example_schema, Secret.COLLECTION_DEFAULT, "The label",
                                        "the password", null, "number", 8, "string", "eight",
                                        "even", true);
```

This next example stores a password synchronously. The function
call will block until the password is stored. So this is appropriate for
non GUI applications.

```vala
Secret.password_store_sync (example_schema, attributes, Secret.COLLECTION_DEFAULT,
                            "The label", "the password", null,
                            "number", 9, "string", "nine", "even", false);
```

## Lookup a password

Here's how to lookup a password in the running secret service,
like gnome-keyring or ksecretservice.

Each stored password has a set of attributes which are
used to lookup the password. If multiple passwords match the
lookup attributes, then the one stored most recently is returned.

These examples use the [example schema](#define-a-password-schema).

This first example looks up a password asynchronously, and is
appropriate for GUI applications so that the UI does not block.

```vala
var attributes = new GLib.HashTable<string,string> ();
attributes["number"] = "8";
attributes["string"] = "eight";
attributes["even"] = "true";

Secret.password_lookupv.begin (example_schema, attributes, null, (obj, async_res) => {
    string password = Secret.password_lookup.end (async_res);
});
```

This next example looks up a password synchronously. The function
call will block until the lookup completes. So this is appropriate for
non GUI applications.

```vala
string password = Secret.password_lookup_sync (example_schema, attributes, null,
                                               "number", 9, "string", "nine", "even", false);
/* password will be null, if no matching password found */
```

## Remove a password

Here's how to remove a password from the running secret service,
like gnome-keyring or ksecretservice.

Each stored password has a set of attributes which are
used to find which password to remove. If multiple passwords match the
attributes, then the one stored most recently is removed.

These examples use the [example schema](#define-a-password-schema).

This first example removes a password asynchronously, and is
appropriate for GUI applications so that the UI does not block.

```vala
var attributes = new GLib.HashTable<string,string> ();
attributes["number"] = "8";
attributes["string"] = "eight";
attributes["even"] = "true";

Secret.password_clearv.begin (example_schema, attributes, null, (obj, async_res) => {
    bool removed = Secret.password_clearv.end (async_res);
});
```

This next example removes a password synchronously. The function
call will block until the removal completes. So this is appropriate for
non GUI applications.

```vala
var attributes = new GLib.HashTable<string,string> ();
attributes["number"] = "8";
attributes["string"] = "eight";
attributes["even"] = "true";

bool removed = Secret.password_clear_sync (example_schema, null,
                                           "number", 8, "string", "eight", "even", true);
/* removed will be true if the password was removed */
```
