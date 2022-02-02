Title: Python Examples
Slug: libsecret-python-example

# Python examples

## Define a password schema

Each stored password has a set of attributes which are later
used to lookup the password. The names and types of the attributes
are defined in a schema. The schema is usually defined once globally.
Here's how to define a schema:

```python
from gi.repository import Secret

EXAMPLE_SCHEMA = Secret.Schema.new("org.mock.type.Store",
    Secret.SchemaFlags.NONE,
    {
        "number": Secret.SchemaAttributeType.INTEGER,
        "string": Secret.SchemaAttributeType.STRING,
        "even": Secret.SchemaAttributeType.BOOLEAN,
    }
)
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

```python
from gi.repository import Secret

def on_password_stored(source, result, unused):
    Secret.password_store_finish(result)
    # ... do something now that the password has been stored

# The attributes used to later lookup the password. These
# attributes should conform to the schema.
attributes = {
    "number": "8",
    "string": "eight",
    "even": "true"
}

Secret.password_store(EXAMPLE_SCHEMA, attributes, Secret.COLLECTION_DEFAULT,
                      "The label", "the password", None, on_password_stored)
```

This next example stores a password synchronously. The function
call will block until the password is stored. So this is appropriate for
non GUI applications.

```python
from gi.repository import Secret

# The attributes used to later lookup the password. These
# attributes should conform to the schema.
attributes = {
    "number": "8",
    "string": "eight",
    "even": "true"
}

Secret.password_store_sync(EXAMPLE_SCHEMA, attributes, Secret.COLLECTION_DEFAULT,
                           "The label", "the password", None)
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

```python
from gi.repository import Secret

def on_password_lookup(source, result, unused):
    password = Secret.password_lookup_finish(result)
    # password will be null, if no matching password found

Secret.password_lookup(EXAMPLE_SCHEMA, { "number": "8", "even": "true" },
                       None, on_password_lookup)
```

This next example looks up a password synchronously. The function
call will block until the lookup completes. So this is appropriate for
non GUI applications.

```python
from gi.repository import Secret

password = Secret.password_lookup_sync(EXAMPLE_SCHEMA, { "number": "8", "even": "true" }, None)
# password will be null, if no matching password found
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

```python
from gi.repository import Secret

def on_password_clear(source, result, unused):
    removed = Secret.password_clear_finish(result)
    # removed will be true if the password was removed

Secret.password_clear(EXAMPLE_SCHEMA, { "number": "8", "even": "true" },
                      None, on_password_clear)
```

This next example removes a password synchronously. The function
call will block until the removal completes. So this is appropriate for
non GUI applications.

```python
from gi.repository import Secret

removed = Secret.password_clear_sync(EXAMPLE_SCHEMA, { "number": "8", "even": "true" }, None)
# removed will be true if the password was removed
```
