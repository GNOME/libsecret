Title: Simple API
Slug: libsecret-simple-api

# Simple API

## SecretPassword

Simple password storage and lookup.

This is a simple API for storing passwords and retrieving passwords in the
Secret Service.

Each password is associated with a set of attributes. Attribute values can be
either strings, integers or booleans.

The names and types of allowed attributes for a given password are defined with
a schema. Certain schemas are predefined. Additional schemas can be defined via
the [struct@Schema] structure.

Each of the functions accept a variable list of attributes names and their
values. Include a `NULL` to terminate the list of attributes.

## SecretSchema

Represents a set of attributes that are stored with an item. These schemas are
used for interoperability between various services storing the same types of
items.

Each schema has a name like `org.gnome.keyring.NetworkPassword`, and defines a
set of attributes, and types (string, integer, boolean) for those attributes.

Attributes are stored as strings in the Secret Service, and the attribute types
simply define standard ways to store integer and boolean values as strings.
Attributes are represented in libsecret via a [struct@GLib.HashTable] with
string keys and values. Even for values that defined as an integer or boolean in
the schema, the attribute values in the [struct@GLib.HashTable] are strings.
Boolean values are stored as the strings 'true' and 'false'. Integer values are
stored in decimal, with a preceding negative sign for negative integers.

Schemas are handled entirely on the client side by this library. The name of the
schema is automatically stored as an attribute on the item.

Normally when looking up passwords only those with matching schema names are
returned. If the schema @flags contain the `SECRET_SCHEMA_DONT_MATCH_NAME` flag,
then lookups will not check that the schema name matches that on the item, only
the schema's attributes are matched. This is useful when you are looking up
items that are not stored by the libsecret library. Other libraries such as
libgnome-keyring don't store the schema name.

Additional schemas can be defined via the %SecretSchema structure like this:

```c
// in a header:

const SecretSchema * example_get_schema (void) G_GNUC_CONST;

#define EXAMPLE_SCHEMA  example_get_schema ()


// in a .c file

const SecretSchema *
example_get_schema (void)
{
    static const SecretSchema the_schema = {
        "org.example.Password", SECRET_SCHEMA_NONE,
        {
            {  "number", SECRET_SCHEMA_ATTRIBUTE_INTEGER },
            {  "string", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "even", SECRET_SCHEMA_ATTRIBUTE_BOOLEAN },
            {  NULL, 0 },
        }
    };
    return &the_schema;
}
```

## Secret Attributes

Each item has a set of attributes, which are used to locate the item later.
These are not stored or transferred in a secure manner. Each attribute has a
string name and a string value. These attributes are represented by a
[struct@GLib.HashTable] with string keys and values.

Use [func@attributes_build] to simply build up a set of attributes.

## DBus Path Related Functions

Secret Service functions which operate on DBus object paths

These are low level functions which operate on DBus object paths of collections
or items, instead of the [class@Collection] or [class@Item] objects themselves.

You can use these functions if you wish to manage access to the secret service
using the DBus API directly, and only wish to use a few calls in libsecret.
