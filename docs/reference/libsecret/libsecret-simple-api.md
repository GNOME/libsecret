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
