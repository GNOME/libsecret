Title: Migrating from libgnome-keyring
Slug: migrating-libgnome-keyring

# Migrating from libgnome-keyring

## Introduction

Conceptually, libgnome-keyring and libsecret are fairly similar. Both
have keyrings, items, and ways to store and retrieve passwords. In both
cases items have attributes. The keys and values of attributes are used
to lookup a password that was stored.

There is a
<link linkend="libsecret-Password-storage">simple password API for storing and retrieving passwords</link>
which is the easiest and recommended way to store passwords. And then
there is a more complicated API which models all the various collections
and items, along with all the possible actions that can be performed on them.

libsecret uses the
<ulink url="http://standards.freedesktop.org/secret-service/">Secret Service DBus API</ulink>
to communicate with gnome-keyring-daemon, and as such exposes features
based on that DBus API.

libsecret has been designed to be threadsafe, and uses the 'GDBus'
code in gio to accomplish this.

Keyrings are called 'collections' in libsecret.

See the relevant section for specifics about how to port the
libgnome-keyring functions or symbols in your project.

## API conversion

Here are some clues on how to migrate various libgnome-keyring
API functions and their logical equivalents in libsecret.

### Item attributes

Remember that attributes are not, and never have been stored in
an encrypted fashion. They are not part of the 'secret', but instead
are a way to lookup a secret item.

All attributes in libsecret are stored as strings. Sets of attributes
are represented by [struct@GLib.HashTable]s and the keys and values of 
these hash tables are strings.

libsecret is far more <link linkend="migrating-schemas">focused on schemas</link>,
and encourages users to define a [struct@Schema] for their password storage.
The schema defines which attributes are allowed an item. Each schema has
a name which is usually a dotted string (eg: `org.gnome.MyProject.Password`).
This schema name is stored internally in the item attributes.

Schemas define whether an attribute should look like an integer,
a boolean, or a free-form string. These types are used when validating
the attribute values, even though the attribute values are stored and
matched as strings. Since attribute values are used primarily
for lookup of items it's important that the string representations of
integers and booleans are always identical. Boolean values are stored
as the strings `true` and `false`.
Integer values are stored in decimal, with a preceding negative sign
for negative integers. libsecret facilitates this using the
[func@attributes_build] and [func@attributes_buildv] functions.

Attributes are meant to be used for lookup of items; they're not
designed to be used as a generic key/value database. Although you can
force libsecret to do the latter, it's better to store your account
information elsewhere if possible, and use libsecret to store the password
or other secret.

Replacements for related libgnome-keyring functions and types
are described below:

<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td>GnomeKeyringAttributeList</td>
        <td>a [struct@GLib.HashTable] of string keys and values</td>
    </tr>
    <tr>
        <td>GnomeKeyringAttribute</td>
        <td>a key/value pair in a [struct@GLib.HashTable] of strings</td>
    </tr>
    <tr>
        <td>GnomeKeyringAttributeType</td>
        <td>[struct@Schema]AttributeType</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ATTRIBUTE_TYPE_STRING</code></td>
        <td><code>SECRET_SCHEMA_ATTRIBUTE_STRING</code></td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32</code></td>
        <td><code>SECRET_SCHEMA_ATTRIBUTE_INTEGER</code></td>
    </tr>
    <tr>
        <td><code>gnome_keyring_attribute_list_index()</code></td>
        <td>use [func@GLib.HashTable.lookup] on the attributes hash table</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_attribute_get_string()</code></td>
        <td>use [func@GLib.HashTable.lookup] on the attributes hash table</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_attribute_get_uint32()</code></td>
        <td>no equivalent, use [func@GLib.HashTable.lookup]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_attribute_list_append_string()</code></td>
        <td>[func@attributes_build]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_attribute_list_append_uint32()</code></td>
        <td>[func@attributes_build]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_attribute_list_copy()</code></td>
        <td>[func@GLib.HashTable.ref]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_attribute_list_free()</code></td>
        <td>[func@GLib.HashTable.unref]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_attribute_list_index()</code></td>
        <td>no equivalent, use [func@GLib.HashTable.lookup]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_attribute_list_new()</code></td>
        <td>[func@attributes_build]</td>
    </tr>
</table>

## Working with schemas

libsecret is far more focused on schemas, and encourages users to
define a [struct@Schema] for their password storage. The schema defines
which attributes are allowed an item. Each schema has a name which
is usually a dotted string (eg: `org.gnome.MyProject.Password`).
This name is stored in the item attributes. The schema name is also
used when looking up an item, to make sure that the stored schema
matches that used during the lookup. If you wish to lookup items that
were stored by libgnome-keyring, you should specify the 
`SECRET_SCHEMA_DONT_MATCH_NAME` flag in the schema so that the schema
name is not matched, since it was not stored by libgnome-keyring.

Schemas define whether an attribute should look like an integer,
a boolean, or a free-form string. These types are used when validating
the attribute values stored, even though the attribute values are
stored and matched as strings.

Replacements for related libgnome-keyring functions and types
are described below:
<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td>GnomeKeyringPasswordSchema</td>
        <td>[struct@Schema]</td>
    </tr>
    <tr>
        <td>GnomeKeyringPasswordSchemaAttribute</td>
        <td>[struct@Schema]Attribute</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ITEM_APPLICATION_SECRET</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ITEM_PK_STORAGE</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ITEM_GENERIC_SECRET</code></td>
        <td>no equivalent, define a specific schema with an appropriate dotted name</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ITEM_NETWORK_PASSWORD</code></td>
        <td>the <code>SECRET_SCHEMA_COMPAT_NETWORK</code> schema, although not recommended for new uses</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ITEM_NOTE</code></td>
        <td>the <code>SECRET_SCHEMA_NOTE</code> schema</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_NETWORK_PASSWORD</code></td>
        <td>the <code>SECRET_SCHEMA_COMPAT_NETWORK</code> schema, although not recommended for new uses</td>
    </tr>
</table>

## Storing passwords and items

It's encouraged to use a [struct@Schema] when storing items and
passwords.

By default most ways of storing an item will now overwrite
another item with the same attributes in the same keyring. To manually
control this behavior use the [func@Item.create].

Replacements for related libgnome-keyring functions and types
are described below:

<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_DEFAULT</code></td>
        <td>[const@COLLECTION_DEFAULT]</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_SESSION</code></td>
        <td>[const@COLLECTION_SESSION]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_store_password()</code></td>
        <td>[func@password_store]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_store_password_sync()</code></td>
        <td>[func@password_store_sync]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_set_network_password()</code></td>
        <td>[func@password_store] with <code>SECRET_SCHEMA_COMPAT_NETWORK</code>
        although this is not recommended for new uses.</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_set_network_password_sync()</code></td>
        <td>[func@password_store_sync] with <code>SECRET_SCHEMA_COMPAT_NETWORK</code>
        although this is not recommended for new uses.</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_create()</code></td>
        <td>[func@Item.create], although using [func@password_store]
        is simpler.</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_create_sync()</code></td>
        <td>[func@Item.create], although using [func@password_store_sync]
        is simpler.</td>
    </tr>
</table>

## Searching for passwords and items

In general libsecret tries not to unlocking keyrings
where not necessary. Many search methods only return one item or
password that matches, preferring already unlocked items, and recently stored
items.

Attributes are meant to be used for lookup of items; they're not
designed to be used as a generic key/value database. Although you can
force libsecret to do the latter, it's better to store your account
information elsewhere if possible, and use libsecret to store the password
or other secret. Because of this many search methods return just the
password or secret.

Replacements for related libgnome-keyring functions and types
are described below:

<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td><code>gnome_keyring_find_password()</code></td>
        <td>[func@password_lookup]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_find_password_sync()</code></td>
        <td>[func@password_lookup_sync]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_find_items()</code></td>
        <td>[method@Service.search], with flags to fine tune behavior</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_find_itemsv()</code></td>
        <td>[method@Service.search], with flags to fine tune behavior</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_find_items_sync()</code></td>
        <td>[method@Service.search_sync], with flags to fine tune behavior</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_find_itemsv_sync()</code></td>
        <td>[method@Service.search], with flags to fine tune behavior</td>
    </tr>
    <tr>
        <td>GnomeKeyringFound</td>
        <td>no equivalent, [method@Service.search] returns a [struct@GLib.List] of
        [class@Item]<!-- -->s, and other methods return passwords directly.</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_found_copy()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_found_free()</code></td>
        <td>[method@GObject.Object.unref] on the each of the items returned from
        [method@Service.search]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_found_list_free()</code></td>
        <td>[func@GLib.List.free_full] used with [method@GObject.Object.unref] on the items returned from
        [method@Service.search]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_find_network_password()</code></td>
        <td>[func@password_lookup] with <code>SECRET_SCHEMA_COMPAT_NETWORK</code>,
        although this only returns one password and no attributes</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_find_network_password_sync()</code></td>
        <td>[func@password_lookup_sync] with <code>SECRET_SCHEMA_COMPAT_NETWORK</code>,
        although this only returns one password and no attributes</td>
    </tr>
    <tr>
        <td>GnomeKeyringNetworkPasswordData</td>
        <td>no equivalent, [func@password_lookup] gets the password directly
        and no attributes</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_network_password_free()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_network_password_list_free()</code></td>
        <td>no equivalent</td>
    </tr>
</table>

## Removing passwords and icons

Neither libgnome-keyring or libsecret allow deletion of locked
items. libsecret tries to make it easier to delete all unlocked items
matching certain attributes.

Replacements for related libgnome-keyring functions and types
are described below:

<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td><code>gnome_keyring_delete_password()</code></td>
        <td>[func@password_clear], although we now try to delete
        all unlocked matching items</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_delete_password_sync()</code></td>
        <td>[func@password_clear_sync], although we now try to delete
        all unlocked matching items</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_delete()</code></td>
        <td>[method@Item.delete]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_delete_sync()</code></td>
        <td>[method@Item.delete_sync]</td>
    </tr>
</table>

##  Item management

In libsecret items are no longer identified by an unsigned integer.
Applications should retrieve items based on their attributes. It is also
possible to identify an item by its DBus object path.

Replacements for related libgnome-keyring functions and types
are described below:

<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_create()</code></td>
        <td>[func@Item.create], although [func@password_store] may be simpler</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_create_sync()</code></td>
        <td>[func@Item.create_sync], although [func@password_store_sync] may be simpler</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_delete()</code></td>
        <td>[method@Item.delete], although [func@password_clear] may be simpler</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_delete_sync()</code></td>
        <td>[method@Item.delete_sync], although [func@password_clear_sync] may be simpler</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_get_info()</code></td>
        <td>properties are loaded on a [class@Item] automatically, use
        [method@Item.load_secret] to load the secret</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_get_info_sync()</code></td>
        <td>properties are loaded on a [class@Item] automatically, use
        [method@Item.load_secret_sync] to load the secret</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_get_info_full()</code></td>
        <td>properties are loaded on a [class@Item] automatically, use
        [method@Item.load_secret] to load the secret</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_get_info_full_sync()</code></td>
        <td>properties are loaded on a [class@Item] automatically, use
        [method@Item.load_secret_sync] to load the secret</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_set_info()</code></td>
        <td>use the appropriate setter methods on [class@Item]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_set_info_sync()</code></td>
        <td>use the appropriate setter methods on [class@Item]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_get_attributes()</code></td>
        <td>[method@Item.get_attributes]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_get_attributes_sync()</code></td>
        <td>[method@Item.get_attributes]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_set_attributes()</code></td>
        <td>[method@Item.set_attributes]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_set_attributes_sync()</code></td>
        <td>[method@Item.set_attributes_sync]</td>
    </tr>
    <tr>
        <td>GnomeKeyringItemType</td>
        <td>replaced by the name of a [struct@Schema]</td>
    </tr>
    <tr>
        <td>GnomeKeyringItemInfo</td>
        <td>[class@Item]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_new()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_copy()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_free()</code></td>
        <td>[method@GObject.Object.unref] on the [class@Item]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_get_display_name()</code></td>
        <td>[method@Item.get_label]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_set_display_name()</code></td>
        <td>[method@Item.set_label]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_get_ctime()</code></td>
        <td>[method@Item.get_created]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_get_mtime()</code></td>
        <td>[method@Item.get_modified]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_get_type()</code></td>
        <td>[method@Item.get_schema_name]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_set_type()</code></td>
        <td>[method@Item.set_attributes] with appropriate schema</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_get_secret()</code></td>
        <td>[method@Item.get_secret]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_set_secret()</code></td>
        <td>[method@Item.set_secret] and [method@Item.set_secret_sync]</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ITEM_INFO_BASICS</code></td>
        <td>no equivalent, all basic item properties are loaded on [class@Item]
        automatically</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_ITEM_INFO_SECRET</code></td>
        <td>use [method@Item.load_secret] and [method@Item.load_secret_sync] to load
        the secret for an item.</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_item_info_set_display_name()</code></td>
        <td></td>
    </tr>
</table>

## Keyring management

In libsecret keyrings are called 'collections'. This is the same
lingo as the underlying Secret Service DBus API. Keyrings are no longer
identified by simple keyring names. Normally applications just use the
default keyrings and these are identified by the aliases
[const@COLLECTION_DEFAULT] and [const@COLLECTION_SESSION]. It is also
possible to identify collections by their DBus object paths.

Replacements for related libgnome-keyring functions and types
are described below:

<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td><code>gnome_keyring_create()</code></td>
        <td>[func@Collection.create]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_create_sync()</code></td>
        <td>[func@Collection.create_sync]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_delete()</code></td>
        <td>[method@Collection.delete]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_delete_sync()</code></td>
        <td>[method@Collection.delete_sync]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_change_password()</code></td>
        <td>no equivalent, use platform specific DBus APIs</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_change_password_sync()</code></td>
        <td>no equivalent, use platform specific DBus APIs</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_list_keyring_names()</code></td>
        <td>[method@Service.load_collections] and [method@Service.get_collections]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_list_keyring_names_sync()</code></td>
        <td>[method@Service.load_collections_sync] and [method@Service.get_collections]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_set_default_keyring()</code></td>
        <td>[method@Service.set_alias]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_set_default_keyring_sync()</code></td>
        <td>[method@Service.set_alias_sync]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_get_default_keyring()</code></td>
        <td>[func@Collection.for_alias] with [const@COLLECTION_DEFAULT]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_get_default_keyring_sync()</code></td>
        <td>[func@Collection.for_alias_sync] with [const@COLLECTION_DEFAULT]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_list_item_ids()</code></td>
        <td>[method@Collection.load_items] and [method@Collection.get_items]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_list_item_ids_sync()</code></td>
        <td>[method@Collection.load_items_sync] and [method@Collection.get_items]</td>
    </tr>
    <tr>
        <td>GnomeKeyringInfo</td>
        <td>[class@Collection] and properties</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_get_info()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_get_info_sync()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_set_info()</code></td>
        <td>no equivalent, use property setters on [class@Collection]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_set_info_sync()</code></td>
        <td>no equivalent, use property setters on [class@Collection]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_info_free()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_info_copy()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_info_set_lock_on_idle()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_info_get_lock_on_idle()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_info_set_lock_timeout()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_info_get_lock_timeout()</code></td>
        <td>no equivalent</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_info_get_mtime()</code></td>
        <td>[method@Collection.get_modified]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_info_get_ctime()</code></td>
        <td>[method@Collection.get_created]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_info_get_is_locked()</code></td>
        <td>[method@Collection.get_locked]</td>
    </tr>
</table>

## Locking and unlocking

In libsecret you can unlock items directly, and the result is
(with gnome-keyring daemon) that the enclosing collection will be unlocked.

It is no longer possible to pass a password to unlock keyrings.
These are automatically prompted for.

Replacements for related libgnome-keyring functions and types
are described below:

<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td><code>gnome_keyring_unlock()</code></td>
        <td>[method@Service.unlock]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_unlock_sync()</code></td>
        <td>[method@Service.unlock_sync]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_lock()</code></td>
        <td>[method@Service.lock]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_lock_sync()</code></td>
        <td>[method@Service.lock_sync]</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_lock_all()</code></td>
        <td>no equivalent, use platform specific DBus APIs</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_lock_all_sync()</code></td>
        <td>no equivalent, use platform specific DBus APIs</td>
    </tr>
</table>

## Non-pageable memory

libsecret no longer provides a full API for using non-pageable
memory. Use the <ulink url="http://developer.gnome.org/gcr/stable/gcr-Non-pageable-Memory.html">equivalent API in the Gcr library</ulink>.

You can request that passwords are returned in non-pageable
memory by using the [func@password_lookup_nonpageable_sync] and
[func@password_lookup_nonpageable_finish] functions.
In addition the contents of [struct@Value] items is stored in
non-pageable memory, unless the system doesn't support this.

Replacements for related libgnome-keyring functions and types
are described below:

<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td><code>gnome_keyring_memory_alloc()</code></td>
        <td>no equivalent, use Gcr</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_memory_free()</code></td>
        <td>[func@password_free], although this only works on strings</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_memory_is_secure()</code></td>
        <td>no equivalent, use Gcr</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_memory_new()</code></td>
        <td>no equivalent, use Gcr</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_memory_realloc()</code></td>
        <td>no equivalent, use Gcr</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_memory_strdup()</code></td>
        <td>no equivalent, use [struct@Value] which is ref-counted, or use Gcr</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_memory_try_alloc()</code></td>
        <td>no equivalent, use Gcr</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_memory_try_realloc()</code></td>
        <td>no equivalent, use Gcr</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_free_password()</code></td>
        <td>[func@password_free]</td>
    </tr>
</table>

## Errors and cancellation

libsecret uses standard the standard [class@Gio.Cancellable] idiom
to cancel operations.

It is not necessary to check whether the keyring daemon is
available before using it. It is started automatically.

Errors are returned as standard [struct@GLib.Error] in the usual way.
There are fewer errors that are worth handling in an intelligent way,
exceptions are in the #SecretError enumeration. It is not recommended
to display any [struct@GLib.Error] message returned by libsecret to the user. Most
of the possible errors are DBus communication problems or similar.

Replacements for related libgnome-keyring functions and types
are described below:

<table>
    <tr>
        <th>libgnome-keyring</th><th>libsecret</th>
    </tr>
    <tr>
        <td><code>gnome_keyring_cancel_request()</code></td>
        <td>[method@Gio.Cancellable.cancel] on a [class@Gio.Cancellable] passed to the relevant operation</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_is_available()</code></td>
        <td>no equivalent, the secret service is autostarted as necessary</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_result_to_message()</code></td>
        <td>use the message in the [struct@GLib.Error], although most failures are not appropriate for display to the user</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_OK</code></td>
        <td>no [struct@GLib.Error] returned</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_DENIED</code></td>
        <td>no longer used, item or collection is simply not unlocked</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON</code></td>
        <td><code>G_DBUS_ERROR_SPAWN_SERVICE_NOT_FOUND</code></td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_ALREADY_UNLOCKED</code></td>
        <td>no error, success returned</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_NO_SUCH_KEYRING</code></td>
        <td>keyrings no longer have names, accessing an missing DBus object has usual failure</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_BAD_ARGUMENTS</code></td>
        <td><code>G_DBUS_ERROR_INVALID_ARGS</code> or precondition failure in libsecret, this is always
        a programmer error</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_IO_ERROR</code></td>
        <td>relevant DBus errors, or <code>SECRET_ERROR_PROTOCOL</code></td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_CANCELLED</code></td>
        <td><code>G_IO_ERROR_CANCELLED</code></td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_KEYRING_ALREADY_EXISTS</code></td>
        <td>no error, simply returns already existing keyring</td>
    </tr>
    <tr>
        <td><code>GNOME_KEYRING_RESULT_NO_MATCH</code></td>
        <td>on error, an empty list is returned</td>
    </tr>
    <tr>
        <td><code>gnome_keyring_string_list_free()</code></td>
        <td>no equivalent</td>
    </tr>
</table>
