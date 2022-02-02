/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2012 Stef Walter
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#if !defined (__SECRET_INSIDE_HEADER__) && !defined (SECRET_COMPILATION)
#error "Only <libsecret/secret.h> can be included directly."
#endif

#ifndef __SECRET_SCHEMAS_H__
#define __SECRET_SCHEMAS_H__

#include <glib.h>

#include "secret-schema.h"

G_BEGIN_DECLS

/*
 * A note or password stored manually by the user.
 */
extern const SecretSchema *  SECRET_SCHEMA_NOTE;

/*
 * This schema is here for compatibility with libgnome-keyring's network
 * password functions.
 */

extern const SecretSchema *  SECRET_SCHEMA_COMPAT_NETWORK;

/**
 * SecretSchemaType:
 * @SECRET_SCHEMA_TYPE_NOTE: Personal passwords
 * @SECRET_SCHEMA_TYPE_COMPAT_NETWORK: Network passwords from older
 *    libgnome-keyring storage
 *
 * Different types of schemas for storing secrets, intended for use with
 * [func@get_schema].
 *
 * ## @SECRET_SCHEMA_NOTE
 *
 * A predefined schema for personal passwords stored by the user in the
 * password manager. This schema has no attributes, and the items are not
 * meant to be used automatically by applications.
 *
 * When used to search for items using this schema, it will only match
 * items that have the same schema. Items stored via libgnome-keyring with the
 * `GNOME_KEYRING_ITEM_NOTE` item type will match.
 *
 * ## @SECRET_SCHEMA_COMPAT_NETWORK
 *
 * A predefined schema that is compatible with items stored via the
 * libgnome-keyring 'network password' functions. This is meant to be used by
 * applications migrating from libgnome-keyring which stored their secrets as
 * 'network passwords'. It is not recommended that new code use this schema.
 *
 * When used to search for items using this schema, it will only match
 * items that have the same schema. Items stored via libgnome-keyring with the
 * `GNOME_KEYRING_ITEM_NETWORK_PASSWORD` item type will match.
 *
 * The following attributes exist in the schema:
 *
 * ### Attributes:
 *
 * <table>
 *     <tr>
 *         <td><tt>user</tt>:</td>
 *         <td>The user name (string).</td>
 *     </tr>
 *     <tr>
 *         <td><tt>domain</tt>:</td>
 *         <td>The login domain or realm (string).</td></tr>
 *     <tr>
 *         <td><tt>object</tt>:</td>
 *         <td>The object or path (string).</td>
 *     </tr>
 *     <tr>
 *         <td><tt>protocol</tt>:</td>
 *         <td>The protocol (a string like 'http').</td>
 *     </tr>
 *     <tr>
 *         <td><tt>port</tt>:</td>
 *         <td>The network port (integer).</td>
 *     </tr>
 *     <tr>
 *         <td><tt>server</tt>:</td>
 *         <td>The hostname or server (string).</td>
 *     </tr>
 *     <tr>
 *         <td><tt>authtype</tt>:</td>
 *         <td>The authentication type (string).</td>
 *     </tr>
 * </table>
 *
 * Since: 0.18.6
 */
typedef enum
{
	SECRET_SCHEMA_TYPE_NOTE,
	SECRET_SCHEMA_TYPE_COMPAT_NETWORK,
} SecretSchemaType;

const SecretSchema *secret_get_schema (SecretSchemaType type);

G_END_DECLS

#endif /* __SECRET_SCHEMAS_H___ */
