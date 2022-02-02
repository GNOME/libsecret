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

#include "config.h"

#include "secret-schema.h"
#include "secret-schemas.h"

static const SecretSchema note_schema = {
	"org.gnome.keyring.Note",
	SECRET_SCHEMA_NONE,
	{
		{  NULL, 0 },
	}
};

const SecretSchema *  SECRET_SCHEMA_NOTE = &note_schema;

static const SecretSchema network_schema = {
	"org.gnome.keyring.NetworkPassword",
	SECRET_SCHEMA_NONE,
	{
		{  "user", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "domain", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "object", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "protocol", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "port", SECRET_SCHEMA_ATTRIBUTE_INTEGER },
		{  "server", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "authtype", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  NULL, 0 },
	}
};

const SecretSchema *  SECRET_SCHEMA_COMPAT_NETWORK = &network_schema;

/**
 * secret_get_schema:
 * @type: type of schema to get
 *
 * Get a secret storage schema of the given @type.
 *
 * C code may access the schemas (such as %SECRET_SCHEMA_NOTE) directly, but
 * language bindings cannot, and must use this accessor.
 *
 * Returns: (transfer none): schema type
 *
 * Since: 0.18.6
 */
const SecretSchema *
secret_get_schema (SecretSchemaType type)
{
	switch (type) {
	case SECRET_SCHEMA_TYPE_NOTE:
		return SECRET_SCHEMA_NOTE;
	case SECRET_SCHEMA_TYPE_COMPAT_NETWORK:
		return SECRET_SCHEMA_COMPAT_NETWORK;
	default:
		g_assert_not_reached ();
	}
	g_return_val_if_reached (NULL);
}
