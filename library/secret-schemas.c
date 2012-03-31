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

static const SecretSchema network_schema = {
	"org.gnome.keyring.NetworkPassword",
	SECRET_SCHEMA_DONT_MATCH_NAME,
	{
		{  "user", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "domain", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "object", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "protocol", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "port", SECRET_SCHEMA_ATTRIBUTE_INTEGER },
		{  "server", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "authtype", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "NULL", 0 },
	}
};

const SecretSchema *  SECRET_SCHEMA_COMPAT_NETWORK = &network_schema;
