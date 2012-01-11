/* GSecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#ifndef __GSECRET_TYPES_H__
#define __GSECRET_TYPES_H__

#include <glib.h>

G_BEGIN_DECLS

#define         GSECRET_ERROR                (gsecret_error_get_quark ())

GQuark          gsecret_error_get_quark      (void) G_GNUC_CONST;

typedef enum {
	GSECRET_ERROR_PROTOCOL = 1,
} GSecretError;

typedef enum {
	GSECRET_ATTRIBUTE_BOOLEAN,
	GSECRET_ATTRIBUTE_STRING,
	GSECRET_ATTRIBUTE_INTEGER
} GSecretSchemaType;

typedef struct {
	const gchar *schema_name;
	struct {
		const gchar* name;
		GSecretSchemaType type;
	} attributes[32];

	/* <private> */
	gpointer reserved1;
	gpointer reserved2;
	gpointer reserved3;
	gpointer reserved4;
	gpointer reserved5;
	gpointer reserved6;
	gpointer reserved7;
	gpointer reserved8;
} GSecretSchema;

typedef struct _GSecretCollection  GSecretCollection;
typedef struct _GSecretItem        GSecretItem;
typedef struct _GSecretPrompt      GSecretPrompt;
typedef struct _GSecretService     GSecretService;
typedef struct _GSecretValue       GSecretValue;

G_END_DECLS

#endif /* __G_SERVICE_H___ */
