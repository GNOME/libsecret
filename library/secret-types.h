/* libsecret - GLib wrapper for Secret Service
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

#ifndef __SECRET_TYPES_H__
#define __SECRET_TYPES_H__

#include <glib.h>

G_BEGIN_DECLS

#define         SECRET_ERROR                (secret_error_get_quark ())

GQuark          secret_error_get_quark      (void) G_GNUC_CONST;

typedef enum {
	SECRET_ERROR_PROTOCOL = 1,
} SecretError;

typedef enum {
	SECRET_ATTRIBUTE_BOOLEAN,
	SECRET_ATTRIBUTE_STRING,
	SECRET_ATTRIBUTE_INTEGER
} SecretSchemaType;

typedef struct {
	const gchar *schema_name;
	struct {
		const gchar* name;
		SecretSchemaType type;
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
} SecretSchema;

typedef struct _SecretCollection  SecretCollection;
typedef struct _SecretItem        SecretItem;
typedef struct _SecretPrompt      SecretPrompt;
typedef struct _SecretService     SecretService;
typedef struct _SecretValue       SecretValue;

G_END_DECLS

#endif /* __G_SERVICE_H___ */
