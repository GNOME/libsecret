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

G_END_DECLS

#endif /* __G_SERVICE_H___ */
