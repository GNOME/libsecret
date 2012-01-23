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

#ifndef __GSECRET_VALUE_H__
#define __GSECRET_VALUE_H__

#include <gio/gio.h>

#include "gsecret-types.h"

G_BEGIN_DECLS

#define             GSECRET_TYPE_VALUE              (gsecret_value_get_type ())

GType               gsecret_value_get_type          (void) G_GNUC_CONST;

GSecretValue*       gsecret_value_new               (const gchar *secret,
                                                     gssize length,
                                                     const gchar *content_type);

GSecretValue*       gsecret_value_new_full          (gchar *secret,
                                                     gssize length,
                                                     const gchar *content_type,
                                                     GDestroyNotify destroy);

const gchar*        gsecret_value_get                (GSecretValue *value,
                                                     gsize *length);

const gchar*        gsecret_value_get_content_type   (GSecretValue *value);

GSecretValue*       gsecret_value_ref                (GSecretValue *value);

void                gsecret_value_unref              (gpointer value);

G_END_DECLS

#endif /* __G_SERVICE_H___ */
