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

#ifndef __GSECRET_DATA_H__
#define __GSECRET_DATA_H__

#include <gio/gio.h>

G_BEGIN_DECLS

#define GSECRET_TYPE_DATA            (gsecret_service_get_type ())

typedef struct _GSecretData        GSecretData;

GType               gsecret_data_get_type           (void) G_GNUC_CONST;

GSecretData*        gsecret_data_new                (const gchar *secret,
                                                     gssize length,
                                                     const gchar *content_type);

GSecretData*        gsecret_data_new_full           (gchar *secret,
                                                     gssize length,
                                                     const gchar *content_type,
                                                     GDestroyNotify destroy);

const gchar*        gsecret_data_get                (GSecretData *data,
                                                     gsize *length);

const gchar*        gsecret_data_get_content_type   (GSecretData *data);

GSecretData*        gsecret_data_ref                (GSecretData *data);

void                gsecret_data_unref              (GSecretData *data);

G_END_DECLS

#endif /* __G_SERVICE_H___ */
