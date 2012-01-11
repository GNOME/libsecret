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

#ifndef __GSECRET_SERVICE_H__
#define __GSECRET_SERVICE_H__

#include <gio/gio.h>

G_BEGIN_DECLS

#define GSECRET_TYPE_SERVICE            (gsecret_service_get_type ())
#define GSECRET_SERVICE(inst)           (GSECRET_TYPE_CHECK_INSTANCE_CAST ((inst), GSECRET_TYPE_SERVICE, GSecretService))
#define GSECRET_SERVICE_CLASS(class)    (GSECRET_TYPE_CHECK_CLASS_CAST ((class), GSECRET_TYPE_SERVICE, GSecretServiceClass))
#define GSECRET_IS_SERVICE(inst)        (GSECRET_TYPE_CHECK_INSTANCE_TYPE ((inst), GSECRET_TYPE_SERVICE))
#define GSECRET_IS_SERVICE_CLASS(class) (GSECRET_TYPE_CHECK_CLASS_TYPE ((class), GSECRET_TYPE_SERVICE))
#define GSECRET_SERVICE_GET_CLASS(inst) (GSECRET_TYPE_INSTANCE_GET_CLASS ((inst), GSECRET_TYPE_SERVICE, GSecretServiceClass))

typedef struct _GSecretServiceClass   GSecretServiceClass;
typedef struct _GSecretServicePrivate GSecretServicePrivate;

struct _GSecretServiceClass {
	GDBusProxyClass parent_class;

	GType collection_type;
	GType item_type;

	padding;
};

struct _GSecretService {
	GDBusProxy parent_instance;
	GSecretServicePrivate *pv;
};

GType             gsecret_service_get_type                   (void) G_GNUC_CONST;

GSecretService*     gsecret_collection_xxx_new                   (void);

GSecretCollection*  gsecret_collection_instance              (GDBusConnection *connection,
                                                              const gchar *object_path);

                    gsecret_collection_delete
                    gsecret_collection_search

                    GSecretItem*        gsecret_collection_create_item                     (xxxx);


                    gsecret_collection_get_items
                    gsecret_collection_get_label
                    gsecret_collection_set_label
                    gsecret_collection_get_locked
                    gsecret_collection_get_created
                    gsecret_collection_get_modified

G_END_DECLS

#endif /* __G_SERVICE_H___ */
