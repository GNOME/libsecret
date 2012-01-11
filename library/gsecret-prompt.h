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

#ifndef __GSECRET_PROMPT_H__
#define __GSECRET_PROMPT_H__

#include <gio/gio.h>

#include "gsecret-types.h"

G_BEGIN_DECLS

#define GSECRET_TYPE_PROMPT            (gsecret_prompt_get_type ())
#define GSECRET_PROMPT(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), GSECRET_TYPE_PROMPT, GSecretPrompt))
#define GSECRET_PROMPT_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), GSECRET_TYPE_PROMPT, GSecretPromptClass))
#define GSECRET_IS_PROMPT(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), GSECRET_TYPE_PROMPT))
#define GSECRET_IS_PROMPT_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), GSECRET_TYPE_PROMPT))
#define GSECRET_PROMPT_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), GSECRET_TYPE_PROMPT, GSecretPromptClass))

typedef struct _GSecretPromptClass   GSecretPromptClass;
typedef struct _GSecretPromptPrivate GSecretPromptPrivate;

struct _GSecretPromptClass {
	GDBusProxyClass parent_class;

	gpointer padding[8];
};

struct _GSecretPrompt {
	GDBusProxy parent_instance;
	GSecretPromptPrivate *pv;
};

GType               gsecret_prompt_get_type                  (void) G_GNUC_CONST;

GSecretPrompt *     gsecret_prompt_instance                  (GSecretService *service,
                                                              const gchar *prompt_path);

gboolean            gsecret_prompt_run                       (GSecretPrompt *self,
                                                              gulong window_id,
                                                              GCancellable *cancellable,
                                                              GError **error);

gboolean            gsecret_prompt_perform_sync              (GSecretPrompt *self,
                                                              gulong window_id,
                                                              GCancellable *cancellable,
                                                              GError **error);

void                gsecret_prompt_perform                   (GSecretPrompt *self,
                                                              gulong window_id,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

gboolean            gsecret_prompt_perform_finish            (GSecretPrompt *self,
                                                              GAsyncResult *result,
                                                              GError **error);

GVariant *          gsecret_prompt_get_result_value          (GSecretPrompt *self);

G_END_DECLS

#endif /* __G_SERVICE_H___ */
