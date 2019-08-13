/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2019 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Daiki Ueno
 */

#if !defined (__SECRET_INSIDE_HEADER__) && !defined (SECRET_COMPILATION)
#error "Only <libsecret/secret.h> can be included directly."
#endif

#ifndef __SECRET_FILE_BACKEND_H__
#define __SECRET_FILE_BACKEND_H__

G_BEGIN_DECLS

#include <glib-object.h>

#define SECRET_TYPE_FILE_BACKEND (secret_file_backend_get_type ())
G_DECLARE_FINAL_TYPE (SecretFileBackend, secret_file_backend, SECRET, FILE_BACKEND, GObject)

G_END_DECLS

#endif /* __SECRET_FILE_BACKEND_H__ */
