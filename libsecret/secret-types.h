/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
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

#if !defined (__SECRET_INSIDE_HEADER__) && !defined (SECRET_COMPILATION)
#error "Only <libsecret/secret.h> can be included directly."
#endif

#ifndef __SECRET_TYPES_H__
#define __SECRET_TYPES_H__

#include <glib.h>

G_BEGIN_DECLS

#define         SECRET_ERROR                (secret_error_get_quark ())

GQuark          secret_error_get_quark      (void) G_GNUC_CONST;

typedef enum {
	SECRET_ERROR_PROTOCOL = 1,
	SECRET_ERROR_IS_LOCKED = 2,
	SECRET_ERROR_NO_SUCH_OBJECT = 3,
	SECRET_ERROR_ALREADY_EXISTS = 4,
	SECRET_ERROR_INVALID_FILE_FORMAT = 5,
	SECRET_ERROR_MISMATCHED_SCHEMA = 6,
	SECRET_ERROR_NO_MATCHING_ATTRIBUTE = 7,
	SECRET_ERROR_WRONG_TYPE = 8,
	SECRET_ERROR_EMPTY_TABLE = 9,
} SecretError;

#define SECRET_COLLECTION_DEFAULT "default"

#define SECRET_COLLECTION_SESSION "session"

typedef enum {
	SECRET_SEARCH_NONE = 0,
	SECRET_SEARCH_ALL = 1 << 1,
	SECRET_SEARCH_UNLOCK = 1 << 2,
	SECRET_SEARCH_LOAD_SECRETS = 1 << 3,
} SecretSearchFlags;

G_END_DECLS

#endif /* __G_SERVICE_H___ */
