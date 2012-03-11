/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2012 Red Hat Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#ifndef SECRET_API_SUBJECT_TO_CHANGE
#error "This API has not yet reached stability."
#endif

#ifndef __SECRET_H__
#define __SECRET_H__

#include <glib.h>

#define __SECRET_INSIDE_HEADER__

#include <secret/secret-collection.h>
#include <secret/secret-enum-types.h>
#include <secret/secret-item.h>
#include <secret/secret-password.h>
#include <secret/secret-prompt.h>
#include <secret/secret-schema.h>
#include <secret/secret-service.h>
#include <secret/secret-value.h>

#undef __SECRET_INSIDE_HEADER__

#endif /* __SECRET_H__ */
