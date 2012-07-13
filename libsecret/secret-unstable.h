/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2012 Red Hat Inc.
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

#ifndef SECRET_API_SUBJECT_TO_CHANGE
#error "This API has not yet reached stability. Define SECRET_API_SUBJECT_TO_CHANGE to acknowledge"
#endif

#ifndef __SECRET_UNSTABLE_H__
#define __SECRET_UNSTABLE_H__

#include <glib.h>

#include <libsecret/secret.h>

#define __SECRET_INSIDE_HEADER__

#include <libsecret/secret-attributes.h>
#include <libsecret/secret-collection.h>
#include <libsecret/secret-enum-types.h>
#include <libsecret/secret-item.h>
#include <libsecret/secret-paths.h>
#include <libsecret/secret-prompt.h>
#include <libsecret/secret-service.h>
#include <libsecret/secret-value.h>

#undef __SECRET_INSIDE_HEADER__

#endif /* __SECRET_UNSTABLE_H__ */
