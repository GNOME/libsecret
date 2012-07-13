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

#ifndef __SECRET_H__
#define __SECRET_H__

#include <glib.h>

#define __SECRET_INSIDE_HEADER__

#include "secret-password.h"
#include "secret-schema.h"
#include "secret-schemas.h"
#include "secret-types.h"

/* This symbol is defined by the secret-unstable.pc pkg-config file */
#ifdef SECRET_WITH_UNSTABLE

#ifndef SECRET_API_SUBJECT_TO_CHANGE
#warning "This API has not yet reached stability. Define SECRET_API_SUBJECT_TO_CHANGE to acknowledge"
#endif

#include "secret-attributes.h"
#include "secret-collection.h"
#include "secret-enum-types.h"
#include "secret-item.h"
#include "secret-paths.h"
#include "secret-prompt.h"
#include "secret-service.h"
#include "secret-value.h"

#endif /* SECRET_WITH_UNSTABLE */

#undef __SECRET_INSIDE_HEADER__

#endif /* __SECRET_H__ */
