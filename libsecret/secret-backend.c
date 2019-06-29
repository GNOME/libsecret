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

#include "config.h"

#include "secret-backend.h"
#include "secret-private.h"

/**
 * SECTION:secret-backend
 * @title: SecretBackend
 * @short_description: A backend implementation of password storage
 *
 * #SecretBackend represents a backend implementation of password
 * storage.
 *
 * Stability: Stable
 */

/**
 * SecretBackend:
 *
 * An object representing a backend implementation of password storage.
 */

/**
 * SecretBackendInterface:
 * @parent_iface: the parent interface
 * @store: implementation of secret_password_store(), required
 * @store_finish: implementation of secret_password_store_finish(), required
 * @lookup: implementation of secret_password_lookup(), required
 * @lookup_finish: implementation of secret_password_lookup_finish(), required
 * @clear: implementation of secret_password_clear(), required
 * @clear_finish: implementation of secret_password_clear_finish(), required
 * @search: implementation of secret_password_search(), required
 * @search_finish: implementation of secret_password_search_finish(), required
 *
 * The interface for #SecretBackend.
 */

/**
 * SecretBackendFlags:
 * @SECRET_BACKEND_NONE: no flags for initializing the #SecretBackend
 * @SECRET_BACKEND_OPEN_SESSION: establish a session for transfer of secrets
 *                               while initializing the #SecretBackend
 * @SECRET_BACKEND_LOAD_COLLECTIONS: load collections while initializing the
 *                                   #SecretBackend
 *
 * Flags which determine which parts of the #SecretBackend are initialized.
 */

G_DEFINE_INTERFACE_WITH_CODE (SecretBackend, secret_backend, G_TYPE_OBJECT,
			      g_type_interface_add_prerequisite(g_define_type_id, G_TYPE_ASYNC_INITABLE);
);

static void
secret_backend_default_init (SecretBackendInterface *iface)
{
	/**
	 * SecretBackend:flags:
	 *
	 * A set of flags describing which parts of the secret backend have
	 * been initialized.
	 */
	g_object_interface_install_property (iface,
	             g_param_spec_flags ("flags", "Flags", "Service flags",
	                                 secret_service_flags_get_type (), SECRET_SERVICE_NONE,
	                                 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

void
_secret_backend_ensure_extension_point (void)
{
	GIOExtensionPoint *ep;
	static gboolean registered = FALSE;

	if (registered)
		return;

	ep = g_io_extension_point_register (SECRET_BACKEND_EXTENSION_POINT_NAME);
	g_io_extension_point_set_required_type (ep, SECRET_TYPE_BACKEND);

	registered = TRUE;
}
