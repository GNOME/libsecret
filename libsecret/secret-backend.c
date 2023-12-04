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

#ifdef WITH_CRYPTO
#include "secret-file-backend.h"
#endif

#include "secret-private.h"

#include "libsecret/secret-enum-types.h"

/**
 * SecretBackend:
 *
 * #SecretBackend represents a backend implementation of password
 * storage.
 *
 * Stability: Stable
 *
 * Since: 0.19.0
 */

/**
 * SecretBackendInterface:
 * @parent_iface: the parent interface
 * @ensure_for_flags: implementation of reinitialization step in constructor, optional
 * @ensure_for_flags_finish: implementation of reinitialization step in constructor, optional
 * @store: implementation of [func@password_store], required
 * @store_finish: implementation of [func@password_store_finish], required
 * @lookup: implementation of [func@password_lookup], required
 * @lookup_finish: implementation of [func@password_lookup_finish], required
 * @clear: implementation of [func@password_clear], required
 * @clear_finish: implementation of [func@password_clear_finish], required
 * @search: implementation of [func@password_search], required
 * @search_finish: implementation of [func@password_search_finish], required
 *
 * The interface for #SecretBackend.
 *
 * Since: 0.19.0
 */

/**
 * SecretBackendFlags:
 * @SECRET_BACKEND_NONE: no flags for initializing the #SecretBackend
 * @SECRET_BACKEND_OPEN_SESSION: establish a session for transfer of secrets
 *   while initializing the #SecretBackend
 * @SECRET_BACKEND_LOAD_COLLECTIONS: load collections while initializing the
 *   #SecretBackend
 *
 * Flags which determine which parts of the #SecretBackend are initialized.
 *
 * Since: 0.19.0
 */

/**
 * SECRET_BACKEND_EXTENSION_POINT_NAME:
 *
 * Extension point for the secret backend.
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
	 *
	 * Since: 0.19.0
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

G_LOCK_DEFINE (backend_instance);
static gpointer backend_instance = NULL;

static SecretBackend *
backend_get_instance (void)
{
	SecretBackend *instance = NULL;

	G_LOCK (backend_instance);
	if (backend_instance != NULL)
		instance = g_object_ref (backend_instance);
	G_UNLOCK (backend_instance);

	return instance;
}

void
_secret_backend_uncache_instance (void)
{
	SecretBackend *instance = NULL;

	G_LOCK (backend_instance);
	instance = backend_instance;
	backend_instance = NULL;
	G_UNLOCK (backend_instance);

	if (instance != NULL)
		g_object_unref (instance);
}

static GType
backend_get_impl_type (void)
{
	const gchar *envvar;
	const gchar *extension_name;
	GIOExtension *e;
	GIOExtensionPoint *ep;

	g_type_ensure (secret_service_get_type ());
#ifdef WITH_CRYPTO
	g_type_ensure (secret_file_backend_get_type ());
#endif

#ifdef WITH_CRYPTO
	if ((g_file_test ("/.flatpak-info", G_FILE_TEST_EXISTS) || g_getenv ("SNAP_NAME") != NULL) &&
	    _secret_file_backend_check_portal_version ())
		extension_name = "file";
	else
#endif
	{
		envvar = g_getenv ("SECRET_BACKEND");
		if (envvar == NULL || *envvar == '\0')
			extension_name = "service";
		else
			extension_name = envvar;
	}

	ep = g_io_extension_point_lookup (SECRET_BACKEND_EXTENSION_POINT_NAME);
	e = g_io_extension_point_get_extension_by_name (ep, extension_name);
	if (e == NULL) {
		g_warning ("Backend extension \"%s\" from SECRET_BACKEND_EXTENSION_POINT_NAME environment variable not found.", extension_name);
		return G_TYPE_NONE;
	}

	return g_io_extension_get_type (e);
}

static void
on_ensure_for_flags (GObject *source_object,
		     GAsyncResult *result,
		     gpointer user_data)
{
	SecretBackendInterface *iface;
	SecretBackend *self = SECRET_BACKEND (source_object);
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	iface = SECRET_BACKEND_GET_IFACE (self);
	if (iface->ensure_for_flags_finish) {
		if (!iface->ensure_for_flags_finish (self, result, &error)) {
			g_task_return_error (task, error);
			g_object_unref (task);
			return;
		}
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

/**
 * secret_backend_get:
 * @flags: flags for which service functionality to ensure is initialized
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Get a #SecretBackend instance.
 *
 * If such a backend already exists, then the same backend is returned.
 *
 * If @flags contains any flags of which parts of the secret backend to
 * ensure are initialized, then those will be initialized before completing.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Since: 0.19.0
 */
void
secret_backend_get (SecretBackendFlags flags,
		    GCancellable *cancellable,
		    GAsyncReadyCallback callback,
		    gpointer user_data)
{
	SecretBackend *backend = NULL;
	SecretBackendInterface *iface;
	GTask *task;

	backend = backend_get_instance ();

	/* Create a whole new backend */
	if (backend == NULL) {
		GType impl_type = backend_get_impl_type ();
		g_return_if_fail (g_type_is_a (impl_type, G_TYPE_ASYNC_INITABLE));
		g_async_initable_new_async (impl_type,
					    G_PRIORITY_DEFAULT,
					    cancellable, callback, user_data,
					    "flags", flags,
					    NULL);

	/* Just have to ensure that the backend matches flags */
	} else {
		task = g_task_new (backend, cancellable, callback, user_data);
		iface = SECRET_BACKEND_GET_IFACE (backend);
		if (iface->ensure_for_flags) {
			g_task_set_source_tag (task, secret_backend_get);
			iface->ensure_for_flags (backend, flags, cancellable,
						 on_ensure_for_flags, task);
		} else {
			g_task_return_boolean (task, TRUE);
			g_object_unref (task);
		}
		g_object_unref (backend);
	}
}

/**
 * secret_backend_get_finish:
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Complete an asynchronous operation to get a #SecretBackend.
 *
 * Returns: (transfer full): a new reference to a #SecretBackend proxy, which
 *   should be released with [method@GObject.Object.unref].
 *
 * Since: 0.19.0
 */
SecretBackend *
secret_backend_get_finish (GAsyncResult *result,
			   GError **error)
{
	GTask *task;
	GObject *backend = NULL;
	GObject *source_object;

	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	task = G_TASK (result);
	source_object = g_task_get_source_object (task);

	g_return_val_if_fail (g_task_is_valid (result, source_object), NULL);

	/* Just ensuring that the backend matches flags */
	if (g_task_get_source_tag (task) == secret_backend_get) {
		if (g_task_had_error (task)) {
			g_task_propagate_pointer (task, error);
		} else {
			backend = g_object_ref (source_object);
		}

	/* Creating a whole new backend */
	} else {
		backend = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object), result, error);
		if (backend) {
			G_LOCK (backend_instance);
			if (backend_instance == NULL)
				backend_instance = backend;
			G_UNLOCK (backend_instance);
		}
	}

	if (backend == NULL)
		return NULL;

	return SECRET_BACKEND (backend);
}
