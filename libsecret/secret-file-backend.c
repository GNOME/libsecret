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
#include "secret-file-backend.h"
#include "secret-file-collection.h"
#include "secret-file-item.h"
#include "secret-private.h"
#include "secret-retrievable.h"

#include "egg/egg-secure-memory.h"
#include "egg/egg-tpm2.h"

EGG_SECURE_DECLARE (secret_file_backend);

#include <gio/gunixfdlist.h>
#include <gio/gunixinputstream.h>
#include <glib-unix.h>

#define PORTAL_BUS_NAME "org.freedesktop.portal.Desktop"
#define PORTAL_OBJECT_PATH "/org/freedesktop/portal/desktop"
#define PORTAL_REQUEST_INTERFACE "org.freedesktop.portal.Request"
#define PORTAL_REQUEST_PATH_PREFIX "/org/freedesktop/portal/desktop/request/"
#define PORTAL_SECRET_INTERFACE "org.freedesktop.portal.Secret"
#define PORTAL_SECRET_VERSION 1

static void secret_file_backend_async_initable_iface (GAsyncInitableIface *iface);
static void secret_file_backend_backend_iface (SecretBackendInterface *iface);

struct _SecretFileBackend {
	GObject parent;
	SecretFileCollection *collection;
	SecretServiceFlags init_flags;
};

G_DEFINE_TYPE_WITH_CODE (SecretFileBackend, secret_file_backend, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, secret_file_backend_async_initable_iface);
			 G_IMPLEMENT_INTERFACE (SECRET_TYPE_BACKEND, secret_file_backend_backend_iface);
			 _secret_backend_ensure_extension_point ();
			 g_io_extension_point_implement (SECRET_BACKEND_EXTENSION_POINT_NAME,
							 g_define_type_id,
							 "file",
							 0)
);

enum {
	PROP_0,
	PROP_FLAGS
};

/* Gets the GFile for this backend and makes sure the parent dirs exist */
static GFile *
get_secret_file (GCancellable *cancellable, GError **error)
{
	const char *envvar = NULL;
	char *path = NULL;
	GFile *file = NULL;
	GFile *dir = NULL;
	gboolean ret;

	envvar = g_getenv ("SECRET_FILE_TEST_PATH");
	if (envvar != NULL && *envvar != '\0') {
		path = g_strdup (envvar);
	} else {
		path = g_build_filename (g_get_user_data_dir (),
		                         "keyrings",
		                         SECRET_COLLECTION_DEFAULT ".keyring",
		                         NULL);
	}

	file = g_file_new_for_path (path);
	g_free (path);

	dir = g_file_get_parent (file);
	if (dir == NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		             "not a valid path");
		g_object_unref (file);
		return NULL;
	}

	ret = g_file_make_directory_with_parents (dir, cancellable, error);
	g_object_unref (dir);
	if (!ret) {
		if (!g_error_matches (*error, G_IO_ERROR, G_IO_ERROR_EXISTS)) {
			g_object_unref (file);
			return NULL;
		}

		g_clear_error (error);
	}

	return file;
}

static void
secret_file_backend_init (SecretFileBackend *self)
{
}

static void
secret_file_backend_set_property (GObject *object,
                                  guint prop_id,
                                  const GValue *value,
                                  GParamSpec *pspec)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (object);

	switch (prop_id) {
	case PROP_FLAGS:
		self->init_flags = g_value_get_flags (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
secret_file_backend_get_property (GObject *object,
                                  guint prop_id,
                                  GValue *value,
                                  GParamSpec *pspec)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (object);

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_flags (value, self->init_flags);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
secret_file_backend_finalize (GObject *object)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (object);

	g_clear_object (&self->collection);

	G_OBJECT_CLASS (secret_file_backend_parent_class)->finalize (object);
}

static void
secret_file_backend_class_init (SecretFileBackendClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->set_property = secret_file_backend_set_property;
	object_class->get_property = secret_file_backend_get_property;
	object_class->finalize = secret_file_backend_finalize;

	/**
	 * SecretFileBackend:flags:
	 *
	 * A set of flags describing which parts of the secret file have
	 * been initialized.
	 */
	g_object_class_override_property (object_class, PROP_FLAGS, "flags");
}

static void
on_collection_new_async (GObject *source_object,
			 GAsyncResult *result,
			 gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretFileBackend *self = g_task_get_source_object (task);
	GObject *object;
	GError *error = NULL;

	object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
					      result,
					      &error);
	if (object == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	self->collection = SECRET_FILE_COLLECTION (object);
	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

typedef struct {
	gint io_priority;
	GFile *file;
	GInputStream *stream;
	gchar *buffer;
	GDBusConnection *connection;
	gchar *request_path;
	guint portal_signal_id;
	GCancellable *cancellable;
	gulong cancellable_signal_id;
	gchar *sender;
} InitClosure;

static void
init_closure_free (gpointer data)
{
	InitClosure *init = data;
	g_object_unref (init->file);
	g_clear_object (&init->stream);
	g_clear_pointer (&init->buffer, egg_secure_free);
	g_clear_object (&init->connection);
	g_clear_pointer (&init->request_path, g_free);
	g_clear_pointer (&init->sender, g_free);
	if (init->cancellable_signal_id) {
		g_cancellable_disconnect (init->cancellable, init->cancellable_signal_id);
		init->cancellable_signal_id = 0;
	}
	/* Note: do not cancel the cancellable here! That's for the API user to
	 * do. We're just keeping track of it here so we can disconnect.
	 */
	g_clear_object (&init->cancellable);
	g_free (init);
}

#define PASSWORD_SIZE 64

static void
on_read_all (GObject *source_object,
	     GAsyncResult *result,
	     gpointer user_data)
{
	GInputStream *stream = G_INPUT_STREAM (source_object);
	GTask *task = G_TASK (user_data);
	InitClosure *init = g_task_get_task_data (task);
	gsize bytes_read;
	SecretValue *password;
	GError *error = NULL;

	if (!g_input_stream_read_all_finish (stream, result, &bytes_read,
					     &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	if (bytes_read != PASSWORD_SIZE) {
		g_task_return_new_error (task,
					 SECRET_ERROR,
					 SECRET_ERROR_PROTOCOL,
					 "invalid password returned from portal");
		g_object_unref (task);
		return;
	}

	password = secret_value_new (init->buffer, bytes_read, "text/plain");
	g_async_initable_new_async (SECRET_TYPE_FILE_COLLECTION,
				    init->io_priority,
				    g_task_get_cancellable (task),
				    on_collection_new_async,
				    task,
				    "file", g_object_ref (init->file),
				    "password", password,
				    NULL);
	g_object_unref (init->file);
	secret_value_unref (password);
}

static void
on_portal_response (GDBusConnection *connection,
		    const gchar *sender_name,
		    const gchar *object_path,
		    const gchar *interface_name,
		    const gchar *signal_name,
		    GVariant *parameters,
		    gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	InitClosure *init = g_task_get_task_data (task);
	guint32 response;

	if (init->cancellable_signal_id) {
		g_cancellable_disconnect (g_task_get_cancellable (task), init->cancellable_signal_id);
		init->cancellable_signal_id = 0;
	}

	g_dbus_connection_signal_unsubscribe (connection,
					      init->portal_signal_id);

	g_variant_get (parameters, "(ua{sv})", &response, NULL);

	switch (response) {
	case 0:
		init->buffer = egg_secure_alloc (PASSWORD_SIZE);
		g_input_stream_read_all_async (init->stream,
					       init->buffer, PASSWORD_SIZE,
					       G_PRIORITY_DEFAULT,
					       g_task_get_cancellable (task),
					       on_read_all,
					       task);
		break;
	case 1:
		g_task_return_new_error (task,
					 G_IO_ERROR,
					 G_IO_ERROR_CANCELLED,
					 "user interaction cancelled");
		g_object_unref (task);
		break;
	case 2:
		g_task_return_new_error (task,
					 G_IO_ERROR,
					 G_IO_ERROR_FAILED,
					 "user interaction failed");
		g_object_unref (task);
		break;
	}
}

static void
on_portal_request_close (GObject *source_object,
			 GAsyncResult *result,
			 gpointer user_data)
{
	GDBusConnection *connection = G_DBUS_CONNECTION (source_object);
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	if (!g_dbus_connection_call_finish (connection, result, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
on_portal_cancel (GCancellable *cancellable,
		  gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	InitClosure *init = g_task_get_task_data (task);

	g_dbus_connection_call (init->connection,
				PORTAL_BUS_NAME,
				init->request_path,
				PORTAL_REQUEST_INTERFACE,
				"Close",
				NULL,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				cancellable,
				on_portal_request_close,
				task);
}

static void
on_portal_retrieve_secret (GObject *source_object,
			   GAsyncResult *result,
			   gpointer user_data)
{
	GDBusConnection *connection = G_DBUS_CONNECTION (source_object);
	GTask *task = G_TASK (user_data);
	InitClosure *init = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GVariant *reply;
	GError *error = NULL;

	reply = g_dbus_connection_call_with_unix_fd_list_finish (connection,
								 NULL,
								 result,
								 &error);
	if (reply == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_variant_unref (reply);

	if (cancellable != NULL)
		init->cancellable_signal_id =
			g_cancellable_connect (cancellable,
					       G_CALLBACK (on_portal_cancel),
					       task,
					       NULL);
}

static void
on_bus_get (GObject *source_object,
	    GAsyncResult *result,
	    gpointer user_data)
{
	GDBusConnection *connection;
	GTask *task = G_TASK (user_data);
	InitClosure *init = g_task_get_task_data (task);
	GUnixFDList *fd_list;
	gint fds[2];
	gint fd_index;
	GVariantBuilder options;
	GError *error = NULL;
	gchar *token;

	connection = g_bus_get_finish (result, &error);
	if (connection == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	token = g_strdup_printf ("libsecret%d", g_random_int_range (0, G_MAXINT));

	init->connection = connection;
	init->sender = g_strdup (g_dbus_connection_get_unique_name (connection) + 1);
	/* We modify the string in place, see
	 * https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Request.html */
	g_strdelimit (init->sender, ".", '_');
	init->request_path = g_strconcat (PORTAL_REQUEST_PATH_PREFIX, init->sender, "/", token, NULL);

	if (!g_unix_open_pipe (fds, FD_CLOEXEC, &error)) {
		g_object_unref (connection);
		g_task_return_error (task, error);
		g_object_unref (task);
		g_free (token);
		return;
	}

	fd_list = g_unix_fd_list_new ();
	fd_index = g_unix_fd_list_append (fd_list, fds[1], &error);
	close (fds[1]);
	if (fd_index < 0) {
		close (fds[0]);
		g_object_unref (fd_list);
		g_object_unref (connection);
		g_task_return_error (task, error);
		g_object_unref (task);
		g_free (token);
		return;
	}

	init->stream = g_unix_input_stream_new (fds[0], TRUE);

	g_variant_builder_init (&options, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&options, "{sv}", "handle_token", g_variant_new_string (token));

	init->portal_signal_id =
		g_dbus_connection_signal_subscribe (connection,
						    PORTAL_BUS_NAME,
						    PORTAL_REQUEST_INTERFACE,
						    "Response",
						    init->request_path,
						    NULL,
						    G_DBUS_SIGNAL_FLAGS_NO_MATCH_RULE,
						    on_portal_response,
						    task,
						    NULL);

	g_dbus_connection_call_with_unix_fd_list (connection,
						  PORTAL_BUS_NAME,
						  PORTAL_OBJECT_PATH,
						  PORTAL_SECRET_INTERFACE,
						  "RetrieveSecret",
						  g_variant_new ("(h@a{sv})",
								 fd_index,
								 g_variant_builder_end (&options)),
						  G_VARIANT_TYPE ("(o)"),
						  G_DBUS_CALL_FLAGS_NONE,
						  -1,
						  fd_list,
						  g_task_get_cancellable (task),
						  on_portal_retrieve_secret,
						  task);
	g_object_unref (fd_list);
	g_free (token);
}

#ifdef WITH_TPM
static GBytes *
load_password_from_tpm (GFile *file, GCancellable *cancellable, GError **error)
{
	EggTpm2Context *context = NULL;
	char *path = NULL;
	char *tpm2_file_path = NULL;
	GFile *tpm2_file = NULL;
	gboolean status;
	GBytes *encrypted = NULL;
	GBytes *decrypted = NULL;

	context = egg_tpm2_initialize (error);
	if (!context)
		return NULL;

	path = g_file_get_path (file);
	tpm2_file_path = g_strdup_printf ("%s.tpm2", path);
	g_free (path);

	tpm2_file = g_file_new_for_path (tpm2_file_path);
	status = g_file_test (tpm2_file_path, G_FILE_TEST_EXISTS);
	g_free (tpm2_file_path);

	if (!status) {
		gconstpointer contents;
		gsize size;

		encrypted = egg_tpm2_generate_master_password (context, error);
		if (!encrypted)
			return NULL;

		contents = g_bytes_get_data (encrypted, &size);
		status = g_file_replace_contents (tpm2_file,
		                                  contents,
		                                  size,
		                                  NULL,
		                                  FALSE,
		                                  G_FILE_CREATE_PRIVATE,
		                                  NULL,
		                                  cancellable,
		                                  error);
		if (!status)
			goto out;
	} else {
		char *contents;
		gsize length;

		status = g_file_load_contents (tpm2_file,
		                               cancellable,
		                               &contents,
		                               &length,
		                               NULL,
		                               error);
		if (!status)
			goto out;

		encrypted = g_bytes_new_take (contents, length);
	}

	decrypted = egg_tpm2_decrypt_master_password (context, encrypted, error);

out:
	g_clear_object (&tpm2_file);
	g_clear_pointer (&encrypted, g_bytes_unref);
	egg_tpm2_finalize (context);

	return decrypted;
}
#endif /* WITH_TPM */

static void
secret_file_backend_real_init_async (GAsyncInitable *initable,
				     int io_priority,
				     GCancellable *cancellable,
				     GAsyncReadyCallback callback,
				     gpointer user_data)
{
	const char *envvar = NULL;
	GFile *file = NULL;
	SecretValue *password;
	GTask *task;
	GError *error = NULL;
	InitClosure *init;

	task = g_task_new (initable, cancellable, callback, user_data);

	file = get_secret_file (cancellable, &error);
	if (file == NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
		g_object_unref (task);
		return;
	}

	envvar = g_getenv ("SECRET_FILE_TEST_PASSWORD");
	if (envvar != NULL && *envvar != '\0') {
		password = secret_value_new (envvar, -1, "text/plain");
		g_async_initable_new_async (SECRET_TYPE_FILE_COLLECTION,
					    io_priority,
					    cancellable,
					    on_collection_new_async,
					    task,
					    "file", file,
					    "password", password,
					    NULL);
		g_object_unref (file);
		secret_value_unref (password);
	} else if (g_file_test ("/.flatpak-info", G_FILE_TEST_EXISTS) || g_getenv ("SNAP_NAME") != NULL) {
		init = g_new0 (InitClosure, 1);
		init->io_priority = io_priority;
		init->file = file;
		if (cancellable)
			init->cancellable = g_object_ref (cancellable);
		g_task_set_task_data (task, init, init_closure_free);
		g_bus_get (G_BUS_TYPE_SESSION, cancellable, on_bus_get, task);
	} else {
#ifdef WITH_TPM
		GBytes *decrypted = NULL;
		gconstpointer data;
		gsize size;

		decrypted = load_password_from_tpm (file, cancellable, &error);
		if (!decrypted) {
			g_task_return_error (task, error);
			g_object_unref (task);
			return;
		}

		data = g_bytes_get_data (decrypted, &size);
		password = secret_value_new (data,size, "text/plain");
		g_bytes_unref (decrypted);
		g_async_initable_new_async (SECRET_TYPE_FILE_COLLECTION,
					    io_priority,
					    cancellable,
					    on_collection_new_async,
					    task,
					    "file", file,
					    "password", password,
					    NULL);

		g_object_unref (file);
		secret_value_unref (password);
		return;
#else
		g_task_return_new_error (task,
					 G_IO_ERROR,
					 G_IO_ERROR_INVALID_ARGUMENT,
					 "master password is not retrievable");
		g_object_unref (task);
#endif
	}
}

static gboolean
secret_file_backend_real_init_finish (GAsyncInitable *initable,
				      GAsyncResult *result,
				      GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, initable), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
secret_file_backend_async_initable_iface (GAsyncInitableIface *iface)
{
	iface->init_async = secret_file_backend_real_init_async;
	iface->init_finish = secret_file_backend_real_init_finish;
}

static void
on_collection_write (GObject *source_object,
		     GAsyncResult *result,
		     gpointer user_data)
{
	SecretFileCollection *collection =
		SECRET_FILE_COLLECTION (source_object);
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	if (!secret_file_collection_write_finish (collection, result, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
secret_file_backend_real_store (SecretBackend *backend,
				const SecretSchema *schema,
				GHashTable *attributes,
				const gchar *collection,
				const gchar *label,
				SecretValue *value,
				GCancellable *cancellable,
				GAsyncReadyCallback callback,
				gpointer user_data)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (backend);
	GTask *task;
	GError *error = NULL;

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return;

	task = g_task_new (self, cancellable, callback, user_data);

	if (!secret_file_collection_replace (self->collection,
					     attributes,
					     label,
					     value,
					     &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	secret_file_collection_write (self->collection,
				      cancellable,
				      on_collection_write,
				      task);
}

static gboolean
secret_file_backend_real_store_finish (SecretBackend *backend,
				       GAsyncResult *result,
				       GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
on_retrieve_secret (GObject *source_object,
		    GAsyncResult *result,
		    gpointer user_data)
{
	SecretRetrievable *retrievable = SECRET_RETRIEVABLE (source_object);
	GTask *task = G_TASK (user_data);
	SecretValue *value;
	GError *error;

	value = secret_retrievable_retrieve_secret_finish (retrievable,
							   result,
							   &error);
	g_object_unref (retrievable);
	if (value == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
	}
	g_task_return_pointer (task, value, secret_value_unref);
	g_object_unref (task);
}

static void
secret_file_backend_real_lookup (SecretBackend *backend,
				 const SecretSchema *schema,
				 GHashTable *attributes,
				 GCancellable *cancellable,
				 GAsyncReadyCallback callback,
				 gpointer user_data)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (backend);
	GTask *task;
	GList *matches;
	GVariant *variant;
	SecretFileItem *item;
	GError *error = NULL;

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	task = g_task_new (self, cancellable, callback, user_data);

	matches = secret_file_collection_search (self->collection, attributes);

	if (matches == NULL) {
		g_task_return_pointer (task, NULL, NULL);
		g_object_unref (task);
		return;
	}

	variant = g_variant_ref (matches->data);
	g_list_free_full (matches, (GDestroyNotify)g_variant_unref);

	item = _secret_file_item_decrypt (variant, self->collection, &error);
	g_variant_unref (variant);
	if (item == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	secret_retrievable_retrieve_secret (SECRET_RETRIEVABLE (item),
					    cancellable,
					    on_retrieve_secret,
					    task);
}

static SecretValue *
secret_file_backend_real_lookup_finish (SecretBackend *backend,
					GAsyncResult *result,
					GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
secret_file_backend_real_clear (SecretBackend *backend,
				const SecretSchema *schema,
				GHashTable *attributes,
				GCancellable *cancellable,
				GAsyncReadyCallback callback,
				gpointer user_data)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (backend);
	GTask *task;
	GError *error = NULL;
	gboolean ret;

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	task = g_task_new (self, cancellable, callback, user_data);

	ret = secret_file_collection_clear (self->collection, attributes, &error);
	if (error != NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	/* No need to write as nothing has been removed. */
	if (!ret) {
		g_task_return_boolean (task, FALSE);
		g_object_unref (task);
		return;
	}

	secret_file_collection_write (self->collection,
				      cancellable,
				      on_collection_write,
				      task);
}

static gboolean
secret_file_backend_real_clear_finish (SecretBackend *backend,
				       GAsyncResult *result,
				       GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
unref_objects (gpointer data)
{
	GList *list = data;

	g_list_free_full (list, g_object_unref);
}

static void
secret_file_backend_real_search (SecretBackend *backend,
				 const SecretSchema *schema,
				 GHashTable *attributes,
				 SecretSearchFlags flags,
				 GCancellable *cancellable,
				 GAsyncReadyCallback callback,
				 gpointer user_data)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (backend);
	GTask *task;
	GList *matches;
	GList *results = NULL;
	GList *l;
	GError *error = NULL;

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return;

	task = g_task_new (self, cancellable, callback, user_data);

	matches = secret_file_collection_search (self->collection, attributes);
	for (l = matches; l; l = g_list_next (l)) {
		SecretFileItem *item = _secret_file_item_decrypt (l->data, self->collection, &error);
		if (item == NULL) {
			g_task_return_error (task, error);
			g_object_unref (task);
			return;
		}
		results = g_list_append (results, item);
	}
	g_list_free_full (matches, (GDestroyNotify)g_variant_unref);

	g_task_return_pointer (task, results, unref_objects);
	g_object_unref (task);
}

static GList *
secret_file_backend_real_search_finish (SecretBackend *backend,
					GAsyncResult *result,
					GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
secret_file_backend_backend_iface (SecretBackendInterface *iface)
{
	iface->store = secret_file_backend_real_store;
	iface->store_finish = secret_file_backend_real_store_finish;
	iface->lookup = secret_file_backend_real_lookup;
	iface->lookup_finish = secret_file_backend_real_lookup_finish;
	iface->clear = secret_file_backend_real_clear;
	iface->clear_finish = secret_file_backend_real_clear_finish;
	iface->search = secret_file_backend_real_search;
	iface->search_finish = secret_file_backend_real_search_finish;
}

gboolean
_secret_file_backend_check_portal_version (void)
{
	GDBusConnection *connection;
	GVariant *ret;
	GVariant *value;
	guint32 version;
	GError *error = NULL;

	connection = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
	if (!connection) {
		g_warning ("couldn't get session bus: %s", error->message);
		g_error_free (error);
		return FALSE;
	}

	ret = g_dbus_connection_call_sync (connection,
					   PORTAL_BUS_NAME,
					   PORTAL_OBJECT_PATH,
					   "org.freedesktop.DBus.Properties",
					   "Get",
					   g_variant_new ("(ss)",
							  PORTAL_SECRET_INTERFACE,
							  "version"),
					   G_VARIANT_TYPE ("(v)"),
					   0, -1, NULL, &error);
	g_object_unref (connection);
	if (!ret) {
		g_info ("secret portal is not available: %s", error->message);
		g_error_free (error);
		return FALSE;
	}

	g_variant_get (ret, "(v)", &value);
	g_variant_unref (ret);
	version = g_variant_get_uint32 (value);
	g_variant_unref (value);
	if (version != PORTAL_SECRET_VERSION) {
		g_info ("secret portal version mismatch: %u != %u", version, PORTAL_SECRET_VERSION);
		return FALSE;
	}

	return TRUE;
}
