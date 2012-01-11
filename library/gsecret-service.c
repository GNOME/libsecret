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

#include "config.h"

#include "gsecret-dbus-generated.h"
#include "gsecret-item.h"
#include "gsecret-private.h"
#include "gsecret-service.h"
#include "gsecret-types.h"
#include "gsecret-value.h"

#ifdef WITH_GCRYPT
#include "egg/egg-dh.h"
#include "egg/egg-hkdf.h"
#include "egg/egg-libgcrypt.h"
#endif

#include "egg/egg-hex.h"
#include "egg/egg-secure-memory.h"

#include <glib.h>
#include <glib/gi18n-lib.h>

#include <gcrypt.h>

EGG_SECURE_GLIB_DEFINITIONS ();

EGG_SECURE_DECLARE (secret_service);

static const gchar *default_bus_name = GSECRET_SERVICE_BUS_NAME;

#define ALGORITHMS_AES    "dh-ietf1024-sha256-aes128-cbc-pkcs7"
#define ALGORITHMS_PLAIN  "plain"

typedef struct {
	gchar *path;
	const gchar *algorithms;
#ifdef WITH_GCRYPT
	gcry_mpi_t prime;
	gcry_mpi_t privat;
	gcry_mpi_t publi;
#endif
	gpointer key;
	gsize n_key;
} GSecretSession;

struct _GSecretServicePrivate {
	gpointer session;
};

G_LOCK_DEFINE (service_instance);
static gpointer service_instance = NULL;

G_DEFINE_TYPE (GSecretService, gsecret_service, G_TYPE_DBUS_PROXY);

typedef struct {
	GAsyncResult *result;
	GMainContext *context;
	GMainLoop *loop;
} SyncClosure;

static SyncClosure *
sync_closure_new (void)
{
	SyncClosure *closure;

	closure = g_new0 (SyncClosure, 1);

	closure->context = g_main_context_new ();
	closure->loop = g_main_loop_new (closure->context, FALSE);

	return closure;
}

static void
sync_closure_free (gpointer data)
{
	SyncClosure *closure = data;

	g_clear_object (&closure->result);
	g_main_loop_unref (closure->loop);
	g_main_context_unref (closure->context);
}

static void
on_sync_result (GObject *source,
                GAsyncResult *result,
                gpointer user_data)
{
	SyncClosure *closure = user_data;
	closure->result = g_object_ref (result);
	g_main_loop_quit (closure->loop);
}

static void
gsecret_session_free (gpointer data)
{
	GSecretSession *session = data;

	if (session == NULL)
		return;

	g_free (session->path);
#ifdef WITH_GCRYPT
	gcry_mpi_release (session->publi);
	gcry_mpi_release (session->privat);
	gcry_mpi_release (session->prime);
#endif
	egg_secure_free (session->key);
	g_free (session);
}

static void
gsecret_service_init (GSecretService *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GSECRET_TYPE_SERVICE,
	                                        GSecretServicePrivate);
}

static void
gsecret_service_finalize (GObject *obj)
{
	GSecretService *self = GSECRET_SERVICE (obj);

	gsecret_session_free (self->pv->session);

	G_OBJECT_CLASS (gsecret_service_parent_class)->finalize (obj);
}

static gboolean
gsecret_service_real_prompt_sync (GSecretService *self,
                                  GSecretPrompt *prompt,
                                  GCancellable *cancellable,
                                  GError **error)
{
	return gsecret_prompt_perform_sync (prompt, 0, cancellable, error);
}

static void
on_real_prompt_completed (GObject *source,
                          GAsyncResult *result,
                          gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;
	gboolean ret;

	ret = gsecret_prompt_perform_finish (GSECRET_PROMPT (source), result, &error);
	g_simple_async_result_set_op_res_gboolean (res, ret);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	g_simple_async_result_complete (res);

	g_object_unref (res);
}

static void
gsecret_service_real_prompt_async (GSecretService *self,
                                   GSecretPrompt *prompt,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
	GSimpleAsyncResult *res;

	res =  g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                  gsecret_service_real_prompt_async);

	gsecret_prompt_perform (prompt, 0, cancellable,
	                        on_real_prompt_completed,
	                        g_object_ref (res));

	g_object_unref (res);
}

static gboolean
gsecret_service_real_prompt_finish (GSecretService *self,
                                    GAsyncResult *result,
                                    GError **error)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	return g_simple_async_result_get_op_res_gboolean (res);
}

static void
gsecret_service_class_init (GSecretServiceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = gsecret_service_finalize;

	klass->prompt_sync = gsecret_service_real_prompt_sync;
	klass->prompt_async = gsecret_service_real_prompt_async;
	klass->prompt_finish = gsecret_service_real_prompt_finish;

	g_type_class_add_private (klass, sizeof (GSecretServicePrivate));
}

void
_gsecret_service_set_default_bus_name (const gchar *bus_name)
{
	g_return_if_fail (bus_name != NULL);
	default_bus_name = bus_name;
}

static void
on_service_instance_gone (gpointer user_data,
                          GObject *where_the_object_was)
{
	G_LOCK (service_instance);

		g_assert (service_instance == where_the_object_was);
		service_instance = NULL;

	G_UNLOCK (service_instance);
}

GSecretService *
_gsecret_service_bare_instance (GDBusConnection *connection,
                                const gchar *bus_name)
{
	GSecretService *service = NULL;
	GError *error = NULL;

	g_return_val_if_fail (G_IS_DBUS_CONNECTION (connection), NULL);

	G_LOCK (service_instance);

		if (service_instance != NULL)
			service = g_object_ref (service_instance);

	G_UNLOCK (service_instance);

	if (service != NULL)
		return service;

	/* Alternate bus name is only used for testing */
	if (bus_name == NULL)
		bus_name = default_bus_name;

	service = g_initable_new (GSECRET_TYPE_SERVICE, NULL, &error,
	                          "g-flags", G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                          "g-interface-info", _gsecret_gen_service_interface_info (),
	                          "g-name", bus_name,
	                          "g-connection", connection,
	                          "g-object-path", GSECRET_SERVICE_PATH,
	                          "g-interface-name", GSECRET_SERVICE_INTERFACE,
	                          NULL);

	if (error != NULL) {
		g_warning ("couldn't create GSecretService object: %s", error->message);
		g_clear_error (&error);
		return NULL;
	}

	g_assert (GSECRET_IS_SERVICE (service));

	G_LOCK (service_instance);

		if (service_instance == NULL) {
			service_instance = service;
			g_object_weak_ref (G_OBJECT (service), on_service_instance_gone, NULL);
		} else {
			g_object_unref (service);
			service = g_object_ref (service_instance);
		}

	G_UNLOCK (service_instance);

	return service;
}

typedef struct {
	GCancellable *cancellable;
	GSecretService *service;
	gboolean ensure_session;
	gchar *bus_name;
} ConnectClosure;

static void
connect_closure_free (gpointer data)
{
	ConnectClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_clear_object (&closure->service);
	g_slice_free (ConnectClosure, closure);
}

static void
on_connect_ensure (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;

	gsecret_service_ensure_session_finish (GSECRET_SERVICE (source), result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_connect_bus (GObject *source,
                GAsyncResult *result,
                gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	ConnectClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GDBusConnection *connection;
	GError *error = NULL;

	connection = g_bus_get_finish (result, &error);
	if (error == NULL) {
		closure->service = _gsecret_service_bare_instance (connection, closure->bus_name);
		if (closure->ensure_session)
			gsecret_service_ensure_session (closure->service, closure->cancellable,
			                                on_connect_ensure, g_object_ref (res));

		else
			g_simple_async_result_complete (res);

		g_object_unref (connection);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (res);
}

void
_gsecret_service_bare_connect (const gchar *bus_name,
                               gboolean ensure_session,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GSimpleAsyncResult *res;
	ConnectClosure *closure;

	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	if (bus_name == NULL)
		bus_name = default_bus_name;

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 _gsecret_service_bare_connect);
	closure = g_slice_new0 (ConnectClosure);
	closure->bus_name = g_strdup (bus_name);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->ensure_session = ensure_session;
	g_simple_async_result_set_op_res_gpointer (res, closure, connect_closure_free);

	g_bus_get (G_BUS_TYPE_SESSION, cancellable, on_connect_bus, g_object_ref (res));

	g_object_unref (res);
}

GSecretService *
_gsecret_service_bare_connect_finish (GAsyncResult *result,
                                      GError **error)
{
	ConnectClosure *closure;
	GSimpleAsyncResult *res;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      _gsecret_service_bare_connect), NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return g_object_ref (closure->service);
}

const gchar *
gsecret_service_get_session_algorithms (GSecretService *self)
{
	GSecretSession *session;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);

	session = g_atomic_pointer_get (&self->pv->session);
	return session ? session->algorithms : NULL;
}

const gchar *
gsecret_service_get_session_path (GSecretService *self)
{
	GSecretSession *session;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);

	session = g_atomic_pointer_get (&self->pv->session);
	return session ? session->path : NULL;
}

#ifdef WITH_GCRYPT

static GVariant *
request_open_session_aes (GSecretSession *session)
{
	gcry_error_t gcry;
	gcry_mpi_t base;
	unsigned char *buffer;
	size_t n_buffer;
	GVariant *argument;

	g_assert (session->prime == NULL);
	g_assert (session->privat == NULL);
	g_assert (session->publi == NULL);

	/* Initialize our local parameters and values */
	if (!egg_dh_default_params ("ietf-ike-grp-modp-1536",
	                            &session->prime, &base))
		g_return_val_if_reached (NULL);

#if 0
	g_printerr ("\n lib prime: ");
	gcry_mpi_dump (session->prime);
	g_printerr ("\n  lib base: ");
	gcry_mpi_dump (base);
	g_printerr ("\n");
#endif

	if (!egg_dh_gen_pair (session->prime, base, 0,
	                      &session->publi, &session->privat))
		g_return_val_if_reached (NULL);
	gcry_mpi_release (base);

	gcry = gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer, &n_buffer, session->publi);
	g_return_val_if_fail (gcry == 0, NULL);
	argument = g_variant_new_from_data (G_VARIANT_TYPE ("ay"),
	                                    buffer, n_buffer, TRUE,
	                                    gcry_free, buffer);

	return g_variant_new ("(sv)", ALGORITHMS_AES, argument);
}

static gboolean
response_open_session_aes (GSecretSession *session,
                           GVariant *response)
{
	gconstpointer buffer;
	GVariant *argument;
	const gchar *sig;
	gsize n_buffer;
	gcry_mpi_t peer;
	gcry_error_t gcry;
	gpointer ikm;
	gsize n_ikm;

	sig = g_variant_get_type_string (response);
	g_return_val_if_fail (sig != NULL, FALSE);

	if (!g_str_equal (sig, "(vo)")) {
		g_warning ("invalid OpenSession() response from daemon with signature: %s", sig);
		return FALSE;
	}

	g_assert (session->path == NULL);
	g_variant_get (response, "(vo)", &argument, &session->path);

	buffer = g_variant_get_fixed_array (argument, &n_buffer, sizeof (guchar));
	gcry = gcry_mpi_scan (&peer, GCRYMPI_FMT_USG, buffer, n_buffer, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);
	g_variant_unref (argument);

#if 0
	g_printerr (" lib publi: ");
	gcry_mpi_dump (session->publi);
	g_printerr ("\n  lib peer: ");
	gcry_mpi_dump (peer);
	g_printerr ("\n");
#endif

	ikm = egg_dh_gen_secret (peer, session->privat, session->prime, &n_ikm);
	gcry_mpi_release (peer);

#if 0
	g_printerr ("   lib ikm:  %s\n", egg_hex_encode (ikm, n_ikm));
#endif

	if (ikm == NULL) {
		g_warning ("couldn't negotiate a valid AES session key");
		g_free (session->path);
		session->path = NULL;
		return FALSE;
	}

	session->n_key = 16;
	session->key = egg_secure_alloc (session->n_key);
	if (!egg_hkdf_perform ("sha256", ikm, n_ikm, NULL, 0, NULL, 0,
	                       session->key, session->n_key))
		g_return_val_if_reached (FALSE);
	egg_secure_free (ikm);

	session->algorithms = ALGORITHMS_AES;
	return TRUE;
}

#endif /* WITH_GCRYPT */

static GVariant *
request_open_session_plain (GSecretSession *session)
{
	GVariant *argument = g_variant_new_string ("");
	return g_variant_new ("(sv)", "plain", argument);
}

static gboolean
response_open_session_plain (GSecretSession *session,
                             GVariant *response)
{
	GVariant *argument;
	const gchar *sig;

	sig = g_variant_get_type_string (response);
	g_return_val_if_fail (sig != NULL, FALSE);

	if (!g_str_equal (sig, "(vo)")) {
		g_warning ("invalid OpenSession() response from daemon with signature: %s",
		           g_variant_get_type_string (response));
		return FALSE;
	}

	g_assert (session->path == NULL);
	g_variant_get (response, "(vo)", &argument, &session->path);
	g_variant_unref (argument);

	g_assert (session->key == NULL);
	g_assert (session->n_key == 0);

	session->algorithms = ALGORITHMS_PLAIN;
	return TRUE;
}

typedef struct {
	GCancellable *cancellable;
	GSecretSession *session;
} OpenSessionClosure;

static void
open_session_closure_free (gpointer data)
{
	OpenSessionClosure *closure = data;
	g_assert (closure);
	g_clear_object (&closure->cancellable);
	gsecret_session_free (closure->session);
	g_free (closure);
}

static void
on_service_open_session_plain (GObject *source,
                               GAsyncResult *result,
                               gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	OpenSessionClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;
	GVariant *response;

	response =  g_dbus_proxy_call_finish (G_DBUS_PROXY (self), result, &error);

	/* A successful response, decode it */
	if (response != NULL) {
		if (response_open_session_plain (closure->session, response)) {

			/* Set value atomically, in case of race condition */
			if (g_atomic_pointer_compare_and_exchange (&(self->pv->session),
			                                           NULL, closure->session))
				closure->session = NULL; /* Service takes ownership */

		} else {
			g_simple_async_result_set_error (res, GSECRET_ERROR, GSECRET_ERROR_PROTOCOL,
			                                 _("Couldn't communicate with the secret storage"));
		}

		g_simple_async_result_complete (res);
		g_variant_unref (response);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (res);
}

#ifdef WITH_GCRYPT

static void
on_service_open_session_aes (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	OpenSessionClosure * closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;
	GVariant *response;

	response =  g_dbus_proxy_call_finish (G_DBUS_PROXY (self), result, &error);

	/* A successful response, decode it */
	if (response != NULL) {
		if (response_open_session_aes (closure->session, response)) {

			/* Set value atomically, in case of race condition */
			if (g_atomic_pointer_compare_and_exchange (&(self->pv->session),
			                                           NULL, closure->session))
				closure->session = NULL; /* Service takes ownership */

		} else {
			g_simple_async_result_set_error (res, GSECRET_ERROR, GSECRET_ERROR_PROTOCOL,
			                                 _("Couldn't communicate with the secret storage"));
		}

		g_simple_async_result_complete (res);
		g_variant_unref (response);

	} else {
		/* AES session not supported, request a plain session */
		if (g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_NOT_SUPPORTED)) {
			g_dbus_proxy_call (G_DBUS_PROXY (source), "OpenSession",
			                   request_open_session_plain (closure->session),
			                   G_DBUS_CALL_FLAGS_NONE, -1,
			                   closure->cancellable, on_service_open_session_plain,
			                   g_object_ref (res));
			g_error_free (error);

		/* Other errors result in a failure */
		} else {
			g_simple_async_result_take_error (res, error);
			g_simple_async_result_complete (res);
		}
	}

	g_object_unref (res);
}



#endif /* WITH_GCRYPT */

void
gsecret_service_ensure_session (GSecretService *self,
                                GCancellable *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
	GSimpleAsyncResult *res;
	OpenSessionClosure *closure;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_ensure_session);

	/* If we have no session, then request an AES session */
	if (g_atomic_pointer_get (&self->pv->session) == NULL) {

		closure = g_new (OpenSessionClosure, 1);
		closure->cancellable = cancellable ? g_object_ref (cancellable) : cancellable;
		closure->session = g_new0 (GSecretSession, 1);
		g_simple_async_result_set_op_res_gpointer (res, closure, open_session_closure_free);

		g_dbus_proxy_call (G_DBUS_PROXY (self), "OpenSession",
#ifdef WITH_GCRYPT
		                   request_open_session_aes (closure->session),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   cancellable, on_service_open_session_aes,
#else
		                   request_open_session_plain (closure->session),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   cancellable, on_service_open_session_plain,
#endif
		                   g_object_ref (res));

	/* Already have a session */
	} else {
		g_simple_async_result_complete_in_idle (res);
	}

	g_object_unref (res);
}

const gchar *
_gsecret_service_ensure_session_finish (GSecretService *self,
                                        GAsyncResult *result,
                                        GCancellable **cancellable,
                                        GError **error)
{
	GSecretSession *session;
	OpenSessionClosure *closure;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || *cancellable == NULL, NULL);

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_ensure_session), NULL);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return NULL;

	if (cancellable) {
		closure = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (result));
		*cancellable = closure->cancellable ? g_object_ref (closure->cancellable) : NULL;
	}

	/* The session we have should never change once created */
	session = g_atomic_pointer_get (&self->pv->session);
	g_assert (session != NULL);
	return session->path;
}

const gchar *
gsecret_service_ensure_session_finish (GSecretService *self,
                                       GAsyncResult *result,
                                       GError **error)
{
	return _gsecret_service_ensure_session_finish (self, result, NULL, error);
}

const gchar *
gsecret_service_ensure_session_sync (GSecretService *self,
                                     GCancellable *cancellable,
                                     GError **error)
{
	GVariant *response;
	GSecretSession *session;
	GError *lerror = NULL;
	gboolean complete = FALSE;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* The session we have should never change once created */
	session = g_atomic_pointer_get (&self->pv->session);
	if (session != NULL)
		return session->path;

	session = g_new0 (GSecretSession, 1);
#ifdef WITH_GCRYPT
	response = g_dbus_proxy_call_sync (G_DBUS_PROXY (self), "OpenSession",
	                                   request_open_session_aes (session),
	                                   G_DBUS_CALL_FLAGS_NONE, -1,
	                                   cancellable, &lerror);

	if (response != NULL) {
		complete = response_open_session_aes (session, response);
		g_variant_unref (response);

	/* AES session not supported, request a plain session */
	} else if (g_error_matches (lerror, G_DBUS_ERROR, G_DBUS_ERROR_NOT_SUPPORTED)) {
		g_clear_error (&lerror);
#endif /* WITH_GCRYPT */
		response = g_dbus_proxy_call_sync (G_DBUS_PROXY (self), "OpenSession",
		                                   request_open_session_plain (session),
		                                   G_DBUS_CALL_FLAGS_NONE, -1,
		                                   cancellable, &lerror);

		if (response != NULL) {
			complete = response_open_session_plain (session, response);
			g_variant_unref (response);
		}
#ifdef WITH_GCRYPT
	}
#endif

	if (lerror == NULL && !complete) {
		g_set_error (&lerror, GSECRET_ERROR, GSECRET_ERROR_PROTOCOL,
		             _("Couldn't communicate with the secret storage"));
	}

	if (lerror != NULL) {
		gsecret_session_free (session);
		g_propagate_error (error, lerror);
		return NULL;
	}

	/* Set value atomically, in case of race condition */
	if (!g_atomic_pointer_compare_and_exchange (&(self->pv->session),
	                                            NULL, session))
		gsecret_session_free (session);

	/* The session we have should never change once created */
	session = g_atomic_pointer_get (&self->pv->session);
	g_assert (session != NULL);
	return session->path;
}

#ifdef WITH_GCRYPT

static gboolean
pkcs7_unpad_bytes_in_place (guchar *padded,
                            gsize *n_padded)
{
	gsize n_pad, i;

	if (*n_padded == 0)
		return FALSE;

	n_pad = padded[*n_padded - 1];

	/* Validate the padding */
	if (n_pad == 0 || n_pad > 16)
		return FALSE;
	if (n_pad > *n_padded)
		return FALSE;
	for (i = *n_padded - n_pad; i < *n_padded; ++i) {
		if (padded[i] != n_pad)
			return FALSE;
	}

	/* The last bit of data */
	*n_padded -= n_pad;

	/* Null teriminate as a courtesy */
	padded[*n_padded] = 0;

	return TRUE;
}

static GSecretValue *
service_decode_aes_secret (GSecretSession *session,
                           gconstpointer param,
                           gsize n_param,
                           gconstpointer value,
                           gsize n_value,
                           const gchar *content_type)
{
	gcry_cipher_hd_t cih;
	gsize n_padded;
	gcry_error_t gcry;
	guchar *padded;
	gsize pos;

	if (n_param != 16) {
		g_message ("received an encrypted secret structure with invalid parameter");
		return NULL;
	}

	if (n_value == 0 || n_value % 16 != 0) {
		g_message ("received an encrypted secret structure with bad secret length");
		return NULL;
	}

	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry != 0) {
		g_warning ("couldn't create AES cipher: %s", gcry_strerror (gcry));
		return NULL;
	}

#if 0
	g_printerr ("    lib iv:  %s\n", egg_hex_encode (param, n_param));
#endif

	gcry = gcry_cipher_setiv (cih, param, n_param);
	g_return_val_if_fail (gcry == 0, NULL);

#if 0
	g_printerr ("   lib key:  %s\n", egg_hex_encode (session->key, session->n_key));
#endif

	gcry = gcry_cipher_setkey (cih, session->key, session->n_key);
	g_return_val_if_fail (gcry == 0, NULL);

	/* Copy the memory buffer */
	n_padded = n_value;
	padded = egg_secure_alloc (n_padded);
	memcpy (padded, value, n_padded);

	/* Perform the decryption */
	for (pos = 0; pos < n_padded; pos += 16) {
		gcry = gcry_cipher_decrypt (cih, (guchar*)padded + pos, 16, NULL, 0);
		g_return_val_if_fail (gcry == 0, FALSE);
	}

	gcry_cipher_close (cih);

	/* Unpad the resulting value */
	if (!pkcs7_unpad_bytes_in_place (padded, &n_padded)) {
		egg_secure_clear (padded, n_padded);
		egg_secure_free (padded);
		g_message ("received an invalid or unencryptable secret");
		return FALSE;
	}

	return gsecret_value_new_full ((gchar *)padded, n_padded, content_type, egg_secure_free);
}

#endif /* WITH_GCRYPT */

static GSecretValue *
service_decode_plain_secret (GSecretSession *session,
                             gconstpointer param,
                             gsize n_param,
                             gconstpointer value,
                             gsize n_value,
                             const gchar *content_type)
{
	if (n_param != 0) {
		g_message ("received a plain secret structure with invalid parameter");
		return NULL;
	}

	return gsecret_value_new (value, n_value, content_type);
}

GSecretValue *
_gsecret_service_decode_secret (GSecretService *self,
                                GVariant *encoded)
{
	GSecretSession *session;
	GSecretValue *result;
	gconstpointer param;
	gconstpointer value;
	gchar *session_path;
	gchar *content_type;
	gsize n_param;
	gsize n_value;
	GVariant *vparam;
	GVariant *vvalue;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (encoded, NULL);

	session = g_atomic_pointer_get (&self->pv->session);
	g_return_val_if_fail (session != NULL, NULL);
	g_assert (session->path != NULL);

	/* Parsing (oayays) */
	g_variant_get_child (encoded, 0, "o", &session_path);

	if (session_path == NULL || !g_str_equal (session_path, session->path)) {
		g_message ("received a secret encoded with wrong session: %s != %s",
		           session_path, session->path);
		g_free (session_path);
		return NULL;
	}

	vparam = g_variant_get_child_value (encoded, 1);
	param = g_variant_get_fixed_array (vparam, &n_param, sizeof (guchar));
	vvalue = g_variant_get_child_value (encoded, 2);
	value = g_variant_get_fixed_array (vvalue, &n_value, sizeof (guchar));
	g_variant_get_child (encoded, 3, "s", &content_type);

#ifdef WITH_GCRYPT
	if (session->key != NULL)
		result = service_decode_aes_secret (session, param, n_param,
		                                    value, n_value, content_type);
	else
#endif
		result = service_decode_plain_secret (session, param, n_param,
		                                      value, n_value, content_type);

	g_variant_unref (vparam);
	g_variant_unref (vvalue);
	g_free (content_type);
	g_free (session_path);

	return result;
}

#ifdef WITH_GCRYPT

static guchar*
pkcs7_pad_bytes_in_secure_memory (gconstpointer secret,
                                  gsize length,
                                  gsize *n_padded)
{
	gsize n_pad;
	guchar *padded;

	/* Pad the secret */
	*n_padded = ((length + 16) / 16) * 16;
	g_assert (length < *n_padded);
	g_assert (*n_padded > 0);
	n_pad = *n_padded - length;
	g_assert (n_pad > 0 && n_pad <= 16);
	padded = egg_secure_alloc (*n_padded);
	memcpy (padded, secret, length);
	memset (padded + length, n_pad, n_pad);
	return padded;
}

static gboolean
service_encode_aes_secret (GSecretSession *session,
                           GSecretValue *value,
                           GVariantBuilder *builder)
{
	gcry_cipher_hd_t cih;
	guchar *padded;
	gsize n_padded, pos;
	gcry_error_t gcry;
	gpointer iv;
	gconstpointer secret;
	gsize n_secret;
	GVariant *child;

	g_variant_builder_add (builder, "o", session->path);

	/* Create the cipher */
	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry != 0) {
		g_warning ("couldn't create AES cipher: %s", gcry_strerror (gcry));
		return FALSE;
	}

	secret = gsecret_value_get (value, &n_secret);

	/* Perform the encoding here */
	padded = pkcs7_pad_bytes_in_secure_memory (secret, n_secret, &n_padded);
	g_assert (padded != NULL);

	/* Setup the IV */
	iv = g_malloc0 (16);
	gcry_create_nonce (iv, 16);
	gcry = gcry_cipher_setiv (cih, iv, 16);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Setup the key */
	gcry = gcry_cipher_setkey (cih, session->key, session->n_key);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Perform the encryption */
	for (pos = 0; pos < n_padded; pos += 16) {
		gcry = gcry_cipher_encrypt (cih, (guchar*)padded + pos, 16, NULL, 0);
		g_return_val_if_fail (gcry == 0, FALSE);
	}

	gcry_cipher_close (cih);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), iv, 16, TRUE, g_free, iv);
	g_variant_builder_add_value (builder, child);
	g_variant_unref (child);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), padded, n_padded, TRUE, egg_secure_free, padded);
	g_variant_builder_add_value (builder, child);
	g_variant_unref (child);

	g_variant_builder_add (builder, "s", gsecret_value_get_content_type (value));
	return TRUE;
}

#endif /* WITH_GCRYPT */

static gboolean
service_encode_plain_secret (GSecretSession *session,
                             GSecretValue *value,
                             GVariantBuilder *builder)
{
	gconstpointer secret;
	gsize n_secret;
	GVariant *child;

	g_variant_builder_add (builder, "o", session->path);

	secret = gsecret_value_get (value, &n_secret);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), "", 0, TRUE, NULL, NULL);
	g_variant_builder_add_value (builder, child);
	g_variant_unref (child);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), secret, n_secret, TRUE,
	                                 gsecret_value_unref, gsecret_value_ref (value));
	g_variant_builder_add_value (builder, child);
	g_variant_unref (child);

	g_variant_builder_add (builder, "s", gsecret_value_get_content_type (value));
	return TRUE;
}

GVariant *
_gsecret_service_encode_secret (GSecretService *self,
                                GSecretValue *value)
{
	GVariantBuilder *builder;
	GSecretSession *session;
	GVariant *result = NULL;
	GVariantType *type;
	gboolean ret;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (value, NULL);

	session = g_atomic_pointer_get (&self->pv->session);
	g_return_val_if_fail (session != NULL, NULL);
	g_assert (session->path != NULL);

	type = g_variant_type_new ("(oayays)");
	builder = g_variant_builder_new (type);

#ifdef WITH_GCRYPT
	if (session->key)
		ret = service_encode_aes_secret (session, value, builder);
	else
#endif
		ret = service_encode_plain_secret (session, value, builder);
	if (ret)
		result = g_variant_builder_end (builder);

	g_variant_builder_unref (builder);
	g_variant_type_free (type);
	return result;
}

static void
on_search_items_complete (GObject *source,
                          GAsyncResult *result,
                          gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;
	GVariant *response;

	response = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	else
		g_simple_async_result_set_op_res_gpointer (res, response,
		                                           (GDestroyNotify)g_variant_unref);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

void
gsecret_service_search_for_paths (GSecretService *self,
                                  GHashTable *attributes,
                                  GCancellable *cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_search_for_paths);

	g_dbus_proxy_call (G_DBUS_PROXY (self), "SearchItems",
	                   g_variant_new ("(@a{ss})",
	                                  _gsecret_util_variant_for_attributes (attributes)),
	                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable,
	                   on_search_items_complete, g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_service_search_for_paths_finish (GSecretService *self,
                                         GAsyncResult *result,
                                         gchar ***unlocked,
                                         gchar ***locked,
                                         GError **error)
{
	GVariant *response;
	GSimpleAsyncResult *res;
	gchar **dummy = NULL;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_search_for_paths), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	if (unlocked || locked) {
		if (!unlocked)
			unlocked = &dummy;
		else if (!locked)
			locked = &dummy;
		response = g_simple_async_result_get_op_res_gpointer (res);
		g_variant_get (response, "(^ao^ao)", unlocked, locked);
	}

	g_strfreev (dummy);
	return TRUE;
}

gboolean
gsecret_service_search_for_paths_sync (GSecretService *self,
                                       GHashTable *attributes,
                                       GCancellable *cancellable,
                                       gchar ***unlocked,
                                       gchar ***locked,
                                       GError **error)
{
	gchar **dummy = NULL;
	GVariant *response;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	response = g_dbus_proxy_call_sync (G_DBUS_PROXY (self), "SearchItems",
	                                   g_variant_new ("(@a{ss})",
	                                                  _gsecret_util_variant_for_attributes (attributes)),
	                                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable, error);

	if (response != NULL) {
		if (unlocked || locked) {
			if (!unlocked)
				unlocked = &dummy;
			else if (!locked)
				locked = &dummy;
			g_variant_get (response, "(^ao^ao)", unlocked, locked);
		}

		g_variant_unref (response);
	}

	g_strfreev (dummy);

	return response != NULL;
}

static void
on_get_secrets_complete (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretParams *params = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	params->out = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	g_simple_async_result_complete (res);

	g_object_unref (res);
}

static void
on_get_secrets_session (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretParams *params = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;
	const gchar *session;

	session = gsecret_service_ensure_session_finish (GSECRET_SERVICE (source),
	                                                 result, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	} else {
		g_dbus_proxy_call (G_DBUS_PROXY (source), "GetSecrets",
		                   g_variant_new ("(@aoo)", params->in, session),
		                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
		                   params->cancellable, on_get_secrets_complete,
		                   g_object_ref (res));
	}

	g_object_unref (res);
}

void
gsecret_service_get_secret_for_path (GSecretService *self,
                                     const gchar *object_path,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	GSimpleAsyncResult *res;
	GSecretParams *params;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (object_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_get_secret_for_path);

	params = _gsecret_params_new (cancellable, g_variant_new_objv (&object_path, 1));
	g_simple_async_result_set_op_res_gpointer (res, params, _gsecret_params_free);

	gsecret_service_ensure_session (self, cancellable,
	                                on_get_secrets_session,
	                                g_object_ref (res));

	g_object_unref (res);
}

static GSecretValue *
service_decode_get_secrets_first (GSecretService *self,
                                  GVariant *out)
{
	GVariantIter *iter;
	GVariant *variant;
	GSecretValue *value;
	const gchar *path;

	g_variant_get (out, "(a{o(oayays)})", &iter);
	while (g_variant_iter_next (iter, "{&o@(oayays)}", &path, &variant)) {
		value = _gsecret_service_decode_secret (self, variant);
		g_variant_unref (variant);
		break;
	}
	g_variant_iter_free (iter);
	return value;
}

static GHashTable *
service_decode_get_secrets_all (GSecretService *self,
                                GVariant *out)
{
	GVariantIter *iter;
	GVariant *variant;
	GHashTable *values;
	GSecretValue *value;
	gchar *path;

	values = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                g_free, gsecret_value_unref);
	g_variant_get (out, "(a{o(oayays)})", &iter);
	while (g_variant_iter_loop (iter, "{o@(oayays)}", &path, &variant)) {
		value = _gsecret_service_decode_secret (self, variant);
		if (value && path)
			g_hash_table_insert (values, g_strdup (path), value);
	}
	g_variant_iter_free (iter);
	return values;
}

GSecretValue *
gsecret_service_get_secret_for_path_finish (GSecretService *self,
                                            GAsyncResult *result,
                                            GError **error)
{
	GSimpleAsyncResult *res;
	GSecretParams *params;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_get_secret_for_path), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	params = g_simple_async_result_get_op_res_gpointer (res);
	return service_decode_get_secrets_first (self, params->out);
}

GSecretValue *
gsecret_service_get_secret_for_path_sync (GSecretService *self,
                                          const gchar *object_path,
                                          GCancellable *cancellable,
                                          GError **error)
{
	const gchar *session;
	GSecretValue *value;
	GVariant *out;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (object_path != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	session = gsecret_service_ensure_session_sync (self, cancellable, error);
	if (!session)
		return NULL;

	out = g_dbus_proxy_call_sync (G_DBUS_PROXY (self), "GetSecrets",
	                              g_variant_new ("(@aoo)",
	                                             g_variant_new_objv (&object_path, 1),
	                                             session),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                              cancellable, error);
	if (!out)
		return NULL;

	value = service_decode_get_secrets_first (self, out);
	g_variant_unref (out);

	return value;
}

void
gsecret_service_get_secrets_for_paths (GSecretService *self,
                                       const gchar **object_paths,
                                       GCancellable *cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
	GSimpleAsyncResult *res;
	GSecretParams *params;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (object_paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_get_secret_for_path);

	params = _gsecret_params_new (cancellable, g_variant_new_objv (object_paths, -1));
	g_simple_async_result_set_op_res_gpointer (res, params, _gsecret_params_free);

	gsecret_service_ensure_session (self, cancellable,
	                                on_get_secrets_session,
	                                g_object_ref (res));

	g_object_unref (res);
}

GHashTable *
gsecret_service_get_secrets_for_paths_finish (GSecretService *self,
                                              GAsyncResult *result,
                                              GError **error)
{
	GSimpleAsyncResult *res;
	GSecretParams *params;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_get_secret_for_path), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	params = g_simple_async_result_get_op_res_gpointer (res);
	return service_decode_get_secrets_all (self, params->out);
}

GHashTable *
gsecret_service_get_secrets_for_paths_sync (GSecretService *self,
                                            const gchar **object_paths,
                                            GCancellable *cancellable,
                                            GError **error)
{
	const gchar *session;
	GHashTable *values;
	GVariant *out;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (object_paths != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	session = gsecret_service_ensure_session_sync (self, cancellable, error);
	if (!session)
		return NULL;

	out = g_dbus_proxy_call_sync (G_DBUS_PROXY (self), "GetSecrets",
	                              g_variant_new ("(@aoo)",
	                                             g_variant_new_objv (object_paths, -1),
	                                             session),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                              cancellable, error);
	if (!out)
		return NULL;

	values = service_decode_get_secrets_all (self, out);
	g_variant_unref (out);

	return values;
}

gboolean
gsecret_service_prompt_sync (GSecretService *self,
                             GSecretPrompt *prompt,
                             GCancellable *cancellable,
                             GError **error)
{
	GSecretServiceClass *klass;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (GSECRET_IS_PROMPT (prompt), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	klass = GSECRET_SERVICE_GET_CLASS (self);
	g_return_val_if_fail (klass->prompt_sync != NULL, FALSE);

	return (klass->prompt_sync) (self, prompt, cancellable, error);
}

void
gsecret_service_prompt_path (GSecretService *self,
                             const gchar *prompt_path,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	GSecretPrompt *prompt;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (prompt_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	prompt = gsecret_prompt_instance (self, prompt_path);

	gsecret_service_prompt (self, prompt, cancellable, callback, user_data);

	g_object_unref (prompt);
}

void
gsecret_service_prompt (GSecretService *self,
                        GSecretPrompt *prompt,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GSecretServiceClass *klass;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (GSECRET_IS_PROMPT (prompt));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	klass = GSECRET_SERVICE_GET_CLASS (self);
	g_return_if_fail (klass->prompt_async != NULL);

	(klass->prompt_async) (self, prompt, cancellable, callback, user_data);
}

gboolean
gsecret_service_prompt_finish (GSecretService *self,
                               GAsyncResult *result,
                               GError **error)
{
	GSecretServiceClass *klass;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	klass = GSECRET_SERVICE_GET_CLASS (self);
	g_return_val_if_fail (klass->prompt_finish != NULL, FALSE);

	return (klass->prompt_finish) (self, result, error);
}

#if 0

void
gsecret_service_store_password (GSecretService *self,
                                const GSecretSchema *schema,
                                const gchar *collection_path,
                                const gchar *label,
                                const gchar *password,
                                GCancellable *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data,
                                ...)
{

}

gboolean
gsecret_service_store_password_finish (GSecretService *self,
                                       GAsyncResult *result,
                                       GError **error)
{

}

void
gsecret_service_store_password_sync (GSecretService *self,
                                     const GSecretSchema *schema,
                                     const gchar *collection,
                                     const gchar *display_name,
                                     const gchar *password,
                                     GCancellable *cancellable,
                                     GError **error,
                                     ...)
{

}

void
gsecret_service_lookup_password (GSecretService *self,
                                 const GSecretSchema *schema,
                                 GCancellable *cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data,
                                 ...)
{

}

gchar *
gsecret_service_lookup_password_finish (GSecretService *self,
                                        GAsyncResult *result,
                                        GError **error)
{

}

gchar *
gsecret_service_lookup_password_sync (GSecretService *self,
                                      const GSecretSchema *schema,
                                      GCancellable *cancellable,
                                      GError **error,
                                      ...)
{

}

#endif

typedef struct {
	GCancellable *cancellable;
	gboolean deleted;
} DeleteClosure;

static void
delete_closure_free (gpointer data)
{
	DeleteClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_slice_free (DeleteClosure, closure);
}

static void
on_delete_prompted (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	gsecret_service_prompt_finish (GSECRET_SERVICE (source), result, &error);

	if (error == NULL)
		closure->deleted = TRUE;
	else
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_delete_complete (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretService *self = GSECRET_SERVICE (g_async_result_get_source_object (user_data));
	const gchar *prompt_path;
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o)", &prompt_path);

		if (_gsecret_util_empty_path (prompt_path)) {
			closure->deleted = TRUE;
			g_simple_async_result_complete (res);

		} else {
			gsecret_service_prompt_path (self, prompt_path,
			                             closure->cancellable,
			                             on_delete_prompted,
			                             g_object_ref (res));
		}

		g_variant_unref (retval);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (self);
	g_object_unref (res);
}

void
gsecret_service_delete_path (GSecretService *self,
                             const gchar *item_path,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (item_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_delete_path);
	closure = g_slice_new0 (DeleteClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, delete_closure_free);

	g_dbus_connection_call (g_dbus_proxy_get_connection (G_DBUS_PROXY (self)),
	                        g_dbus_proxy_get_name (G_DBUS_PROXY (self)),
	                        item_path, GSECRET_ITEM_INTERFACE,
	                        "Delete", g_variant_new ("()"), G_VARIANT_TYPE ("(o)"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                        cancellable, on_delete_complete, g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_service_delete_path_finish (GSecretService *self,
                                    GAsyncResult *result,
                                    GError **error)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_delete_path), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->deleted;
}

gboolean
gsecret_service_delete_path_sync (GSecretService *self,
                                  const gchar *item_path,
                                  GCancellable *cancellable,
                                  GError **error)
{
	SyncClosure *closure;
	gboolean result;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (item_path != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	closure = sync_closure_new ();
	g_main_context_push_thread_default (closure->context);

	gsecret_service_delete_path (self, item_path, cancellable, on_sync_result, closure);

	g_main_loop_run (closure->loop);

	result = gsecret_service_delete_path_finish (self, closure->result, error);

	g_main_context_pop_thread_default (closure->context);
	sync_closure_free (closure);

	return result;
}

static void
on_delete_password_complete (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretService *self = GSECRET_SERVICE (g_async_result_get_source_object (user_data));
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	closure->deleted = gsecret_service_delete_path_finish (self, result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);

	g_object_unref (self);
	g_object_unref (res);
}

static void
on_search_delete_password (GObject *source,
                           GAsyncResult *result,
                           gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretService *self = GSECRET_SERVICE (g_async_result_get_source_object (user_data));
	const gchar *path = NULL;
	GError *error = NULL;
	gchar **locked;
	gchar **unlocked;

	gsecret_service_search_for_paths_finish (self, result, &unlocked, &locked, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else {
		/* Choose the first path */
		if (unlocked && unlocked[0])
			path = unlocked[0];
		else if (locked && locked[0])
			path = locked[0];

		/* Nothing to delete? */
		if (path == NULL) {
			closure->deleted = FALSE;
			g_simple_async_result_complete (res);

		/* Delete the first path */
		} else {
			closure->deleted = TRUE;
			gsecret_service_delete_path (self, path,
			                             closure->cancellable,
			                             on_delete_password_complete,
			                             g_object_ref (res));
		}
	}

	g_strfreev (locked);
	g_strfreev (unlocked);
	g_object_unref (self);
	g_object_unref (res);
}

void
gsecret_service_delete_password (GSecretService *self,
                                 const GSecretSchema *schema,
                                 GCancellable *cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data,
                                 ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (GSECRET_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	gsecret_service_delete_passwordv (self, attributes, cancellable,
	                                 callback, user_data);

	g_hash_table_unref (attributes);
}

void
gsecret_service_delete_passwordv (GSecretService *self,
                                  GHashTable *attributes,
                                  GCancellable *cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_if_fail (GSECRET_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_delete_password);
	closure = g_slice_new0 (DeleteClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, delete_closure_free);

	gsecret_service_search_for_paths (self, attributes, cancellable,
	                                  on_search_delete_password, g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_service_delete_password_finish (GSecretService *self,
                                        GAsyncResult *result,
                                        GError **error)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_delete_password), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->deleted;
}

gboolean
gsecret_service_delete_password_sync (GSecretService *self,
                                      const GSecretSchema* schema,
                                      GCancellable *cancellable,
                                      GError **error,
                                      ...)
{
	GHashTable *attributes;
	gboolean result;
	va_list va;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	va_start (va, error);
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	result = gsecret_service_delete_passwordv_sync (self, attributes, cancellable, error);

	g_hash_table_unref (attributes);

	return result;
}

gboolean
gsecret_service_delete_passwordv_sync (GSecretService *self,
                                       GHashTable *attributes,
                                       GCancellable *cancellable,
                                       GError **error)
{
	SyncClosure *closure;
	gboolean result;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	closure = sync_closure_new ();
	g_main_context_push_thread_default (closure->context);

	gsecret_service_delete_passwordv (self, attributes, cancellable,
	                                  on_sync_result, closure);

	g_main_loop_run (closure->loop);

	result = gsecret_service_delete_password_finish (self, closure->result, error);

	g_main_context_pop_thread_default (closure->context);
	sync_closure_free (closure);

	return result;
}
