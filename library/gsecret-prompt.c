/* GSecret - GLib wrapper for Secret Prompt
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
#include "gsecret-private.h"
#include "gsecret-prompt.h"

#include <glib.h>
#include <glib/gi18n-lib.h>

#include <gcrypt.h>

typedef struct _GSecretPromptPrivate {
	/* Locked by mutex */
	GMutex mutex;
	gint prompted;
	GVariant *last_result;
} GSecretPromptPrivate;

G_DEFINE_TYPE (GSecretPrompt, gsecret_prompt, G_TYPE_DBUS_PROXY);

static void
gsecret_prompt_init (GSecretPrompt *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GSECRET_TYPE_PROMPT,
	                                        GSecretPromptPrivate);

	g_mutex_init (&self->pv->mutex);
}

static void
gsecret_prompt_finalize (GObject *obj)
{
	GSecretPrompt *self = GSECRET_PROMPT (obj);

	g_mutex_clear (&self->pv->mutex);
	if (self->pv->last_result)
		g_variant_unref (self->pv->last_result);

	G_OBJECT_CLASS (gsecret_prompt_parent_class)->finalize (obj);
}

static void
gsecret_prompt_class_init (GSecretPromptClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = gsecret_prompt_finalize;

	g_type_class_add_private (klass, sizeof (GSecretPromptPrivate));
}

typedef struct {
	GMainLoop *loop;
	GAsyncResult *result;
} RunClosure;

static void
on_prompt_run_complete (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	RunClosure *closure = user_data;
	closure->result = g_object_ref (result);
	g_main_loop_quit (closure->loop);
}

GSecretPrompt *
gsecret_prompt_instance (GSecretService *service,
                         const gchar *prompt_path)
{
	GDBusProxy *proxy;
	GSecretPrompt *prompt;
	GError *error = NULL;

	g_return_val_if_fail (GSECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (prompt_path != NULL, NULL);

	proxy = G_DBUS_PROXY (service);
	prompt = g_initable_new (GSECRET_TYPE_PROMPT, NULL, &error,
	                         "g-flags", G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                         "g-interface-info", _gsecret_gen_prompt_interface_info (),
	                         "g-name", g_dbus_proxy_get_name (proxy),
	                         "g-connection", g_dbus_proxy_get_connection (proxy),
	                         "g-object-path", prompt_path,
	                         "g-interface-name", GSECRET_PROMPT_INTERFACE,
	                         NULL);

	if (error != NULL) {
		g_warning ("couldn't create GSecretPrompt object: %s", error->message);
		g_clear_error (&error);
		return NULL;
	}

	return prompt;
}

gboolean
gsecret_prompt_run (GSecretPrompt *self,
                    gulong window_id,
                    GCancellable *cancellable,
                    GError **error)
{
	GMainContext *context;
	RunClosure *closure;
	gboolean ret;

	g_return_val_if_fail (GSECRET_IS_PROMPT (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	context = g_main_context_get_thread_default ();

	closure = g_new0 (RunClosure, 1);
	closure->loop = g_main_loop_new (context, FALSE);

	gsecret_prompt_perform (self, window_id, cancellable,
	                        on_prompt_run_complete, closure);

	g_main_loop_run (closure->loop);

	ret = gsecret_prompt_perform_finish (self, closure->result, error);

	g_main_loop_unref (closure->loop);
	g_object_unref (closure->result);
	g_free (closure);

	return ret;
}

gboolean
gsecret_prompt_perform_sync (GSecretPrompt *self,
                             gulong window_id,
                             GCancellable *cancellable,
                             GError **error)
{
	GMainContext *context;
	gboolean ret;

	g_return_val_if_fail (GSECRET_IS_PROMPT (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	context = g_main_context_new ();
	g_main_context_push_thread_default (context);

	ret = gsecret_prompt_run (self, window_id, cancellable, error);

	/* Needed to prevent memory leaks */
	while (g_main_context_iteration (context, FALSE));

	g_main_context_pop_thread_default (context);
	g_main_context_unref (context);

	return ret;
}

typedef struct {
	GDBusConnection *connection;
	GCancellable *call_cancellable;
	GCancellable *async_cancellable;
	gulong cancelled_sig;
	gboolean prompting;
	gboolean dismissed;
	gboolean vanished;
	gboolean completed;
	guint signal;
	guint watch;
} PerformClosure;

static void
perform_closure_free (gpointer data)
{
	PerformClosure *closure = data;
	g_object_unref (closure->call_cancellable);
	g_clear_object (&closure->async_cancellable);
	g_object_unref (closure->connection);
	g_assert (closure->signal == 0);
	g_assert (closure->watch == 0);
	g_slice_free (PerformClosure, closure);
}

static void
perform_prompt_complete (GSimpleAsyncResult *res,
                         gboolean dismissed)
{
	PerformClosure *closure = g_simple_async_result_get_op_res_gpointer (res);

	closure->dismissed = dismissed;
	if (closure->completed)
		return;
	closure->completed = TRUE;

	if (closure->signal)
		g_dbus_connection_signal_unsubscribe (closure->connection, closure->signal);
	closure->signal = 0;

	if (closure->watch)
		g_bus_unwatch_name (closure->watch);
	closure->watch = 0;

	if (closure->cancelled_sig)
		g_signal_handler_disconnect (closure->async_cancellable, closure->cancelled_sig);
	closure->cancelled_sig = 0;

	g_simple_async_result_complete (res);
}

static void
on_prompt_completed (GDBusConnection *connection,
                     const gchar *sender_name,
                     const gchar *object_path,
                     const gchar *interface_name,
                     const gchar *signal_name,
                     GVariant *parameters,
                     gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretPrompt *self = GSECRET_PROMPT (g_async_result_get_source_object (user_data));
	PerformClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	gboolean dismissed;

	closure->prompting = FALSE;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(bv)"))) {
		g_warning ("GSecretPrompt received invalid %s signal of type %s",
		           signal_name, g_variant_get_type_string (parameters));
		perform_prompt_complete (res, TRUE);

	} else {
		g_mutex_lock (&self->pv->mutex);
		g_variant_get (parameters, "(bv)", &dismissed, &self->pv->last_result);
		g_mutex_unlock (&self->pv->mutex);

		perform_prompt_complete (res, dismissed);
	}

	g_object_unref (self);
}

static void
on_prompt_prompted (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	PerformClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretPrompt *self = GSECRET_PROMPT (source);
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (self), result, &error);

	if (retval)
		g_variant_unref (retval);
	if (closure->vanished)
		g_clear_error (&error);

	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		perform_prompt_complete (res, TRUE);

	} else {
		g_mutex_lock (&self->pv->mutex);
		closure->prompting = TRUE;
		self->pv->prompted = TRUE;
		g_mutex_unlock (&self->pv->mutex);

		/* And now we wait for the signal */
	}

	g_object_unref (res);
}

static void
on_prompt_vanished (GDBusConnection *connection,
                    const gchar *name,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	PerformClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	closure->vanished = TRUE;
	g_cancellable_cancel (closure->call_cancellable);
	perform_prompt_complete (res, TRUE);
}

static void
on_prompt_dismissed (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	PerformClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretPrompt *self = GSECRET_PROMPT (source);
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (self), result, &error);

	if (retval)
		g_variant_unref (retval);
	if (closure->vanished)
		g_clear_error (&error);
	if (g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD))
		g_clear_error (&error);

	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		perform_prompt_complete (res, TRUE);
	}

	g_object_unref (res);
}

static void
on_prompt_cancelled (GCancellable *cancellable,
                     gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	PerformClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretPrompt *self = GSECRET_PROMPT (g_async_result_get_source_object (user_data));

	/* Instead of cancelling our dbus calls, we cancel the prompt itself via this dbus call */

	g_dbus_proxy_call (G_DBUS_PROXY (self), "Dismiss", g_variant_new ("()"),
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                   closure->call_cancellable,
	                   on_prompt_dismissed, g_object_ref (res));

	g_object_unref (self);
}

void
gsecret_prompt_perform (GSecretPrompt *self,
                        gulong window_id,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GSimpleAsyncResult *res;
	PerformClosure *closure;
	const gchar *owner_name;
	const gchar *object_path;
	gboolean prompted;
	GDBusProxy *proxy;
	gchar *window;

	g_return_if_fail (GSECRET_IS_PROMPT (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	g_mutex_lock (&self->pv->mutex);
	prompted = self->pv->prompted;
	g_mutex_unlock (&self->pv->mutex);

	if (prompted) {
		g_warning ("The prompt object has already had its prompt called.");
		return;
	}

	proxy = G_DBUS_PROXY (self);

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_prompt_perform);
	closure = g_slice_new0 (PerformClosure);
	closure->connection = g_object_ref (g_dbus_proxy_get_connection (proxy));
	closure->call_cancellable = g_cancellable_new ();
	closure->async_cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, perform_closure_free);

	if (window_id == 0)
		window = g_strdup ("");
	else
		window = g_strdup_printf ("%lu", window_id);

	owner_name = g_dbus_proxy_get_name_owner (proxy);
	object_path = g_dbus_proxy_get_object_path (proxy);

	closure->signal = g_dbus_connection_signal_subscribe (closure->connection, owner_name,
	                                                      GSECRET_PROMPT_INTERFACE,
	                                                      GSECRET_PROMPT_SIGNAL_COMPLETED,
	                                                      object_path, NULL,
	                                                      G_DBUS_SIGNAL_FLAGS_NONE,
	                                                      on_prompt_completed,
	                                                      g_object_ref (res),
	                                                      g_object_unref);

	closure->watch = g_bus_watch_name_on_connection (closure->connection, owner_name,
	                                                 G_BUS_NAME_WATCHER_FLAGS_NONE, NULL,
	                                                 on_prompt_vanished,
	                                                 g_object_ref (res),
	                                                 g_object_unref);

	if (closure->async_cancellable) {
		closure->cancelled_sig = g_cancellable_connect (closure->async_cancellable,
		                                                G_CALLBACK (on_prompt_cancelled),
		                                                res, NULL);
	}

	g_dbus_proxy_call (proxy, "Prompt", g_variant_new ("(s)", window),
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                   closure->call_cancellable, on_prompt_prompted, g_object_ref (res));

	g_free (window);
	g_object_unref (res);
}

gboolean
gsecret_prompt_perform_finish (GSecretPrompt *self,
                               GAsyncResult *result,
                               GError **error)
{
	PerformClosure *closure;
	GSimpleAsyncResult *res;

	g_return_val_if_fail (GSECRET_IS_PROMPT (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                                                      gsecret_prompt_perform), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return !closure->dismissed;
}

GVariant *
gsecret_prompt_get_result_value (GSecretPrompt *self,
                                 const GVariantType *expected_type)
{
	GVariant *last_result;
	gchar *string;

	g_return_val_if_fail (GSECRET_IS_PROMPT (self), NULL);

	g_mutex_lock (&self->pv->mutex);
	if (self->pv->last_result)
		last_result = g_variant_ref (self->pv->last_result);
	else
		last_result = NULL;
	g_mutex_unlock (&self->pv->mutex);

	if (last_result != NULL && expected_type != NULL &&
	    !g_variant_is_of_type (last_result, expected_type)) {
		string = g_variant_type_dup_string (expected_type);
		g_warning ("received unexpected result type %s from Completed signal instead of expected %s",
		           g_variant_get_type_string (last_result), string);
		g_variant_unref (last_result);
		g_free (string);
		return NULL;
	}

	return last_result;
}
