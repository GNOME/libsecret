/* libsecret - GLib wrapper for Secret Prompt
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

#include "config.h"

#include "secret-dbus-generated.h"
#include "secret-private.h"
#include "secret-prompt.h"

#include <glib.h>
#include <glib/gi18n-lib.h>

/**
 * SecretPrompt:
 *
 * A prompt in the Service
 *
 * A proxy object representing a prompt that the Secret Service will display
 * to the user.
 *
 * Certain actions on the Secret Service require user prompting to complete,
 * such as creating a collection, or unlocking a collection. When such a prompt
 * is necessary, then a #SecretPrompt object is created by this library, and
 * passed to the [method@Service.prompt] method. In this way it is handled
 * automatically.
 *
 * In order to customize prompt handling, override the
 * [vfunc@Service.prompt_async] and [vfunc@Service.prompt_finish] virtual
 * methods of the [class@Service] class.
 *
 * Stability: Stable
 */

/**
 * SecretPromptClass:
 * @parent_class: the parent class
 *
 * The class for #SecretPrompt.
 */

struct _SecretPromptPrivate {
	gint prompted;
};

G_DEFINE_TYPE_WITH_PRIVATE (SecretPrompt, secret_prompt, G_TYPE_DBUS_PROXY);

static void
secret_prompt_init (SecretPrompt *self)
{
	self->pv = secret_prompt_get_instance_private (self);
}

static void
secret_prompt_class_init (SecretPromptClass *klass)
{
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

SecretPrompt *
_secret_prompt_instance (SecretService *service,
                         const gchar *prompt_path)
{
	GDBusProxy *proxy;
	SecretPrompt *prompt;
	GError *error = NULL;

	g_return_val_if_fail (SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (prompt_path != NULL, NULL);

	proxy = G_DBUS_PROXY (service);
	prompt = g_initable_new (SECRET_TYPE_PROMPT, NULL, &error,
	                         "g-flags", G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                         "g-interface-info", _secret_gen_prompt_interface_info (),
	                         "g-name", g_dbus_proxy_get_name (proxy),
	                         "g-connection", g_dbus_proxy_get_connection (proxy),
	                         "g-object-path", prompt_path,
	                         "g-interface-name", SECRET_PROMPT_INTERFACE,
	                         NULL);

	if (error != NULL) {
		g_warning ("couldn't create SecretPrompt object: %s", error->message);
		g_clear_error (&error);
		return NULL;
	}

	return prompt;
}

/**
 * secret_prompt_run:
 * @self: a prompt
 * @window_id: (nullable): string form of XWindow id for parent window to be transient for
 * @cancellable: (nullable): optional cancellation object
 * @return_type: the variant type of the prompt result
 * @error: location to place an error on failure
 *
 * Runs a prompt and performs the prompting.
 *
 * Returns a variant result if the prompt was completed and not dismissed. The
 * type of result depends on the action the prompt is completing, and is defined
 * in the Secret Service DBus API specification.
 *
 * If @window_id is non-null then it is used as an XWindow id on Linux. The API
 * expects this id to be converted to a string using the `%d` printf format. The
 * Secret Service can make its prompt transient for the window with this id. In
 * some Secret Service implementations this is not possible, so the behavior
 * depending on this should degrade gracefully.
 *
 * This runs the dialog in a recursive mainloop. When run from a user interface
 * thread, this means the user interface will remain responsive. Care should be
 * taken that appropriate user interface actions are disabled while running the
 * prompt.
 *
 * Returns: (transfer full): %NULL if the prompt was dismissed or an error occurred
 */
GVariant *
secret_prompt_run (SecretPrompt *self,
                   const gchar *window_id,
                   GCancellable *cancellable,
                   const GVariantType *return_type,
                   GError **error)
{
	GMainContext *context;
	RunClosure *closure;
	GVariant *retval;

	g_return_val_if_fail (SECRET_IS_PROMPT (self), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	context = g_main_context_get_thread_default ();

	closure = g_new0 (RunClosure, 1);
	closure->loop = g_main_loop_new (context, FALSE);

	secret_prompt_perform (self, window_id, return_type, cancellable,
	                       on_prompt_run_complete, closure);

	g_main_loop_run (closure->loop);

	retval = secret_prompt_perform_finish (self, closure->result, error);

	g_main_loop_unref (closure->loop);
	g_object_unref (closure->result);
	g_free (closure);

	return retval;
}

/**
 * secret_prompt_perform_sync:
 * @self: a prompt
 * @window_id: (nullable): string form of XWindow id for parent window to be transient for
 * @cancellable: (nullable): optional cancellation object
 * @return_type: the variant type of the prompt result
 * @error: location to place an error on failure
 *
 * Runs a prompt and performs the prompting.
 *
 * Returns a variant result if the prompt was completed and not dismissed. The
 * type of result depends on the action the prompt is completing, and is defined
 * in the Secret Service DBus API specification.
 *
 * If @window_id is non-null then it is used as an XWindow id on Linux. The API
 * expects this id to be converted to a string using the `%d` printf format. The
 * Secret Service can make its prompt transient for the window with this id. In
 * some Secret Service implementations this is not possible, so the behavior
 * depending on this should degrade gracefully.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): %NULL if the prompt was dismissed or an error occurred
 */
GVariant *
secret_prompt_perform_sync (SecretPrompt *self,
                            const gchar *window_id,
                            GCancellable *cancellable,
                            const GVariantType *return_type,
                            GError **error)
{
	GMainContext *context;
	GVariant *retval;

	g_return_val_if_fail (SECRET_IS_PROMPT (self), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	context = g_main_context_new ();
	g_main_context_push_thread_default (context);

	retval = secret_prompt_run (self, window_id, cancellable, return_type, error);

	/* Needed to prevent memory leaks */
	while (g_main_context_iteration (context, FALSE));

	g_main_context_pop_thread_default (context);
	g_main_context_unref (context);

	return retval;
}

typedef struct {
	GDBusConnection *connection;
	GCancellable *call_cancellable;
	gulong cancelled_sig;
	gboolean prompting;
	gboolean dismissed;
	gboolean vanished;
	gboolean completed;
	GVariant *result;
	guint signal;
	guint watch;
	GVariantType *return_type;
} PerformClosure;

static void
perform_closure_free (gpointer data)
{
	PerformClosure *closure = data;
	g_object_unref (closure->call_cancellable);
	g_object_unref (closure->connection);
	if (closure->result)
		g_variant_unref (closure->result);
	if (closure->return_type)
		g_variant_type_free (closure->return_type);
	g_assert (closure->signal == 0);
	g_assert (closure->watch == 0);
	g_free (closure);
}

static void
perform_prompt_complete (GTask *task,
                         gboolean dismissed)
{
	PerformClosure *closure = g_task_get_task_data (task);
	GCancellable *async_cancellable = g_task_get_cancellable (task);
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
		g_signal_handler_disconnect (async_cancellable, closure->cancelled_sig);
	closure->cancelled_sig = 0;
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
	GTask *task = G_TASK (user_data);
	PerformClosure *closure = g_task_get_task_data (task);
	gboolean dismissed;

	closure->prompting = FALSE;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(bv)"))) {
		g_warning ("SecretPrompt received invalid %s signal of type %s",
		           signal_name, g_variant_get_type_string (parameters));
		perform_prompt_complete (task, TRUE);
		g_task_return_boolean (task, TRUE);

	} else {
		g_variant_get (parameters, "(bv)", &dismissed, &closure->result);
		perform_prompt_complete (task, dismissed);
		g_task_return_boolean (task, TRUE);
	}
}

static void
on_prompt_prompted (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	PerformClosure *closure = g_task_get_task_data (task);
	SecretPrompt *self = SECRET_PROMPT (source);
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (self), result, &error);

	if (retval)
		g_variant_unref (retval);
	if (closure->vanished)
		g_clear_error (&error);

	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
		perform_prompt_complete (task, TRUE);

	} else {
		closure->prompting = TRUE;
		g_atomic_int_set (&self->pv->prompted, 1);

		/* And now we wait for the signal */
	}

	g_clear_object (&task);
}

static void
on_prompt_vanished (GDBusConnection *connection,
                    const gchar *name,
                    gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	PerformClosure *closure = g_task_get_task_data (task);
	closure->vanished = TRUE;
	g_cancellable_cancel (closure->call_cancellable);
	perform_prompt_complete (task, TRUE);
	g_task_return_boolean (task, TRUE);
}

static void
on_prompt_dismissed (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	PerformClosure *closure = g_task_get_task_data (task);
	SecretPrompt *self = SECRET_PROMPT (source);
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
		perform_prompt_complete (task, TRUE);
		g_task_return_error (task, error);
	}

	g_clear_object (&task);
}

static void
on_prompt_cancelled (GCancellable *cancellable,
                     gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretPrompt *self = SECRET_PROMPT (g_task_get_source_object (task));
	PerformClosure *closure = g_task_get_task_data (task);

	/* Instead of cancelling our dbus calls, we cancel the prompt itself via this dbus call */

	g_dbus_proxy_call (G_DBUS_PROXY (self), "Dismiss", g_variant_new ("()"),
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                   closure->call_cancellable,
	                   on_prompt_dismissed, g_object_ref (task));
}

/**
 * secret_prompt_perform:
 * @self: a prompt
 * @window_id: (nullable): string form of XWindow id for parent window to be transient for
 * @return_type: the variant type of the prompt result
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Runs a prompt and performs the prompting.
 *
 * Returns %TRUE if the prompt was completed and not dismissed.
 *
 * If @window_id is non-null then it is used as an XWindow id on Linux. The API
 * expects this id to be converted to a string using the `%d` printf format. The
 * Secret Service can make its prompt transient for the window with this id. In
 * some Secret Service implementations this is not possible, so the behavior
 * depending on this should degrade gracefully.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_prompt_perform (SecretPrompt *self,
                       const gchar *window_id,
                       const GVariantType *return_type,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	GTask *task;
	PerformClosure *closure;
	GCancellable *async_cancellable;
	gchar *owner_name;
	const gchar *object_path;
	gboolean prompted;
	GDBusProxy *proxy;

	g_return_if_fail (SECRET_IS_PROMPT (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	prompted = g_atomic_int_get (&self->pv->prompted);
	if (prompted) {
		g_warning ("The prompt object has already had its prompt called.");
		return;
	}

	proxy = G_DBUS_PROXY (self);

	task = g_task_new (self, cancellable, callback, user_data);
	async_cancellable = g_task_get_cancellable (task);
	g_task_set_source_tag (task, secret_prompt_perform);
	closure = g_new0 (PerformClosure, 1);
	closure->connection = g_object_ref (g_dbus_proxy_get_connection (proxy));
	closure->call_cancellable = g_cancellable_new ();
	async_cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->return_type = return_type ? g_variant_type_copy (return_type) : NULL;
	g_task_set_task_data (task, closure, perform_closure_free);
	g_task_set_check_cancellable (task, FALSE);

	if (window_id == NULL)
		window_id = "";

	owner_name = g_dbus_proxy_get_name_owner (proxy);
	object_path = g_dbus_proxy_get_object_path (proxy);

	closure->signal = g_dbus_connection_signal_subscribe (closure->connection, owner_name,
	                                                      SECRET_PROMPT_INTERFACE,
	                                                      SECRET_PROMPT_SIGNAL_COMPLETED,
	                                                      object_path, NULL,
	                                                      G_DBUS_SIGNAL_FLAGS_NONE,
	                                                      on_prompt_completed,
	                                                      g_object_ref (task),
	                                                      g_object_unref);

	closure->watch = g_bus_watch_name_on_connection (closure->connection, owner_name,
	                                                 G_BUS_NAME_WATCHER_FLAGS_NONE, NULL,
	                                                 on_prompt_vanished,
	                                                 g_object_ref (task),
	                                                 g_object_unref);

	if (async_cancellable) {
		closure->cancelled_sig = g_cancellable_connect (async_cancellable,
		                                                G_CALLBACK (on_prompt_cancelled),
		                                                g_object_ref (task), g_object_unref);
	}

	g_dbus_proxy_call (proxy, "Prompt", g_variant_new ("(s)", window_id),
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                   closure->call_cancellable, on_prompt_prompted, g_object_ref (task));

	g_clear_object (&task);
	g_free (owner_name);
}

/**
 * secret_prompt_perform_finish:
 * @self: a prompt
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to run a prompt and perform the prompting.
 *
 * Returns a variant result if the prompt was completed and not dismissed. The
 * type of result depends on the action the prompt is completing, and is
 * defined in the Secret Service DBus API specification.
 *
 * Returns: (transfer full): %NULL if the prompt was dismissed or an error occurred,
 *   a variant result if the prompt was successful
 */
GVariant *
secret_prompt_perform_finish (SecretPrompt *self,
                              GAsyncResult *result,
                              GError **error)
{
	PerformClosure *closure;
	gchar *string;

	g_return_val_if_fail (SECRET_IS_PROMPT (self), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_task_is_valid (result, self), NULL);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) == secret_prompt_perform, NULL);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	closure = g_task_get_task_data (G_TASK (result));
	if (closure->result == NULL)
		return NULL;
	if (closure->return_type != NULL && !g_variant_is_of_type (closure->result, closure->return_type)) {
		string = g_variant_type_dup_string (closure->return_type);
		g_warning ("received unexpected result type %s from Completed signal instead of expected %s",
		           g_variant_get_type_string (closure->result), string);
		g_free (string);
		return NULL;
	}
	return g_variant_ref (closure->result);
}
