Title: C Examples
Slug: libsecret-c-example

# C Examples

## Define a password schema

Each stored password has a set of attributes which are later
used to lookup the password. The names and types of the attributes
are defined in a schema. The schema is usually defined once globally.
Here's how to define a schema:

```c
// in a header: 

const SecretSchema * example_get_schema (void) G_GNUC_CONST;

#define EXAMPLE_SCHEMA  example_get_schema ()


// in a .c file: 

const SecretSchema *
example_get_schema (void)
{
    static const SecretSchema the_schema = {
        "org.example.Password", SECRET_SCHEMA_NONE,
        {
            {  "number", SECRET_SCHEMA_ATTRIBUTE_INTEGER },
            {  "string", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "even", SECRET_SCHEMA_ATTRIBUTE_BOOLEAN },
            {  "NULL", 0 },
        }
    };
    return &the_schema;
}
```

See the [other examples](#store-a-password) for how to use the schema.

## Store a password

Here's how to store a password in the running secret service,
like gnome-keyring or ksecretservice.

Each stored password has a set of attributes which are later
used to lookup the password. The attributes should not contain
secrets, as they are not stored in an encrypted fashion.

These examples use the [example schema](#define-a-password-schema).

This first example stores a password asynchronously, and is
appropriate for GUI applications so that the UI does not block.

```c
static void
on_password_stored (GObject *source,
                    GAsyncResult *result,
                    gpointer unused)
{
    GError *error = NULL;

    secret_password_store_finish (result, &error);
    if (error != NULL) {
        /* ... handle the failure here */
        g_error_free (error);
    } else {
        /* ... do something now that the password has been stored */
    }
}

/*
 * The variable argument list is the attributes used to later
 * lookup the password. These attributes must conform to the schema.
 */
secret_password_store (EXAMPLE_SCHEMA, SECRET_COLLECTION_DEFAULT, "The label",
                       "the password", NULL, on_password_stored, NULL,
                       "number", 8,
                       "string", "eight",
                       "even", TRUE,
                       NULL);
```

This next example stores a password synchronously. The function
call will block until the password is stored. So this is appropriate for
non GUI applications.

```c
GError *error = NULL;

/*
 * The variable argument list is the attributes used to later
 * lookup the password. These attributes must conform to the schema.
 */
secret_password_store_sync (EXAMPLE_SCHEMA, SECRET_COLLECTION_DEFAULT,
                            "The label", "the password", NULL, &error,
                            "number", 9,
                            "string", "nine",
                            "even", FALSE,
                            NULL);

if (error != NULL) {
    /* ... handle the failure here */
    g_error_free (error);
} else {
    /* ... do something now that the password has been stored */
}
```

## Lookup a password

Here's how to lookup a password in the running secret service,
like gnome-keyring or ksecretservice.

Each stored password has a set of attributes which are
used to lookup the password. If multiple passwords match the
lookup attributes, then the one stored most recently is returned.

These examples use the [example schema](#define-a-password-schema).

This first example looks up a password asynchronously, and is
appropriate for GUI applications so that the UI does not block.

```c
static void
on_password_lookup (GObject *source,
                    GAsyncResult *result,
                    gpointer unused)
 {
    GError *error = NULL;

    gchar *password = secret_password_lookup_finish (result, &error);

    if (error != NULL) {
        /* ... handle the failure here */
        g_error_free (error);

    } else if (password == NULL) {
        /* password will be null, if no matching password found */

    } else {
        /* ... do something with the password */
        secret_password_free (password);
    }

}

/*
 * The variable argument list is the attributes used to later
 * lookup the password. These attributes must conform to the schema.
 */
secret_password_lookup (EXAMPLE_SCHEMA, NULL, on_password_lookup, NULL,
                        "string", "nine",
                        "even", FALSE,
                        NULL);
```

This next example looks up a password synchronously. The function
call will block until the lookup completes. So this is appropriate for
non GUI applications.

```c
GError *error = NULL;

/* The attributes used to lookup the password should conform to the schema. */
gchar *password = secret_password_lookup_sync (EXAMPLE_SCHEMA, NULL, &error,
                                               "string", "nine",
                                               "even", FALSE,
                                               NULL);

if (error != NULL) {
    /* ... handle the failure here */
    g_error_free (error);

} else if (password == NULL) {
    /* password will be null, if no matching password found */

} else {
    /* ... do something with the password */
    secret_password_free (password);
}
```


## Remove a password

Here's how to remove a password from the running secret service,
like gnome-keyring or ksecretservice.

Each stored password has a set of attributes which are
used to find which password to remove. If multiple passwords match the
attributes, then the one stored most recently is removed.

These examples use the [example schema](#define-a-password-schema).

This first example removes a password asynchronously, and is
appropriate for GUI applications so that the UI does not block.

```c
static void
on_password_cleared (GObject *source,
                     GAsyncResult *result,
                     gpointer unused)
 {
    GError *error = NULL;

    gboolean removed = secret_password_clear_finish (result, &error);

    if (error != NULL) {
        /* ... handle the failure here */
        g_error_free (error);

    } else {
        /* removed will be TRUE if a password was removed */
    }
}

/*
 * The variable argument list is the attributes used to later
 * lookup the password. These attributes must conform to the schema.
 */
secret_password_clear (EXAMPLE_SCHEMA, NULL, on_password_cleared, NULL,
                       "string", "nine",
                       "even", FALSE,
                       NULL);
```

This next example looks up a password synchronously. The function
call will block until the lookup completes. So this is appropriate for
non GUI applications.

```c
GError *error = NULL;

/*
 * The variable argument list is the attributes used to later
 * lookup the password. These attributes must conform to the schema.
 */
gboolean removed = secret_password_clear_sync (EXAMPLE_SCHEMA, NULL, &error,
                                               "string", "nine",
                                               "even", FALSE,
                                               NULL);

if (error != NULL) {
    /* ... handle the failure here */
    g_error_free (error);

} else {
    /* removed will be TRUE if a password was removed */
}
```
