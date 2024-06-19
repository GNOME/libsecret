Title: Using libsecret
Slug: libsecret-using

# Using libsecret in builds or scripts

## C: Compiling with libsecret

Like other GNOME libraries, libsecret uses `pkg-config` to provide compiler
options. The package name is `libsecret-1`. So in your `configure.ac` script,you
might specify something like:

```
PKG_CHECK_MODULES(LIBSECRET, [libsecret-1 >= 1.0])
AC_SUBST(LIBSECRET_CFLAGS)
AC_SUBST(LIBSECRET_LIBS)
```

Code using libsecret should include the header like this:

```c
#include <libsecret/secret.h>
```

Including individual headers besides the main header files is not permitted and
will cause an error.

Some parts of the libsecret API are not yet stable. To use them you need use the
`libsecret-unstable` package. The API contained in this package will change from
time to time. Here's how you would do it:

```
PKG_CHECK_MODULES(LIBSECRET, [libsecret-unstable >= 1.0])
AC_SUBST(LIBSECRET_CFLAGS)
AC_SUBST(LIBSECRET_LIBS)
```

## Javascript: Importing libsecret

In Javascript use the standard introspection import mechanism to get at
libsecret:

```js
const Secret = imports.gi.Secret;

// ... and here's a sample line of code which uses the import
var schema = new Secret.Schema.new("org.mock.Schema",
	Secret.SchemaFlags.NONE, { "name", Secret.SchemaAttributeType.STRING });
```


## Python: Importing libsecret

In python use the standard introspection import mechanism to get at libsecret:

```python
import gi
gi.require_version("Secret", "1")
from gi.repository import Secret

# ... and a here's sample line of code which uses the import
schema = Secret.Schema.new("org.mock.Schema",
	Secret.SchemaFlags.NONE, { "name": Secret.SchemaAttributeType.STRING })
```

## Vala: Compiling with libsecret

The package name is `libsecret-1`. You can use it like
this in your `Makefile.am` file:

```
AM_VALAFLAGS = \
	--pkg=libsecret-1
```

Some parts of the libsecret API are not yet stable.
To use them you need to define the `SECRET_WITH_UNSTABLE` C preprocessor
macro to use them, or else the build will fail:

```
AM_CPPFLAGS = \
	-DSECRET_WITH_UNSTABLE=1
```
