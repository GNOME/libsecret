libsecret
=========

A [GObject]-based library for accessing the Secret Service API of the
[freedesktop.org project], a cross-desktop effort to access passwords, tokens
and other types of secrets. libsecret provides a convenient wrapper for these
methods so consumers do not have to call the low-level DBus methods.

The actual Secret Service API spec can be found at
https://specifications.freedesktop.org/secret-service/.

Documentation
--------

You can find the nightly documentation at https://gnome.pages.gitlab.gnome.org/libsecret/.

Building
--------

To build and install libsecret, you can use the following commands:

```
$ meson _build
$ ninja -C _build
$ ninja -C _build install
```

Contributing
-------------

You can browse the code, issues and more at libsecret's [GitLab repository].

If you find a bug in libsecret, please file an issue on the [issue tracker].
Please try to add reproducible steps and the relevant version of libsecret.

If you want to contribute functionality or bug fixes, please open a Merge
Request (MR). For more info on how to do this, see GitLab's [help pages on
MR's].

If libsecret is not translated in your language or you believe that the
current translation has errors, you can join one of the various translation
teams in GNOME. Translators do not commit directly to Git, but are advised to
use our separate translation infrastructure instead. More info can be found at
the [translation project wiki page].

Releases
-------------

The release tarballs use [semantic versioning] since 0.19.0, which
basically means:

- The major version will be incremented if backward incompatible changes are added
- The minor version will be incremented if new functionality is added in a backward compatible manner
- The patch version will be incremented if only backward compatible bug fixes are added

Note that there is no stable/unstable indication in whether the minor
version number is even or odd.


[GObject]: https://developer.gnome.org/gobject/stable/
[freedesktop.org project]: https://www.freedesktop.org/
[GitLab repository]: https://gitlab.gnome.org/GNOME/libsecret
[help pages on MR's]: https://docs.gitlab.com/ee/gitlab-basics/add-merge-request.html
[issue tracker]: https://gitlab.gnome.org/GNOME/libsecret/issues
[translation project wiki page]: https://wiki.gnome.org/TranslationProject/
[semantic versioning]: https://semver.org
