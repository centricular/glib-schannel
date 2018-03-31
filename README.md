# glib-schannel
GLib GIO TLS backend using the Windows SChannel API

[glib-networking](https://git.gnome.org/browse/glib-networking) already provides a GIO module that implements a [GIO TLS backend](https://developer.gnome.org/gio/stable/GTlsBackend.html), but it uses [GnuTLS](https://en.wikipedia.org/wiki/GnuTLS).

This project builds a GIO module that uses the [TLS implementation provided by Windows](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380516(v=vs.85).aspx) as part of the SChannel API.

Advantages include reduced external dependencies, easier security updates, and better integration with the Windows certificate store.

See also [glib-openssl](https://git.gnome.org/browse/glib-openssl/) which does the same but uses OpenSSL.
