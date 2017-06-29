tlsbase_sources = [
  'gtlsconnection-base.c',
  'gtlsinputstream-base.c',
  'gtlsoutputstream-base.c',
]

tlsbase = static_library('tlsbase',
  tlsbase_sources,
  dependencies: [ gio, glib, gobject ],
  include_directories: config_h_include,
  c_args: extra_args + common_flags,
)

tlsbase_dep = declare_dependency(
  link_with: tlsbase,
  include_directories: include_directories('.'),
  dependencies: [ gio, glib, gobject ],
)
