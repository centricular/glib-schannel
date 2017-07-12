tlsschannel_sources = [
  'gtlsmodule-schannel.c',
  'gtlsbackend-schannel.c',
  'gtlsdatabase-schannel.c',
  'gtlscertificate-schannel.c',
  'gtlsconnection-schannel.c',
  'gtlsclientconnection-schannel.c',
  'gtlsserverconnection-schannel.c',
  'gtlsutils-schannel.c',
]

schannel_args = ['-DSECURITY_WIN32=1']

gioschannel = shared_module('gioschannel',
  tlsschannel_sources,
  dependencies: [tlsbase_dep, schannel_dep, gio, glib, gobject ],
  include_directories: config_h_include,
  install: true,
  install_dir: giomoduledir,
  c_args: extra_args + common_flags + schannel_args,
)

gioschannel_static = static_library('gioschannel-static',
  tlsschannel_sources,
  dependencies: [tlsbase_dep, schannel_dep, gio, glib, gobject ],
  include_directories: config_h_include,
  install: true,
  install_dir: giomoduledir,
  c_args: extra_args + common_flags + schannel_args + ['-DG_IO_MODULE_BUILD_STATIC'],
)

gioschannel_inc = include_directories([ '.', '..' ])
gioschannel_dep = declare_dependency(link_with: gioschannel_static,
  include_directories: [ gioschannel_inc, config_h_include ],
  dependencies: [tlsbase_dep, schannel_dep, gio, glib, gobject ],
  compile_args: ['-DG_IO_MODULE_BUILD_STATIC'],
)

