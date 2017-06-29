project('glib-schannel', 'c',
  version: '2.50.2',
  meson_version: '>= 0.38.0',
  license: 'LGPL-2.1',
)

cc = meson.get_compiler('c')

glib_req = '2.46.0'
glib = dependency('glib-2.0', version: '>=' + glib_req)
gobject = dependency('gobject-2.0', version: '>=' + glib_req)
gio = dependency('gio-2.0', version: '>=' + glib_req)
giomoduledir = gio.get_pkgconfig_variable('giomoduledir')
gio_querymodules = find_program('gio-querymodules')

cc.has_header('windows.h')
cc.has_header('security.h')
cc.has_header('wincrypt.h')
cc.has_header('ncrypt.h')
cc.has_header('schannel.h')
cc.has_header('sspi.h')
schannel_dep = [cc.find_library('secur32'), cc.find_library('crypt32'), cc.find_library('ncrypt')]

# Compiler flags
if cc.get_id() == 'msvc'
  # Make MSVC more pedantic, this is a recommended pragma list
  # from _Win32_Programming_ by Rector and Newcomer.  Taken from
  # glib's msvc_recommended_pragmas.h--please see that file for
  # the meaning of the warning codes used here
  test_cflags = [
    '-we4002',
    '-we4003',
    '-w14010',
    '-we4013',
    '-w14016',
    '-we4020',
    '-we4021',
    '-we4027',
    '-we4029',
    '-we4033',
    '-we4035',
    '-we4045',
    '-we4047',
    '-we4049',
    '-we4053',
    '-we4071',
    '-we4150',
    '-we4819'
  ]
else
  test_cflags = [
    '-Wpointer-arith',
    '-Wmissing-declarations',
    '-Wformat=2',
    '-Wstrict-prototypes',
    '-Wmissing-prototypes',
    '-Wnested-externs',
    '-Wold-style-definition',
    '-Wdeclaration-after-statement',
    '-Wunused',
    '-Wuninitialized',
    '-Wshadow',
    '-Wmissing-noreturn',
    '-Wmissing-format-attribute',
    '-Wredundant-decls',
    '-Wlogical-op',
    '-Wcast-align',
  ]
endif
common_flags = []
foreach cflag: test_cflags
  if cc.has_argument(cflag)
    common_flags += [ cflag ]
  endif
endforeach

# Require at least Windows 7
common_flags += [ '-D_WIN32_WINNT=0x0601', '-DWINVER=0x0601', '-DNTDDI_VERSION=0x06010000' ]

extra_args= []
# Detect and set symbol visibility
if cc.get_id() == 'msvc'
  extra_args += ['-D_GLIB_EXTERN=__declspec (dllexport) extern']
endif

config_h = configuration_data()
config_h.set_quoted('GETTEXT_PACKAGE', meson.project_name())
config_h.set_quoted('LOCALE_DIR', join_paths(get_option('prefix'), get_option('localedir')))
config_h.set('G_DISABLE_DEPRECATED', true)
config_h.set_quoted('G_LOG_DOMAIN', 'GLib-SChannel')

configure_file(
  output: 'config.h',
  configuration: config_h,
)
config_h_include = include_directories('.')

subdir('tls/base')
subdir('tls/schannel')

