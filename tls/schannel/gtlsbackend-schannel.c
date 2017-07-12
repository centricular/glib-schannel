/*
 * gtlsbackend-schannel.c
 *
 * Copyright (C) 2017 Sebastian Dröge <sebastian@centricular.com>
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"

#include "gtlsbackend-schannel.h"
#include "gtlsdatabase-schannel.h"
#include "gtlscertificate-schannel.h"
#include "gtlsclientconnection-schannel.h"
#include "gtlsserverconnection-schannel.h"

struct _GTlsBackendSchannel
{
  GObject parent;
};

static void g_tls_backend_schannel_interface_init (GTlsBackendInterface *iface);

#ifdef G_IO_MODULE_BUILD_STATIC
G_DEFINE_TYPE_WITH_CODE (GTlsBackendSchannel, g_tls_backend_schannel, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_BACKEND,
                                                g_tls_backend_schannel_interface_init))
#else
G_DEFINE_DYNAMIC_TYPE_EXTENDED (GTlsBackendSchannel, g_tls_backend_schannel, G_TYPE_OBJECT, 0,
                                G_IMPLEMENT_INTERFACE_DYNAMIC (G_TYPE_TLS_BACKEND,
                                                               g_tls_backend_schannel_interface_init))
#endif

static void
g_tls_backend_schannel_init (GTlsBackendSchannel *backend)
{
}

static void
g_tls_backend_schannel_class_init (GTlsBackendSchannelClass *klass)
{
}

#ifndef G_IO_MODULE_BUILD_STATIC
static void
g_tls_backend_schannel_class_finalize (GTlsBackendSchannelClass *backend_class)
{
}
#endif

static gboolean
g_tls_backend_schannel_supports_tls (GTlsBackend *backend)
{
  return TRUE;
}

static gboolean
g_tls_backend_schannel_supports_dtls (GTlsBackend *backend)
{
  return FALSE;
}

static GTlsDatabase *
g_tls_backend_schannel_get_default_database (GTlsBackend *backend)
{
  G_LOCK_DEFINE_STATIC (default_database);
  static GTlsDatabase *database = NULL;

  G_LOCK (default_database);
  if (!database)
    database = g_tls_system_database_schannel_new ();
  G_UNLOCK (default_database);

  return g_object_ref (database);
}

static void
g_tls_backend_schannel_interface_init (GTlsBackendInterface *iface)
{
  iface->supports_tls = g_tls_backend_schannel_supports_tls;
  iface->supports_dtls = g_tls_backend_schannel_supports_dtls;
  iface->get_default_database = g_tls_backend_schannel_get_default_database;
  iface->get_file_database_type = g_tls_file_database_schannel_get_type;
  iface->get_certificate_type = g_tls_certificate_schannel_get_type;
  iface->get_client_connection_type = g_tls_client_connection_schannel_get_type;
  iface->get_server_connection_type = g_tls_server_connection_schannel_get_type;
}

#ifdef G_IO_MODULE_BUILD_STATIC
void
g_io_module_schannel_load_static (void)
{
  g_io_extension_point_set_required_type (g_io_extension_point_register (G_TLS_BACKEND_EXTENSION_POINT_NAME), G_TYPE_TLS_BACKEND);
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
                                  g_tls_backend_schannel_get_type(),
                                  "schannel",
                                  100);
}

#else
void
g_tls_backend_schannel_register (GIOModule *module)
{
  g_tls_backend_schannel_register_type (G_TYPE_MODULE (module));
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
                                  g_tls_backend_schannel_get_type(),
                                  "schannel",
                                  100);

  g_type_plugin_use (g_type_get_plugin (G_TYPE_TLS_BACKEND_SCHANNEL));
}
#endif
