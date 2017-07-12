/*
 * gtlsmodule-schannel.c
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

#include <gio/gio.h>

#include "gtlsmodule-schannel.h"
#include "gtlsbackend-schannel.h"

#ifdef G_IO_MODULE_BUILD_STATIC
void
g_io_module_schannel_register (void)
{
  g_io_module_schannel_load_static ();
}
#else
void
g_io_module_load (GIOModule *module)
{
  g_tls_backend_schannel_register (module);
}

void
g_io_module_unload (GIOModule *module)
{
}

gchar **
g_io_module_query (void)
{
  return g_strsplit (G_TLS_BACKEND_EXTENSION_POINT_NAME, "!", -1);
}
#endif
