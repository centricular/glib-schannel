/*
 * gtlsbackend-schannel.h
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

#ifndef __G_TLS_BACKEND_SCHANNEL_H__
#define __G_TLS_BACKEND_SCHANNEL_H__

#include <gio/gio.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_BACKEND_SCHANNEL (g_tls_backend_schannel_get_type ())
G_DECLARE_FINAL_TYPE (GTlsBackendSchannel, g_tls_backend_schannel,
                      G, TLS_BACKEND_SCHANNEL, GObject)

#ifdef G_IO_MODULE_BUILD_STATIC
void g_io_module_schannel_load_static (void);
#else
void g_tls_backend_schannel_register (GIOModule *module);
#endif

G_END_DECLS

#endif /* __G_TLS_BACKEND_SCHANNEL_H___ */
