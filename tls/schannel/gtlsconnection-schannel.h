/*
 * gtlsconnection-schannel.h
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

#ifndef __G_TLS_CONNECTION_SCHANNEL_H__
#define __G_TLS_CONNECTION_SCHANNEL_H__

#include <gio/gio.h>

#include <windows.h>
#include <sspi.h>
#include <schannel.h>

#include "gtlsconnection-base.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_CONNECTION_SCHANNEL            (g_tls_connection_schannel_get_type ())
#define G_TLS_CONNECTION_SCHANNEL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), G_TYPE_TLS_CONNECTION_SCHANNEL, GTlsConnectionSchannel))
#define G_TLS_CONNECTION_SCHANNEL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), G_TYPE_TLS_CONNECTION_SCHANNEL, GTlsConnectionSchannelClass))
#define G_IS_TLS_CONNECTION_SCHANNEL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), G_TYPE_TLS_CONNECTION_SCHANNEL))
#define G_IS_TLS_CONNECTION_SCHANNEL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), G_TYPE_TLS_CONNECTION_SCHANNEL))
#define G_TLS_CONNECTION_SCHANNEL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), G_TYPE_TLS_CONNECTION_SCHANNEL, GTlsConnectionSchannelClass))

typedef struct _GTlsConnectionSchannel      GTlsConnectionSchannel;
typedef struct _GTlsConnectionSchannelClass GTlsConnectionSchannelClass;

struct _GTlsConnectionSchannel {
  GTlsConnectionBase parent;

  CredHandle cred;
  gboolean cred_valid;
  CtxtHandle context;
  gboolean context_valid;

  gboolean shutting_down;

  guint8 *inbuf;
  gsize inbuf_alloc_len, inbuf_len;

  guint8 *outbuf;
  gsize outbuf_alloc_len, outbuf_len;
  gsize outbuf_offset;

  SecPkgContext_StreamSizes stream_sizes;
  guint8 *encbuf;
  gsize encbuf_alloc_len, encbuf_len;
  gsize encbuf_offset;
};

struct _GTlsConnectionSchannelClass {
  GTlsConnectionBaseClass parent_class;
};

GType g_tls_connection_schannel_get_type (void);

#ifdef G_DEFINE_AUTOPTR_CLEANUP_FUNC
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GTlsConnectionSchannel, g_object_unref)
#endif

G_END_DECLS

#endif /* __G_TLS_CONNECTION_SCHANNEL_H__ */

