/*
 * gtlsserverconnection-schannel.c
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

#include "gtlsserverconnection-schannel.h"
#include "gtlscertificate-schannel.h"
#include "gtlsdatabase-schannel.h"

/* mingw does not have these */
#ifndef SP_PROT_TLS1_0_SERVER
#define SP_PROT_TLS1_0_SERVER 0x00000040
#endif

#ifndef SP_PROT_TLS1_1_SERVER
#define SP_PROT_TLS1_1_SERVER 0x00000100
#endif

#ifndef SP_PROT_TLS1_2_SERVER
#define SP_PROT_TLS1_2_SERVER 0x00000400
#endif

#ifndef SECBUFFER_ALERT
#define SECBUFFER_ALERT 0x11
#endif

#ifndef ASC_REQ_MANUAL_CRED_VALIDATION
#define ASC_REQ_MANUAL_CRED_VALIDATION 0x00000002
#endif

enum {
  PROP_AUTHENTICATION_MODE = 1
};

struct _GTlsServerConnectionSchannel {
  GTlsConnectionSchannel parent;
};

typedef struct _GTlsServerConnectionSchannelPrivate {
  GTlsAuthenticationMode authentication_mode;
} GTlsServerConnectionSchannelPrivate;

static void g_tls_server_connection_schannel_initable_interface_init (GInitableIface *iface);
static void g_tls_server_connection_schannel_server_connection_interface_init (GTlsServerConnectionInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsServerConnectionSchannel, g_tls_server_connection_schannel, G_TYPE_TLS_CONNECTION_SCHANNEL,
                         G_ADD_PRIVATE (GTlsServerConnectionSchannel)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, g_tls_server_connection_schannel_initable_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_SERVER_CONNECTION, g_tls_server_connection_schannel_server_connection_interface_init))

static void
g_tls_server_connection_schannel_set_property (GObject * obj, guint property_id, const GValue *value, GParamSpec *pspec)
{
  GTlsServerConnectionSchannel *schannel = G_TLS_SERVER_CONNECTION_SCHANNEL (obj);
  GTlsServerConnectionSchannelPrivate *priv = g_tls_server_connection_schannel_get_instance_private (schannel);

  switch (property_id) {
    case PROP_AUTHENTICATION_MODE:
      priv->authentication_mode = g_value_get_enum (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
g_tls_server_connection_schannel_get_property (GObject * obj, guint property_id, GValue *value, GParamSpec *pspec)
{
  GTlsServerConnectionSchannel *schannel = G_TLS_SERVER_CONNECTION_SCHANNEL (obj);
  GTlsServerConnectionSchannelPrivate *priv = g_tls_server_connection_schannel_get_instance_private (schannel);

  switch (property_id) {
    case PROP_AUTHENTICATION_MODE:
      g_value_set_enum (value, priv->authentication_mode);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static GTlsConnectionBaseStatus
g_tls_server_connection_schannel_handshake (GTlsConnectionBase *tls, GCancellable *cancellable, GError **error)
{
  GTlsServerConnectionSchannel *schannel = G_TLS_SERVER_CONNECTION_SCHANNEL (tls);
  GTlsServerConnectionSchannelPrivate *priv = g_tls_server_connection_schannel_get_instance_private (schannel);
  GTlsConnectionSchannel *base = G_TLS_CONNECTION_SCHANNEL (schannel);
  ULONG req_flags, ret_flags;
  SECURITY_STATUS sspi_status;
  gsize to_read;
  gint i;
  GTlsConnectionBaseStatus ret = G_TLS_CONNECTION_BASE_OK;

  if (!base->cred_valid) {
    GTlsCertificate *server_cert;
    GTlsDatabase *database;
    SCHANNEL_CRED auth_data;
    PCCERT_CONTEXT pa_cred[1];

    memset (&auth_data, 0, sizeof (auth_data));
    auth_data.dwVersion = SCHANNEL_CRED_VERSION;
    auth_data.grbitEnabledProtocols = SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_2_SERVER;
    /* FIXME keep this? The client connection has a property */
    auth_data.grbitEnabledProtocols |= SP_PROT_SSL3_SERVER;
    /* we do certificate validation ourselves later */
    auth_data.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_IGNORE_NO_REVOCATION_CHECK | SCH_CRED_IGNORE_REVOCATION_OFFLINE;

    server_cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (schannel));
    if (server_cert) {
      auth_data.cCreds = 1;
      auth_data.paCred = pa_cred;
      auth_data.paCred[0] = g_tls_certificate_schannel_get_context (server_cert);
    }

    database = g_tls_connection_get_database (G_TLS_CONNECTION (schannel));
    if (database)
      auth_data.hRootStore = g_tls_database_schannel_get_store (database);

    if ((sspi_status = AcquireCredentialsHandle (NULL, UNISP_NAME, SECPKG_CRED_INBOUND,
                                  NULL, &auth_data, NULL, NULL, &base->cred,
                                  NULL)) != SEC_E_OK) {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC, "Failed to acquire credentials handle");
      return G_TLS_CONNECTION_BASE_ERROR;
    }
    base->cred_valid = TRUE;
  }

  req_flags = ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_MANUAL_CRED_VALIDATION |
              ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_STREAM;
  if (priv->authentication_mode == G_TLS_AUTHENTICATION_REQUIRED)
    req_flags |= ASC_REQ_MUTUAL_AUTH;

  /* RFC 5246 6.2.1: 1 byte ContentType, 2 bytes ProtocolVersion, 2 bytes
   * length. After this SChannel knows how much is missing */
  to_read = 5;

  sspi_status = SEC_E_INCOMPLETE_MESSAGE;
  while (sspi_status == SEC_I_CONTINUE_NEEDED || sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
    SecBuffer outbuf[3];
    SecBufferDesc outbuf_desc;
    SecBuffer inbuf[3];
    SecBufferDesc inbuf_desc;

    memset (outbuf, 0, sizeof (outbuf));
    memset (&outbuf_desc, 0, sizeof (outbuf_desc));
    memset (inbuf, 0, sizeof (inbuf));
    memset (&inbuf_desc, 0, sizeof (inbuf_desc));

    if (!base->inbuf) {
      /* RFC 5246 6.2.1: At most 2**14 byte chunks */
      base->inbuf_alloc_len = 16384;
      while (base->inbuf_alloc_len < to_read)
        base->inbuf_alloc_len *= 2;
      base->inbuf = g_new (guint8, base->inbuf_alloc_len);
      base->inbuf_len = 0;
    }

    /* Need to read new? Or have data that needs to be passed still? */
    if (base->inbuf_len == 0 || sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
      gssize n_read;

      if (base->inbuf_alloc_len < base->inbuf_len + to_read) {
        while (base->inbuf_alloc_len < base->inbuf_len + to_read)
          base->inbuf_alloc_len *= 2;
        base->inbuf = g_realloc (base->inbuf, base->inbuf_alloc_len);
      }

      g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (schannel), G_IO_IN, TRUE, cancellable);
      n_read = g_pollable_stream_read (g_io_stream_get_input_stream (tls->base_io_stream),
                                       base->inbuf + base->inbuf_len, to_read, TRUE, cancellable,
                                       &tls->read_error);
      ret = g_tls_connection_base_pop_io (G_TLS_CONNECTION_BASE (schannel), G_IO_IN, n_read > 0, error);
      if (ret != G_TLS_CONNECTION_BASE_OK) {
        sspi_status = SEC_E_INTERNAL_ERROR;
        break;
      }
      base->inbuf_len += n_read;

      outbuf[0].BufferType = SECBUFFER_TOKEN;
      outbuf[0].pvBuffer = NULL;
      outbuf[0].cbBuffer = 0;
      outbuf[1].BufferType = SECBUFFER_ALERT;
      outbuf[1].pvBuffer = NULL;
      outbuf[1].cbBuffer = 0;
      outbuf[2].BufferType = SECBUFFER_EMPTY;
      outbuf[2].pvBuffer = NULL;
      outbuf[2].cbBuffer = 0;
      outbuf_desc.ulVersion = SECBUFFER_VERSION;
      outbuf_desc.pBuffers = outbuf;
      outbuf_desc.cBuffers = 3;
      inbuf[0].BufferType = SECBUFFER_TOKEN;
      inbuf[0].pvBuffer = base->inbuf;
      inbuf[0].cbBuffer = base->inbuf_len;
      inbuf[1].BufferType = SECBUFFER_EMPTY;
      inbuf[1].pvBuffer = NULL;
      inbuf[1].cbBuffer = 0;
      inbuf_desc.ulVersion = SECBUFFER_VERSION;
      inbuf_desc.pBuffers = inbuf;
      inbuf_desc.cBuffers = 2;
    }

    sspi_status = AcceptSecurityContext (&base->cred, base->context_valid ? &base->context : NULL, &inbuf_desc,
                                         req_flags, 0, &base->context, &outbuf_desc, &ret_flags, NULL);

    if (sspi_status == SEC_I_CONTINUE_NEEDED)
      base->context_valid = TRUE;

    if (sspi_status != SEC_E_OK &&
        sspi_status != SEC_I_CONTINUE_NEEDED &&
        sspi_status != SEC_E_INCOMPLETE_MESSAGE) {
      break;
    }

    if (outbuf[0].cbBuffer > 0) {
      gsize n_written;
      gboolean success;

      g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (schannel), G_IO_OUT, TRUE, cancellable);
      success = g_pollable_stream_write_all (g_io_stream_get_output_stream (tls->base_io_stream),
                                             outbuf[0].pvBuffer, outbuf[0].cbBuffer, TRUE, &n_written, cancellable,
                                             &tls->write_error);
      ret = g_tls_connection_base_pop_io (G_TLS_CONNECTION_BASE (schannel), G_IO_OUT, success, error);
      if (ret != G_TLS_CONNECTION_BASE_OK) {
        sspi_status = SEC_E_INTERNAL_ERROR;
        break;
      }
    }

    for (i = 0; i < G_N_ELEMENTS (outbuf); i++) {
      FreeContextBuffer (outbuf[i].pvBuffer);
      outbuf[i].pvBuffer = NULL;
    }

    if (sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
      /* Incomplete message, we have to continue reading and keep what we read
       * so far */
      if (inbuf[1].BufferType == SECBUFFER_MISSING && inbuf[1].cbBuffer > 0) {
        to_read = inbuf[1].cbBuffer;
      } else {
        to_read = 1;
      }
    } else {
      /* Complete message, next */
      to_read = 5;

      /* Remaining encrypted data, either further handshake data or actual
       * payload after handshake finished */
      if (inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer > 0) {
        memmove (base->inbuf, base->inbuf + base->inbuf_len - inbuf[1].cbBuffer, inbuf[1].cbBuffer);
        base->inbuf_len = inbuf[1].cbBuffer;
      } else {
        base->inbuf_len = 0;
      }
    }
  }

  memset (&base->stream_sizes, 0, sizeof (base->stream_sizes));

  if (sspi_status == SEC_E_OK) {
    return G_TLS_CONNECTION_BASE_OK;
  }

  if (sspi_status == SEC_E_NO_CREDENTIALS) {
    g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED, "Need to provide server-side certificate");
    ret = G_TLS_CONNECTION_BASE_ERROR;
  } else if (sspi_status == SEC_I_CONTEXT_EXPIRED) {
    if (!base->shutting_down) {
      base->shutting_down = TRUE;
      g_tls_server_connection_schannel_handshake (tls, cancellable, NULL);
    }
    g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_EOF, "TLS connection closed");
    ret = G_TLS_CONNECTION_BASE_ERROR;
  } else if (sspi_status != SEC_E_INTERNAL_ERROR || ret == G_TLS_CONNECTION_BASE_OK) {
    g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC, "Context error 0x%08x", (guint32) sspi_status);
    ret = G_TLS_CONNECTION_BASE_ERROR;
  }

  if (base->context_valid) {
    DeleteSecurityContext (&base->context);
    base->context_valid = FALSE;
  }

  if (base->cred_valid) {
    FreeCredentialsHandle (&base->cred);
    base->cred_valid = FALSE;
  }

  return ret;
}

static void
g_tls_server_connection_schannel_class_init (GTlsServerConnectionSchannelClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;
  GTlsConnectionBaseClass *base_connection_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  gobject_class->set_property = g_tls_server_connection_schannel_set_property;
  gobject_class->get_property = g_tls_server_connection_schannel_get_property;

  g_object_class_override_property (gobject_class, PROP_AUTHENTICATION_MODE, "authentication-mode");

  base_connection_class->handshake = g_tls_server_connection_schannel_handshake;
}

static gboolean
g_tls_server_connection_schannel_initable_init (GInitable *initable, GCancellable *cancellable, GError **error)
{
  return TRUE;
}

static void
g_tls_server_connection_schannel_initable_interface_init (GInitableIface *iface)
{
  iface->init = g_tls_server_connection_schannel_initable_init;
}

static void
g_tls_server_connection_schannel_server_connection_interface_init (GTlsServerConnectionInterface *iface)
{
}

static void
g_tls_server_connection_schannel_init (GTlsServerConnectionSchannel *schannel)
{
}
