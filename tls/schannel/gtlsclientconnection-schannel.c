/*
 * gtlsclientconnection-schannel.c
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

#include "gtlsclientconnection-schannel.h"
#include "gtlscertificate-schannel.h"
#include "gtlsutils-schannel.h"

/* mingw does not have these */
#ifndef SP_PROT_TLS1_0_CLIENT
#define SP_PROT_TLS1_0_CLIENT 0x00000080
#endif

#ifndef SP_PROT_TLS1_1_CLIENT
#define SP_PROT_TLS1_1_CLIENT 0x00000200
#endif

#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT 0x00000800
#endif

#ifndef SECBUFFER_ALERT
#define SECBUFFER_ALERT 0x11
#endif

enum {
  PROP_ACCEPTED_CAS = 1,
  PROP_SERVER_IDENTITY,
  PROP_USE_SSL3,
  PROP_VALIDATION_FLAGS
};

struct _GTlsClientConnectionSchannel {
  GTlsConnectionSchannel parent;
};

typedef struct _GTlsClientConnectionSchannelPrivate {
  GSocketConnectable *server_identity;
  gboolean use_ssl3;
  GTlsCertificateFlags validation_flags;
  GList *accepted_cas;
} GTlsClientConnectionSchannelPrivate;

static void g_tls_client_connection_schannel_client_connection_interface_init (GTlsClientConnectionInterface *iface);
static void g_tls_client_connection_schannel_initable_interface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsClientConnectionSchannel, g_tls_client_connection_schannel, G_TYPE_TLS_CONNECTION_SCHANNEL,
                         G_ADD_PRIVATE (GTlsClientConnectionSchannel)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, g_tls_client_connection_schannel_initable_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_CLIENT_CONNECTION, g_tls_client_connection_schannel_client_connection_interface_init))

static void
g_tls_client_connection_schannel_set_property (GObject * obj, guint property_id, const GValue *value, GParamSpec *pspec)
{
  GTlsClientConnectionSchannel *schannel = G_TLS_CLIENT_CONNECTION_SCHANNEL (obj);
  GTlsClientConnectionSchannelPrivate *priv = g_tls_client_connection_schannel_get_instance_private (schannel);

  switch (property_id) {
    case PROP_SERVER_IDENTITY:
      if (priv->server_identity)
        g_object_unref (priv->server_identity);
      priv->server_identity = g_value_dup_object (value);
      break;
    case PROP_USE_SSL3:
      priv->use_ssl3 = g_value_get_boolean (value);
      break;
    case PROP_VALIDATION_FLAGS:
      priv->validation_flags = g_value_get_flags (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
g_tls_client_connection_schannel_get_property (GObject * obj, guint property_id, GValue *value, GParamSpec *pspec)
{
  GTlsClientConnectionSchannel *schannel = G_TLS_CLIENT_CONNECTION_SCHANNEL (obj);
  GTlsClientConnectionSchannelPrivate *priv = g_tls_client_connection_schannel_get_instance_private (schannel);

  switch (property_id) {
    case PROP_ACCEPTED_CAS: {
      g_value_set_pointer (value, g_list_copy_deep (priv->accepted_cas, (GCopyFunc) g_byte_array_ref, NULL));
      break;
    }
    case PROP_SERVER_IDENTITY:
      g_value_set_object (value, priv->server_identity);
      break;
    case PROP_USE_SSL3:
      g_value_set_boolean (value, priv->use_ssl3);
      break;
    case PROP_VALIDATION_FLAGS:
      g_value_set_flags (value, priv->validation_flags);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
g_tls_client_connection_schannel_finalize (GObject * obj)
{
  GTlsClientConnectionSchannel *schannel = G_TLS_CLIENT_CONNECTION_SCHANNEL (obj);
  GTlsClientConnectionSchannelPrivate *priv = g_tls_client_connection_schannel_get_instance_private (schannel);

  g_list_free_full (priv->accepted_cas, (GDestroyNotify) g_byte_array_unref);
  priv->accepted_cas = NULL;

  G_OBJECT_CLASS (g_tls_client_connection_schannel_parent_class)->finalize (obj);
}

/* Retrieves the CA certificates that the server would accept */
static void
g_tls_client_connection_retrieve_cas (GTlsClientConnectionSchannel *schannel)
{
  GTlsClientConnectionSchannelPrivate *priv = g_tls_client_connection_schannel_get_instance_private (schannel);
  GTlsConnectionSchannel *base = G_TLS_CONNECTION_SCHANNEL (schannel);
  SECURITY_STATUS sspi_status;
  SecPkgContext_IssuerListInfoEx cas;
  GQueue accepted_cas = G_QUEUE_INIT;
  gint i;

  g_list_free_full (priv->accepted_cas, (GDestroyNotify) g_byte_array_unref);
  priv->accepted_cas = NULL;

  if (!base->context_valid)
    return;

  sspi_status = QueryContextAttributes (&base->context, SECPKG_ATTR_ISSUER_LIST_EX, &cas);
  if (sspi_status != SEC_E_OK)
    return;

  for (i = 0; i < cas.cIssuers; i++) {
    GByteArray *arr;

    arr = g_byte_array_sized_new (cas.aIssuers[i].cbData);
    g_byte_array_append (arr, cas.aIssuers[i].pbData, cas.aIssuers[i].cbData);
    g_queue_push_tail (&accepted_cas, arr);
  }

  FreeContextBuffer (cas.aIssuers);

  priv->accepted_cas = accepted_cas.head;
}

static GTlsConnectionBaseStatus
g_tls_client_connection_schannel_handshake (GTlsConnectionBase *tls, GCancellable *cancellable, GError **error)
{
  GTlsClientConnectionSchannel *schannel = G_TLS_CLIENT_CONNECTION_SCHANNEL (tls);
  GTlsClientConnectionSchannelPrivate *priv = g_tls_client_connection_schannel_get_instance_private (schannel);
  GTlsConnectionSchannel *base = G_TLS_CONNECTION_SCHANNEL (schannel);
  ULONG req_flags, ret_flags;
  gchar *aserver_name;
  SECURITY_STATUS sspi_status;
  gsize to_read;
  gint i;
  gboolean first = TRUE;
  GTlsConnectionBaseStatus ret = G_TLS_CONNECTION_BASE_OK;

  if (priv->server_identity) {
    gchar *server_name = NULL;

    server_name = g_tls_schannel_socket_connectable_to_string (priv->server_identity);
    aserver_name = g_locale_from_utf8 (server_name, -1, NULL, NULL, NULL);
    g_free (server_name);
  } else {
    aserver_name = NULL;
  }

new_credentials:
  if (!base->cred_valid) {
    GTlsCertificate *client_cert;
    SCHANNEL_CRED auth_data;
    PCCERT_CONTEXT pa_cred[1];

    memset (&auth_data, 0, sizeof (auth_data));
    auth_data.dwVersion = SCHANNEL_CRED_VERSION;
    auth_data.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;
    if (priv->use_ssl3)
      auth_data.grbitEnabledProtocols |= SP_PROT_SSL3_CLIENT;
    /* Certificate validation happens manually because GIO wants control over
     * that instead of just letting the system figure it out */
    auth_data.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS |
                        SCH_CRED_IGNORE_NO_REVOCATION_CHECK | SCH_CRED_IGNORE_REVOCATION_OFFLINE;

    /* Certificate for client authentication, if any */
    client_cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (schannel));
    if (client_cert) {
      auth_data.cCreds = 1;
      auth_data.paCred = pa_cred;
      auth_data.paCred[0] = g_tls_certificate_schannel_get_context (client_cert);
    }

    if (AcquireCredentialsHandle (NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND,
                                  NULL, &auth_data, NULL, NULL, &base->cred,
                                  NULL) != SEC_E_OK) {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC, "Failed to acquire credentials handle");
      return G_TLS_CONNECTION_BASE_ERROR;
    }
    base->cred_valid = TRUE;
  }

  req_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_MANUAL_CRED_VALIDATION |
              ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;

  /* RFC 5246 6.2.1: 1 byte ContentType, 2 bytes ProtocolVersion, 2 bytes
   * length. After this SChannel knows how much is missing */
  to_read = 5;

  sspi_status = SEC_I_CONTINUE_NEEDED;
  while (sspi_status == SEC_I_CONTINUE_NEEDED || sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
    SecBuffer outbuf[3];
    SecBufferDesc outbuf_desc;
    SecBuffer inbuf[3];
    SecBufferDesc inbuf_desc;

    memset (outbuf, 0, sizeof (outbuf));
    memset (&outbuf_desc, 0, sizeof (outbuf_desc));
    memset (inbuf, 0, sizeof (inbuf));
    memset (&inbuf_desc, 0, sizeof (inbuf_desc));

    if (first) {
      /* Nothing to read here the first time, or after SEC_I_INCOMPLETE_CREDENTIALS */
      outbuf[0].BufferType = SECBUFFER_EMPTY;
      outbuf[0].pvBuffer = NULL;
      outbuf[0].cbBuffer = 0;
      outbuf_desc.ulVersion = SECBUFFER_VERSION;
      outbuf_desc.pBuffers = outbuf;
      outbuf_desc.cBuffers = 1;
      inbuf[0].BufferType = SECBUFFER_EMPTY;
      inbuf[0].pvBuffer = NULL;
      inbuf[0].cbBuffer = 0;
      inbuf_desc.ulVersion = SECBUFFER_VERSION;
      inbuf_desc.pBuffers = inbuf;
      inbuf_desc.cBuffers = 1;

      first = FALSE;
    } else {
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
      }

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

    sspi_status = InitializeSecurityContext (&base->cred, base->context_valid ? &base->context : NULL, aserver_name,
                                             req_flags, 0, 0, inbuf[0].cbBuffer > 0 ? &inbuf_desc : NULL, 0,
                                             &base->context, &outbuf_desc, &ret_flags, NULL);
    base->context_valid = TRUE;

    /* The server *might* want to get a certificate from us */
    if (sspi_status == SEC_I_INCOMPLETE_CREDENTIALS) {
      GTlsInteraction *interaction;

      /* We need to call again without reading any data from the network */
      first = TRUE;
      g_tls_client_connection_retrieve_cas (schannel);

      if ((interaction = g_tls_connection_get_interaction (G_TLS_CONNECTION (schannel)))) {
        GTlsInteractionResult res;

        res = g_tls_interaction_invoke_request_certificate (interaction, G_TLS_CONNECTION (schannel), 0,
                                                            G_TLS_CONNECTION_BASE (schannel)->read_cancellable, error);
        /* Need to get new credentials now that include the certificate */
        if (res == G_TLS_INTERACTION_HANDLED) {
          FreeCredentialsHandle (&base->cred);
          base->cred_valid = FALSE;

          goto new_credentials;
        }
      }

      /* try continue anyway, the server might *request* a certificate but not require it */
      sspi_status = SEC_I_CONTINUE_NEEDED;
    } else if (sspi_status != SEC_E_OK &&
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
  g_free (aserver_name);

  if (sspi_status == SEC_E_OK) {
    return G_TLS_CONNECTION_BASE_OK;
  }

  if (sspi_status == SEC_E_NO_CREDENTIALS) {
    g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED, "Need to provide client-side certificate");
    ret = G_TLS_CONNECTION_BASE_ERROR;
    g_tls_client_connection_retrieve_cas (schannel);
  } else if (sspi_status == SEC_I_CONTEXT_EXPIRED) {
    if (!base->shutting_down) {
      base->shutting_down = TRUE;
      g_tls_client_connection_schannel_handshake (tls, cancellable, NULL);
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
g_tls_client_connection_schannel_copy_session_state (GTlsClientConnection *tls, GTlsClientConnection *source)
{
  /* TODO: Not clear how this is supposed to work */
  g_warn_if_reached ();
}

static void
g_tls_client_connection_schannel_class_init (GTlsClientConnectionSchannelClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;
  GTlsConnectionBaseClass *base_connection_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  gobject_class->set_property = g_tls_client_connection_schannel_set_property;
  gobject_class->get_property = g_tls_client_connection_schannel_get_property;
  gobject_class->finalize = g_tls_client_connection_schannel_finalize;

  g_object_class_override_property (gobject_class, PROP_ACCEPTED_CAS, "accepted-cas");
  g_object_class_override_property (gobject_class, PROP_SERVER_IDENTITY, "server-identity");
  g_object_class_override_property (gobject_class, PROP_USE_SSL3, "use-ssl3");
  g_object_class_override_property (gobject_class, PROP_VALIDATION_FLAGS, "validation-flags");

  base_connection_class->handshake = g_tls_client_connection_schannel_handshake;
}

static void
g_tls_client_connection_schannel_client_connection_interface_init (GTlsClientConnectionInterface *iface)
{
  iface->copy_session_state = g_tls_client_connection_schannel_copy_session_state;
}

static gboolean
g_tls_client_connection_schannel_initable_init (GInitable *initable, GCancellable *cancellable, GError **error)
{
  return TRUE;
}

static void
g_tls_client_connection_schannel_initable_interface_init (GInitableIface *iface)
{
  iface->init = g_tls_client_connection_schannel_initable_init;
}

static void
g_tls_client_connection_schannel_init (GTlsClientConnectionSchannel *schannel)
{
}
