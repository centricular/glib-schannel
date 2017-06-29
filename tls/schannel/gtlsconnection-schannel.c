/*
 * gtlsconnection-schannel.c
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

#include "gtlsconnection-schannel.h"
#include "gtlscertificate-schannel.h"

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

G_DEFINE_ABSTRACT_TYPE (GTlsConnectionSchannel, g_tls_connection_schannel, G_TYPE_TLS_CONNECTION_BASE)

static void
g_tls_connection_schannel_finalize (GObject * obj)
{
  GTlsConnectionSchannel *schannel = G_TLS_CONNECTION_SCHANNEL (obj);

  g_free (schannel->inbuf);
  schannel->inbuf = NULL;

  g_free (schannel->outbuf);
  schannel->outbuf = NULL;

  g_free (schannel->encbuf);
  schannel->encbuf = NULL;

  if (schannel->context_valid) {
    DeleteSecurityContext (&schannel->context);
    schannel->context_valid = FALSE;
  }

  if (schannel->cred_valid) {
    FreeCredentialsHandle (&schannel->cred);
    schannel->cred_valid = FALSE;
  }

  G_OBJECT_CLASS (g_tls_connection_schannel_parent_class)->finalize (obj);
}

static GTlsConnectionBaseStatus
g_tls_connection_schannel_request_rehandshake (GTlsConnectionBase *tls, GCancellable *cancellable, GError **error)
{

  /* Nothing to be done here, we just have to call the handshake code again */
  /* FIXME: Do we need to flush any pending data from our buffers? */

  return G_TLS_CONNECTION_BASE_OK;
}

static GTlsConnectionBaseStatus
g_tls_connection_schannel_complete_handshake (GTlsConnectionBase *tls, GError **error)
{
  GTlsConnectionSchannel *schannel = G_TLS_CONNECTION_SCHANNEL (tls);
  GTlsDatabase *database;
  PCCERT_CONTEXT peer_certificate, last_issuer = NULL;
  GTlsCertificate *last_issuer_cert = NULL, *cert;
  GPtrArray *issuers;
  SECURITY_STATUS sspi_status;
  gint i;
  GTlsCertificateFlags cert_flags = 0;
  GTlsConnectionBaseStatus ret;
  GSocketConnectable *identity = NULL;

  /* Get the peer certificate, if any, and validate it */
  if (G_IS_TLS_CLIENT_CONNECTION (schannel))
    identity = g_tls_client_connection_get_server_identity (G_TLS_CLIENT_CONNECTION (schannel));

  g_assert (schannel->context_valid);

  sspi_status = QueryContextAttributes (&schannel->context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (gpointer) &peer_certificate);
  if (sspi_status != SEC_E_OK || !peer_certificate) {
    if (G_IS_TLS_CLIENT_CONNECTION (schannel)) {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE, "Peer did not return a valid TLS certificate");
      return G_TLS_CONNECTION_BASE_ERROR;
    } else {
      return G_TLS_CONNECTION_BASE_OK;
    }
  }
  database = g_tls_connection_get_database (G_TLS_CONNECTION (schannel));

  /* Get issuer chain */
  issuers = g_ptr_array_new ();
  last_issuer = peer_certificate;

  /* FIXME: There can be multiple issuers for a certificate, and the docs
   * suggest to use CertGetCertificateChain(). But this works for now */
  do {
    DWORD dwflags = 0;

    last_issuer = CertGetIssuerCertificateFromStore (last_issuer->hCertStore, last_issuer, NULL, &dwflags);
    if (last_issuer)
      g_ptr_array_add (issuers, (gpointer) last_issuer);
  } while (last_issuer != NULL);

  for (i = issuers->len - 1; i >= 0; i--) {
    GTlsCertificate *tmp;

    last_issuer = issuers->pdata[i];
    tmp = g_object_new (G_TYPE_TLS_CERTIFICATE_SCHANNEL, "database", database, "cert-context", last_issuer,
                        "issuer", last_issuer_cert, NULL);
    if (last_issuer_cert)
      g_object_unref (last_issuer_cert);
    last_issuer_cert = tmp;
  }
  cert = g_object_new (G_TYPE_TLS_CERTIFICATE_SCHANNEL, "database", database, "cert-context", peer_certificate,
                       "issuer", last_issuer_cert, NULL);
  if (last_issuer_cert)
    g_object_unref (last_issuer_cert);
  g_ptr_array_unref (issuers);

  /* Verify chain */
  if (!database) {
    cert_flags |= G_TLS_CERTIFICATE_UNKNOWN_CA;
    cert_flags |= g_tls_certificate_verify (cert, identity, NULL);
  } else {
    cert_flags |= g_tls_database_verify_chain (database, cert,
                                               G_IS_TLS_CLIENT_CONNECTION (schannel) ?
                                                  G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER :
                                                  G_TLS_DATABASE_PURPOSE_AUTHENTICATE_CLIENT,
                                               identity,
                                               g_tls_connection_get_interaction (G_TLS_CONNECTION (schannel)),
                                               G_TLS_DATABASE_VERIFY_NONE,
                                               NULL, NULL);
  }

  if (!g_tls_connection_base_accept_peer_certificate (G_TLS_CONNECTION_BASE (schannel), cert, cert_flags)) {
    g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE, "Unacceptable server certificate");
    ret = G_TLS_CONNECTION_BASE_ERROR;
  } else {
    ret = G_TLS_CONNECTION_BASE_OK;
  }
  g_tls_connection_base_set_peer_certificate (G_TLS_CONNECTION_BASE (schannel), cert, cert_flags);
  g_object_unref (cert);

  return ret;
}

static GTlsConnectionBaseStatus
g_tls_connection_schannel_read (GTlsConnectionBase *tls, void *buffer, gsize count, gboolean blocking, gssize *nread,
                                GCancellable *cancellable, GError **error)
{
  GTlsConnectionSchannel *schannel = G_TLS_CONNECTION_SCHANNEL (tls);
  SECURITY_STATUS sspi_status = SEC_E_OK;
  gsize to_read;
  GTlsConnectionBaseStatus ret = G_TLS_CONNECTION_BASE_OK;

  if (count == 0)
    return G_TLS_CONNECTION_BASE_OK;

  /* Any leftover decrypted data */
  if (schannel->outbuf_len > 0) {
    *nread = MIN (schannel->outbuf_len, count);
    memcpy (buffer, schannel->outbuf + schannel->outbuf_offset, *nread);
    if (*nread >= schannel->outbuf_len) {
      schannel->outbuf_len = 0;
      schannel->outbuf_offset = 0;
    } else {
      schannel->outbuf_offset += *nread;
      schannel->outbuf_len -= *nread;
    }

    return G_TLS_CONNECTION_BASE_OK;
  }

  /* Must be 0, otherwise we would've returned that immediately */
  g_assert (schannel->outbuf_len == 0);
  g_assert (schannel->outbuf_offset == 0);

  to_read = 5;
  do {
    SecBuffer inbuf[4];
    SecBufferDesc inbuf_desc;

    if (!schannel->inbuf) {
      /* RFC 5246 6.2.1: At most 2**14 byte chunks */
      schannel->inbuf_alloc_len = 16384;
      while (schannel->inbuf_alloc_len < to_read)
        schannel->inbuf_alloc_len *= 2;
      schannel->inbuf = g_new (guint8, schannel->inbuf_alloc_len);
      schannel->inbuf_len = 0;
    }

    /* Need to read new? Or have data that needs to be passed still? */
    if (schannel->inbuf_len == 0 || sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
      gssize n_read;

      if (schannel->inbuf_alloc_len < schannel->inbuf_len + to_read) {
        while (schannel->inbuf_alloc_len < schannel->inbuf_len + to_read)
          schannel->inbuf_alloc_len *= 2;
        schannel->inbuf = g_realloc (schannel->inbuf, schannel->inbuf_alloc_len);
      }

      g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (schannel), G_IO_IN, blocking, cancellable);
      n_read = g_pollable_stream_read (g_io_stream_get_input_stream (tls->base_io_stream),
                                       schannel->inbuf + schannel->inbuf_len, to_read, blocking, cancellable,
                                       &tls->read_error);
      ret = g_tls_connection_base_pop_io (G_TLS_CONNECTION_BASE (schannel), G_IO_IN, n_read > 0, error);
      if (ret != G_TLS_CONNECTION_BASE_OK) {
        *nread = 0;
        sspi_status = SEC_E_INTERNAL_ERROR;
        break;
      }
      schannel->inbuf_len += n_read;
    }

    inbuf[0].BufferType = SECBUFFER_DATA;
    inbuf[0].pvBuffer = schannel->inbuf;
    inbuf[0].cbBuffer = schannel->inbuf_len;
    inbuf[1].BufferType = SECBUFFER_EMPTY;
    inbuf[1].pvBuffer = NULL;
    inbuf[1].cbBuffer = 0;
    inbuf[2].BufferType = SECBUFFER_EMPTY;
    inbuf[2].pvBuffer = NULL;
    inbuf[2].cbBuffer = 0;
    inbuf[3].BufferType = SECBUFFER_EMPTY;
    inbuf[3].pvBuffer = NULL;
    inbuf[3].cbBuffer = 0;
    inbuf_desc.ulVersion = SECBUFFER_VERSION;
    inbuf_desc.pBuffers = inbuf;
    inbuf_desc.cBuffers = 4;

    sspi_status = DecryptMessage (&schannel->context, &inbuf_desc, 0, NULL);

    if (inbuf[1].BufferType == SECBUFFER_DATA && inbuf[1].cbBuffer > 0) {
      *nread = MIN (inbuf[1].cbBuffer, count);
      memcpy (buffer, inbuf[1].pvBuffer, *nread);

      /* Leftover for next call */
      if (*nread < inbuf[1].cbBuffer) {
        if (!schannel->outbuf) {
          schannel->outbuf_alloc_len = 16384;
          while (schannel->outbuf_alloc_len < inbuf[1].cbBuffer - *nread)
            schannel->outbuf_alloc_len *= 2;
          schannel->outbuf = g_new (guint8, schannel->outbuf_alloc_len);
          schannel->outbuf_len = 0;
          schannel->outbuf_offset = 0;
        }

        if (schannel->outbuf_alloc_len < inbuf[1].cbBuffer - *nread) {
          while (schannel->outbuf_alloc_len < inbuf[1].cbBuffer - *nread)
            schannel->outbuf_alloc_len *= 2;
          schannel->outbuf = g_realloc (schannel->outbuf, schannel->outbuf_alloc_len);
        }

        schannel->outbuf_len = inbuf[1].cbBuffer - *nread;
        memcpy (schannel->outbuf, ((guint8 *) inbuf[1].pvBuffer) + *nread, schannel->outbuf_len);
      }
    }

    if (sspi_status != SEC_E_OK &&
        sspi_status != SEC_E_INCOMPLETE_MESSAGE) {
      break;
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
      /* Complete message */
      to_read = 5;

      /* Remaining encrypted data, either further handshake data or actual
       * payload after handshake finished */
      if (inbuf[3].BufferType == SECBUFFER_EXTRA && inbuf[3].cbBuffer > 0) {
        memmove (schannel->inbuf, schannel->inbuf + schannel->inbuf_len - inbuf[3].cbBuffer, inbuf[3].cbBuffer);
        schannel->inbuf_len = inbuf[3].cbBuffer;
      } else {
        schannel->inbuf_len = 0;
      }

      break;
    }
  } while (sspi_status == SEC_E_INCOMPLETE_MESSAGE || (sspi_status == SEC_E_OK && *nread == 0));

  if (sspi_status == SEC_I_RENEGOTIATE) {
    return G_TLS_CONNECTION_BASE_REHANDSHAKE;
  } else if (sspi_status == SEC_I_CONTEXT_EXPIRED) {
    schannel->shutting_down = TRUE;
    G_TLS_CONNECTION_BASE_GET_CLASS (tls)->handshake (tls, cancellable, NULL);
    g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_EOF, "TLS connection closed");
  } else if (sspi_status == SEC_E_OK) {
    return G_TLS_CONNECTION_BASE_OK;
  } else {
    if (sspi_status != SEC_E_INTERNAL_ERROR || ret == G_TLS_CONNECTION_BASE_OK) {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC, "Context error 0x%08x", (guint32) sspi_status);
      ret = G_TLS_CONNECTION_BASE_ERROR;
    }

    return ret;
  }

  return G_TLS_CONNECTION_BASE_ERROR;
}

static GTlsConnectionBaseStatus
g_tls_connection_schannel_write (GTlsConnectionBase *tls, const void *buffer, gsize count, gboolean blocking,
                                 gssize *nwrote, GCancellable *cancellable, GError **error)
{
  GTlsConnectionSchannel *schannel = G_TLS_CONNECTION_SCHANNEL (tls);
  SECURITY_STATUS sspi_status = SEC_E_OK;
  gsize len;
  SecBuffer outbuf[4];
  SecBufferDesc outbuf_desc;
  GTlsConnectionBaseStatus ret = G_TLS_CONNECTION_BASE_OK;

  if (schannel->stream_sizes.cbMaximumMessage == 0) {
    sspi_status = QueryContextAttributes (&schannel->context, SECPKG_ATTR_STREAM_SIZES, &schannel->stream_sizes);
    if (sspi_status != SEC_E_OK) {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC, "Failed to query context attributes");
      return G_TLS_CONNECTION_BASE_ERROR;
    }
  }

  if (schannel->encbuf_len > 0) {
    gsize n_written = 0;
    gboolean success;

    g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (schannel), G_IO_OUT, blocking, cancellable);
    success = g_pollable_stream_write_all (g_io_stream_get_output_stream (tls->base_io_stream),
                                           schannel->encbuf + schannel->encbuf_offset, schannel->encbuf_len,
                                           blocking, &n_written, cancellable, &tls->write_error);

    if (n_written > 0) {
      schannel->encbuf_offset += n_written;
      schannel->encbuf_len -= n_written;
    }

    ret = g_tls_connection_base_pop_io (G_TLS_CONNECTION_BASE (schannel), G_IO_OUT, success, error);
    if (ret != G_TLS_CONNECTION_BASE_OK)
      return ret;
  }

  /* Must be 0, otherwise we would've written that immediately */
  g_assert (schannel->encbuf_len == 0);
  g_assert (schannel->encbuf_offset == 0);

  count = MIN (count, schannel->stream_sizes.cbMaximumMessage);
  len = schannel->stream_sizes.cbHeader + count + schannel->stream_sizes.cbTrailer;

  if (!schannel->encbuf) {
    schannel->encbuf_alloc_len = 16384;
    while (schannel->encbuf_alloc_len < len)
      schannel->encbuf_alloc_len *= 2;
    schannel->encbuf = g_new (guint8, schannel->encbuf_alloc_len);
    schannel->encbuf_len = 0;
    schannel->encbuf_offset = 0;
  }

  if (schannel->encbuf_alloc_len < len) {
    while (schannel->encbuf_alloc_len < len)
      schannel->encbuf_alloc_len *= 2;
    schannel->encbuf = g_realloc (schannel->encbuf, schannel->encbuf_alloc_len);
  }

  memcpy (schannel->encbuf + schannel->stream_sizes.cbHeader, buffer, count);

  outbuf[0].BufferType = SECBUFFER_STREAM_HEADER;
  outbuf[0].pvBuffer = schannel->encbuf;
  outbuf[0].cbBuffer = schannel->stream_sizes.cbHeader;
  outbuf[1].BufferType = SECBUFFER_DATA;
  outbuf[1].pvBuffer = schannel->encbuf + schannel->stream_sizes.cbHeader;
  outbuf[1].cbBuffer = count;
  outbuf[2].BufferType = SECBUFFER_STREAM_TRAILER;
  outbuf[2].pvBuffer = schannel->encbuf + schannel->stream_sizes.cbHeader + count;
  outbuf[2].cbBuffer = schannel->stream_sizes.cbTrailer;
  outbuf[3].BufferType = SECBUFFER_EMPTY;
  outbuf[3].pvBuffer = NULL;
  outbuf[3].cbBuffer = 0;
  outbuf_desc.ulVersion = SECBUFFER_VERSION;
  outbuf_desc.pBuffers = outbuf;
  outbuf_desc.cBuffers = 4;

  sspi_status = EncryptMessage (&schannel->context, 0, &outbuf_desc, 0);

  if (sspi_status == SEC_E_OK) {
    gsize n_written = 0;
    gboolean success;

    schannel->encbuf_len = outbuf[0].cbBuffer + outbuf[1].cbBuffer + outbuf[2].cbBuffer;

    g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (schannel), G_IO_OUT, blocking, cancellable);
    success = g_pollable_stream_write_all (g_io_stream_get_output_stream (tls->base_io_stream),
                                           schannel->encbuf, schannel->encbuf_len, blocking, &n_written,
                                           cancellable, &tls->write_error);
    if (!success && g_error_matches (tls->write_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
      *nwrote = MIN (count, n_written > outbuf[0].cbBuffer ? n_written - outbuf[0].cbBuffer : 0);
      if (n_written > 0) {
        schannel->encbuf_offset += n_written;
        schannel->encbuf_len -= n_written;
      }
    } else {
      *nwrote = count;
      schannel->encbuf_len = 0;
      schannel->encbuf_offset = 0;
    }
    ret = g_tls_connection_base_pop_io (G_TLS_CONNECTION_BASE (schannel), G_IO_OUT, success, error);

    return ret;
  } else {
    if (sspi_status == SEC_E_CONTEXT_EXPIRED || sspi_status == SEC_I_CONTEXT_EXPIRED) {
        G_TLS_CONNECTION_BASE_GET_CLASS (tls)->handshake (tls, cancellable, NULL);
        g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_EOF, "TLS connection closed");
    } else {
        g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC, "Context error 0x%08x", (guint32) sspi_status);
    }
    return G_TLS_CONNECTION_BASE_ERROR;
  }
}

static GTlsConnectionBaseStatus
g_tls_connection_schannel_close (GTlsConnectionBase *tls, GCancellable *cancellable, GError **error)
{
  GTlsConnectionSchannel *schannel = G_TLS_CONNECTION_SCHANNEL (tls);
  SecBuffer buf;
  SecBufferDesc buf_desc;
  DWORD token;
  SECURITY_STATUS sspi_status = SEC_E_OK;

  token = SCHANNEL_SHUTDOWN;
  buf.BufferType = SECBUFFER_TOKEN;
  buf.pvBuffer = &token;
  buf.cbBuffer = sizeof (token);

  buf_desc.ulVersion = SECBUFFER_VERSION;
  buf_desc.pBuffers = &buf;
  buf_desc.cBuffers = 1;

  sspi_status = ApplyControlToken (&schannel->context, &buf_desc);
  if (sspi_status != SEC_E_OK) {
    g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC, "Context error 0x%08x", (guint32) sspi_status);
    return G_TLS_CONNECTION_BASE_ERROR;
  }

  schannel->shutting_down = TRUE;

  return G_TLS_CONNECTION_BASE_GET_CLASS (tls)->handshake (tls, cancellable, error);
}

static void
g_tls_connection_schannel_class_init (GTlsConnectionSchannelClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;
  GTlsConnectionBaseClass *base_connection_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  gobject_class->finalize = g_tls_connection_schannel_finalize;

  base_connection_class->request_rehandshake = g_tls_connection_schannel_request_rehandshake;
  base_connection_class->complete_handshake  = g_tls_connection_schannel_complete_handshake;
  base_connection_class->read_fn             = g_tls_connection_schannel_read;
  base_connection_class->write_fn            = g_tls_connection_schannel_write;
  base_connection_class->close_fn            = g_tls_connection_schannel_close;
}

static void
g_tls_connection_schannel_init (GTlsConnectionSchannel *schannel)
{
}
