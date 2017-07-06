/*
 * gtlsutils-schannel.c
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

#include "gtlsutils-schannel.h"

gchar *
g_tls_schannel_socket_connectable_to_string (GSocketConnectable *identity)
{
  gchar *server_name;

  if (G_IS_NETWORK_ADDRESS (identity)) {
    server_name = g_strdup (g_network_address_get_hostname (G_NETWORK_ADDRESS (identity)));
  } else if (G_IS_NETWORK_SERVICE (identity)) {
    server_name = g_strdup (g_network_service_get_domain (G_NETWORK_SERVICE (identity)));
  } else if (G_IS_INET_SOCKET_ADDRESS (identity)) {
    GInetAddress * addr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (identity));
    server_name = g_inet_address_to_string (addr);
  } else {
    g_warn_if_reached ();
    server_name = NULL;
  }

  return server_name;
}

GTlsCertificateFlags
g_tls_schannel_certificate_flags_from_chain (PCCERT_CHAIN_CONTEXT chain_context)
{
  DWORD error_status = chain_context->TrustStatus.dwErrorStatus;
  GTlsCertificateFlags certificate_flags = 0;

  if ((error_status & (CERT_TRUST_IS_NOT_TIME_VALID |
                       CERT_TRUST_CTL_IS_NOT_TIME_VALID)))
    certificate_flags |= G_TLS_CERTIFICATE_NOT_ACTIVATED |
                         G_TLS_CERTIFICATE_EXPIRED;

  if ((error_status & (CERT_TRUST_IS_UNTRUSTED_ROOT |
                       CERT_TRUST_IS_EXPLICIT_DISTRUST |
                       CERT_TRUST_IS_PARTIAL_CHAIN)))
    certificate_flags |= G_TLS_CERTIFICATE_UNKNOWN_CA;

  if ((error_status & CERT_TRUST_IS_REVOKED))
    certificate_flags |= G_TLS_CERTIFICATE_REVOKED;

  if ((error_status & CERT_TRUST_IS_NOT_SIGNATURE_VALID)) {
    if ((error_status & CERT_TRUST_HAS_WEAK_SIGNATURE)) {
      certificate_flags |= G_TLS_CERTIFICATE_INSECURE;
    } else {
      certificate_flags |= G_TLS_CERTIFICATE_GENERIC_ERROR;
    }
  }

  return certificate_flags;
}

GTlsCertificateFlags
g_tls_schannel_certificate_flags_from_policy_status (PCERT_CHAIN_POLICY_STATUS policy_status)
{
  if (!policy_status->dwError)
    return 0;

  switch (policy_status->dwError) {
    case CRYPT_E_REVOKED:
      return G_TLS_CERTIFICATE_REVOKED;
    case CERT_E_EXPIRED:
    case CERT_E_VALIDITYPERIODNESTING:
      return G_TLS_CERTIFICATE_EXPIRED;
    case CERT_E_INVALID_NAME:
    case CERT_E_CN_NO_MATCH:
      return G_TLS_CERTIFICATE_BAD_IDENTITY;
    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_UNTRUSTEDTESTROOT:
    case CERT_E_CHAINING:
    case TRUST_E_CERT_SIGNATURE:
      return G_TLS_CERTIFICATE_UNKNOWN_CA;
    default:
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
  }
}
