/*
 * gtlsutils-schannel.h
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

#ifndef __G_TLS_UTILS_SCHANNEL_H__
#define __G_TLS_UTILS_SCHANNEL_H__

#include <gio/gio.h>

#include <windows.h>
#include <wincrypt.h>

G_BEGIN_DECLS

gchar *              g_tls_schannel_socket_connectable_to_string         (GSocketConnectable *identity);

GTlsCertificateFlags g_tls_schannel_certificate_flags_from_chain         (PCCERT_CHAIN_CONTEXT chain_context);
GTlsCertificateFlags g_tls_schannel_certificate_flags_from_policy_status (PCERT_CHAIN_POLICY_STATUS policy_status);

G_END_DECLS

#endif /* __G_TLS_UTILS_SCHANNEL_H__ */

