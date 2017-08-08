/*
 * gtlsdatabase-schannel.c
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

#include "gtlsdatabase-schannel.h"
#include "gtlscertificate-schannel.h"
#include "gtlsutils-schannel.h"
#include <wininet.h>

/* mingw does not have these */
#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x1000
#endif

enum {
  PROP_DB_CERT_STORE = 1,
  PROP_DB_N_PROPERTIES
};

static GParamSpec *db_properties[PROP_DB_N_PROPERTIES] = { NULL, };

typedef struct _GTlsDatabaseSchannelPrivate {
  HCERTSTORE cert_store;
  HCERTCHAINENGINE engine;
} GTlsDatabaseSchannelPrivate;

G_DEFINE_TYPE_WITH_CODE (GTlsDatabaseSchannel, g_tls_database_schannel, G_TYPE_TLS_DATABASE,
                         G_ADD_PRIVATE (GTlsDatabaseSchannel))

static void
g_tls_database_schannel_set_property (GObject * obj, guint property_id, const GValue *value, GParamSpec *pspec)
{
  GTlsDatabaseSchannel *schannel = G_TLS_DATABASE_SCHANNEL (obj);
  GTlsDatabaseSchannelPrivate *priv = g_tls_database_schannel_get_instance_private (schannel);

  switch (property_id) {
    case PROP_DB_CERT_STORE:
      priv->cert_store = g_value_get_pointer (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
g_tls_database_schannel_get_property (GObject * obj, guint property_id, GValue *value, GParamSpec *pspec)
{
  GTlsDatabaseSchannel *schannel = G_TLS_DATABASE_SCHANNEL (obj);
  GTlsDatabaseSchannelPrivate *priv = g_tls_database_schannel_get_instance_private (schannel);

  switch (property_id) {
    case PROP_DB_CERT_STORE:
      g_value_set_pointer (value, priv->cert_store);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
g_tls_database_schannel_finalize (GObject * obj)
{
  GTlsDatabaseSchannel *schannel = G_TLS_DATABASE_SCHANNEL (obj);
  GTlsDatabaseSchannelPrivate *priv = g_tls_database_schannel_get_instance_private (schannel);

  if (priv->cert_store) {
    CertCloseStore (priv->cert_store, 0);
    priv->cert_store = NULL;
  }

  if (priv->engine) {
    CertFreeCertificateChainEngine (priv->engine);
    priv->engine = NULL;
  }

  G_OBJECT_CLASS (g_tls_database_schannel_parent_class)->finalize (obj);
}

static gchar *
g_tls_database_schannel_create_certificate_handle (GTlsDatabase *database, GTlsCertificate *certificate)
{
  PCCERT_CONTEXT cert_context;
  BYTE hash[20];
  DWORD size;

  cert_context = g_tls_certificate_schannel_get_context (certificate);

  if (!CertGetCertificateContextProperty (cert_context, CERT_HASH_PROP_ID, hash, &size)) {
    g_warn_if_reached ();
    return NULL;
  }

  return g_base64_encode (hash, size);
}

static GTlsCertificate *
g_tls_database_schannel_lookup_certificate_for_handle (GTlsDatabase *database, const gchar *handle,
                                                       GTlsInteraction *interaction, GTlsDatabaseLookupFlags flags,
                                                       GCancellable *cancellable, GError **error)
{
  GTlsDatabaseSchannel *schannel = G_TLS_DATABASE_SCHANNEL (database);
  GTlsDatabaseSchannelPrivate *priv = g_tls_database_schannel_get_instance_private (schannel);
  CRYPT_HASH_BLOB hash_blob;
  gsize hash_blob_length;
  PCCERT_CONTEXT cert_context;

  memset (&hash_blob, 0, sizeof (hash_blob));
  hash_blob.pbData = g_base64_decode (handle, &hash_blob_length);
  if (!hash_blob.pbData) {
    g_warn_if_reached ();
    return NULL;
  }
  hash_blob.cbData = hash_blob_length;

  if (!(cert_context = CertFindCertificateInStore (priv->cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                                   CERT_FIND_HASH |
                                                   ((flags & G_TLS_DATABASE_LOOKUP_KEYPAIR) ? CERT_FIND_HAS_PRIVATE_KEY : 0),
                                                   &hash_blob, NULL))) {
    g_free (hash_blob.pbData);
    return NULL;
  }

  return g_tls_certificate_schannel_new_from_context(database, cert_context);
}

static GTlsCertificate *
g_tls_database_schannel_lookup_certificate_issuer (GTlsDatabase *database, GTlsCertificate *certificate,
                                                   GTlsInteraction *interaction, GTlsDatabaseLookupFlags flags,
                                                   GCancellable *cancellable, GError **error)
{
  GTlsDatabaseSchannel *schannel = G_TLS_DATABASE_SCHANNEL (database);
  GTlsDatabaseSchannelPrivate *priv = g_tls_database_schannel_get_instance_private (schannel);
  PCCERT_CONTEXT cert_context;
  PCCERT_CONTEXT issuer_context;
  DWORD issuer_flags = 0;

  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  cert_context = g_tls_certificate_schannel_get_context (certificate);

  if (!(issuer_context = CertGetIssuerCertificateFromStore (priv->cert_store, cert_context, NULL, &issuer_flags)))
    return NULL;

  return g_tls_certificate_schannel_new_from_context(database, issuer_context);
}

static GList *
g_tls_database_schannel_lookup_certificates_issued_by (GTlsDatabase *database, GByteArray *issuer_raw_dn,
                                                       GTlsInteraction *interaction, GTlsDatabaseLookupFlags flags,
                                                       GCancellable *cancellable, GError **error)
{
  GTlsDatabaseSchannel *schannel = G_TLS_DATABASE_SCHANNEL (database);
  GTlsDatabaseSchannelPrivate *priv = g_tls_database_schannel_get_instance_private (schannel);
  CERT_NAME_BLOB name_blob;
  PCCERT_CONTEXT cert_context;
  GQueue certificates = G_QUEUE_INIT;

  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  memset (&name_blob, 0, sizeof (name_blob));
  name_blob.pbData = issuer_raw_dn->data;
  name_blob.cbData = issuer_raw_dn->len;

  cert_context = NULL;
  while ((cert_context = CertFindCertificateInStore (priv->cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                                     CERT_FIND_ISSUER_NAME |
                                                     ((flags & G_TLS_DATABASE_LOOKUP_KEYPAIR) ? CERT_FIND_HAS_PRIVATE_KEY : 0),
                                                     &name_blob, cert_context))) {
    g_queue_push_tail (&certificates, g_tls_certificate_schannel_new_from_context(database,
                                                                                  CertDuplicateCertificateContext (cert_context)));
  }

  return certificates.head;
}

static GTlsCertificateFlags
g_tls_database_schannel_verify_chain (GTlsDatabase *database, GTlsCertificate *chain, const gchar *purpose,
                                      GSocketConnectable *identity, GTlsInteraction *interaction, GTlsDatabaseVerifyFlags flags,
                                      GCancellable *cancellable, GError **error)
{
  GTlsDatabaseSchannel *schannel = G_TLS_DATABASE_SCHANNEL (database);
  GTlsDatabaseSchannelPrivate *priv = g_tls_database_schannel_get_instance_private (schannel);
  PCCERT_CONTEXT cert_context;
  HCERTSTORE cert_store = NULL;
  GTlsCertificate *issuer;
  PCCERT_CHAIN_CONTEXT chain_context;
  CERT_CHAIN_PARA chain_para;
  gchar *purposes[1] = { (gchar *) purpose };
  SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_policy_para;
  CERT_CHAIN_POLICY_PARA policy_para;
  CERT_CHAIN_POLICY_STATUS policy_status;
  GTlsCertificateFlags certificate_flags = 0;
  wchar_t *wserver_name;

  memset (&chain_para, 0, sizeof (chain_para));
  chain_para.cbSize = sizeof (chain_para);
  chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
  chain_para.RequestedUsage.Usage.cUsageIdentifier = purpose ? 1 : 0;
  chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = purposes;

  cert_context = g_tls_certificate_schannel_get_context (chain);

  /* Add all issuer certificates to a temporary database */
  cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  issuer = g_tls_certificate_get_issuer (cert);
  while (issuer) {
    PCCERT_CONTEXT issuer_context = g_tls_certificate_schannel_get_context (issuer);
    CertAddCertificateContextToStore (cert_store, issuer_context);
    issuer = g_tls_certificate_get_issuer (cert);
  }

  if (!CertGetCertificateChain (priv->engine, cert_context, NULL, priv->cert_store,
                                &chain_para, CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY |
                                             CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
                                NULL, &chain_context)) {
    /* We could check GetLastError() but that does not give us
     * anything useful we could put into the GTlsCertificateFlags */
    certificate_flags |= G_TLS_CERTIFICATE_GENERIC_ERROR;
    return certificate_flags;
  }

  certificate_flags |= g_tls_schannel_certificate_flags_from_chain (chain_context);

  if (identity) {
    gchar *server_name;

    server_name = g_tls_schannel_socket_connectable_to_string (identity);
    wserver_name = g_utf8_to_utf16 (server_name, -1, NULL, NULL, NULL);
    g_free (server_name);
  } else {
    wserver_name = NULL;
  }

  memset (&ssl_policy_para, 0, sizeof (ssl_policy_para));
  ssl_policy_para.cbStruct = sizeof (ssl_policy_para);
  ssl_policy_para.dwAuthType = (!purpose || strcmp (purpose, G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER) == 0) ?
                               AUTHTYPE_SERVER : AUTHTYPE_CLIENT;
  ssl_policy_para.fdwChecks = wserver_name ? 0 : SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
  ssl_policy_para.pwszServerName = wserver_name;

  memset (&policy_para, 0, sizeof (policy_para));
  policy_para.cbSize = sizeof (policy_para);
  policy_para.pvExtraPolicyPara = &ssl_policy_para;

  memset (&policy_status, 0, sizeof (policy_status));
  policy_status.cbSize = sizeof (policy_status);

  /* If the certificate chain is known to be revoked or no revocation
   * information is known whatsoever, don't check for that (again) when
   * verifying the policy below */
  if ((certificate_flags & G_TLS_CERTIFICATE_REVOKED) ||
      (chain_context->TrustStatus.dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) ||
      (chain_context->TrustStatus.dwErrorStatus & CERT_TRUST_IS_OFFLINE_REVOCATION)) {
    ssl_policy_para.fdwChecks |= SECURITY_FLAG_IGNORE_REVOCATION;
    policy_para.dwFlags |= CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS;
  }

  /* And don't check for other things we already know have failed */
  if ((certificate_flags & G_TLS_CERTIFICATE_EXPIRED)) {
    LONG cmp;

    ssl_policy_para.fdwChecks |= SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    policy_para.dwFlags |= CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS;

    /* Both flags are set by the code above as we don't know, so check here
     * whether the certificate is not activated yet or expired */
    cmp = CertVerifyTimeValidity (NULL, priv->cert_context->pCertInfo);
    if (cmp == 1)
      certificate_flags &= ~G_TLS_CERTIFICATE_NOT_ACTIVATED;
    else if (cmp == -1)
      certificate_flags &= ~G_TLS_CERTIFICATE_EXPIRED;
    /* Otherwise it must be any of the certificates in the chain or nesting is
     * wrong, for which we have no way of specifying that in GIO */
  }

  if ((certificate_flags & G_TLS_CERTIFICATE_UNKNOWN_CA)) {
    ssl_policy_para.fdwChecks |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    policy_para.dwFlags |= CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG;
  }

  if (!CertVerifyCertificateChainPolicy (CERT_CHAIN_POLICY_SSL, chain_context, &policy_para, &policy_status)) {
    g_free (wserver_name);
    CertFreeCertificateChain (chain_context);
    return certificate_flags | G_TLS_CERTIFICATE_GENERIC_ERROR;
  }
  g_free (wserver_name);
  CertFreeCertificateChain (chain_context);

  certificate_flags |= g_tls_schannel_certificate_flags_from_policy_status (&policy_status);

  return certificate_flags;
}

static void
g_tls_database_schannel_constructed (GObject * obj)
{
  GTlsDatabaseSchannel *schannel = G_TLS_DATABASE_SCHANNEL (obj);
  GTlsDatabaseSchannelPrivate *priv = g_tls_database_schannel_get_instance_private (schannel);

  if (!G_IS_TLS_SYSTEM_DATABASE_SCHANNEL (obj)) {
    CERT_CHAIN_ENGINE_CONFIG engine_config;

    /* if this is not the system store, we want a custom chain engine that uses our store as the exclusive one.
     * Otherwise the system store will always also be used
     */
    memset (&engine_config, 0, sizeof (engine_config));
    engine_config.cbSize = sizeof (engine_config);
    engine_config.hExclusiveRoot = priv->cert_store;

    if (!CertCreateCertificateChainEngine (&engine_config, &priv->engine))
      g_warn_if_reached ();
  }

  if (G_OBJECT_CLASS (g_tls_database_schannel_parent_class)->constructed)
    G_OBJECT_CLASS (g_tls_database_schannel_parent_class)->constructed (obj);
}

static void
g_tls_database_schannel_class_init (GTlsDatabaseSchannelClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;
  GTlsDatabaseClass *database_class = (GTlsDatabaseClass *) klass;

  gobject_class->set_property = g_tls_database_schannel_set_property;
  gobject_class->get_property = g_tls_database_schannel_get_property;
  gobject_class->finalize = g_tls_database_schannel_finalize;
  gobject_class->constructed = g_tls_database_schannel_constructed;

  db_properties[PROP_DB_CERT_STORE] =
    g_param_spec_pointer ("cert-store", "Cert Store", "Certificate Store to use",
                          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

  g_object_class_install_properties (gobject_class,
                                     PROP_DB_N_PROPERTIES,
                                     db_properties);

  database_class->create_certificate_handle = g_tls_database_schannel_create_certificate_handle;
  database_class->lookup_certificate_for_handle = g_tls_database_schannel_lookup_certificate_for_handle;
  database_class->lookup_certificate_issuer = g_tls_database_schannel_lookup_certificate_issuer;
  database_class->lookup_certificates_issued_by = g_tls_database_schannel_lookup_certificates_issued_by;
  database_class->verify_chain = g_tls_database_schannel_verify_chain;
}

static void
g_tls_database_schannel_init (GTlsDatabaseSchannel *schannel)
{
}

HCERTSTORE
g_tls_database_schannel_get_store (GTlsDatabase * database)
{
  GTlsDatabaseSchannel *schannel = G_TLS_DATABASE_SCHANNEL (database);
  GTlsDatabaseSchannelPrivate *priv = g_tls_database_schannel_get_instance_private (schannel);

  return priv->cert_store;
}

struct _GTlsSystemDatabaseSchannel {
  GTlsDatabaseSchannel parent;
};

static void g_tls_system_database_schannel_initable_interface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsSystemDatabaseSchannel, g_tls_system_database_schannel, G_TYPE_TLS_DATABASE_SCHANNEL,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, g_tls_system_database_schannel_initable_interface_init))

static GObject*
g_tls_system_database_schannel_constructor (GType type, guint n_construct_properties, GObjectConstructParam *construct_properties)
{
  GObject *obj;
  guint i;

  for (i = 0; i < n_construct_properties; i++) {
    if (construct_properties[i].pspec == db_properties[PROP_DB_CERT_STORE]) {
      HCERTSTORE cert_store, child_store;

      /* Create a collection store with all the stores, as would also be done by the default certificate chain engine */
      cert_store = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);

      child_store = CertOpenStore (CERT_STORE_PROV_SYSTEM, 0, 0,
                                   CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                   "Root");
      CertAddStoreToCollection (cert_store, child_store, 0, 0);
      CertCloseStore (child_store, 0);

      child_store = CertOpenStore (CERT_STORE_PROV_SYSTEM, 0, 0,
                                   CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                   "MY");
      CertAddStoreToCollection (cert_store, child_store, 0, 0);
      CertCloseStore (child_store, 0);

      child_store = CertOpenStore (CERT_STORE_PROV_SYSTEM, 0, 0,
                                   CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                   "Trust");
      CertAddStoreToCollection (cert_store, child_store, 0, 0);
      CertCloseStore (child_store, 0);

      child_store = CertOpenStore (CERT_STORE_PROV_SYSTEM, 0, 0,
                                   CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                   "CA");
      CertAddStoreToCollection (cert_store, child_store, 0, 0);
      CertCloseStore (child_store, 0);

      g_value_set_pointer (construct_properties[i].value, cert_store);
      break;
    }
  }

  obj = G_OBJECT_CLASS (g_tls_system_database_schannel_parent_class)->constructor (type, n_construct_properties, construct_properties);

  return obj;
}

static void
g_tls_system_database_schannel_class_init (GTlsSystemDatabaseSchannelClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;

  gobject_class->constructor = g_tls_system_database_schannel_constructor;
}

static gboolean
g_tls_system_database_schannel_initable_init (GInitable *initable, GCancellable *cancellable, GError **error)
{
  return TRUE;
}

static void
g_tls_system_database_schannel_initable_interface_init (GInitableIface *iface)
{
  iface->init = g_tls_system_database_schannel_initable_init;
}

static void
g_tls_system_database_schannel_init (GTlsSystemDatabaseSchannel *schannel)
{
}

GTlsDatabase *
g_tls_system_database_schannel_new (void)
{
  return g_object_new (G_TYPE_TLS_SYSTEM_DATABASE_SCHANNEL, NULL);
}

enum {
  PROP_FILE_DB_ANCHORS = 1,
  PROP_FILE_DB_N_PROPERTIES
};

struct _GTlsFileDatabaseSchannel {
  GTlsDatabaseSchannel parent;
};

typedef struct _GTlsFileDatabaseSchannelPrivate {
  gchar *anchors;
} GTlsFileDatabaseSchannelPrivate;

static void g_tls_file_database_schannel_initable_interface_init (GInitableIface *iface);
static void g_tls_file_database_schannel_file_database_interface_init (GTlsFileDatabaseInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsFileDatabaseSchannel, g_tls_file_database_schannel, G_TYPE_TLS_DATABASE_SCHANNEL,
                         G_ADD_PRIVATE (GTlsFileDatabaseSchannel)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, g_tls_file_database_schannel_initable_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_FILE_DATABASE, g_tls_file_database_schannel_file_database_interface_init))

static void
g_tls_file_database_schannel_load (GTlsFileDatabaseSchannel *schannel)
{
  GTlsFileDatabaseSchannelPrivate *priv = g_tls_file_database_schannel_get_instance_private (schannel);
  GTlsDatabaseSchannelPrivate *db_priv = g_tls_database_schannel_get_instance_private (G_TLS_DATABASE_SCHANNEL (schannel));
  gchar *pem = NULL, *p_begin, *p_end;
  gsize pem_length;
  const gchar begin_marker[] = "-----BEGIN CERTIFICATE-----";
  const gint begin_length = sizeof (begin_marker);
  const gchar end_marker[] = "-----END CERTIFICATE-----";

  if (!priv->anchors)
    return;

  if (!g_file_get_contents (priv->anchors, &pem, &pem_length, NULL)) {
    g_warn_if_reached ();
    return;
  }

  /* Parse PEM, one certificate at a time */
  p_begin = pem;

  p_begin = g_strstr_len (p_begin, -1, begin_marker);
  while (p_begin) {
    BYTE *der = NULL;
    DWORD length;

    p_end = g_strstr_len (p_begin, -1, end_marker);
    if (!p_end)
      break;

    p_begin += begin_length;
    length = p_end - p_begin;
    der = g_new (BYTE, length);
    if (!CryptStringToBinary (p_begin, length, CRYPT_STRING_BASE64, der, &length, 0, 0)) {
      g_warn_if_reached ();
      goto next;
    }

    if (!CertAddEncodedCertificateToStore (db_priv->cert_store,
                                           X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                           der, length, CERT_STORE_ADD_NEWER, NULL)) {
      g_warn_if_reached ();
      goto next;
    }

next:
    g_free (der);
    p_begin = g_strstr_len (p_end, -1, begin_marker);
  }

  g_free (pem);

}

static void
g_tls_file_database_schannel_set_property (GObject * obj, guint property_id, const GValue *value, GParamSpec *pspec)
{
  GTlsFileDatabaseSchannel *schannel = G_TLS_FILE_DATABASE_SCHANNEL (obj);
  GTlsFileDatabaseSchannelPrivate *priv = g_tls_file_database_schannel_get_instance_private (schannel);
  GTlsDatabaseSchannelPrivate *db_priv = g_tls_database_schannel_get_instance_private (G_TLS_DATABASE_SCHANNEL (schannel));

  switch (property_id) {
    case PROP_FILE_DB_ANCHORS:
      /* Remove all old certificates, if any */
      g_free (priv->anchors);
      CertCloseStore (db_priv->cert_store, 0);
      db_priv->cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
      priv->anchors = g_value_dup_string (value);
      g_tls_file_database_schannel_load (schannel);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
g_tls_file_database_schannel_get_property (GObject * obj, guint property_id, GValue *value, GParamSpec *pspec)
{
  GTlsFileDatabaseSchannel *schannel = G_TLS_FILE_DATABASE_SCHANNEL (obj);
  GTlsFileDatabaseSchannelPrivate *priv = g_tls_file_database_schannel_get_instance_private (schannel);

  switch (property_id) {
    case PROP_FILE_DB_ANCHORS:
      g_value_set_string (value, priv->anchors);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
g_tls_file_database_schannel_finalize (GObject * obj)
{
  GTlsFileDatabaseSchannel *schannel = G_TLS_FILE_DATABASE_SCHANNEL (obj);
  GTlsFileDatabaseSchannelPrivate *priv = g_tls_file_database_schannel_get_instance_private (schannel);

  g_free (priv->anchors);
  priv->anchors = NULL;

  G_OBJECT_CLASS (g_tls_file_database_schannel_parent_class)->finalize (obj);
}

static GObject*
g_tls_file_database_schannel_constructor (GType type, guint n_construct_properties, GObjectConstructParam *construct_properties)
{
  GObject *obj;
  guint i;

  for (i = 0; i < n_construct_properties; i++) {
    if (construct_properties[i].pspec == db_properties[PROP_DB_CERT_STORE]) {
      HCERTSTORE cert_store;

      cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
      g_value_set_pointer (construct_properties[i].value, cert_store);

      break;
    }
  }

  obj = G_OBJECT_CLASS (g_tls_file_database_schannel_parent_class)->constructor (type, n_construct_properties, construct_properties);

  return obj;
}

static void
g_tls_file_database_schannel_class_init (GTlsFileDatabaseSchannelClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;

  gobject_class->set_property = g_tls_file_database_schannel_set_property;
  gobject_class->get_property = g_tls_file_database_schannel_get_property;
  gobject_class->finalize = g_tls_file_database_schannel_finalize;
  gobject_class->constructor = g_tls_file_database_schannel_constructor;

  g_object_class_override_property (gobject_class, PROP_FILE_DB_ANCHORS, "anchors");
}

static gboolean
g_tls_file_database_schannel_initable_init (GInitable *initable, GCancellable *cancellable, GError **error)
{
  return TRUE;
}

static void
g_tls_file_database_schannel_initable_interface_init (GInitableIface *iface)
{
  iface->init = g_tls_file_database_schannel_initable_init;
}

static void
g_tls_file_database_schannel_file_database_interface_init (GTlsFileDatabaseInterface *iface)
{
}

static void
g_tls_file_database_schannel_init (GTlsFileDatabaseSchannel *schannel)
{
}

GTlsDatabase *
g_tls_file_database_schannel_new (const gchar * filename)
{
  return g_object_new (G_TYPE_TLS_FILE_DATABASE_SCHANNEL, "anchors", filename, NULL);
}
