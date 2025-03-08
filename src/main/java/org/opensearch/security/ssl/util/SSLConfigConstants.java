/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.security.ssl.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.OpenSearchSecuritySSLPlugin;

import io.netty.handler.ssl.OpenSsl;

public final class SSLConfigConstants {
    /**
     * Global configurations
     */
    public static final Long OPENSSL_1_1_1_BETA_9 = 0x10101009L;
    public static final boolean OPENSSL_AVAILABLE = OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable();
    public static final String DEFAULT_STORE_PASSWORD = "changeit"; // #16
    public static final String JDK_TLS_REJECT_CLIENT_INITIATED_RENEGOTIATION = "jdk.tls.rejectClientInitiatedRenegotiation";
    public static final String[] ALLOWED_SSL_PROTOCOLS = { "TLSv1.3", "TLSv1.2", "TLSv1.1" };

    /**
     * Shared settings prefixes/postfixes
     */
    public static final String ENABLED = "enabled";
    public static final String CLIENT_AUTH_MODE = "clientauth_mode";
    public static final String ENFORCE_CERT_RELOAD_DN_VERIFICATION = "enforce_cert_reload_dn_verification";
    public static final String DEFAULT_STORE_TYPE = "JKS";
    public static final String SSL_PREFIX = "plugins.security.ssl.";

    public static final String KEYSTORE_TYPE = "keystore_type";
    public static final String KEYSTORE_ALIAS = "keystore_alias";
    public static final String KEYSTORE_FILEPATH = "keystore_filepath";
    public static final String KEYSTORE_PASSWORD = "keystore_password";
    public static final String KEYSTORE_KEY_PASSWORD = "keystore_keypassword";

    public static final String TRUSTSTORE_ALIAS = "truststore_alias";
    public static final String TRUSTSTORE_FILEPATH = "truststore_filepath";
    public static final String TRUSTSTORE_TYPE = "truststore_type";
    public static final String TRUSTSTORE_PASSWORD = "truststore_password";

    public static final String PEM_KEY_FILEPATH = "pemkey_filepath";
    public static final String PEM_CERT_FILEPATH = "pemcert_filepath";
    public static final String PEM_TRUSTED_CAS_FILEPATH = "pemtrustedcas_filepath";
    public static final String EXTENDED_KEY_USAGE_ENABLED = "extended_key_usage_enabled";

    public static final String ENABLE_OPENSSL_IF_AVAILABLE = "enable_openssl_if_available";
    public static final String ENABLED_PROTOCOLS = "enabled_protocols";
    public static final String ENABLED_CIPHERS = "enabled_ciphers";
    public static final String PEM_KEY_PASSWORD = "pemkey_password";

    /**
     * HTTP transport security settings
     */
    public static final String HTTP_SETTINGS = "http";
    public static final String SSL_HTTP_PREFIX = SSL_PREFIX + HTTP_SETTINGS + ".";
    public static final String SSL_HTTP_CRL_PREFIX = SSL_HTTP_PREFIX + "crl.";

    // http enable settings
    public static final boolean SECURITY_SSL_HTTP_ENABLED_DEFAULT = false;
    public static final String SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE = SSL_HTTP_PREFIX + ENABLE_OPENSSL_IF_AVAILABLE;
    public static final String SECURITY_SSL_HTTP_ENABLED = SSL_HTTP_PREFIX + ENABLED;
    public static final String SECURITY_SSL_HTTP_ENABLED_CIPHERS = SSL_HTTP_PREFIX + ENABLED_CIPHERS;
    public static final String SECURITY_SSL_HTTP_ENABLED_PROTOCOLS = SSL_HTTP_PREFIX + ENABLED_PROTOCOLS;

    // http allowed settings
    public static final String[] ALLOWED_OPENSSL_HTTP_PROTOCOLS = ALLOWED_SSL_PROTOCOLS;
    public static final String[] ALLOWED_OPENSSL_HTTP_PROTOCOLS_PRIOR_OPENSSL_1_1_1_BETA_9 = { "TLSv1.2", "TLSv1.1", "TLSv1" };

    // http keystore settings
    public static final String SECURITY_SSL_HTTP_KEYSTORE_TYPE = SSL_HTTP_PREFIX + KEYSTORE_TYPE;
    public static final String SECURITY_SSL_HTTP_KEYSTORE_ALIAS = SSL_HTTP_PREFIX + KEYSTORE_ALIAS;
    public static final String SECURITY_SSL_HTTP_KEYSTORE_FILEPATH = SSL_HTTP_PREFIX + KEYSTORE_FILEPATH;
    public static final String SECURITY_SSL_HTTP_PEMKEY_FILEPATH = SSL_HTTP_PREFIX + PEM_KEY_FILEPATH;
    public static final String SECURITY_SSL_HTTP_PEMCERT_FILEPATH = SSL_HTTP_PREFIX + PEM_CERT_FILEPATH;

    // http truststore settings
    public static final String SECURITY_SSL_HTTP_CLIENTAUTH_MODE = SSL_HTTP_PREFIX + CLIENT_AUTH_MODE;
    public static final String SECURITY_SSL_HTTP_TRUSTSTORE_TYPE = SSL_HTTP_PREFIX + TRUSTSTORE_TYPE;
    public static final String SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS = SSL_HTTP_PREFIX + TRUSTSTORE_ALIAS;
    public static final String SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH = SSL_HTTP_PREFIX + TRUSTSTORE_FILEPATH;
    public static final String SECURITY_SSL_HTTP_ENFORCE_CERT_RELOAD_DN_VERIFICATION = SSL_HTTP_PREFIX
        + ENFORCE_CERT_RELOAD_DN_VERIFICATION;
    public static final String SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH = SSL_HTTP_PREFIX + PEM_TRUSTED_CAS_FILEPATH;

    // http cert revocation list settings
    public static final String SECURITY_SSL_HTTP_CRL_FILE = SSL_HTTP_CRL_PREFIX + "file_path";
    public static final String SECURITY_SSL_HTTP_CRL_VALIDATE = SSL_HTTP_CRL_PREFIX + "validate";
    public static final String SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP = SSL_HTTP_CRL_PREFIX + "prefer_crlfile_over_ocsp";
    public static final String SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES = SSL_HTTP_CRL_PREFIX + "check_only_end_entities";
    public static final String SECURITY_SSL_HTTP_CRL_DISABLE_OCSP = SSL_HTTP_CRL_PREFIX + "disable_ocsp";
    public static final String SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP = SSL_HTTP_CRL_PREFIX + "disable_crldp";
    public static final String SECURITY_SSL_HTTP_CRL_VALIDATION_DATE = SSL_HTTP_CRL_PREFIX + "validation_date";

    /**
     * Transport layer (node-to-node) settings.
     * Transport layer acts both as client and server within the cluster.
     * Security settings for each role may be configured separately.
     */
    public static final String TRANSPORT_SETTINGS = "transport.";
    public static final String SSL_TRANSPORT_SERVER_EXTENDED_PREFIX = "server.";
    public static final String SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX = "client.";
    public static final String SSL_TRANSPORT_PREFIX = SSL_PREFIX + TRANSPORT_SETTINGS;
    public static final String SSL_TRANSPORT_CLIENT_PREFIX = SSL_PREFIX + TRANSPORT_SETTINGS + SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX;
    public static final String SSL_TRANSPORT_SERVER_PREFIX = SSL_PREFIX + TRANSPORT_SETTINGS + SSL_TRANSPORT_SERVER_EXTENDED_PREFIX;

    // transport enable settings
    public static final boolean SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT = true;
    public static final String SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE = SSL_TRANSPORT_PREFIX + ENABLE_OPENSSL_IF_AVAILABLE;
    public static final String SECURITY_SSL_TRANSPORT_ENABLED = SSL_TRANSPORT_PREFIX + ENABLED;
    public static final String SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS = SSL_TRANSPORT_PREFIX + ENABLED_CIPHERS;
    public static final String SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS = SSL_TRANSPORT_PREFIX + ENABLED_PROTOCOLS;

    // transport allowed settings
    public static final String[] ALLOWED_OPENSSL_TRANSPORT_PROTOCOLS = ALLOWED_SSL_PROTOCOLS;
    public static final String[] ALLOWED_OPENSSL_TRANSPORT_PROTOCOLS_PRIOR_OPENSSL_1_1_1_BETA_9 = { "TLSv1.2", "TLSv1.1" };

    // transport keystore settings
    public static final String SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE = SSL_TRANSPORT_PREFIX + KEYSTORE_TYPE;
    public static final String SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH = SSL_TRANSPORT_PREFIX + KEYSTORE_FILEPATH;
    public static final String SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED = SSL_TRANSPORT_PREFIX + EXTENDED_KEY_USAGE_ENABLED;
    public static final boolean SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED_DEFAULT = false;

    // transport shared keystore settings
    public static final String SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS = SSL_TRANSPORT_PREFIX + KEYSTORE_ALIAS;
    public static final String SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH = SSL_TRANSPORT_PREFIX + PEM_KEY_FILEPATH;
    public static final String SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH = SSL_TRANSPORT_PREFIX + PEM_CERT_FILEPATH;

    // transport shared truststore settings
    public static final String SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE = SSL_TRANSPORT_PREFIX + TRUSTSTORE_TYPE;
    public static final String SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS = SSL_TRANSPORT_PREFIX + TRUSTSTORE_ALIAS;
    public static final String SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH = SSL_TRANSPORT_PREFIX + TRUSTSTORE_FILEPATH;
    public static final String SECURITY_SSL_TRANSPORT_ENFORCE_CERT_RELOAD_DN_VERIFICATION = SSL_TRANSPORT_PREFIX
        + ENFORCE_CERT_RELOAD_DN_VERIFICATION;
    public static final String SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH = SSL_TRANSPORT_PREFIX + PEM_TRUSTED_CAS_FILEPATH;

    // transport server keystore settings
    public static final String SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS = SSL_TRANSPORT_SERVER_PREFIX + KEYSTORE_ALIAS;
    public static final String SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH = SSL_TRANSPORT_SERVER_PREFIX + PEM_KEY_FILEPATH;
    public static final String SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH = SSL_TRANSPORT_SERVER_PREFIX + PEM_CERT_FILEPATH;

    // transport server truststore settings
    public static final String SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS = SSL_TRANSPORT_SERVER_PREFIX + TRUSTSTORE_ALIAS;
    public static final String SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH = SSL_TRANSPORT_SERVER_PREFIX
        + PEM_TRUSTED_CAS_FILEPATH;

    public static final String SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS = SSL_TRANSPORT_PREFIX + "principal_extractor_class";
    public static final String SECURITY_SSL_ALLOW_CLIENT_INITIATED_RENEGOTIATION = SSL_PREFIX + "allow_client_initiated_renegotiation";

    // transport client keystore settings
    public static final String SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS = SSL_TRANSPORT_CLIENT_PREFIX + KEYSTORE_ALIAS;
    public static final String SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH = SSL_TRANSPORT_CLIENT_PREFIX + PEM_KEY_FILEPATH;
    public static final String SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH = SSL_TRANSPORT_CLIENT_PREFIX + PEM_CERT_FILEPATH;

    // transport client truststore settings
    public static final String SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS = SSL_TRANSPORT_CLIENT_PREFIX + TRUSTSTORE_ALIAS;
    public static final String SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH = SSL_TRANSPORT_CLIENT_PREFIX
        + PEM_TRUSTED_CAS_FILEPATH;

    public static final String SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION = SSL_TRANSPORT_PREFIX
        + "enforce_hostname_verification";
    public static final String SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME = SSL_TRANSPORT_PREFIX
        + "resolve_hostname";
    public static final String SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID = SSL_PREFIX + "client.external_context_id";

    public static String[] getSecureSSLProtocols(Settings settings, boolean http) {
        List<String> configuredProtocols = null;

        if (settings != null) {
            if (http) {
                configuredProtocols = settings.getAsList(SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, Collections.emptyList());
            } else {
                configuredProtocols = settings.getAsList(SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, Collections.emptyList());
            }
        }

        if (configuredProtocols != null && configuredProtocols.size() > 0) {
            return configuredProtocols.toArray(new String[0]);
        }

        return ALLOWED_SSL_PROTOCOLS.clone();
    }

    // @formatter:off
    public static final String[] ALLOWED_SSL_CIPHERS = {
        // TLS_<key exchange and authentication algorithms>_WITH_<bulk cipher and message authentication algorithms>

        // Example (including unsafe ones)
        // Protocol: TLS, SSL
        // Key Exchange RSA, Diffie-Hellman, ECDH, SRP, PSK
        // Authentication RSA, DSA, ECDSA
        // Bulk Ciphers RC4, 3DES, AES
        // Message Authentication HMAC-SHA256, HMAC-SHA1, HMAC-MD5

        // thats what chrome 48 supports (https://cc.dcsec.uni-hannover.de/)
        // (c0,2b)ECDHE-ECDSA-AES128-GCM-SHA256128 BitKey exchange: ECDH, encryption: AES, MAC: SHA256.
        // (c0,2f)ECDHE-RSA-AES128-GCM-SHA256128 BitKey exchange: ECDH, encryption: AES, MAC: SHA256.
        // (00,9e)DHE-RSA-AES128-GCM-SHA256128 BitKey exchange: DH, encryption: AES, MAC: SHA256.
        // (cc,14)ECDHE-ECDSA-CHACHA20-POLY1305-SHA256128 BitKey exchange: ECDH, encryption: ChaCha20 Poly1305, MAC: SHA256.
        // (cc,13)ECDHE-RSA-CHACHA20-POLY1305-SHA256128 BitKey exchange: ECDH, encryption: ChaCha20 Poly1305, MAC: SHA256.
        // (c0,0a)ECDHE-ECDSA-AES256-SHA256 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        // (c0,14)ECDHE-RSA-AES256-SHA256 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        // (00,39)DHE-RSA-AES256-SHA256 BitKey exchange: DH, encryption: AES, MAC: SHA1.
        // (c0,09)ECDHE-ECDSA-AES128-SHA128 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        // (c0,13)ECDHE-RSA-AES128-SHA128 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        // (00,33)DHE-RSA-AES128-SHA128 BitKey exchange: DH, encryption: AES, MAC: SHA1.
        // (00,9c)RSA-AES128-GCM-SHA256128 BitKey exchange: RSA, encryption: AES, MAC: SHA256.
        // (00,35)RSA-AES256-SHA256 BitKey exchange: RSA, encryption: AES, MAC: SHA1.
        // (00,2f)RSA-AES128-SHA128 BitKey exchange: RSA, encryption: AES, MAC: SHA1.
        // (00,0a)RSA-3DES-EDE-SHA168 BitKey exchange: RSA, encryption: 3DES, MAC: SHA1.

        // thats what firefox 42 supports (https://cc.dcsec.uni-hannover.de/)
        // (c0,2b) ECDHE-ECDSA-AES128-GCM-SHA256
        // (c0,2f) ECDHE-RSA-AES128-GCM-SHA256
        // (c0,0a) ECDHE-ECDSA-AES256-SHA
        // (c0,09) ECDHE-ECDSA-AES128-SHA
        // (c0,13) ECDHE-RSA-AES128-SHA
        // (c0,14) ECDHE-RSA-AES256-SHA
        // (00,33) DHE-RSA-AES128-SHA
        // (00,39) DHE-RSA-AES256-SHA
        // (00,2f) RSA-AES128-SHA
        // (00,35) RSA-AES256-SHA
        // (00,0a) RSA-3DES-EDE-SHA

        // Mozilla modern browsers
        // https://wiki.mozilla.org/Security/Server_Side_TLS
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",

        // TLS 1.3
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256", // Open SSL >= 1.1.1 and Java >= 12

        // TLS 1.2 CHACHA20 POLY1305 supported by Java >= 12 and
        // OpenSSL >= 1.1.0
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

        // IBM
        "SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "SSL_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "SSL_DHE_DSS_WITH_AES_128_GCM_SHA256",
        "SSL_DHE_DSS_WITH_AES_256_GCM_SHA384",
        "SSL_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "SSL_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "SSL_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "SSL_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "SSL_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "SSL_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "SSL_DHE_RSA_WITH_AES_128_CBC_SHA",
        "SSL_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "SSL_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "SSL_DHE_DSS_WITH_AES_256_CBC_SHA",
        "SSL_DHE_RSA_WITH_AES_256_CBC_SHA"

        // some others
        // "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        // "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        // "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        // "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        // "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        // "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        // "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        // "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        // "TLS_RSA_WITH_AES_128_CBC_SHA256",
        // "TLS_RSA_WITH_AES_128_GCM_SHA256",
        // "TLS_RSA_WITH_AES_128_CBC_SHA",
        // "TLS_RSA_WITH_AES_256_CBC_SHA",
    };
    // @formatter:on

    public static List<String> getSecureSSLCiphers(Settings settings, boolean http) {

        List<String> configuredCiphers = null;

        if (settings != null) {
            if (http) {
                configuredCiphers = settings.getAsList(SECURITY_SSL_HTTP_ENABLED_CIPHERS, Collections.emptyList());
            } else {
                configuredCiphers = settings.getAsList(SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, Collections.emptyList());
            }
        }

        if (configuredCiphers != null && configuredCiphers.size() > 0) {
            return configuredCiphers;
        }

        return Collections.unmodifiableList(Arrays.asList(ALLOWED_SSL_CIPHERS));
    }

    private SSLConfigConstants() {

    }

}
