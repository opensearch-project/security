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

package com.amazon.opendistroforelasticsearch.security.ssl.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.elasticsearch.common.settings.Settings;

public final class SSLConfigConstants {

    public static final String OPENDISTRO_SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE = "opendistro_security.ssl.http.enable_openssl_if_available";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_ENABLED = "opendistro_security.ssl.http.enabled";
    public static final boolean OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_DEFAULT = false;
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE = "opendistro_security.ssl.http.clientauth_mode";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_ALIAS = "opendistro_security.ssl.http.keystore_alias";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH = "opendistro_security.ssl.http.keystore_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_FILEPATH = "opendistro_security.ssl.http.pemkey_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_PASSWORD = "opendistro_security.ssl.http.pemkey_password";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_PEMCERT_FILEPATH = "opendistro_security.ssl.http.pemcert_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH = "opendistro_security.ssl.http.pemtrustedcas_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD = "opendistro_security.ssl.http.keystore_password";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD = "opendistro_security.ssl.http.keystore_keypassword";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_TYPE = "opendistro_security.ssl.http.keystore_type";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS = "opendistro_security.ssl.http.truststore_alias";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH = "opendistro_security.ssl.http.truststore_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD = "opendistro_security.ssl.http.truststore_password";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_TYPE = "opendistro_security.ssl.http.truststore_type";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE = "opendistro_security.ssl.transport.enable_openssl_if_available";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED = "opendistro_security.ssl.transport.enabled";
    public static final boolean OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT = true;
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION = "opendistro_security.ssl.transport.enforce_hostname_verification";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME = "opendistro_security.ssl.transport.resolve_hostname";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS = "opendistro_security.ssl.transport.keystore_alias";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH = "opendistro_security.ssl.transport.keystore_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH = "opendistro_security.ssl.transport.pemkey_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD = "opendistro_security.ssl.transport.pemkey_password";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH = "opendistro_security.ssl.transport.pemcert_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH = "opendistro_security.ssl.transport.pemtrustedcas_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD = "opendistro_security.ssl.transport.keystore_password";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD = "opendistro_security.ssl.transport.keystore_keypassword";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE = "opendistro_security.ssl.transport.keystore_type";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS = "opendistro_security.ssl.transport.truststore_alias";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH = "opendistro_security.ssl.transport.truststore_filepath";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD = "opendistro_security.ssl.transport.truststore_password";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE = "opendistro_security.ssl.transport.truststore_type";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS = "opendistro_security.ssl.transport.enabled_ciphers";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS = "opendistro_security.ssl.transport.enabled_protocols";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_CIPHERS = "opendistro_security.ssl.http.enabled_ciphers";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_PROTOCOLS = "opendistro_security.ssl.http.enabled_protocols";
    public static final String OPENDISTRO_SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID = "opendistro_security.ssl.client.external_context_id";
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS = "opendistro_security.ssl.transport.principal_extractor_class";

    public static final String OPENDISTRO_SECURITY_SSL_HTTP_CRL_FILE = "opendistro_security.ssl.http.crl.file_path";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_CRL_VALIDATE = "opendistro_security.ssl.http.crl.validate";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP = "opendistro_security.ssl.http.crl.prefer_crlfile_over_ocsp";
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES = "opendistro_security.ssl.http.crl.check_only_end_entities";    
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_CRL_DISABLE_OCSP = "opendistro_security.ssl.http.crl.disable_ocsp";    
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP = "opendistro_security.ssl.http.crl.disable_crldp";   
    public static final String OPENDISTRO_SECURITY_SSL_HTTP_CRL_VALIDATION_DATE = "opendistro_security.ssl.http.crl.validation_date";

    public static final String OPENDISTRO_SECURITY_SSL_ALLOW_CLIENT_INITIATED_RENEGOTIATION = "opendistro_security.ssl.allow_client_initiated_renegotiation";

    public static final String DEFAULT_STORE_PASSWORD = "changeit"; //#16
    
    public static final String JDK_TLS_REJECT_CLIENT_INITIATED_RENEGOTIATION = "jdk.tls.rejectClientInitiatedRenegotiation";
    
    private static final String[] _SECURE_SSL_PROTOCOLS = {"TLSv1.3", "TLSv1.2", "TLSv1.1"};
    
    public static final String[] getSecureSSLProtocols(Settings settings, boolean http)
    {
        List<String> configuredProtocols = null;
        
        if(settings != null) {
            if(http) {
                configuredProtocols = settings.getAsList(OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, Collections.emptyList());
            } else {
                configuredProtocols = settings.getAsList(OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, Collections.emptyList());
            }
        }
        
        if(configuredProtocols != null && configuredProtocols.size() > 0) {
            return configuredProtocols.toArray(new String[0]);
        }
        
        return _SECURE_SSL_PROTOCOLS.clone();
    }
    
    // @formatter:off
    private static final String[] _SECURE_SSL_CIPHERS = 
        {
        //TLS_<key exchange and authentication algorithms>_WITH_<bulk cipher and message authentication algorithms>
        
        //Example (including unsafe ones)
        //Protocol: TLS, SSL
        //Key Exchange    RSA, Diffie-Hellman, ECDH, SRP, PSK
        //Authentication  RSA, DSA, ECDSA
        //Bulk Ciphers    RC4, 3DES, AES
        //Message Authentication  HMAC-SHA256, HMAC-SHA1, HMAC-MD5
        

        //thats what chrome 48 supports (https://cc.dcsec.uni-hannover.de/)
        //(c0,2b)ECDHE-ECDSA-AES128-GCM-SHA256128 BitKey exchange: ECDH, encryption: AES, MAC: SHA256.
        //(c0,2f)ECDHE-RSA-AES128-GCM-SHA256128 BitKey exchange: ECDH, encryption: AES, MAC: SHA256.
        //(00,9e)DHE-RSA-AES128-GCM-SHA256128 BitKey exchange: DH, encryption: AES, MAC: SHA256.
        //(cc,14)ECDHE-ECDSA-CHACHA20-POLY1305-SHA256128 BitKey exchange: ECDH, encryption: ChaCha20 Poly1305, MAC: SHA256.
        //(cc,13)ECDHE-RSA-CHACHA20-POLY1305-SHA256128 BitKey exchange: ECDH, encryption: ChaCha20 Poly1305, MAC: SHA256.
        //(c0,0a)ECDHE-ECDSA-AES256-SHA256 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        //(c0,14)ECDHE-RSA-AES256-SHA256 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        //(00,39)DHE-RSA-AES256-SHA256 BitKey exchange: DH, encryption: AES, MAC: SHA1.
        //(c0,09)ECDHE-ECDSA-AES128-SHA128 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        //(c0,13)ECDHE-RSA-AES128-SHA128 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        //(00,33)DHE-RSA-AES128-SHA128 BitKey exchange: DH, encryption: AES, MAC: SHA1.
        //(00,9c)RSA-AES128-GCM-SHA256128 BitKey exchange: RSA, encryption: AES, MAC: SHA256.
        //(00,35)RSA-AES256-SHA256 BitKey exchange: RSA, encryption: AES, MAC: SHA1.
        //(00,2f)RSA-AES128-SHA128 BitKey exchange: RSA, encryption: AES, MAC: SHA1.
        //(00,0a)RSA-3DES-EDE-SHA168 BitKey exchange: RSA, encryption: 3DES, MAC: SHA1.
        
        //thats what firefox 42 supports (https://cc.dcsec.uni-hannover.de/)
        //(c0,2b) ECDHE-ECDSA-AES128-GCM-SHA256
        //(c0,2f) ECDHE-RSA-AES128-GCM-SHA256
        //(c0,0a) ECDHE-ECDSA-AES256-SHA
        //(c0,09) ECDHE-ECDSA-AES128-SHA
        //(c0,13) ECDHE-RSA-AES128-SHA
        //(c0,14) ECDHE-RSA-AES256-SHA
        //(00,33) DHE-RSA-AES128-SHA
        //(00,39) DHE-RSA-AES256-SHA
        //(00,2f) RSA-AES128-SHA
        //(00,35) RSA-AES256-SHA
        //(00,0a) RSA-3DES-EDE-SHA

        //Mozilla modern browsers
        //https://wiki.mozilla.org/Security/Server_Side_TLS
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
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        
        //TLS 1.3
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256", //Open SSL >= 1.1.1 and Java >= 12
        
        //TLS 1.2 CHACHA20 POLY1305 supported by Java >= 12 and
        //OpenSSL >= 1.1.0
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        
        //IBM
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
        
        //some others
        //"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        //"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        //"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 
        //"TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 
        //"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        //"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 
        //"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        //"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        //"TLS_RSA_WITH_AES_128_CBC_SHA256",
        //"TLS_RSA_WITH_AES_128_GCM_SHA256",
        //"TLS_RSA_WITH_AES_128_CBC_SHA",
        //"TLS_RSA_WITH_AES_256_CBC_SHA",
        };
    // @formatter:on
    
    public static final List<String> getSecureSSLCiphers(Settings settings, boolean http) {
        
        List<String> configuredCiphers = null;
        
        if(settings != null) {
            if(http) {
                configuredCiphers = settings.getAsList(OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_CIPHERS, Collections.emptyList());
            } else {
                configuredCiphers = settings.getAsList(OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, Collections.emptyList());
            }
        }
        
        if(configuredCiphers != null && configuredCiphers.size() > 0) {
            return configuredCiphers;
        }

        return Collections.unmodifiableList(Arrays.asList(_SECURE_SSL_CIPHERS));
    }
    
    private SSLConfigConstants() {

    }

}
