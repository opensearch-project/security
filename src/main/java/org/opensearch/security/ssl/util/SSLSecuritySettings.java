/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.ssl.util;

import io.netty.util.internal.PlatformDependent;
import org.opensearch.common.Booleans;
import org.opensearch.common.settings.Setting;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

public class SSLSecuritySettings {
    public static final Setting<String> SECURITY_SSL_HTTP_CLIENTAUTH_MODE = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_ALIAS = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_PASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_PASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_TYPE = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_TYPE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_TRUSTSTORE_TYPE = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_ENABLED = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENABLED = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<List<String>> SECURITY_SSL_HTTP_ENABLED_CIPHERS = Setting.listSetting(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED_CIPHERS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<List<String>> SECURITY_SSL_HTTP_ENABLED_PROTOCOLS = Setting.listSetting(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<List<String>> SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS = Setting.listSetting(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<List<String>> SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS = Setting.listSetting(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<String> SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, Setting.Property.NodeScope, Setting.Property.Filtered);
    
    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    
    public static final Setting<String> SECURITY_SSL_HTTP_PEMCERT_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_PEMKEY_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_PEMKEY_PASSWORD = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_PASSWORD, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    
    public static final Setting<String> SECURITY_SSL_HTTP_CRL_FILE = Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_CRL_FILE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_VALIDATE = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_CRL_VALIDATE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_DISABLE_OCSP = Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Long> SECURITY_SSL_HTTP_CRL_VALIDATION_DATE = Setting.longSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, Setting.Property.NodeScope, Setting.Property.Filtered);
}
