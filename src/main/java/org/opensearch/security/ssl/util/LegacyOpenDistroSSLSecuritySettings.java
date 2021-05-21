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
import org.opensearch.security.ssl.OpenSearchSecuritySSLPlugin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

public class LegacyOpenDistroSSLSecuritySettings {
    public static final Setting<String> SECURITY_SSL_HTTP_CLIENTAUTH_MODE = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_ALIAS = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_PASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_KEYSTORE_TYPE = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_TRUSTSTORE_TYPE = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_ENABLED = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED, LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENABLED = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED, LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<List<String>> SECURITY_SSL_HTTP_ENABLED_CIPHERS = Setting.listSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_CIPHERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<List<String>> SECURITY_SSL_HTTP_ENABLED_PROTOCOLS = Setting.listSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<List<String>> SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS = Setting.listSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<List<String>> SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS = Setting.listSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<String> SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, OPENSSL_SUPPORTED, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, OPENSSL_SUPPORTED,Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.listSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope));//not filtered here
    //settings.add(Setting.listSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope));//not filtered here
    //settings.add(Setting.listSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope));//not filtered here
    //settings.add(Setting.listSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope));//not filtered here
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, Setting.Property.NodeScope, Setting.Property.Filtered));

    public static final Setting<Boolean> SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered));
    //if(extendedKeyUsageEnabled) {
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //} else {
    
    
    
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //}
    public static final Setting<String> SECURITY_SSL_HTTP_PEMCERT_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_PEMKEY_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_PEMKEY_PASSWORD = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    public static final Setting<String> SECURITY_SSL_HTTP_CRL_FILE = Setting.simpleString(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_FILE, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_VALIDATE = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_VALIDATE, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_HTTP_CRL_DISABLE_OCSP = Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Long> SECURITY_SSL_HTTP_CRL_VALIDATION_DATE = Setting.longSetting(LegacyOpenDistroSSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, -1, -1, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
        //settings.add(Setting.simpleString(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.boolSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        //settings.add(Setting.longSetting(LegacyOpenDistroSSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, -1, -1, Setting.Property.NodeScope, Setting.Property.Filtered));
        //return settings;
     

}
