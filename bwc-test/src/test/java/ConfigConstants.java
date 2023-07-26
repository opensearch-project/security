/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.commons;

import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.core.common.settings.SecureString;

public class ConfigConstants {

    public static final String HTTPS = "https";
    public static final String HTTP = "http";
    public static final String HOST_DEFAULT = "localhost";
    public static final String HTTP_PORT = "http.port";
    public static final int HTTP_PORT_DEFAULT = 9200;
    public static final String CONTENT_TYPE = "content-type";
    public static final String CONTENT_TYPE_DEFAULT = "application/json";
    public static final String AUTHORIZATION = "Authorization";

    // These reside in security plugin.
    public static final String OPENSEARCH_SECURITY_SSL_HTTP_PEMCERT_FILEPATH = "plugins.security.ssl.http.pemcert_filepath";
    public static final String OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH = "plugins.security.ssl.http.keystore_filepath";
    /**
     * @deprecated in favor of the {@link #OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD_SETTING} secure setting
     */
    @Deprecated
    public static final String OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD = "plugins.security.ssl.http.keystore_password";

    /**
     * @deprecated in favor of the {@link #OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD_SETTING} secure setting
     */
    @Deprecated
    public static final String OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD = "plugins.security.ssl.http.keystore_keypassword";
    private static final String SECURE_SUFFIX = "_secure";

    private static Setting<SecureString> createFallbackInsecureSetting(String key) {
        return new Setting<>(key, (settings) -> "", (strValue) -> new SecureString(strValue.toCharArray()));
    }

    public static final Setting<SecureString> OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD_SETTING = SecureSetting
        .secureString(
            OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD + SECURE_SUFFIX,
            createFallbackInsecureSetting(OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD)
        );
    public static final Setting<SecureString> OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD_SETTING = SecureSetting
        .secureString(
            OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD + SECURE_SUFFIX,
            createFallbackInsecureSetting(OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD)
        );
    public static final String OPENSEARCH_SECURITY_INJECTED_ROLES = "opendistro_security_injected_roles";
    public static final String INJECTED_USER = "injected_user";
    public static final String OPENSEARCH_SECURITY_USE_INJECTED_USER_FOR_PLUGINS = "plugins.security_use_injected_user_for_plugins";
    public static final String OPENSEARCH_SECURITY_SSL_HTTP_ENABLED = "plugins.security.ssl.http.enabled";
    public static final String OPENSEARCH_SECURITY_USER_INFO_THREAD_CONTEXT = "_opendistro_security_user_info";
}