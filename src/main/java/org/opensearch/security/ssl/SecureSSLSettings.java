/*
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
package org.opensearch.security.ssl;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.opensearch.common.settings.Setting;
import org.opensearch.security.setting.SecurableLegacySetting;

import static org.opensearch.security.ssl.util.SSLConfigConstants.DEFAULT_STORE_PASSWORD;

/**
 * Container for secured settings (passwords for certs, keystores) and the now deprecated original settings
 */
public final class SecureSSLSettings {
    private static final String PREFIX = "plugins.security.ssl";
    private static final String HTTP_PREFIX = PREFIX + ".http";
    private static final String TRANSPORT_PREFIX = PREFIX + ".transport";

    // http settings
    public final static SecurableLegacySetting SECURITY_SSL_HTTP_PEMKEY_PASSWORD = new SecurableLegacySetting(
        HTTP_PREFIX + ".pemkey_password"
    );
    public final static SecurableLegacySetting SECURITY_SSL_HTTP_KEYSTORE_PASSWORD = new SecurableLegacySetting(
        HTTP_PREFIX + ".keystore_password"
    );
    public final static SecurableLegacySetting SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD = new SecurableLegacySetting(
        HTTP_PREFIX + ".keystore_keypassword"
    );
    public final static SecurableLegacySetting SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD = new SecurableLegacySetting(
        HTTP_PREFIX + ".truststore_password",
        DEFAULT_STORE_PASSWORD
    );

    // transport settings
    public final static SecurableLegacySetting SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD = new SecurableLegacySetting(
        TRANSPORT_PREFIX + ".pemkey_password"
    );
    public final static SecurableLegacySetting SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD = new SecurableLegacySetting(
        TRANSPORT_PREFIX + ".server.pemkey_password"
    );
    public final static SecurableLegacySetting SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD = new SecurableLegacySetting(
        TRANSPORT_PREFIX + ".client.pemkey_password"
    );
    public final static SecurableLegacySetting SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD = new SecurableLegacySetting(
        TRANSPORT_PREFIX + ".keystore_password"
    );
    public final static SecurableLegacySetting SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD = new SecurableLegacySetting(
        TRANSPORT_PREFIX + ".keystore_keypassword"
    );
    public final static SecurableLegacySetting SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD = new SecurableLegacySetting(
        TRANSPORT_PREFIX + ".server.keystore_keypassword"
    );
    public final static SecurableLegacySetting SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD = new SecurableLegacySetting(
        TRANSPORT_PREFIX + ".client.keystore_keypassword"
    );
    public final static SecurableLegacySetting SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD = new SecurableLegacySetting(
        TRANSPORT_PREFIX + ".truststore_password",
        DEFAULT_STORE_PASSWORD
    );

    private SecureSSLSettings() {}

    public static List<Setting<?>> getSecureSettings() {
        return Arrays.stream(SecureSSLSettings.class.getDeclaredFields())
            .filter(field -> SecurableLegacySetting.class.isAssignableFrom(field.getType()))
            .map(field -> {
                try {
                    return (SecurableLegacySetting) field.get(null);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException("Unable to access field: " + field.getName(), e);
                }
            })
            .flatMap(setting -> Stream.of(setting.asSetting(), setting.asInsecureSetting()))
            .collect(Collectors.toList());
    }
}
