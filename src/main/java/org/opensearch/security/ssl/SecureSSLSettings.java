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
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;

import static org.opensearch.security.ssl.util.SSLConfigConstants.DEFAULT_STORE_PASSWORD;

/**
 * Container for secured settings (passwords for certs, keystores) and the now deprecated original settings
 */
public final class SecureSSLSettings {
    private static final Logger LOG = LogManager.getLogger(SecureSSLSettings.class);

    private static final String SECURE_SUFFIX = "_secure";
    private static final String PREFIX = "plugins.security.ssl";
    private static final String HTTP_PREFIX = PREFIX + ".http";
    private static final String TRANSPORT_PREFIX = PREFIX + ".transport";

    public enum SSLSetting {
        // http settings
        SECURITY_SSL_HTTP_PEMKEY_PASSWORD(HTTP_PREFIX + ".pemkey_password"),
        SECURITY_SSL_HTTP_KEYSTORE_PASSWORD(HTTP_PREFIX + ".keystore_password"),
        SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD(HTTP_PREFIX + ".keystore_keypassword"),
        SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD(HTTP_PREFIX + ".truststore_password", DEFAULT_STORE_PASSWORD),

        // transport settings
        SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD(TRANSPORT_PREFIX + ".pemkey_password"),
        SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD(TRANSPORT_PREFIX + ".server.pemkey_password"),
        SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD(TRANSPORT_PREFIX + ".client.pemkey_password"),
        SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD(TRANSPORT_PREFIX + ".keystore_password"),
        SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD(TRANSPORT_PREFIX + ".keystore_keypassword"),
        SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD(TRANSPORT_PREFIX + ".server.keystore_keypassword"),
        SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD(TRANSPORT_PREFIX + ".client.keystore_keypassword"),
        SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD(TRANSPORT_PREFIX + ".truststore_password", DEFAULT_STORE_PASSWORD);

        SSLSetting(String insecurePropertyName) {
            this(insecurePropertyName, null);
        }

        SSLSetting(String insecurePropertyName, String defaultValue) {
            this.insecurePropertyName = insecurePropertyName;
            this.propertyName = String.format("%s%s", this.insecurePropertyName, SECURE_SUFFIX);
            this.defaultValue = defaultValue;
        }

        public final String insecurePropertyName;

        public final String propertyName;

        public final String defaultValue;

        public Setting<SecureString> asSetting() {
            return SecureSetting.secureString(this.propertyName, new InsecureFallbackStringSetting(this.insecurePropertyName));
        }

        public Setting<SecureString> asInsecureSetting() {
            return new InsecureFallbackStringSetting(this.insecurePropertyName);
        }

        public String getSetting(Settings settings) {
            return this.getSetting(settings, this.defaultValue);
        }

        public String getSetting(Settings settings, String defaultValue) {
            return Optional.of(this.asSetting().get(settings))
                .filter(ss -> ss.length() > 0)
                .map(SecureString::toString)
                .orElse(defaultValue);
        }
    }

    private SecureSSLSettings() {}

    public static List<Setting<?>> getSecureSettings() {
        return Arrays.stream(SSLSetting.values())
            .flatMap(setting -> Stream.of(setting.asSetting(), setting.asInsecureSetting()))
            .collect(Collectors.toList());
    }

    /**
     * Alternative to InsecureStringSetting, which doesn't raise an exception if allow_insecure_settings is false, but
     * instead log.WARNs the violation. This is to appease a potential cyclic dependency between commons-utils
     */
    private static class InsecureFallbackStringSetting extends Setting<SecureString> {
        private final String name;

        private InsecureFallbackStringSetting(String name) {
            super(name, "", s -> new SecureString(s.toCharArray()), Property.Deprecated, Property.Filtered, Property.NodeScope);
            this.name = name;
        }

        public SecureString get(Settings settings) {
            if (this.exists(settings)) {
                LOG.warn(
                    "Setting [{}] has a secure counterpart [{}{}] which should be used instead - allowing for legacy SSL setups",
                    this.name,
                    this.name,
                    SECURE_SUFFIX
                );
            }

            return super.get(settings);
        }
    }
}
