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

package org.opensearch.security.setting;

import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;

/**
 * Wrapper for legacy settings that support a secure variant located in the Keystore.
 * <p>
 * Secure name is the insecure name with "_secure" appended to it.
 */
public class SecurableLegacySetting {
    private static final Logger LOG = LogManager.getLogger(SecurableLegacySetting.class);

    public static final String SECURE_SUFFIX = "_secure";

    public final String insecurePropertyName;

    public final String propertyName;

    public final String defaultValue;

    public SecurableLegacySetting(String insecurePropertyName) {
        this(insecurePropertyName, null);
    }

    public SecurableLegacySetting(String insecurePropertyName, String defaultValue) {
        this(insecurePropertyName, String.format("%s%s", insecurePropertyName, SECURE_SUFFIX), defaultValue);
    }

    public SecurableLegacySetting(String insecurePropertyName, String propertyName, String defaultValue) {
        super();
        this.insecurePropertyName = insecurePropertyName;
        this.propertyName = propertyName;
        this.defaultValue = defaultValue;
    }

    public Setting<SecureString> asSetting() {
        final Setting<SecureString> fallback = new InsecureFallbackStringSetting(this.insecurePropertyName, this.propertyName);
        return SecureSetting.secureString(this.propertyName, fallback);
    }

    public Setting<SecureString> asInsecureSetting() {
        return new InsecureFallbackStringSetting(this.insecurePropertyName, this.propertyName);
    }

    public String getSetting(Settings settings) {
        return this.getSetting(settings, this.defaultValue);
    }

    public String getSetting(Settings settings, String defaultValue) {
        return Optional.of(this.asSetting().get(settings)).filter(ss -> ss.length() > 0).map(SecureString::toString).orElse(defaultValue);
    }

    /**
     * Alternative to InsecureStringSetting, which doesn't raise an exception if allow_insecure_settings is false, but
     * instead log.WARNs the violation. This is to appease a potential cyclic dependency between commons-utils
     */
    private static class InsecureFallbackStringSetting extends Setting<SecureString> {
        private final String name;
        private final String secureName;

        private InsecureFallbackStringSetting(String name, String secureName) {
            super(name, "", s -> new SecureString(s.toCharArray()), Property.Deprecated, Property.Filtered, Property.NodeScope);
            this.name = name;
            this.secureName = secureName;
        }

        public SecureString get(Settings settings) {
            if (this.exists(settings)) {
                LOG.warn(
                    "Setting [{}] has a secure counterpart [{}] which should be used instead. Allowing use of {} for legacy setups",
                    this.name,
                    this.secureName,
                    this.name
                );
            }

            return super.get(settings);
        }
    }
}
