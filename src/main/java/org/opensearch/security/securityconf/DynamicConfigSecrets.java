/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.securityconf;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.core.common.settings.SecureString;

public final class DynamicConfigSecrets implements AutoCloseable {

    public static final String SETTING_PREFIX = "plugins.security.dynamic_config.secrets.";

    public static final Setting.AffixSetting<SecureString> SETTING = Setting.prefixKeySetting(
        SETTING_PREFIX,
        key -> SecureSetting.secureString(key, null)
    );

    private static final Pattern REFERENCE_PATTERN = Pattern.compile("\\$\\{keystore:([A-Za-z0-9_.-]+)}");

    private Map<String, char[]> secrets;

    public DynamicConfigSecrets(Settings settings) {
        this.secrets = load(settings);
    }

    public synchronized Settings resolve(Settings settings) {
        Settings.Builder resolved = Settings.builder().put(settings);
        settings.keySet().forEach(key -> {
            String value = settings.get(key);
            if (value != null) {
                resolved.put(key, resolve(value));
            }
        });
        return resolved.build();
    }

    public synchronized void validate(Settings settings) {
        settings.keySet().forEach(key -> {
            String value = settings.get(key);
            if (value != null) {
                resolve(value);
            }
        });
    }

    public synchronized void reload(Settings settings, Runnable rebuild) {
        Map<String, char[]> replacement = load(settings);
        Map<String, char[]> previous = secrets;
        secrets = replacement;
        try {
            rebuild.run();
            clear(previous);
        } catch (RuntimeException | Error e) {
            secrets = previous;
            clear(replacement);
            try {
                rebuild.run();
            } catch (RuntimeException | Error rollbackException) {
                e.addSuppressed(rollbackException);
            }
            throw e;
        }
    }

    private String resolve(String value) {
        Matcher matcher = REFERENCE_PATTERN.matcher(value);
        if (!matcher.matches()) {
            return value;
        }

        String alias = matcher.group(1);
        char[] secret = secrets.get(alias);
        if (secret == null) {
            throw new SettingsException("Keystore setting [" + SETTING_PREFIX + alias + "] referenced by dynamic configuration is missing");
        }
        return new String(secret);
    }

    private static Map<String, char[]> load(Settings settings) {
        Map<String, char[]> loaded = new HashMap<>();
        try {
            SETTING.getAsMap(settings).forEach((alias, secureString) -> {
                try (secureString) {
                    loaded.put(alias, secureString.getChars().clone());
                }
            });
            return Collections.unmodifiableMap(loaded);
        } catch (RuntimeException | Error e) {
            clear(loaded);
            throw e;
        }
    }

    private static void clear(Map<String, char[]> secrets) {
        secrets.values().forEach(secret -> Arrays.fill(secret, '\0'));
    }

    @Override
    public synchronized void close() {
        clear(secrets);
        secrets = Collections.emptyMap();
    }
}
