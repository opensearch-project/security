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

package org.opensearch.security.authtoken.jwt;

import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.stream.Stream;
import javax.crypto.SecretKey;

import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;
import org.opensearch.security.ssl.config.KeyStoreUtils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.PemKeyReader;

/**
 * The on-behalf-of signing and encryption keys loaded from a keystore file (PKCS12 or BCFKS) configured in
 * {@code opensearch.yml}, with the keystore and key passwords held in the node's secure settings
 * ({@code opensearch-keystore}). Keeps both the key material and its passwords out of the security index.
 * <p>
 * Secure settings are only readable during node construction, so the keys are loaded once at startup; a
 * misconfigured keystore fails the node start. A key that is not configured here is {@code null}, and the
 * Base64 {@code signing_key} / {@code encryption_key} from the dynamic on-behalf-of config is used instead.
 */
public record OnBehalfOfKeys(SecretKey signingKey, SecretKey encryptionKey) {

    public static final OnBehalfOfKeys NONE = new OnBehalfOfKeys(null, null);

    static final String SETTINGS_PREFIX = ConfigConstants.SECURITY_SETTINGS_PREFIX + "on_behalf_of.";

    static final KeystoreKeySettings SIGNING_KEY = new KeystoreKeySettings("signing_key");
    static final KeystoreKeySettings ENCRYPTION_KEY = new KeystoreKeySettings("encryption_key");

    public static List<Setting<?>> getSettings() {
        return List.of(
            SIGNING_KEY.filepath,
            SIGNING_KEY.type,
            SIGNING_KEY.alias,
            SIGNING_KEY.password,
            SIGNING_KEY.keyPassword,
            ENCRYPTION_KEY.filepath,
            ENCRYPTION_KEY.type,
            ENCRYPTION_KEY.alias,
            ENCRYPTION_KEY.password,
            ENCRYPTION_KEY.keyPassword
        );
    }

    /**
     * @param settings   the node settings, including the secure settings
     * @param configPath the node's config directory, which relative keystore paths resolve against
     * @throws IllegalArgumentException if a key is configured but cannot be loaded
     */
    public static OnBehalfOfKeys load(final Settings settings, final Path configPath) {
        return new OnBehalfOfKeys(SIGNING_KEY.load(settings, configPath), ENCRYPTION_KEY.load(settings, configPath));
    }

    @Override
    public String toString() {
        return "OnBehalfOfKeys[signingKey=" + describe(signingKey) + ", encryptionKey=" + describe(encryptionKey) + "]";
    }

    private static String describe(final SecretKey key) {
        return key != null ? "****" : "<not set>";
    }

    /** The settings of one key, all under {@code plugins.security.on_behalf_of.<key>.}. */
    static final class KeystoreKeySettings {
        final String prefix;
        final Setting<String> filepath;
        final Setting<String> type;
        final Setting<String> alias;
        final Setting<SecureString> password;
        final Setting<SecureString> keyPassword;

        private KeystoreKeySettings(final String key) {
            this.prefix = SETTINGS_PREFIX + key + ".";
            this.filepath = Setting.simpleString(prefix + "keystore_filepath", Property.NodeScope, Property.Filtered);
            this.type = Setting.simpleString(prefix + "keystore_type", Property.NodeScope, Property.Filtered);
            this.alias = Setting.simpleString(prefix + "keystore_alias", Property.NodeScope, Property.Filtered);
            this.password = SecureSetting.secureString(prefix + "keystore_password", null);
            this.keyPassword = SecureSetting.secureString(prefix + "keystore_keypassword", null);
        }

        /**
         * Returns {@code null} if none of this key's settings is present. Otherwise the key is loaded, and any
         * failure is rethrown naming this key's settings, so it is clear which of the two keys is broken.
         */
        SecretKey load(final Settings settings, final Path configPath) {
            if (Stream.of(filepath, type, alias, password, keyPassword).noneMatch(s -> s.exists(settings))) {
                return null; // not configured here: the inline key from the dynamic config applies
            }
            final String configuredType = type.exists(settings) ? type.get(settings) : null;
            // HKDF and the HMAC/JWS libraries need the key bytes, which a non-extractable token key never exposes.
            if (PemKeyReader.PKCS11.equalsIgnoreCase(configuredType)) {
                throw new IllegalArgumentException(type.getKey() + ": PKCS#11 is not supported for on-behalf-of keys, use a keystore file");
            }
            // An empty alias is a valid keystore alias, so a missing one must not silently fall back to "".
            requireSetting(settings, alias);
            requireSetting(settings, filepath);
            // The passwords stay char[] and are wiped when their secure settings are closed.
            try (
                SecureString storePassword = password.get(settings); //
                SecureString entryPassword = keyPassword.get(settings)
            ) {
                final char[] storeChars = storePassword.isEmpty() ? null : storePassword.getChars();
                // As with keytool, the key password defaults to the keystore password.
                final char[] entryChars = entryPassword.isEmpty() ? storeChars : entryPassword.getChars();

                final Path path = configPath.resolve(filepath.get(settings)).toAbsolutePath();
                final KeyStore store = KeyStoreUtils.loadKeyStore(
                    path,
                    PemKeyReader.extractStoreType(path.toString(), configuredType),
                    storeChars
                );
                return KeyStoreUtils.loadSecretKey(store, alias.get(settings), entryChars);
            } catch (final RuntimeException e) {
                throw new IllegalArgumentException("Cannot load the key configured under " + prefix + "*: " + e.getMessage(), e);
            }
        }

        private void requireSetting(final Settings settings, final Setting<?> setting) {
            if (!setting.exists(settings)) {
                throw new IllegalArgumentException(setting.getKey() + " is required when a keystore is configured under " + prefix + "*");
            }
        }
    }
}
