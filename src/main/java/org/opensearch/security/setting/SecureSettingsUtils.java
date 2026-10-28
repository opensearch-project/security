/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.setting;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

/**
 * Functionality around secure settings held in the node's {@code opensearch.keystore}
 */
public final class SecureSettingsUtils {

    private SecureSettingsUtils() {}

    /**
     * Reads a secret key from a secure file setting ({@code opensearch-keystore add-file}). The file holds the raw
     * key bytes, not Base64; they are copied into the key and then wiped.
     *
     * @throws IllegalArgumentException if the file is empty or cannot be read
     */
    public static SecretKey secretKey(final Setting<InputStream> secureFile, final Settings settings, final String algorithm) {
        byte[] keyBytes = null;
        try (InputStream in = secureFile.get(settings)) {
            keyBytes = in.readAllBytes();
            if (keyBytes.length == 0) {
                throw new IllegalArgumentException(secureFile.getKey() + " is empty.");
            }
            return new SecretKeySpec(keyBytes, algorithm);
        } catch (final IOException e) {
            throw new IllegalArgumentException("Cannot read " + secureFile.getKey() + ": " + e.getMessage(), e);
        } finally {
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }
}
