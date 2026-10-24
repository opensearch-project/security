/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.security.setting;

import java.io.InputStream;
import java.util.Arrays;
import javax.crypto.SecretKey;

import org.junit.Test;

import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;

public class SecureSettingsUtilsTest {

    private static final Setting<InputStream> KEY_FILE = SecureSetting.secureFile("test.secure_file", null);

    @Test
    public void testReadsTheRawBytesAsSecretKey() {
        final byte[] keyBytes = new byte[64];
        Arrays.fill(keyBytes, (byte) 1);

        final SecretKey key = SecureSettingsUtils.secretKey(KEY_FILE, settingsWithKeyFile(keyBytes), "HmacSHA512");

        assertThat(key.getEncoded(), equalTo(keyBytes));
        assertThat(key.getAlgorithm(), equalTo("HmacSHA512"));
    }

    @Test
    public void testEmptyFileIsRejectedNamingTheSetting() {
        final Settings settings = settingsWithKeyFile(new byte[0]);

        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> SecureSettingsUtils.secretKey(KEY_FILE, settings, "AES")
        );
        assertThat(e.getMessage(), equalTo("test.secure_file is empty."));
    }

    private static Settings settingsWithKeyFile(final byte[] content) {
        final MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setFile(KEY_FILE.getKey(), content);
        return Settings.builder().setSecureSettings(secureSettings).build();
    }
}
