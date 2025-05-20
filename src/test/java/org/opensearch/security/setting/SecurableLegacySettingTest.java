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

import org.junit.Test;

import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class SecurableLegacySettingTest {
    private final String settingName = "test.setting";
    private final SecurableLegacySetting secureSetting = new SecurableLegacySetting(settingName);

    @Test
    public void testSettingNames() {
        assertThat(secureSetting.propertyName, is(settingName + SecurableLegacySetting.SECURE_SUFFIX));
        assertThat(secureSetting.insecurePropertyName, is(settingName));
    }

    @Test
    public void testGetSecureSetting() {
        final var mockSecureSettings = new MockSecureSettings();

        mockSecureSettings.setString(secureSetting.propertyName, "test-password");
        final var settings = Settings.builder().setSecureSettings(mockSecureSettings).build();
        final var password = secureSetting.getSetting(settings);
        assertThat(password, is("test-password"));
    }

    @Test
    public void testGetInsecureSetting() {
        final var settings = Settings.builder().put(settingName, "test-password").build();
        final var password = secureSetting.getSetting(settings);
        assertThat(password, is("test-password"));
    }

    @Test
    public void testShouldFavorSecureOverInsecureSetting() {
        final var mockSecureSettings = new MockSecureSettings();
        mockSecureSettings.setString(secureSetting.propertyName, "secure-password");
        final var settings = Settings.builder()
            .setSecureSettings(mockSecureSettings)
            .put(secureSetting.insecurePropertyName, "insecure-password")
            .build();
        final var password = secureSetting.getSetting(settings);
        assertThat(password, is("secure-password"));
    }
}
