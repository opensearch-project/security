/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.security.ssl;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;

import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_HTTP_PEMKEY_PASSWORD;

public class SecureSSLSettingsTest {
    @Test
    public void testGetSettings() {
        final var settings = SecureSSLSettings.getSecureSettings();
        Assert.assertNotNull(settings);
        Assert.assertTrue(settings.size() > 0);
    }

    @Test
    public void testGetSecureSetting() {
        final var mockSecureSettings = new MockSecureSettings();
        mockSecureSettings.setString(SECURITY_SSL_HTTP_PEMKEY_PASSWORD.propertyName, "test-password");
        final var settings = Settings.builder().setSecureSettings(mockSecureSettings).build();
        final var password = SECURITY_SSL_HTTP_PEMKEY_PASSWORD.getSetting(settings);
        Assert.assertEquals("test-password", password);
    }

    @Test
    public void testGetInsecureSetting() {
        final var settings = Settings.builder().put(SECURITY_SSL_HTTP_PEMKEY_PASSWORD.insecurePropertyName, "test-password").build();
        final var password = SECURITY_SSL_HTTP_PEMKEY_PASSWORD.getSetting(settings);
        Assert.assertEquals("test-password", password);
    }

    @Test
    public void testShouldFavorSecureOverInsecureSetting() {
        final var mockSecureSettings = new MockSecureSettings();
        mockSecureSettings.setString(SECURITY_SSL_HTTP_PEMKEY_PASSWORD.propertyName, "secure-password");
        final var settings = Settings.builder()
            .setSecureSettings(mockSecureSettings)
            .put(SECURITY_SSL_HTTP_PEMKEY_PASSWORD.insecurePropertyName, "insecure-password")
            .build();
        final var password = SECURITY_SSL_HTTP_PEMKEY_PASSWORD.getSetting(settings);
        Assert.assertEquals("secure-password", password);
    }
}
