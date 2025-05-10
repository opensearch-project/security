/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.security.ssl;

import org.junit.Assert;
import org.junit.Test;

public class SecureSSLSettingsTest {
    @Test
    public void testGetSettings() {
        final var settings = SecureSSLSettings.getSecureSettings();
        Assert.assertNotNull(settings);
        Assert.assertTrue(settings.size() > 0);
    }
}
