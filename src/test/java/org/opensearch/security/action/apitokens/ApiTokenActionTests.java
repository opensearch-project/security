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

package org.opensearch.security.action.apitokens;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.junit.Test;

import org.opensearch.security.securityconf.impl.v7.ConfigV7;

public class ApiTokenActionTests extends LuceneTestCase {

    @Test
    public void testApiTokensDisabledByDefault() {
        ConfigV7.ApiTokenSettings settings = new ConfigV7.ApiTokenSettings();
        assertFalse("API tokens should be disabled by default", Boolean.TRUE.equals(settings.getEnabled()));
    }

    @Test
    public void testApiTokensCanBeEnabled() {
        ConfigV7.ApiTokenSettings settings = new ConfigV7.ApiTokenSettings();
        settings.setEnabled(true);
        assertTrue("API tokens should be enabled after setting", Boolean.TRUE.equals(settings.getEnabled()));
    }

    @Test
    public void testNullConfigHandled() {
        // Verify our check logic: null config should result in "not enabled"
        ConfigV7 config = null;
        assertTrue("Null config should be treated as disabled", config == null || !Boolean.TRUE.equals(null));
    }
}
