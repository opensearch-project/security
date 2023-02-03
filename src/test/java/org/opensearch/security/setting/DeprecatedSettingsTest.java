/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.security.setting;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.opensearch.security.setting.DeprecatedSettings.checkForDeprecatedSetting;

@RunWith(MockitoJUnitRunner.class)
public class DeprecatedSettingsTest {

    @Mock
    private DeprecationLogger logger;

    private DeprecationLogger original; 

    @Before
    public void before() {
        original = DeprecatedSettings.DEPRECATION_LOGGER;
        DeprecatedSettings.DEPRECATION_LOGGER = logger;
    }

    @After
    public void after() {
        DeprecatedSettings.DEPRECATION_LOGGER = original;
        verifyNoMoreInteractions(logger);
    }

    @Test
    public void testCheckForDeprecatedSettingNoLegacy() {
        final Settings settings = Settings.builder().put("properKey", "value").build();

        checkForDeprecatedSetting(settings, "legacyKey", "properKey");

        verifyNoInteractions(logger);
    }

    @Test
    public void testCheckForDeprecatedSettingFoundLegacy() {
        final Settings settings = Settings.builder().put("legacyKey", "value").build();

        checkForDeprecatedSetting(settings, "legacyKey", "properKey");

        verify(logger).deprecate(eq("legacyKey"), anyString(), any(), any());
    }
}
