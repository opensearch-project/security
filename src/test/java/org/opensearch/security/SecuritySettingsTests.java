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

package org.opensearch.security;

import org.junit.Assert;
import org.junit.Test;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.LegacyOpenDistroSecuritySettings;
import org.opensearch.security.support.SecuritySettings;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

public class SecuritySettingsTests {
    
    @Test
    public void testLegacyOpenDistroSettingsFallback() {
        Assert.assertEquals(
                SecuritySettings.SECURITY_ADVANCED_MODULES_ENABLED.get(Settings.EMPTY),
                LegacyOpenDistroSecuritySettings.SECURITY_ADVANCED_MODULES_ENABLED.get(Settings.EMPTY)
        );
    }
    
    @Test
    public void testSettingsGetValue() {
        Settings settings = Settings.builder().put("plugins.security.disabled", false).build();
        Assert.assertEquals(SecuritySettings.SECURITY_DISABLED.get(settings), false);
        Assert.assertEquals(LegacyOpenDistroSecuritySettings.SECURITY_DISABLED.get(settings), false);
    }
    
    @Test
    public void testSettingsGetValueWithLegacyFallback() {
        Settings settings = Settings.builder()
                .put("opendistro_security.disabled", false)
                .put("opendistro_security.config_index_name", "test")
        .build();

        Assert.assertEquals(SecuritySettings.SECURITY_DISABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_CONFIG_INDEX_NAME.get(settings), "test");
        
    }
}
