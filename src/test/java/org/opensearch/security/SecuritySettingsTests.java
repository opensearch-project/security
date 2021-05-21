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

import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.LegacyOpenDistroSSLSecuritySettings;
import org.opensearch.security.ssl.util.SSLSecuritySettings;
import org.opensearch.security.support.LegacyOpenDistroSecuritySettings;
import org.opensearch.security.support.SecuritySettings;

import java.util.Map;

public class SecuritySettingsTests {
    
    @Test
    public void testLegacyOpenDistroSettingsFallback() {
        Assert.assertEquals(
                SecuritySettings.SECURITY_ADVANCED_MODULES_ENABLED.get(Settings.EMPTY),
                LegacyOpenDistroSecuritySettings.SECURITY_ADVANCED_MODULES_ENABLED.get(Settings.EMPTY)
        );
        Assert.assertEquals(
                SSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED.get(Settings.EMPTY),
                LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED.get(Settings.EMPTY)
        );
    }
    
    @Test
    public void testSettingsGetValue() {
        Settings settings = Settings.builder()
                .put("plugins.security.disabled", true)
                .put("plugins.security.ssl.http.enabled", true)
        .build();
        Assert.assertEquals(SecuritySettings.SECURITY_DISABLED.get(settings), true);
        Assert.assertEquals(LegacyOpenDistroSecuritySettings.SECURITY_DISABLED.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED.get(settings), true);
        Assert.assertEquals(LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED.get(settings), false);
    }
    
    @Test
    public void testSettingsGetValueWithLegacyFallback() {
        Settings settings = Settings.builder()
                .put("opendistro_security.disabled", false)
                .put("opendistro_security.config_index_name", "test")
                .putList("opendistro_security.restapi.roles_enabled", "a", "b")
                .put("opendistro_security.audit.threadpool.size", 12)
                .put("opendistro_security.audit.endpoints.1.value", "value 1")
                .put("opendistro_security.audit.endpoints.2.value", "value 2")
                .put("opendistro_security.ssl.http.crl.validation_date", 1)
        .build();

        Assert.assertEquals(SecuritySettings.SECURITY_DISABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_CONFIG_INDEX_NAME.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_RESTAPI_ROLES_ENABLED.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_THREADPOOL_SIZE.get(settings), Integer.valueOf(12));
        Map<String, Settings> asMap = SecuritySettings.SECURITY_AUDIT_CONFIG_ENDPOINTS.get(settings).getAsGroups();
        Assert.assertEquals(2, asMap.size());
        Assert.assertEquals(asMap.get("1").get("value"), "value 1");
        Assert.assertEquals(asMap.get("2").get("value"), "value 2");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE.get(settings), Long.valueOf(1));
    }
}
