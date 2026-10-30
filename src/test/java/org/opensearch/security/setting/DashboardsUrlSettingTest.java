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

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class DashboardsUrlSettingTest {

    @Test
    public void initialValueIsNullWhenNotConfigured() {
        DashboardsUrlSetting setting = new DashboardsUrlSetting(Settings.builder().build());
        assertThat(setting.getDynamicSettingValue(), is(nullValue()));
    }

    @Test
    public void initialValueIsReadFromSettings() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_DASHBOARDS_URL, "https://dashboards.example.com").build();
        DashboardsUrlSetting setting = new DashboardsUrlSetting(settings);
        assertThat(setting.getDynamicSettingValue(), equalTo("https://dashboards.example.com"));
    }

    @Test
    public void dynamicSettingKeyMatchesConstant() {
        DashboardsUrlSetting setting = new DashboardsUrlSetting(Settings.builder().build());
        assertThat(setting.getDynamicSetting().getKey(), equalTo(ConfigConstants.SECURITY_DASHBOARDS_URL));
    }

    @Test
    public void dynamicSettingIsNodeScopeAndDynamic() {
        DashboardsUrlSetting setting = new DashboardsUrlSetting(Settings.builder().build());
        assertThat(setting.getDynamicSetting().hasNodeScope(), is(true));
        assertThat(setting.getDynamicSetting().isDynamic(), is(true));
    }

    @Test
    public void valueCanBeUpdatedAtRuntime() {
        DashboardsUrlSetting setting = new DashboardsUrlSetting(Settings.builder().build());
        setting.setDynamicSettingValue("https://new-dashboards.example.com");
        assertThat(setting.getDynamicSettingValue(), equalTo("https://new-dashboards.example.com"));
    }
}
