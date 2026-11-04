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

import java.util.Set;

import org.junit.Test;

import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThrows;

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

    @Test
    public void validatorAcceptsAbsoluteHttpAndHttpsUrls() {
        assertThat(DashboardsUrlSetting.parseAndValidate("http://dashboards.example.com"), equalTo("http://dashboards.example.com"));
        assertThat(
            DashboardsUrlSetting.parseAndValidate("https://dashboards.example.com:5601"),
            equalTo("https://dashboards.example.com:5601")
        );
        assertThat(
            DashboardsUrlSetting.parseAndValidate("HTTPS://dashboards.example.com/base/"),
            equalTo("HTTPS://dashboards.example.com/base/")
        );
    }

    @Test
    public void validatorAcceptsEmptyValueToClearOverride() {
        assertThat(DashboardsUrlSetting.parseAndValidate(""), equalTo(""));
        assertThat(DashboardsUrlSetting.parseAndValidate(null), equalTo(""));
    }

    @Test
    public void validatorRejectsValueWithoutScheme() {
        assertThrows(IllegalArgumentException.class, () -> DashboardsUrlSetting.parseAndValidate("dashboards.example.com"));
    }

    @Test
    public void validatorRejectsNonHttpScheme() {
        assertThrows(IllegalArgumentException.class, () -> DashboardsUrlSetting.parseAndValidate("ftp://dashboards.example.com"));
        assertThrows(IllegalArgumentException.class, () -> DashboardsUrlSetting.parseAndValidate("file:///etc/passwd"));
    }

    @Test
    public void validatorRejectsValueWithoutHost() {
        assertThrows(IllegalArgumentException.class, () -> DashboardsUrlSetting.parseAndValidate("https://"));
        assertThrows(IllegalArgumentException.class, () -> DashboardsUrlSetting.parseAndValidate("https:///path"));
    }

    @Test
    public void validatorRejectsValueWithSpaces() {
        assertThrows(IllegalArgumentException.class, () -> DashboardsUrlSetting.parseAndValidate("https://dashboards example.com"));
        assertThrows(IllegalArgumentException.class, () -> DashboardsUrlSetting.parseAndValidate(" "));
    }

    @Test
    public void clusterSettingsUpdateIsRejectedForInvalidValue() {
        DashboardsUrlSetting setting = new DashboardsUrlSetting(Settings.builder().build());
        ClusterSettings clusterSettings = new ClusterSettings(Settings.EMPTY, Set.of(setting.getDynamicSetting()));
        setting.registerClusterSettingsChangeListener(clusterSettings);

        Settings invalid = Settings.builder().put(ConfigConstants.SECURITY_DASHBOARDS_URL, "not-a-url").build();
        assertThrows(IllegalArgumentException.class, () -> clusterSettings.applySettings(invalid));
        assertThat(setting.getDynamicSettingValue(), is(nullValue()));
    }

    @Test
    public void clusterSettingsUpdateAppliesValidValueAndClearResetsIt() {
        DashboardsUrlSetting setting = new DashboardsUrlSetting(Settings.builder().build());
        ClusterSettings clusterSettings = new ClusterSettings(Settings.EMPTY, Set.of(setting.getDynamicSetting()));
        setting.registerClusterSettingsChangeListener(clusterSettings);

        clusterSettings.applySettings(Settings.builder().put(ConfigConstants.SECURITY_DASHBOARDS_URL, "https://new.example.com").build());
        assertThat(setting.getDynamicSettingValue(), equalTo("https://new.example.com"));

        clusterSettings.applySettings(Settings.EMPTY);
        assertThat(setting.getDynamicSettingValue(), equalTo(""));
    }
}
