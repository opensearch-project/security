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

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

/**
 * Dynamic cluster setting for OpenSearch Dashboards URL used in SAML authentication flow.
 * This setting takes precedence over the kibana_url configured in the security index
 * when both are present, allowing runtime updates without modifying security configuration.
 */
public class DashboardsUrlSetting extends OpensearchDynamicSetting<String> {

    private static final String SETTING = ConfigConstants.SECURITY_DASHBOARDS_URL;

    public DashboardsUrlSetting(final Settings settings) {
        super(getSetting(), getSettingInitialValue(settings));
    }

    private static Setting<String> getSetting() {
        return Setting.simpleString(SETTING, Setting.Property.NodeScope, Setting.Property.Dynamic, Setting.Property.Sensitive);
    }

    private static String getSettingInitialValue(final Settings settings) {
        return settings.get(SETTING, null);
    }

    @Override
    protected String getClusterChangeMessage(final String dynamicSettingNewValue) {
        if (dynamicSettingNewValue == null || dynamicSettingNewValue.isEmpty()) {
            return "Dashboards URL cluster setting has been cleared. Will fall back to security configuration.";
        }
        return String.format("Detected change in settings, cluster setting for Dashboards URL is now: %s", dynamicSettingNewValue);
    }
}
