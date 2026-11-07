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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

/**
 * Dynamic cluster setting for OpenSearch Dashboards URL used in SAML authentication flow.
 * This setting takes precedence over the kibana_url configured in the security index
 * when both are present, allowing runtime updates without modifying security configuration.
 * <p>
 * The setting is cluster-wide. Only the SAML auth domain with {@code challenge: true} starts the SAML login
 * flow (builds the ACS URL and validates the response destination), so the value effectively applies to that
 * domain. Other SAML auth domains do not use it for any login flow.
 * <p>
 * {@code kibana_url} is still required in the SAML authenticator configuration. This setting overrides it
 * but does not replace it: clearing the setting falls back to {@code kibana_url}.
 * <p>
 * The value must be an absolute {@code http} or {@code https} URI with a host, or empty to clear the override.
 */
public class DashboardsUrlSetting extends OpensearchDynamicSetting<String> {

    private static final String SETTING = ConfigConstants.SECURITY_DASHBOARDS_URL;

    public DashboardsUrlSetting(final Settings settings) {
        super(getSetting(), getSettingInitialValue(settings));
    }

    private static Setting<String> getSetting() {
        return new Setting<>(
            SETTING,
            "",
            DashboardsUrlSetting::parseAndValidate,
            Setting.Property.NodeScope,
            Setting.Property.Dynamic,
            Setting.Property.Sensitive
        );
    }

    /**
     * Accepts an empty value (no override) or an absolute http/https URI with a host.
     */
    static String parseAndValidate(final String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        final URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException e) {
            throw invalid(value, "must be a valid URI: " + e.getReason());
        }
        final String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw invalid(value, "must be an absolute http or https URL");
        }
        if (uri.getHost() == null) {
            throw invalid(value, "must contain a host");
        }
        return value;
    }

    private static IllegalArgumentException invalid(final String value, final String reason) {
        return new IllegalArgumentException("Failed to parse value [" + value + "] for setting [" + SETTING + "]: " + reason);
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
