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

public class TransportPassiveAuthSetting extends OpensearchDynamicSetting<Boolean> {

    private static final String SETTING = ConfigConstants.SECURITY_UNSUPPORTED_PASSIVE_INTERTRANSPORT_AUTH_INITIALLY;

    public TransportPassiveAuthSetting(final Settings settings) {
        super(getSetting(), getSettingInitialValue(settings));
    }

    private static Setting<Boolean> getSetting() {
        return Setting.boolSetting(SETTING, false, Setting.Property.NodeScope, Setting.Property.Dynamic);
    }

    private static Boolean getSettingInitialValue(final Settings settings) {
        return settings.getAsBoolean(SETTING, false);
    }

    @Override
    protected String getClusterChangeMessage(final Boolean dynamicSettingNewValue) {
        return String.format(
            "Detected change in settings, cluster setting for transportPassiveAuth is %s",
            dynamicSettingNewValue ? "enabled" : "disabled"
        );
    }
}
