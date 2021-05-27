package com.amazon.opendistroforelasticsearch.security.setting;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

public class TransportPassiveAuthSetting extends OpensearchDynamicSetting<Boolean> {

    public TransportPassiveAuthSetting(final Settings settings) {
        super(Setting.boolSetting(
                ConfigConstants.OPENDISTRO_SECURITY_PASSIVE_INTERTRANSPORT_AUTH_INITIALLY,
                false,
                Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Dynamic),
                settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false));
    }

    @Override
    protected String getClusterChangeMessage(final Boolean dynamicSettingNewValue) {
        return String.format("Detected change in settings, cluster setting for transportPassiveAuth is %s", dynamicSettingNewValue ? "enabled" : "disabled");
    }
}
