package com.amazon.opendistroforelasticsearch.security.setting;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

public class DisableAnonymousAuthComplianceSetting extends ElasticsearchDynamicSetting<Boolean>{

    public DisableAnonymousAuthComplianceSetting(final Settings settings) {
        super(Setting.boolSetting(
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION,
                false,
                Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Dynamic),
                settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false));
    }

    @Override
    protected String getClusterChangeMessage(final Boolean dynamicSettingNewValue) {
        return String.format("Detected change in settings, cluster setting for anonymousAuthSettingDisabled is %s", dynamicSettingNewValue ? "enabled" : "disabled");
    }
}
