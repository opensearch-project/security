package com.amazon.opendistroforelasticsearch.security.securityconf;

import com.amazon.opendistroforelasticsearch.security.securityconf.impl.WhitelistingSettings;

public abstract class WhitelistingSettingsModel {
    public abstract WhitelistingSettings getWhitelistingSettings();
}
