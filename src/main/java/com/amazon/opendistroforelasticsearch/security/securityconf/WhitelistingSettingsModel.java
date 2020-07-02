package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.List;

public abstract class WhitelistingSettingsModel {
    public abstract Boolean getWhitelistingEnabled();
    public abstract List<String> getWhitelistedAPIs();
}
