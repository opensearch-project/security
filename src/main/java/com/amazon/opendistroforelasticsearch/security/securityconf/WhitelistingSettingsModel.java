package com.amazon.opendistroforelasticsearch.security.securityconf;

import com.amazon.opendistroforelasticsearch.security.securityconf.impl.HttpRequestMethods;
import java.util.List;
import java.util.Map;

public abstract class WhitelistingSettingsModel {
    public abstract Boolean getWhitelistingEnabled();
    public abstract Map<String, List<HttpRequestMethods>> getWhitelistedAPIs();
}
