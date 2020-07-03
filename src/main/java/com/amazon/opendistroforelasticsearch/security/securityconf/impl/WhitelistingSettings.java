package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class WhitelistingSettings {
    @JsonProperty(value = "whitelisting_enabled")
    private boolean whitelisting_enabled;
    @JsonProperty(value = "whitelisted_APIs")
    private Map<String, List<HttpRequestMethods>> whitelisted_APIs;

    /**
     * Used to parse the yml files, do not remove.
     */
    public WhitelistingSettings() {
        whitelisting_enabled = false;
        whitelisted_APIs = Collections.emptyMap();
    }

    public WhitelistingSettings(WhitelistingSettings whitelistingSettings) {
        this.whitelisting_enabled = whitelistingSettings.getWhitelistingEnabled();
        this.whitelisted_APIs = whitelistingSettings.getWhitelistedAPIs();
    }

    @JsonProperty(value = "whitelisting_enabled")
    public boolean getWhitelistingEnabled() {
        return this.whitelisting_enabled;
    }

    @JsonProperty(value = "whitelisting_enabled")
    public void setWhitelistingEnabled(Boolean whitelistingEnabled) {
        this.whitelisting_enabled = whitelistingEnabled;
    }

    @JsonProperty(value = "whitelisted_APIs")
    public Map<String, List<HttpRequestMethods>> getWhitelistedAPIs() {
        return this.whitelisted_APIs;
    }

    @JsonProperty(value = "whitelisted_APIs")
    public void setWhitelistedAPIs(Map<String, List<HttpRequestMethods>> whitelistedAPIs) {
        this.whitelisted_APIs = whitelistedAPIs;
    }

    @Override
    public String toString() {
        return "WhitelistingSetting [whitelisting_enabled=" + whitelisting_enabled + ", whitelisted_APIs=" + whitelisted_APIs + ']';
    }
}
