package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;

public class WhitelistingSettings {
    @JsonProperty(value = "whitelisting_enabled")
    private boolean whitelisting_enabled;
    @JsonProperty(value = "whitelisted_APIs")
    private List<String> whitelisted_APIs;

    public WhitelistingSettings() {
        whitelisting_enabled = false;
        whitelisted_APIs = Collections.emptyList();
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
    public List<String> getWhitelistedAPIs() {
        return this.whitelisted_APIs;
    }

    @JsonProperty(value = "whitelisted_APIs")
    public void setWhitelistedAPIs(List<String> whitelistedAPIs) {
        this.whitelisted_APIs = whitelistedAPIs;
    }

    @Override
    public String toString() {
        return "WhitelistingSetting [whitelisting_enabled=" + whitelisting_enabled + ", whitelisted_APIs=" + whitelisted_APIs + ']';
    }
}
