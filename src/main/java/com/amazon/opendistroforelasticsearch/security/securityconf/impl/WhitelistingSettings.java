package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class WhitelistingSettings {
    @JsonProperty(value = "whitelistingEnabled")
    private boolean whitelistingEnabled;
    @JsonProperty(value = "whitelistedAPIs")
    private List<String> whitelistedAPIs;

    public WhitelistingSettings() {
        whitelistingEnabled = false;
        whitelistedAPIs = new ArrayList<>(Arrays.asList(
                "/_cat/plugins",
                "/_cluster/health",
                "/_cat/nodes"
        ));
    }

    public WhitelistingSettings(WhitelistingSettings whitelistingSettings) {
        this.whitelistingEnabled = whitelistingSettings.getWhitelistingEnabled();
        this.whitelistedAPIs = whitelistingSettings.getWhitelistedAPIs();
    }

    @JsonProperty(value = "whitelistingEnabled")
    public boolean getWhitelistingEnabled() {
        return this.whitelistingEnabled;
    }

    @JsonProperty(value = "whitelistingEnabled")
    public void setWhitelistingEnabled(Boolean whitelistingEnabled) {
        this.whitelistingEnabled = whitelistingEnabled;
    }

    @JsonProperty(value = "whitelistedAPIs")
    public List<String> getWhitelistedAPIs() {
        return this.whitelistedAPIs;
    }

    @JsonProperty(value = "whitelistedAPIs")
    public void setWhitelistedAPIs(List<String> whitelistedAPIs) {
        this.whitelistedAPIs = whitelistedAPIs;
    }

    @Override
    public String toString() {
        return "WhitelistingSetting [whitelistingEnabled=" + whitelistingEnabled + ", whitelistedAPIs=" + whitelistedAPIs + ']';
    }
}
