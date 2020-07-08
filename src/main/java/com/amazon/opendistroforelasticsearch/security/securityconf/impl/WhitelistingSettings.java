package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class WhitelistingSettings {
    @JsonProperty(value = "enabled")
    private boolean enabled;
    @JsonProperty(value = "requests")
    private Map<String, List<HttpRequestMethods>> requests;

    /**
     * Used to parse the yml files, do not remove.
     */
    public WhitelistingSettings() {
        enabled = false;
        requests = Collections.emptyMap();
    }

    public WhitelistingSettings(WhitelistingSettings whitelistingSettings) {
        this.enabled = whitelistingSettings.getEnabled();
        this.requests = whitelistingSettings.getRequests();
    }

    @JsonProperty(value = "enabled")
    public boolean getEnabled() {
        return this.enabled;
    }

    @JsonProperty(value = "enabled")
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @JsonProperty(value = "requests")
    public Map<String, List<HttpRequestMethods>> getRequests() {
        return this.requests;
    }

    @JsonProperty(value = "requests")
    public void setRequests(Map<String, List<HttpRequestMethods>> requests) {
        this.requests = requests;
    }

    @Override
    public String toString() {
        return "WhitelistingSetting [enabled=" + enabled + ", requests=" + requests + ']';
    }
}
