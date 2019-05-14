package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Meta {
    
    
    private String type;
    private int config_version;
    
    private CType cType;
    
    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
        cType = CType.fromString(type);
    }
    public int getConfig_version() {
        return config_version;
    }
    public void setConfig_version(int config_version) {
        this.config_version = config_version;
    }
    
    @JsonIgnore
    public CType getCType() {
        return cType;
    }

    @Override
    public String toString() {
        return "Meta [type=" + type + ", config_version=" + config_version + ", cType=" + cType + "]";
    }
    
    
}
