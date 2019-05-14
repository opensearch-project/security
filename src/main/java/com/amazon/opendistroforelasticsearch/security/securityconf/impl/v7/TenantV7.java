package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;
import com.amazon.opendistroforelasticsearch.security.securityconf.StaticDefinable;

public class TenantV7 implements Hideable, StaticDefinable {

    private boolean reserved;
    private boolean hidden;
    @JsonProperty(value = "static")
    private boolean _static;
    private String description;
    
    public boolean isHidden() {
        return hidden;
    }
    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public boolean isReserved() {
        return reserved;
    }
    public void setReserved(boolean reserved) {
        this.reserved = reserved;
    }
    
    
    @JsonProperty(value = "static")
    public boolean isStatic() {
        return _static;
    }
    @JsonProperty(value = "static")
    public void setStatic(boolean _static) {
        this._static = _static;
    }
    @Override
    public String toString() {
        return "TenantV7 [reserved=" + reserved + ", hidden=" + hidden + ", _static=" + _static + ", description=" + description + "]";
    }
    
    
}