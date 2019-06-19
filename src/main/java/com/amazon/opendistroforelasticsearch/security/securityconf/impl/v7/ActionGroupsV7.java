package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7;

import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;
import com.amazon.opendistroforelasticsearch.security.securityconf.StaticDefinable;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ActionGroupsV6;

public class ActionGroupsV7 implements Hideable, StaticDefinable {

    
    
    private boolean reserved;
    private boolean hidden;
    @JsonProperty(value = "static")
    private boolean _static;
    private List<String> allowed_actions = Collections.emptyList();
    private String type;
    private String description;
    
    public ActionGroupsV7() {
        super();
    }
    public ActionGroupsV7(String agName, ActionGroupsV6 ag6) {
        reserved = ag6.isReserved();
        hidden = ag6.isHidden();
        allowed_actions = ag6.getPermissions();
        type = agName.toLowerCase().contains("cluster")?"cluster":"index";
        description = "Migrated from v6";
    }

    public ActionGroupsV7(String key, List<String> allowed_actions) {
        this.allowed_actions = allowed_actions;
        type = "unknown";
        description = "Migrated from v6 (legacy)";
    }
    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
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
    public boolean isHidden() {
        return hidden;
    }
    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }
    public List<String> getAllowed_actions() {
        return allowed_actions;
    }
    public void setAllowed_actions(List<String> allowed_actions) {
        this.allowed_actions = allowed_actions;
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
        return "ActionGroupsV7 [reserved=" + reserved + ", hidden=" + hidden + ", _static=" + _static + ", allowed_actions=" + allowed_actions
                + ", type=" + type + ", description=" + description + "]";
    }
    
    
    
    
}