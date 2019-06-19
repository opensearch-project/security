package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6;

import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;

public class RoleMappingsV6 implements Hideable {

    private boolean readonly;
    private boolean hidden;
    private List<String> backendroles = Collections.emptyList();
    private List<String> hosts= Collections.emptyList();
    private List<String> users= Collections.emptyList();
    private List<String> andBackendroles= Collections.emptyList();




    public RoleMappingsV6() {
        super();
    }

    public boolean isReadonly() {
        return readonly;
    }
    public void setReadonly(boolean readonly) {
        this.readonly = readonly;
    }
    public boolean isHidden() {
        return hidden;
    }
    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }
    public List<String> getBackendroles() {
        return backendroles;
    }
    public void setBackendroles(List<String> backendroles) {
        this.backendroles = backendroles;
    }
    public List<String> getHosts() {
        return hosts;
    }
    public void setHosts(List<String> hosts) {
        this.hosts = hosts;
    }
    public List<String> getUsers() {
        return users;
    }
    public void setUsers(List<String> users) {
        this.users = users;
    }

    @JsonProperty(value="and_backendroles")
    public List<String> getAndBackendroles() {
        return andBackendroles;
    }
    public void setAndBackendroles(List<String> andBackendroles) {
        this.andBackendroles = andBackendroles;
    }

    @Override
    public String toString() {
        return "RoleMappings [readonly=" + readonly + ", hidden=" + hidden + ", backendroles=" + backendroles + ", hosts=" + hosts + ", users="
                + users + ", andBackendroles=" + andBackendroles + "]";
    }
    
    @JsonIgnore
    public boolean isReserved() {
        return readonly;
    }

}