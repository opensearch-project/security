package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7;

import java.util.Collections;
import java.util.List;

import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;
import com.amazon.opendistroforelasticsearch.security.securityconf.RoleMappings;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.RoleMappingsV6;

public class RoleMappingsV7 extends RoleMappings implements Hideable {

    private boolean reserved;
    private boolean hidden;
    private List<String> backend_roles = Collections.emptyList();
    private List<String> and_backend_roles= Collections.emptyList();
    private String description;

    public RoleMappingsV7() {
        super();
    }

    public RoleMappingsV7(RoleMappingsV6 roleMappingsV6) {
        super();
        this.reserved = roleMappingsV6.isReserved();
        this.hidden = roleMappingsV6.isHidden();
        this.backend_roles = roleMappingsV6.getBackendroles();
        this.and_backend_roles = roleMappingsV6.getAndBackendroles();
        this.description = "Migrated from v6";
        setHosts(roleMappingsV6.getHosts());
        setUsers(roleMappingsV6.getUsers());
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



    public List<String> getBackend_roles() {
        return backend_roles;
    }



    public void setBackend_roles(List<String> backend_roles) {
        this.backend_roles = backend_roles;
    }



    public List<String> getAnd_backend_roles() {
        return and_backend_roles;
    }



    public void setAnd_backend_roles(List<String> and_backend_roles) {
        this.and_backend_roles = and_backend_roles;
    }



    public String getDescription() {
        return description;
    }



    public void setDescription(String description) {
        this.description = description;
    }



    @Override
    public String toString() {
        return "RoleMappingsV7 [reserved=" + reserved + ", hidden=" + hidden + ", backend_roles=" + backend_roles + ", hosts=" + getHosts() + ", users="
                + getUsers() + ", and_backend_roles=" + and_backend_roles + ", description=" + description + "]";
    }


    

}