package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;

public class RoleV6 implements Hideable {

    private boolean readonly;
    private boolean hidden;
    private List<String> cluster = Collections.emptyList();
    private Map<String, String> tenants = Collections.emptyMap();
    private Map<String, Index> indices = Collections.emptyMap();

    public static class Index {

        @JsonIgnore
        private final Map<String, List<String>> types = new HashMap<>();

        @JsonAnySetter
        void setTypes0(String key, List<String> value) {
            types.put(key, value);
        }

        @JsonAnyGetter
        public Map<String, List<String>> getTypes() {
            return types;
        }
        
        private String _dls_;
        private List<String> _fls_;
        private List<String> _masked_fields_;

        
        
        public String get_dls_() {
            return _dls_;
        }

        public List<String> get_fls_() {
            return _fls_;
        }

        public List<String> get_masked_fields_() {
            return _masked_fields_;
        }

        @Override
        public String toString() {
            return "Index [types=" + types + ", _dls_=" + _dls_ + ", _fls_=" + _fls_ + ", _masked_fields_=" + _masked_fields_ + "]";
        }

        

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

    public List<String> getCluster() {
        return cluster;
    }

    public void setCluster(List<String> cluster) {
        this.cluster = cluster;
    }

    public Map<String, String> getTenants() {
        return tenants;
    }

    public void setTenants(Map<String, String> tenants) {
        this.tenants = tenants;
    }

    public Map<String, Index> getIndices() {
        return indices;
    }

    public void setIndices(Map<String, Index> indices) {
        this.indices = indices;
    }

    @Override
    public String toString() {
        return "Role [readonly=" + readonly + ", hidden=" + hidden + ", cluster=" + cluster + ", tenants=" + tenants + ", indices=" + indices + "]";
    }
    
    @JsonIgnore
    public boolean isReserved() {
        return readonly;
    }

}