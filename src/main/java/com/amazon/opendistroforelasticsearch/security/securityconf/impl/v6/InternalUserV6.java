package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hashed;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;

public class InternalUserV6 implements Hideable, Hashed {
        
        private String hash;
        private boolean readonly;
        private boolean hidden;
        private List<String> roles = Collections.emptyList();
        private Map<String, String> attributes = Collections.emptyMap();
        private String username;

        

        public InternalUserV6(String hash, boolean readonly, boolean hidden, List<String> roles, Map<String, String> attributes, String username) {
            super();
            this.hash = hash;
            this.readonly = readonly;
            this.hidden = hidden;
            this.roles = roles;
            this.attributes = attributes;
            this.username = username;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public InternalUserV6() {
            super();
            //default constructor
        }
        
        public String getHash() {
            return hash;
        }
        public void setHash(String hash) {
            this.hash = hash;
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
        public List<String> getRoles() {
            return roles;
        }
        public void setRoles(List<String> roles) {
            this.roles = roles;
        }
        public Map<String, String> getAttributes() {
            return attributes;
        }
        public void setAttributes(Map<String, String> attributes) {
            this.attributes = attributes;
        }

        @Override
        public String toString() {
            return "SgInternalUser [hash=" + hash + ", readonly=" + readonly + ", hidden=" + hidden + ", roles=" + roles + ", attributes="
                    + attributes + "]";
        }
        
        @JsonIgnore
        public boolean isReserved() {
            return readonly;
        }

        @Override
        @JsonIgnore
        public void clearHash() {
            hash = "";
        }
        
        

    }