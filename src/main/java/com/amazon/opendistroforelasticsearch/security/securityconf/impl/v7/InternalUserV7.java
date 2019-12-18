package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hashed;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;
import com.amazon.opendistroforelasticsearch.security.securityconf.StaticDefinable;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.InternalUserV6;

public class InternalUserV7 implements Hideable, Hashed, StaticDefinable {
        
        private String hash;
        private boolean reserved;
        private boolean hidden;
        @JsonProperty(value = "static")
        private boolean _static;
        private List<String> backend_roles = Collections.emptyList();
        private Map<String, String> attributes = Collections.emptyMap();
        private String description;
        private List<String> opendistro_security_roles = Collections.emptyList();

        private InternalUserV7(String hash, boolean reserved, boolean hidden, List<String> backend_roles, Map<String, String> attributes) {
            super();
            this.hash = hash;
            this.reserved = reserved;
            this.hidden = hidden;
            this.backend_roles = backend_roles;
            this.attributes = attributes;
        }

        public InternalUserV7() {
            super();
            //default constructor
        }
        
        public InternalUserV7(InternalUserV6 u6) {
            hash = u6.getHash();
            reserved = u6.isReserved();
            hidden = u6.isHidden();
            backend_roles = u6.getRoles();
            attributes = u6.getAttributes();
            description = "Migrated from v6";
        }

        public String getHash() {
            return hash;
        }
        public void setHash(String hash) {
            this.hash = hash;
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

        public List<String> getOpendistro_security_roles() {
            return opendistro_security_roles;
        }

        public void setOpendistro_security_roles(List<String> opendistro_security_roles) {
            this.opendistro_security_roles = opendistro_security_roles;
        }

        public Map<String, String> getAttributes() {
            return attributes;
        }
        public void setAttributes(Map<String, String> attributes) {
            this.attributes = attributes;
        }

        @Override
        public String toString() {
            return "InternalUserV7 [hash=" + hash + ", reserved=" + reserved + ", hidden=" + hidden + ", _static=" + _static + ", backend_roles="
                    + backend_roles + ", attributes=" + attributes + ", description=" + description + "]";
        }

        @Override
        @JsonIgnore
        public void clearHash() {
            hash = "";
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
        
        
    }