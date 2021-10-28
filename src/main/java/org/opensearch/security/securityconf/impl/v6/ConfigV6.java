/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */


package org.opensearch.security.securityconf.impl.v6;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auth.internal.InternalAuthenticationBackend;

public class ConfigV6 {

    public Dynamic dynamic;

    
    
    @Override
    public String toString() {
        return "Config [dynamic=" + dynamic + "]";
    }

    public static class Dynamic {


        public String filtered_alias_mode = "warn";
        public boolean disable_rest_auth;
        public boolean disable_intertransport_auth;
        public boolean respect_request_indices_options;
        public String license;
        public Kibana kibana = new Kibana();
        public Http http = new Http();
        public Authc authc = new Authc();
        public Authz authz = new Authz();
        public AuthFailureListeners auth_failure_listeners = new AuthFailureListeners();
        public boolean do_not_fail_on_forbidden;
        public boolean multi_rolespan_enabled;
        public String hosts_resolver_mode = "ip-only";
        public String transport_userrname_attribute;
        public boolean do_not_fail_on_forbidden_empty;
    
        @Override
        public String toString() {
            return "Dynamic [filtered_alias_mode=" + filtered_alias_mode + ", kibana=" + kibana + ", http=" + http + ", authc=" + authc + ", authz="
                    + authz + "]";
        }
    }

    public static class Kibana {

        public boolean multitenancy_enabled = true;
        public String server_username = "kibanaserver";
        public String opendistro_role = null;
        public String index = ".kibana";
        public boolean do_not_fail_on_forbidden;
        @Override
        public String toString() {
            return "Kibana [multitenancy_enabled=" + multitenancy_enabled + ", server_username=" + server_username + ", opendistro_role=" + opendistro_role
                    + ", index=" + index + ", do_not_fail_on_forbidden=" + do_not_fail_on_forbidden + "]";
        }
        
        
        
    }
    
    public static class Http {
        public boolean anonymous_auth_enabled = false;
        public Xff xff = new Xff();
        @Override
        public String toString() {
            return "Http [anonymous_auth_enabled=" + anonymous_auth_enabled + ", xff=" + xff + "]";
        }
        
        
    }
    
    public static class AuthFailureListeners {
        @JsonIgnore
        private final Map<String, AuthFailureListener> listeners = new HashMap<>();

        @JsonAnySetter
        void setListeners(String key, AuthFailureListener value) {
            listeners.put(key, value);
        }

        @JsonAnyGetter
        public Map<String, AuthFailureListener> getListeners() {
            return listeners;
        }

        
    }
    
    public static class AuthFailureListener {
        public String type;
        public String authentication_backend;
        public int allowed_tries = 10;
        public int time_window_seconds = 60 * 60;
        public int block_expiry_seconds = 60 * 10;
        public int max_blocked_clients = 100_000;
        public int max_tracked_clients = 100_000;
        
        public AuthFailureListener() {
            super();
        }
        
        @JsonIgnore
        public String asJson() {
            try {
                return DefaultObjectMapper.writeValueAsString(this, false);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    public static class Xff {
        public boolean enabled = true;
        public String internalProxies = Pattern.compile(
                "10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "192\\.168\\.\\d{1,3}\\.\\d{1,3}|" +
                        "169\\.254\\.\\d{1,3}\\.\\d{1,3}|" +
                        "127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "172\\.1[6-9]{1}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "172\\.2[0-9]{1}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "172\\.3[0-1]{1}\\.\\d{1,3}\\.\\d{1,3}").toString();
        public String remoteIpHeader="X-Forwarded-For";
        public String proxiesHeader="X-Forwarded-By";
        public String trustedProxies;
        @Override
        public String toString() {
            return "Xff [enabled=" + enabled + ", internalProxies=" + internalProxies + ", remoteIpHeader=" + remoteIpHeader + ", proxiesHeader="
                    + proxiesHeader + ", trustedProxies=" + trustedProxies + "]";
        }
        
        
    }
    
    public static class Authc {
        
        @JsonIgnore
        private final Map<String, AuthcDomain> domains = new HashMap<>();

        @JsonAnySetter
        void setDomains(String key, AuthcDomain value) {
            domains.put(key, value);
        }

        @JsonAnyGetter
        public Map<String, AuthcDomain> getDomains() {
            return domains;
        }

        @Override
        public String toString() {
            return "Authc [domains=" + domains + "]";
        }
        
        
    }
    
    public static class AuthcDomain {
        public boolean http_enabled= true;
        public boolean transport_enabled= true;
        public boolean enabled= true;
        public int order = 0;
        public HttpAuthenticator http_authenticator = new HttpAuthenticator();
        public AuthcBackend authentication_backend = new AuthcBackend();
        @Override
        public String toString() {
            return "AuthcDomain [http_enabled=" + http_enabled + ", transport_enabled=" + transport_enabled + ", enabled=" + enabled + ", order="
                    + order + ", http_authenticator=" + http_authenticator + ", authentication_backend=" + authentication_backend + "]";
        }
        
        
    }

    public static class HttpAuthenticator {
        public boolean challenge = true;
        public String type;
        public Map<String, Object> config = Collections.emptyMap();
        
        @JsonIgnore
        public String configAsJson() {
            try {
                return DefaultObjectMapper.writeValueAsString(config, false);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String toString() {
            return "HttpAuthenticator [challenge=" + challenge + ", type=" + type + ", config=" + config + "]";
        }
        
        
    }
    
    public static class AuthzBackend {
        public String type = "noop";
        public Map<String, Object> config = Collections.emptyMap();
        
        @JsonIgnore
        public String configAsJson() {
            try {
                return DefaultObjectMapper.writeValueAsString(config, false);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String toString() {
            return "AuthzBackend [type=" + type + ", config=" + config + "]";
        }
        
        
    }
    
    public static class AuthcBackend {
        public String type = InternalAuthenticationBackend.class.getName();
        public Map<String, Object> config = Collections.emptyMap();
        
        @JsonIgnore
        public String configAsJson() {
            try {
                return DefaultObjectMapper.writeValueAsString(config, false);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String toString() {
            return "AuthcBackend [type=" + type + ", config=" + config + "]";
        }
        
        
    }
    
    public static class Authz {
        @JsonIgnore
        private final Map<String, AuthzDomain> domains = new HashMap<>();

        @JsonAnySetter
        void setDomains(String key, AuthzDomain value) {
            domains.put(key, value);
        }

        @JsonAnyGetter
        public Map<String, AuthzDomain> getDomains() {
            return domains;
        }

        @Override
        public String toString() {
            return "Authz [domains=" + domains + "]";
        }
        
        
    }
    
    public static class AuthzDomain {
        public boolean http_enabled = true;
        public boolean transport_enabled = true;
        public boolean enabled = true;
        public AuthzBackend authorization_backend = new AuthzBackend();
        @Override
        public String toString() {
            return "AuthzDomain [http_enabled=" + http_enabled + ", transport_enabled=" + transport_enabled + ", enabled=" + enabled + ", authorization_backend=" + authorization_backend + "]";
        }
        
        
    }
   
}