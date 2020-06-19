package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auth.internal.InternalAuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6;

public class ConfigV7 {

    public Dynamic dynamic;

    public ConfigV7() {
        super();
    }

    public ConfigV7(ConfigV6 c6) {
        dynamic = new Dynamic();
        
        dynamic.filtered_alias_mode = c6.dynamic.filtered_alias_mode;
        dynamic.disable_rest_auth = c6.dynamic.disable_rest_auth;
        dynamic.disable_intertransport_auth = c6.dynamic.disable_intertransport_auth;
        dynamic.respect_request_indices_options = c6.dynamic.respect_request_indices_options;
        dynamic.license = c6.dynamic.license;
        dynamic.do_not_fail_on_forbidden = c6.dynamic.do_not_fail_on_forbidden || c6.dynamic.kibana.do_not_fail_on_forbidden;
        dynamic.do_not_fail_on_forbidden_empty = c6.dynamic.do_not_fail_on_forbidden_empty;
        dynamic.multi_rolespan_enabled = c6.dynamic.multi_rolespan_enabled;
        dynamic.hosts_resolver_mode = c6.dynamic.hosts_resolver_mode;
        dynamic.transport_userrname_attribute = c6.dynamic.transport_userrname_attribute;
        
        dynamic.kibana = new Kibana();
        
        dynamic.kibana.index = c6.dynamic.kibana.index;
        dynamic.kibana.multitenancy_enabled = c6.dynamic.kibana.multitenancy_enabled;
        dynamic.kibana.server_username = c6.dynamic.kibana.server_username;
        
        dynamic.http = new Http();
        
        dynamic.http.anonymous_auth_enabled = c6.dynamic.http.anonymous_auth_enabled;
        
        dynamic.http.xff = new Xff();
        
        dynamic.http.xff.enabled = c6.dynamic.http.xff.enabled;
        dynamic.http.xff.internalProxies = c6.dynamic.http.xff.internalProxies;
        dynamic.http.xff.remoteIpHeader = c6.dynamic.http.xff.remoteIpHeader;
        
        dynamic.authc = new Authc();
        
        dynamic.authc.domains.putAll(c6.dynamic.authc.getDomains().entrySet().stream().collect(Collectors.toMap(
                entry -> entry.getKey(), 
                entry -> new AuthcDomain(entry.getValue()))));
        
        dynamic.authz = new Authz();
        
        dynamic.authz.domains.putAll(c6.dynamic.authz.getDomains().entrySet().stream().collect(Collectors.toMap(
                entry -> entry.getKey(), 
                entry -> new AuthzDomain(entry.getValue()))));
        
        dynamic.auth_failure_listeners = new AuthFailureListeners();
        dynamic.auth_failure_listeners.listeners.putAll(c6.dynamic.auth_failure_listeners.getListeners().entrySet().stream().collect(Collectors.toMap(
                entry -> entry.getKey(), 
                entry -> new AuthFailureListener(entry.getValue()))));
    }

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
        public boolean multi_rolespan_enabled = true;
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
        public String opendistro_role = "";
        public String index = ".kibana";
        @Override
        public String toString() {
            return "Kibana [multitenancy_enabled=" + multitenancy_enabled + ", server_username=" + server_username + ", opendistro_role=" + opendistro_role
            + ", index=" + index + "]";
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

        public AuthFailureListener(com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6.AuthFailureListener v6) {
            super();
            this.type = v6.type;
            this.authentication_backend = v6.authentication_backend;
            this.allowed_tries = v6.allowed_tries;
            this.time_window_seconds = v6.time_window_seconds;
            this.block_expiry_seconds = v6.block_expiry_seconds;
            this.max_blocked_clients = v6.max_blocked_clients;
            this.max_tracked_clients = v6.max_tracked_clients;
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
        public boolean enabled = false;
        public String internalProxies = Pattern.compile(
                "10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "192\\.168\\.\\d{1,3}\\.\\d{1,3}|" +
                        "169\\.254\\.\\d{1,3}\\.\\d{1,3}|" +
                        "127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "172\\.1[6-9]{1}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "172\\.2[0-9]{1}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "172\\.3[0-1]{1}\\.\\d{1,3}\\.\\d{1,3}").toString();
        public String remoteIpHeader="X-Forwarded-For";
        @Override
        public String toString() {
            return "Xff [enabled=" + enabled + ", internalProxies=" + internalProxies + ", remoteIpHeader=" + remoteIpHeader+"]";
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
        //public boolean enabled= true;
        public int order = 0;
        public HttpAuthenticator http_authenticator = new HttpAuthenticator();
        public AuthcBackend authentication_backend = new AuthcBackend();
        public String description;
        
        public AuthcDomain() {
            super();
        }
        
        public AuthcDomain(com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6.AuthcDomain v6) {
            super();
            http_enabled = v6.http_enabled && v6.enabled;
            transport_enabled = v6.transport_enabled && v6.enabled;
//            if(v6.enabled)vv {
//                http_enabled = true;
//                transport_enabled = true;
//            }
            order = v6.order;
            http_authenticator = new HttpAuthenticator(v6.http_authenticator);
            authentication_backend = new AuthcBackend(v6.authentication_backend);
            description = "Migrated from v6";
        }

        @Override
        public String toString() {
            return "AuthcDomain [http_enabled=" + http_enabled + ", transport_enabled=" + transport_enabled + ", order=" + order
                    + ", http_authenticator=" + http_authenticator + ", authentication_backend=" + authentication_backend + ", description="
                    + description + "]";
        }
        
        
    }

    public static class HttpAuthenticator {
        public boolean challenge = true;
        public String type;
        public Map<String, Object> config = Collections.emptyMap();
        
        public HttpAuthenticator() {
            super();
        }


        public HttpAuthenticator(com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6.HttpAuthenticator v6) {
            this.challenge = v6.challenge;
            this.type = v6.type;
            this.config = v6.config;
        }


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
        
        
        
        public AuthzBackend() {
            super();
        }



        public AuthzBackend(com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6.AuthzBackend v6) {
            this.type = v6.type;
            this.config = v6.config;
        }



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
        
        
        
        public AuthcBackend() {
            super();
        }



        public AuthcBackend(com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6.AuthcBackend v6) {
            this.type = v6.type;
            this.config = v6.config;
        }



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
        public AuthzBackend authorization_backend = new AuthzBackend();
        public String description;
        
        public AuthzDomain() {
            super();
        }
        
        public AuthzDomain(com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6.AuthzDomain v6) {
            http_enabled = v6.http_enabled && v6.enabled;
            transport_enabled = v6.transport_enabled && v6.enabled;
            authorization_backend = new AuthzBackend(v6.authorization_backend);
            description = "Migrated from v6";
        }

        @Override
        public String toString() {
            return "AuthzDomain [http_enabled=" + http_enabled + ", transport_enabled=" + transport_enabled
                    + ", authorization_backend=" + authorization_backend + ", description=" + description + "]";
        }
        
        
    }
   
}