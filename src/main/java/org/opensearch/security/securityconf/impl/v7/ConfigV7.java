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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.securityconf.impl.v7;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auth.internal.InternalAuthenticationBackend;
import org.opensearch.security.securityconf.impl.DashboardSignInOption;
import org.opensearch.security.setting.DeprecatedSettings;

public class ConfigV7 {

    public static int ALLOWED_TRIES_DEFAULT = 10;
    public static int TIME_WINDOW_SECONDS_DEFAULT = 60 * 60;
    public static int BLOCK_EXPIRY_SECONDS_DEFAULT = 60 * 10;
    public static int MAX_BLOCKED_CLIENTS_DEFAULT = 100_000;
    public static int MAX_TRACKED_CLIENTS_DEFAULT = 100_000;

    public Dynamic dynamic;

    public ConfigV7() {
        super();
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
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public boolean multi_rolespan_enabled = true;
        public String hosts_resolver_mode = "ip-only";
        public String transport_userrname_attribute;
        public boolean do_not_fail_on_forbidden_empty;
        public OnBehalfOfSettings on_behalf_of = new OnBehalfOfSettings();

        @Override
        public String toString() {
            return "Dynamic [filtered_alias_mode="
                + filtered_alias_mode
                + ", kibana="
                + kibana
                + ", http="
                + http
                + ", authc="
                + authc
                + ", authz="
                + authz
                + ", on_behalf_of="
                + on_behalf_of
                + "]";
        }
    }

    public static class Kibana {

        @JsonInclude(JsonInclude.Include.NON_NULL)
        public boolean multitenancy_enabled = true;
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public boolean private_tenant_enabled = true;
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public String default_tenant = "";
        public String server_username = "kibanaserver";
        public String opendistro_role = null;
        public String index = ".kibana";
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public List<DashboardSignInOption> sign_in_options = Arrays.asList(DashboardSignInOption.BASIC);

        @Override
        public String toString() {
            return "Kibana [multitenancy_enabled="
                + multitenancy_enabled
                + ", private_tenant_enabled="
                + private_tenant_enabled
                + ", default_tenant="
                + default_tenant
                + ", server_username="
                + server_username
                + ", opendistro_role="
                + opendistro_role
                + ", index="
                + index
                + ", sign_in_options="
                + sign_in_options
                + "]";
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
        public List<String> ignore_hosts;
        public int allowed_tries = ALLOWED_TRIES_DEFAULT;
        public int time_window_seconds = TIME_WINDOW_SECONDS_DEFAULT;
        public int block_expiry_seconds = BLOCK_EXPIRY_SECONDS_DEFAULT;
        public int max_blocked_clients = MAX_BLOCKED_CLIENTS_DEFAULT;
        public int max_tracked_clients = MAX_TRACKED_CLIENTS_DEFAULT;

        public AuthFailureListener() {
            super();
        }

        public AuthFailureListener(
            String type,
            String authentication_backend,
            List<String> ignore_hosts,
            int allowed_tries,
            int time_window_seconds,
            int block_expiry_seconds,
            int max_blocked_clients,
            int max_tracked_clients
        ) {
            this.type = type;
            this.authentication_backend = authentication_backend;
            this.ignore_hosts = ignore_hosts;
            this.allowed_tries = allowed_tries;
            this.time_window_seconds = time_window_seconds;
            this.block_expiry_seconds = block_expiry_seconds;
            this.max_blocked_clients = max_blocked_clients;
            this.max_tracked_clients = max_tracked_clients;
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
            "10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|"
                + "192\\.168\\.\\d{1,3}\\.\\d{1,3}|"
                + "169\\.254\\.\\d{1,3}\\.\\d{1,3}|"
                + "127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|"
                + "172\\.1[6-9]{1}\\.\\d{1,3}\\.\\d{1,3}|"
                + "172\\.2[0-9]{1}\\.\\d{1,3}\\.\\d{1,3}|"
                + "172\\.3[0-1]{1}\\.\\d{1,3}\\.\\d{1,3}"
        ).toString();
        public String remoteIpHeader = "X-Forwarded-For";

        @Override
        public String toString() {
            return "Xff [enabled=" + enabled + ", internalProxies=" + internalProxies + ", remoteIpHeader=" + remoteIpHeader + "]";
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

        @JsonInclude(JsonInclude.Include.NON_NULL)
        public boolean http_enabled = true;
        @JsonInclude(JsonInclude.Include.NON_NULL)
        // public boolean enabled= true;
        public int order = 0;
        public HttpAuthenticator http_authenticator = new HttpAuthenticator();
        public AuthcBackend authentication_backend = new AuthcBackend();
        public String description;

        public AuthcDomain() {
            super();
        }

        @Override
        public String toString() {
            return "AuthcDomain [http_enabled="
                + http_enabled
                + ", order="
                + order
                + ", http_authenticator="
                + http_authenticator
                + ", authentication_backend="
                + authentication_backend
                + ", description="
                + description
                + "]";
        }

        @JsonAnySetter
        public void unknownPropertiesHandler(String name, Object value) throws JsonMappingException {
            switch (name) {
                case "transport_enabled":
                    DeprecatedSettings.logCustomDeprecationMessage(
                        String.format(
                            "In AuthcDomain, using http_authenticator=%s, authentication_backend=%s",
                            http_authenticator,
                            authentication_backend
                        ),
                        name
                    );
                    break;
                default:
                    throw new UnrecognizedPropertyException(
                        null,
                        "Unrecognized field " + name + " present in the input data for AuthcDomain config",
                        null,
                        AuthcDomain.class,
                        name,
                        null
                    );
            }
        }

    }

    public static class HttpAuthenticator {
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public boolean challenge = true;
        public String type;
        public Map<String, Object> config = Collections.emptyMap();

        public HttpAuthenticator() {
            super();
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
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public boolean http_enabled = true;
        public AuthzBackend authorization_backend = new AuthzBackend();
        public String description;

        public AuthzDomain() {
            super();
        }

        @Override
        public String toString() {
            return "AuthzDomain [http_enabled="
                + http_enabled
                + ", authorization_backend="
                + authorization_backend
                + ", description="
                + description
                + "]";
        }

        @JsonAnySetter
        public void unknownPropertiesHandler(String name, Object value) throws JsonMappingException {
            switch (name) {
                case "transport_enabled":
                    DeprecatedSettings.logCustomDeprecationMessage(
                        String.format("In AuthzDomain, using authorization_backend=%s", authorization_backend),
                        name
                    );
                    break;
                default:
                    throw new UnrecognizedPropertyException(
                        null,
                        "Unrecognized field " + name + " present in the input data for AuthzDomain config",
                        null,
                        AuthzDomain.class,
                        name,
                        null
                    );
            }
        }
    }

    public static class OnBehalfOfSettings {
        @JsonProperty("enabled")
        private Boolean oboEnabled = Boolean.FALSE;
        @JsonProperty("signing_key")
        private String signingKey;
        @JsonProperty("encryption_key")
        private String encryptionKey;

        @JsonIgnore
        public String configAsJson() {
            try {
                return DefaultObjectMapper.writeValueAsString(this, false);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        public Boolean getOboEnabled() {
            return oboEnabled;
        }

        public void setOboEnabled(Boolean oboEnabled) {
            this.oboEnabled = oboEnabled;
        }

        public String getSigningKey() {
            return signingKey;
        }

        public void setSigningKey(String signingKey) {
            this.signingKey = signingKey;
        }

        public String getEncryptionKey() {
            return encryptionKey;
        }

        public void setEncryptionKey(String encryptionKey) {
            this.encryptionKey = encryptionKey;
        }

        @Override
        public String toString() {
            return "OnBehalfOfSettings [ enabled=" + oboEnabled + ", signing_key=" + signingKey + ", encryption_key=" + encryptionKey + "]";
        }
    }

}
