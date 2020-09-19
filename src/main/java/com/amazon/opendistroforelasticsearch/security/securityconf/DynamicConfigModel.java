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
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.net.InetAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.amazon.opendistroforelasticsearch.security.auth.AuthDomain;
import com.amazon.opendistroforelasticsearch.security.auth.AuthFailureListener;
import com.amazon.opendistroforelasticsearch.security.auth.AuthorizationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.blocking.ClientBlockRegistry;
import com.amazon.opendistroforelasticsearch.security.auth.internal.InternalAuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.internal.NoOpAuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.internal.NoOpAuthorizationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.limiting.AddressBasedRateLimiter;
import com.amazon.opendistroforelasticsearch.security.auth.limiting.UserNameBasedRateLimiter;
import com.amazon.opendistroforelasticsearch.security.http.HTTPBasicAuthenticator;
import com.amazon.opendistroforelasticsearch.security.http.HTTPClientCertAuthenticator;
import com.amazon.opendistroforelasticsearch.security.http.HTTPProxyAuthenticator;
import com.amazon.opendistroforelasticsearch.security.http.proxy.HTTPExtendedProxyAuthenticator;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;

public abstract class DynamicConfigModel {
    
    protected final Logger log = LogManager.getLogger(this.getClass());
    public abstract SortedSet<AuthDomain> getRestAuthDomains();
    public abstract Set<AuthorizationBackend> getRestAuthorizers();
    public abstract SortedSet<AuthDomain> getTransportAuthDomains();
    public abstract Set<AuthorizationBackend> getTransportAuthorizers();
    public abstract String getTransportUsernameAttribute();
    public abstract boolean isAnonymousAuthenticationEnabled();
    public abstract boolean isXffEnabled();
    public abstract String getInternalProxies();
    public abstract String getRemoteIpHeader();
    public abstract boolean isRestAuthDisabled();
    public abstract boolean isInterTransportAuthDisabled();
    public abstract boolean isRespectRequestIndicesEnabled();
    public abstract String getKibanaServerUsername();
    public abstract String getKibanaOpendistroRole();
    public abstract String getKibanaIndexname();
    public abstract boolean isKibanaMultitenancyEnabled();
    public abstract boolean isDnfofEnabled();
    public abstract boolean isMultiRolespanEnabled();
    public abstract String getFilteredAliasMode();
    public abstract String getHostsResolverMode();
    public abstract boolean isDnfofForEmptyResultsEnabled();
    
    public abstract List<AuthFailureListener> getIpAuthFailureListeners();
    public abstract Multimap<String, AuthFailureListener> getAuthBackendFailureListeners();
    public abstract List<ClientBlockRegistry<InetAddress>> getIpClientBlockRegistries();
    public abstract Multimap<String, ClientBlockRegistry<String>> getAuthBackendClientBlockRegistries();
    
    protected final Map<String, String> authImplMap = new HashMap<>();

    public DynamicConfigModel() {
        super();
        
        authImplMap.put("intern_c", InternalAuthenticationBackend.class.getName());
        authImplMap.put("intern_z", NoOpAuthorizationBackend.class.getName());

        authImplMap.put("internal_c", InternalAuthenticationBackend.class.getName());
        authImplMap.put("internal_z", NoOpAuthorizationBackend.class.getName());

        authImplMap.put("noop_c", NoOpAuthenticationBackend.class.getName());
        authImplMap.put("noop_z", NoOpAuthorizationBackend.class.getName());

        authImplMap.put("ldap_c", "com.amazon.dlic.auth.ldap.backend.LDAPAuthenticationBackend");
        authImplMap.put("ldap_z", "com.amazon.dlic.auth.ldap.backend.LDAPAuthorizationBackend");
        
        authImplMap.put("ldap2_c", "com.amazon.dlic.auth.ldap2.LDAPAuthenticationBackend2");
        authImplMap.put("ldap2_z", "com.amazon.dlic.auth.ldap2.LDAPAuthorizationBackend2");

        authImplMap.put("basic_h", HTTPBasicAuthenticator.class.getName());
        authImplMap.put("proxy_h", HTTPProxyAuthenticator.class.getName());
        authImplMap.put("extended-proxy_h", HTTPExtendedProxyAuthenticator.class.getName());
        authImplMap.put("clientcert_h", HTTPClientCertAuthenticator.class.getName());
        authImplMap.put("kerberos_h", "com.amazon.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator");
        authImplMap.put("jwt_h", "com.amazon.dlic.auth.http.jwt.HTTPJwtAuthenticator");
        authImplMap.put("openid_h", "com.amazon.dlic.auth.http.jwt.keybyoidc.HTTPJwtKeyByOpenIdConnectAuthenticator");
        authImplMap.put("saml_h", "com.amazon.dlic.auth.http.saml.HTTPSamlAuthenticator");
        
        authImplMap.put("ip_authFailureListener", AddressBasedRateLimiter.class.getName());
        authImplMap.put("username_authFailureListener", UserNameBasedRateLimiter.class.getName());
    }
    
    
    
}
