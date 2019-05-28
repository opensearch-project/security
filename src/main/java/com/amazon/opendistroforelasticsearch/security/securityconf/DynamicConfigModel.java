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
        authImplMap.put("clientcert_h", HTTPClientCertAuthenticator.class.getName());
        authImplMap.put("kerberos_h", "com.amazon.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator");
        authImplMap.put("jwt_h", "com.amazon.dlic.auth.http.jwt.HTTPJwtAuthenticator");
        authImplMap.put("openid_h", "com.amazon.dlic.auth.http.jwt.keybyoidc.HTTPJwtKeyByOpenIdConnectAuthenticator");
        authImplMap.put("saml_h", "com.amazon.dlic.auth.http.saml.HTTPSamlAuthenticator");
        
        authImplMap.put("ip_authFailureListener", AddressBasedRateLimiter.class.getName());
        authImplMap.put("username_authFailureListener", UserNameBasedRateLimiter.class.getName());
    }
    
    
    
}
