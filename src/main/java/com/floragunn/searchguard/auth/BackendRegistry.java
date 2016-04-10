/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.auth;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend;
import com.floragunn.searchguard.auth.internal.NoOpAuthenticationBackend;
import com.floragunn.searchguard.auth.internal.NoOpAuthorizationBackend;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.ConfigChangeListener;
import com.floragunn.searchguard.filter.SearchGuardRestFilter;
import com.floragunn.searchguard.http.HTTPBasicAuthenticator;
import com.floragunn.searchguard.http.HTTPProxyAuthenticator;
import com.floragunn.searchguard.http.XFFResolver;
import com.floragunn.searchguard.support.LogHelper;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

public class BackendRegistry implements ConfigChangeListener {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Map<String, String> authImplMap = new HashMap<String, String>();
    private final SortedSet<AuthDomain> authDomains = new TreeSet<AuthDomain>();
    private volatile boolean initialized;
    //private final ClusterService cse;
    private final TransportConfigUpdateAction tcua;
    private final AdminDNs adminDns;
    private final XFFResolver xffResolver;
    private volatile HTTPAuthenticator httpAuthenticator = null;

    private Cache<AuthCredentials, User> userCache = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .removalListener(new RemovalListener<AuthCredentials, User>() {
                @Override
                public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                    log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                }
            }).build();

    @Inject
    public BackendRegistry(final RestController controller, final TransportConfigUpdateAction tcua, final ClusterService cse,
            final AdminDNs adminDns, final XFFResolver xffResolver) {
        tcua.addConfigChangeListener("config", this);
        controller.registerFilter(new SearchGuardRestFilter(this));
        //this.cse = cse;
        this.tcua = tcua;
        this.adminDns = adminDns;
        this.xffResolver = xffResolver;
        
        authImplMap.put("intern_c", InternalAuthenticationBackend.class.getName());
        authImplMap.put("intern_z", NoOpAuthorizationBackend.class.getName());
        
        authImplMap.put("noop_c", NoOpAuthenticationBackend.class.getName());
        authImplMap.put("noop_z", NoOpAuthorizationBackend.class.getName());
        
        authImplMap.put("ldap_c", "com.floragunn.dlic.auth.ldap.backend.LDAPAuthenticationBackend");
        authImplMap.put("ldap_z", "com.floragunn.dlic.auth.ldap.backend.LDAPAuthorizationBackend");
        
        
        authImplMap.put("basic_h", HTTPBasicAuthenticator.class.getName());
        authImplMap.put("proxy_h", HTTPProxyAuthenticator.class.getName());
        
    }
    
    public void invalidateCache() {
        userCache.invalidateAll();
    }

    private <T> T newInstance(final String clazzOrShortcut, String type, final Settings settings) throws ClassNotFoundException, NoSuchMethodException,
            SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        
        String clazz = clazzOrShortcut;
        
        if(authImplMap.containsKey(clazz+"_"+type)) {
            clazz = authImplMap.get(clazz+"_"+type);
        }
        
        final Class<T> t = (Class<T>) Class.forName(clazz);

        try {
            final Constructor<T> tctor = t.getConstructor(Settings.class);
            return tctor.newInstance(settings);
        } catch (final Exception e) {
            final Constructor<T> tctor = t.getConstructor(Settings.class, TransportConfigUpdateAction.class);
            return tctor.newInstance(settings, tcua);
        }
    }

    @Override
    public void onChange(final String event, final Settings settings) {
        authDomains.clear();
        httpAuthenticator = null;
        
        Settings httpAuthSettings = settings.getByPrefix("searchguard.dynamic.http.authenticator.");

        try {
            httpAuthenticator = newInstance(
                    httpAuthSettings.get("type", HTTPBasicAuthenticator.class.getName()),"h",
                    httpAuthSettings);
        } catch (Exception e1) {
            log.error("Unable to initialize http authenticator {} due to {}", httpAuthSettings, e1.toString());
            httpAuthenticator = new HTTPBasicAuthenticator(httpAuthSettings);
        }
        
        final Map<String, Settings> dyn = settings.getGroups("searchguard.dynamic.authcz");

        for (final String ad : dyn.keySet()) {
            final Settings ads = dyn.get(ad);
            if (ads.getAsBoolean("enabled", true)) {
                try {
                    final AuthenticationBackend authenticationBackend = newInstance(
                            ads.get("authentication_backend.type", InternalAuthenticationBackend.class.getName()),"c",
                            ads);
                    final AuthorizationBackend authorizationBackend = newInstance(
                            ads.get("authorization_backend.type", "com.floragunn.searchguard.auth.internal.NoOpAuthorizationBackend"),"z",
                            ads);
                    authDomains.add(new AuthDomain(authenticationBackend, authorizationBackend,
                            ads.getAsInt("order", 0)));
                } catch (final Exception e) {
                    log.error("Unable to initialize auth domain {} due to {}", e, ad, e.toString());
                }

            }
        }
        
        if(authDomains.isEmpty()) {
            authDomains.add(new AuthDomain(new InternalAuthenticationBackend(Settings.EMPTY, tcua), new NoOpAuthorizationBackend(Settings.EMPTY), 0));
        }

        initialized = (httpAuthenticator != null && authDomains.size() > 0);
    }

    @Override
    public void validate(final String event, final Settings settings) throws ElasticsearchSecurityException {

    }

    /**
     * 
     * @param request
     * @param channel
     * @return The authenticated user, null means another roundtrip
     * @throws ElasticsearchSecurityException
     */
    public boolean authenticate(final RestRequest request, final RestChannel channel) throws ElasticsearchSecurityException {

        if(log.isTraceEnabled()) {
            log.trace(LogHelper.toString(request));
        }
        
        if(adminDns.isAdmin((String) request.getFromContext("_sg_ssl_principal"))) {
            //PKI authenticated REST call
            request.putInContext("_sg_internal_request", Boolean.TRUE);
            return true;
        }
        
        if (!isInitialized()) {
            log.warn("Not yet initialized");
            channel.sendResponse(new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, "Search Guard not initialized (SG11)"));
            return false;
        }

        request.putInContext("_sg_remote_address", xffResolver.resolve(request));

        
        final AuthCredentials ac = httpAuthenticator.authenticate(request, channel);
        
        if (ac == null) {
            // roundtrip
            return false;
        }
        
        boolean authenticated = false;
        
        for (final Iterator iterator = new TreeSet<AuthDomain>(authDomains).iterator(); iterator.hasNext();) {

            final AuthDomain authDomain = (AuthDomain) iterator.next();
            User authenticatedUser = null;
            
            log.debug("User '{}' is in cache? {} (cache size: {})", ac.getUsername(), userCache.getIfPresent(ac)!=null, userCache.size());
            
            try {
                try {
                    authenticatedUser = userCache.get(ac, new Callable<User>() {
                        @Override
                        public User call() throws Exception {
                            log.debug(ac.getUsername()+" not cached, return from backend directly");
                            User authenticatedUser = authDomain.getBackend().authenticate(ac);
                            authDomain.getAbackend().fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), (Object) null));
                            return authenticatedUser;
                        }
                    });
                } catch (Exception e) {
                    throw new ElasticsearchSecurityException("", e.getCause());
                }
                
                 //authenticatedUser.addRoles(ac.getBackendRoles());
                log.debug("User '{}' is authenticated", authenticatedUser);
                request.putInContext("_sg_user", authenticatedUser);
                authenticated = true;
                break;
            } catch (final ElasticsearchSecurityException e) {
                log.info("Cannot authenticate user (or add roles) with ad {} due to {}, try next", authDomain.getOrder(), e.toString());
                continue;
            }
            
        }
        
        if(!authenticated) {
            httpAuthenticator.requestAuthentication(channel);
        }
        
        // TODO check if anonymous access is allowed
        return authenticated;
    }

    @Override
    public boolean isInitialized() {
        return initialized;
    }

    public boolean authenticate(final TransportRequest tr, final TransportChannel channel) throws ElasticsearchSecurityException {

        final User origPKIuser = tr.getFromContext("_sg_user");

        if (!isInitialized()) {
            return true;
        }
        /*
        if(!isInitialized() && adminDns.isAdmin(origPKIuser.getName())) {

        } else if (!isInitialized()) {
            log.warn("Not yet initialized");
            try {
                channel.sendResponse(new ElasticsearchSecurityException("Not initialized "+origPKIuser));
            } catch (IOException e) {
                throw new ElasticsearchSecurityException("Unexpected IO exception", e);
            }
            return false;
        }
         */

        if (origPKIuser == null) {
            throw new ElasticsearchSecurityException("no PKI user found");
        }

        User aU = origPKIuser;
        final String impersonatedUser = tr.getHeader("sg.impersonate.as");

        try {
            if (impersonatedUser != null && !adminDns.isImpersonationAllowed(new LdapName(origPKIuser.getName()), impersonatedUser)) {
                throw new ElasticsearchSecurityException(origPKIuser.getName() + " is not allowed to impersonate as " + impersonatedUser);

            } else if (impersonatedUser != null) {
                aU = new User(impersonatedUser);
                log.debug("Impersonate as '{}'", impersonatedUser);

            }
        } catch (final InvalidNameException e1) {
            throw new ElasticsearchSecurityException("PKI does not have a valid name (" + origPKIuser.getName() + "), should never happen",
                    e1);
        }

        tr.putInContext("_sg_user", aU);

        //fill roles only
        /*for (final Iterator iterator = new TreeSet<AuthDomain>(authDomains).iterator(); iterator.hasNext();) {

            final AuthDomain authDomain = (AuthDomain) iterator.next();
            try {
                authDomain.getAbackend().fillRoles(aU, new AuthCredentials(aU.getName(), (Object) null));
            } catch (final ElasticsearchSecurityException e) {
                log.info("Cannot add roles for user {} with ad {}, try next", aU.getName(), authDomain.getOrder());
                continue;
            }
        }*/
        
        return true;
    }

}
