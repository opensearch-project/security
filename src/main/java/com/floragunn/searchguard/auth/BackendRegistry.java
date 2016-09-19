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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.Callable;
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
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend;
import com.floragunn.searchguard.auth.internal.NoOpAuthenticationBackend;
import com.floragunn.searchguard.auth.internal.NoOpAuthorizationBackend;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.ConfigChangeListener;
import com.floragunn.searchguard.filter.SearchGuardRestFilter;
import com.floragunn.searchguard.http.HTTPBasicAuthenticator;
import com.floragunn.searchguard.http.HTTPClientCertAuthenticator;
import com.floragunn.searchguard.http.HTTPHostAuthenticator;
import com.floragunn.searchguard.http.HTTPProxyAuthenticator;
import com.floragunn.searchguard.http.XFFResolver;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HTTPHelper;
import com.floragunn.searchguard.support.LogHelper;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

public class BackendRegistry implements ConfigChangeListener {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Map<String, String> authImplMap = new HashMap<String, String>();
    private final SortedSet<AuthDomain> authDomains = new TreeSet<AuthDomain>();
    private final Set<AuthorizationBackend> authorizers = new HashSet<AuthorizationBackend>();
    private volatile boolean initialized;
    private final TransportConfigUpdateAction tcua;
    private final AdminDNs adminDns;
    private final XFFResolver xffResolver;
    private volatile boolean anonymousAuthEnabled = false;
    private final Settings esSettings;
    private final InternalAuthenticationBackend iab;
    private final AuditLog auditLog;

    private Cache<AuthCredentials, User> userCache = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .removalListener(new RemovalListener<AuthCredentials, User>() {
                @Override
                public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                    log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                }
            }).build();
    
    private Cache<String, User> userCacheTransport = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .removalListener(new RemovalListener<String, User>() {
                @Override
                public void onRemoval(RemovalNotification<String, User> notification) {
                    log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                }
            }).build();
    
    private Cache<AuthCredentials, User> authenticatedUserCacheTransport = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .removalListener(new RemovalListener<AuthCredentials, User>() {
                @Override
                public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                    log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                }
            }).build();

    @Inject
    public BackendRegistry(final Settings settings, final RestController controller, final TransportConfigUpdateAction tcua, final ClusterService cse,
            final AdminDNs adminDns, final XFFResolver xffResolver, InternalAuthenticationBackend iab, AuditLog auditLog) {
        tcua.addConfigChangeListener("config", this);
        controller.registerFilter(new SearchGuardRestFilter(this, auditLog));
        this.tcua = tcua;
        this.adminDns = adminDns;
        this.esSettings = settings;
        this.xffResolver = xffResolver;
        this.iab = iab;
        this.auditLog = auditLog;
        
        authImplMap.put("intern_c", InternalAuthenticationBackend.class.getName());
        authImplMap.put("intern_z", NoOpAuthorizationBackend.class.getName());
        
        authImplMap.put("internal_c", InternalAuthenticationBackend.class.getName());
        authImplMap.put("internal_z", NoOpAuthorizationBackend.class.getName());
        
        authImplMap.put("noop_c", NoOpAuthenticationBackend.class.getName());
        authImplMap.put("noop_z", NoOpAuthorizationBackend.class.getName());
        
        authImplMap.put("ldap_c", "com.floragunn.dlic.auth.ldap.backend.LDAPAuthenticationBackend");
        authImplMap.put("ldap_z", "com.floragunn.dlic.auth.ldap.backend.LDAPAuthorizationBackend");
        
        authImplMap.put("basic_h", HTTPBasicAuthenticator.class.getName());
        authImplMap.put("proxy_h", HTTPProxyAuthenticator.class.getName());
        authImplMap.put("clientcert_h", HTTPClientCertAuthenticator.class.getName());
        authImplMap.put("kerberos_h", "com.floragunn.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator");
        authImplMap.put("jwt_h", "com.floragunn.dlic.auth.http.jwt.HTTPJwtAuthenticator");
        authImplMap.put("host_h", HTTPHostAuthenticator.class.getName());
    }
    
    public void invalidateCache() {
        userCache.invalidateAll();
        userCacheTransport.invalidateAll();
        authenticatedUserCacheTransport.invalidateAll();
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
            log.warn("Unable to create instance of class {} with (Settings.class) constructor due to {}", e, t, e.toString());
            final Constructor<T> tctor = t.getConstructor(Settings.class, TransportConfigUpdateAction.class);
            return tctor.newInstance(settings, tcua);
        }
    }

    @Override
    public void onChange(final String event, final Settings settings) {
        authDomains.clear();
        anonymousAuthEnabled = settings.getAsBoolean("searchguard.dynamic.http.anonymous_auth_enabled", false);
        
        final Map<String, Settings> authzDyn = settings.getGroups("searchguard.dynamic.authz");
        
        for (final String ad : authzDyn.keySet()) {
            final Settings ads = authzDyn.get(ad);
            if (ads.getAsBoolean("enabled", true)) {
                try {
                    final AuthorizationBackend authorizationBackend = newInstance(
                            ads.get("authorization_backend.type", "noop"),"z",
                            Settings.builder().put(esSettings).put(ads.getAsSettings("authorization_backend.config")).build());
                    authorizers.add(authorizationBackend);
                } catch (final Exception e) {
                    log.error("Unable to initialize AuthorizationBackend {} due to {}", e, ad, e.toString());
                }
            }
        }
        
        final Map<String, Settings> dyn = settings.getGroups("searchguard.dynamic.authc");

        for (final String ad : dyn.keySet()) {
            final Settings ads = dyn.get(ad);
            if (ads.getAsBoolean("enabled", true)) {
                try {
                    AuthenticationBackend authenticationBackend;
                    String authBackendClazz = ads.get("authentication_backend.type", InternalAuthenticationBackend.class.getName());
                    if(authBackendClazz.equals(InternalAuthenticationBackend.class.getName())
                            || authBackendClazz.equals("internal")
                            || authBackendClazz.equals("intern")) {
                        authenticationBackend = iab;
                    } else {
                        authenticationBackend = newInstance(
                                authBackendClazz,"c",
                                Settings.builder().put(esSettings).put(ads.getAsSettings("authentication_backend.config")).build());
                    }
                    
                    String httpAuthenticatorType = ads.get("http_authenticator.type"); //no default
                    HTTPAuthenticator httpAuthenticator = httpAuthenticatorType==null?null:  (HTTPAuthenticator) newInstance(httpAuthenticatorType,"h",
                            Settings.builder().put(esSettings).put(ads.getAsSettings("http_authenticator.config")).build());
                                        
                    authDomains.add(new AuthDomain(authenticationBackend, httpAuthenticator,
                            ads.getAsBoolean("http_authenticator.challenge", true), ads.getAsInt("order", 0)));
                } catch (final Exception e) {
                    log.error("Unable to initialize auth domain {} due to {}", e, ad, e.toString());
                }

            }
        }
        
        if(authDomains.isEmpty()) {
            authDomains.add(new AuthDomain(iab, new HTTPBasicAuthenticator(Settings.EMPTY), true, 0));
        }

        initialized = true;
    }

    @Override
    public void validate(final String event, final Settings settings) throws ElasticsearchSecurityException {

    }

    public boolean authenticate(final TransportRequest request, final TransportChannel channel) throws ElasticsearchSecurityException {
        
        boolean impersonated = impersonate(request, channel);

        final User user = request.getFromContext(ConfigConstants.SG_USER);
        
        if(user == null) {
            return false;
        }
        
        if(adminDns.isAdmin(user.getName())) {
            return true;
        }
        
        AuthCredentials _creds = null;
        final String authorizationHeader = request.getHeader("Authorization");
        
        _creds = HTTPHelper.extractCredentials(authorizationHeader, log);
        
        final AuthCredentials creds = _creds;
        
        if(log.isDebugEnabled() && creds != null) {
            log.debug("User {} submitted also basic credentials: {}", user.getName(), creds);
        }
          
        for (final Iterator<AuthDomain> iterator = new TreeSet<AuthDomain>(authDomains).iterator(); iterator.hasNext();) {

            final AuthDomain authDomain = (AuthDomain) iterator.next();
            User authenticatedUser = null;

            if(creds == null) {
                
                if(log.isDebugEnabled()) {
                    log.debug("Transport User '{}' is in cache? {} (cache size: {})", user.getName(), userCacheTransport.getIfPresent(user.getName())!=null, userCacheTransport.size());
                }
                
                try {
                    authenticatedUser = userCacheTransport.get(user.getName(), new Callable<User>() {
                        @Override
                        public User call() throws Exception {
                            if (log.isDebugEnabled()) {
                                log.debug(user.getName() + " not cached, return from backend directly");
                            }

                            if (authDomain.getBackend().exists(user)) {
                                for (final AuthorizationBackend ab : authorizers) {

                                    // TODO transform username

                                    try {
                                        ab.fillRoles(user, new AuthCredentials(user.getName()));
                                    } catch (Exception e) {
                                        log.error("Problems retrieving roles for {} from {}", user, ab.getClass());
                                    }
                                }
                                return user;
                            }

                            throw new Exception("no such user " + user.getName());
                        }
                    });
                } catch (Exception e) {
                    log.error("Unexpected exception {} ", e, e.toString());
                    throw new ElasticsearchSecurityException(e.toString(), e);
                }
            } else {
                //auth
                
                if (log.isDebugEnabled()) {
                    log.debug("Transport User '{}' is in cache? {} (cache size: {})", creds.getUsername(),
                            authenticatedUserCacheTransport.getIfPresent(creds) != null, authenticatedUserCacheTransport.size());
                }

                try {
                    authenticatedUser = authenticatedUserCacheTransport.get(creds, new Callable<User>() {
                        @Override
                        public User call() throws Exception {
                            if (log.isDebugEnabled()) {
                                log.debug(creds.getUsername() + " not cached, return from backend directly");
                            }

                            // full authentication
                            User _user = authDomain.getBackend().authenticate(creds);

                            for (final AuthorizationBackend ab : authorizers) {

                                // TODO transform username

                                try {
                                    ab.fillRoles(_user, new AuthCredentials(_user.getName()));
                                } catch (Exception e) {
                                    log.error("Problems retrieving roles for {} from {}", _user, ab.getClass());
                                }
                            }
                            return _user;
                        }
                    });
                } catch (Exception e) {
                    log.error("Unexpected exception {} ", e, e.toString());
                    throw new ElasticsearchSecurityException(e.toString(), e);
                } finally {
                    creds.clearSecrets();
                }
            }
     
            try {              
                
                if(authenticatedUser == null) {
                    log.info("Cannot authenticate user (or add roles) with ad {} due to user is null, try next", authDomain.getOrder());
                    continue;
                }
                
                if(adminDns.isAdmin(authenticatedUser.getName())) {
                    log.error("Cannot authenticate user because admin user is not permitted to login");
                    auditLog.logFailedLogin(authenticatedUser.getName(), request);
                    return false;
                }
                
                 //authenticatedUser.addRoles(ac.getBackendRoles());
                if(log.isDebugEnabled()) {
                    log.debug("User '{}' is authenticated", authenticatedUser);
                }
                request.putInContext(ConfigConstants.SG_USER, authenticatedUser);
                return true;
            } catch (final ElasticsearchSecurityException e) {
                log.info("Cannot authenticate user (or add roles) with ad {} due to {}, try next", authDomain.getOrder(), e.toString());
                continue;
            }
            
        }//end for
        
        if(creds == null) {
            auditLog.logFailedLogin(user.getName(), request);
        } else {
            auditLog.logFailedLogin(creds.getUsername(), request);
        }
        
        
        return false;
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
        
        String sslPrincipal = (String) request.getFromContext(ConfigConstants.SG_SSL_PRINCIPAL);
        if(adminDns.isAdmin(sslPrincipal)) {
            //PKI authenticated REST call
            request.putInContext(ConfigConstants.SG_USER, new User(sslPrincipal));
            return true;
        }
        
        if (!isInitialized()) {
            log.error("Not yet initialized");
            channel.sendResponse(new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, "Search Guard not initialized (SG11)"));
            return false;
        }
        
        request.putInContext(ConfigConstants.SG_REMOTE_ADDRESS, xffResolver.resolve(request));
        
        boolean authenticated = false;
        
        User authenticatedUser = null;
        
        AuthCredentials authCredenetials = null;
        
        HTTPAuthenticator firstChallengingHttpAuthenticator = null;
        
        for (final Iterator<AuthDomain> iterator = new TreeSet<AuthDomain>(authDomains).iterator(); iterator.hasNext();) {

            final AuthDomain authDomain = iterator.next();
            
            final HTTPAuthenticator httpAuthenticator = authDomain.getHttpAuthenticator();
            
            if(httpAuthenticator == null) {
                continue; //this domain is for transport protocol only
            }
            
            if(authDomain.isChallenge() && firstChallengingHttpAuthenticator == null) {
                firstChallengingHttpAuthenticator = httpAuthenticator;
            }

            if(log.isDebugEnabled()) {
                log.debug("Try to extract auth creds from http {} ",httpAuthenticator.getType());
            }
            final AuthCredentials ac;
            try {
                ac = httpAuthenticator.extractCredentials(request);
            } catch (Exception e1) {
                log.info("{} extracting credentials from {}", e1, e1.toString(), httpAuthenticator.getType());
                continue;
            }
            authCredenetials = ac;
            
            if (ac == null) {
                //no credentials found in request
                if(anonymousAuthEnabled) {
                    continue;
                }
                        
                if(authDomain.isChallenge() && httpAuthenticator.reRequestAuthentication(channel, null)) {
                    return false;
                } else {
                    //no reRequest possible
                    continue;
                    //log.debug("extraction authentication credentials from http request finally failed");
                    //channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED));
                    //return false;
                }      
            } else if (!ac.isComplete()) {
                //credentials found in request but we need another client challenge
                if(httpAuthenticator.reRequestAuthentication(channel, ac)) {
                    return false;
                } else {
                    //no reRequest possible
                    continue;
                    //log.error(httpAuthenticator.getClass()+" does not support reRequestAuthentication but return incomplete authentication credentials");
                    //channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED));
                    //return false;
                }
              
            } 
            ////credentials found in request and they are complete

            if(log.isDebugEnabled()) {
                log.debug("User '{}' is in cache? {} (cache size: {})", ac.getUsername(), userCache.getIfPresent(ac)!=null, userCache.size());
            }
            
            try {
                try {
                    authenticatedUser = userCache.get(ac, new Callable<User>() {
                        @Override
                        public User call() throws Exception {
                            if(log.isDebugEnabled()) {
                                log.debug(ac.getUsername()+" not cached, return from "+authDomain.getBackend().getType()+" backend directly");
                            }
                            User authenticatedUser = authDomain.getBackend().authenticate(ac);
                            for (final AuthorizationBackend ab : authorizers) {
                                
                                //TODO transform username
                                
                                try {
                                    ab.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName()));
                                } catch (Exception e) {
                                    log.error("Problems retrieving roles for {} from {}", authenticatedUser, ab.getClass());
                                }
                            }
                            //authDomain.getAbackend().fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), (Object) null));
                            return authenticatedUser;
                        }
                    });
                } catch (Exception e) {
                    log.error("Unexpected exception {} ", e, e.toString());
                    throw new ElasticsearchSecurityException(e.toString(), e);
                } finally {
                    ac.clearSecrets();
                }
                
                if(authenticatedUser == null) {
                    log.info("Cannot authenticate user (or add roles) with ad {} due to user is null, try next", authDomain.getOrder());
                    continue;
                }
                
                if(adminDns.isAdmin(authenticatedUser.getName())) {
                    log.error("Cannot authenticate user because admin user is not permitted to login via HTTP");
                    channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN));
                    return false;
                }
                
                 //authenticatedUser.addRoles(ac.getBackendRoles());
                if(log.isDebugEnabled()) {
                    log.debug("User '{}' is authenticated", authenticatedUser);
                }
                request.putInContext(ConfigConstants.SG_USER, authenticatedUser);
                authenticated = true;
                break;
            } catch (final ElasticsearchSecurityException e) {
                log.info("Cannot authenticate user (or add roles) with ad {} due to {}, try next", authDomain.getOrder(), e.toString());
                continue;
            }
            
        }//end for
        
        if(!authenticated) {
            //if(httpAuthenticator.reRequestAuthentication(channel, null)) {
            //  return false;
            //}
            //no reRequest possible
            
            if(authCredenetials == null && anonymousAuthEnabled) {
                request.putInContext(ConfigConstants.SG_USER, User.ANONYMOUS);
                if(log.isDebugEnabled()) {
                    log.debug("Anonymous User is authenticated");
                }
                return true;
            }
            
            if(firstChallengingHttpAuthenticator != null) {
                if(firstChallengingHttpAuthenticator.reRequestAuthentication(channel, null)) {
                    return false;
                }
            }
            
            if(log.isDebugEnabled()) {
                log.debug("Authentication finally failed");
            }
            auditLog.logFailedLogin(authCredenetials == null ? null:authCredenetials.getUsername(), request);
            channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED));
            return false;
        }
        
        return authenticated;
    }

    @Override
    public boolean isInitialized() {
        return initialized;
    }

   private boolean impersonate(final TransportRequest tr, final TransportChannel channel) throws ElasticsearchSecurityException {

        final String impersonatedUser = tr.getHeader("sg_impersonate_as");
        
        if(Strings.isNullOrEmpty(impersonatedUser)) {
            return false; //nothing to do
        }
        
        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Could not check for impersonation because Search Guard is not yet initialized");
        }

        final User origPKIuser = tr.getFromContext(ConfigConstants.SG_USER);
        if (origPKIuser == null) {
            throw new ElasticsearchSecurityException("no original PKI user found");
        }

        User aU = origPKIuser;

        if (adminDns.isAdmin(impersonatedUser)) {
            throw new ElasticsearchSecurityException("'"+origPKIuser.getName() + "' is not allowed to impersonate as an adminuser  '" + impersonatedUser+"'");
        }
        
        try {
            if (impersonatedUser != null && !adminDns.isImpersonationAllowed(new LdapName(origPKIuser.getName()), impersonatedUser)) {
                throw new ElasticsearchSecurityException("'"+origPKIuser.getName() + "' is not allowed to impersonate as '" + impersonatedUser+"'");
            } else if (impersonatedUser != null) {
                aU = new User(impersonatedUser);
                if(log.isDebugEnabled()) {
                    log.debug("Impersonate from '{}' to '{}'",origPKIuser.getName(), impersonatedUser);
                }
            }
        } catch (final InvalidNameException e1) {
            throw new ElasticsearchSecurityException("PKI does not have a valid name ('" + origPKIuser.getName() + "'), should never happen",
                    e1);
        }

        tr.putInContext(ConfigConstants.SG_USER, Objects.requireNonNull((User) aU));
        return true;
    }

}
