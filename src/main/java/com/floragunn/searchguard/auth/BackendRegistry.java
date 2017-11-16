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

import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend;
import com.floragunn.searchguard.auth.internal.NoOpAuthenticationBackend;
import com.floragunn.searchguard.auth.internal.NoOpAuthorizationBackend;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.ConfigurationChangeListener;
import com.floragunn.searchguard.http.HTTPBasicAuthenticator;
import com.floragunn.searchguard.http.HTTPClientCertAuthenticator;
import com.floragunn.searchguard.http.HTTPProxyAuthenticator;
import com.floragunn.searchguard.http.XFFResolver;
import com.floragunn.searchguard.ssl.util.Utils;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HTTPHelper;
import com.floragunn.searchguard.support.ReflectionHelper;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

public class BackendRegistry implements ConfigurationChangeListener {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Map<String, String> authImplMap = new HashMap<String, String>();
    private final SortedSet<AuthDomain> restAuthDomains = new TreeSet<AuthDomain>();
    private final Set<AuthorizationBackend> restAuthorizers = new HashSet<AuthorizationBackend>();
    private final SortedSet<AuthDomain> transportAuthDomains = new TreeSet<AuthDomain>();
    private final Set<AuthorizationBackend> transportAuthorizers = new HashSet<AuthorizationBackend>();
    private volatile boolean initialized;
    private final AdminDNs adminDns;
    private final XFFResolver xffResolver;
    private volatile boolean anonymousAuthEnabled = false;
    private final Settings esSettings;
    private final Path configPath;
    private final InternalAuthenticationBackend iab;
    private final AuditLog auditLog;
    private final ThreadPool threadPool;
    private final int ttlInMin;
    private Cache<AuthCredentials, User> userCache;
    private Cache<String, User> userCacheTransport;
    private Cache<AuthCredentials, User> authenticatedUserCacheTransport;
    private Cache<String, User> restImpersonationCache;
    
    private void createCaches() {
        userCache = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<AuthCredentials, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                    }
                }).build();
        
        userCacheTransport = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<String, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<String, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();
        
        authenticatedUserCacheTransport = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<AuthCredentials, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                    }
                }).build();

        restImpersonationCache = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<String, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<String, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();
    }

    public BackendRegistry(final Settings settings, final Path configPath, final AdminDNs adminDns, 
            final XFFResolver xffResolver, final InternalAuthenticationBackend iab, final AuditLog auditLog, final ThreadPool threadPool) {
        this.adminDns = adminDns;
        this.esSettings = settings;
        this.configPath = configPath;
        this.xffResolver = xffResolver;
        this.iab = iab;
        this.auditLog = auditLog;
        this.threadPool = threadPool;
        
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
        
        this.ttlInMin = settings.getAsInt(ConfigConstants.SEARCHGUARD_CACHE_TTL_MINUTES, 60);
        createCaches();
    }

    public boolean isInitialized() {
        return initialized;
    }
    
    public void invalidateCache() {
        userCache.invalidateAll();
        userCacheTransport.invalidateAll();
        authenticatedUserCacheTransport.invalidateAll();
        restImpersonationCache.invalidateAll();
    }

    @Override
    public void onChange(final Settings settings) {
        
        //TODO synchronize via semaphore/atomicref
        restAuthDomains.clear();
        transportAuthDomains.clear();
        restAuthorizers.clear();
        transportAuthorizers.clear();
        invalidateCache();
        anonymousAuthEnabled = settings.getAsBoolean("searchguard.dynamic.http.anonymous_auth_enabled", false);
        
        final Map<String, Settings> authzDyn = settings.getGroups("searchguard.dynamic.authz");
        
        for (final String ad : authzDyn.keySet()) {
            final Settings ads = authzDyn.get(ad);
            final boolean enabled = ads.getAsBoolean("enabled", true);
            final boolean httpEnabled = enabled && ads.getAsBoolean("http_enabled", true);
            final boolean transportEnabled = enabled && ads.getAsBoolean("transport_enabled", true);
            
            
            if (httpEnabled || transportEnabled) {
                try {
                    final AuthorizationBackend authorizationBackend = newInstance(
                            ads.get("authorization_backend.type", "noop"),"z",
                            Settings.builder().put(esSettings).put(ads.getAsSettings("authorization_backend.config")).build(), configPath);
                    
                    if (httpEnabled) {
                        restAuthorizers.add(authorizationBackend);
                    }
                    
                    if (transportEnabled) {
                        transportAuthorizers.add(authorizationBackend);
                    }
                } catch (final Exception e) {
                    log.error("Unable to initialize AuthorizationBackend {} due to {}", ad, e.toString(),e);
                }
            }
        }
        
        final Map<String, Settings> dyn = settings.getGroups("searchguard.dynamic.authc");

        for (final String ad : dyn.keySet()) {
            final Settings ads = dyn.get(ad);
            final boolean enabled = ads.getAsBoolean("enabled", true);
            final boolean httpEnabled = enabled && ads.getAsBoolean("http_enabled", true);
            final boolean transportEnabled = enabled && ads.getAsBoolean("transport_enabled", true);
            
            if (httpEnabled || transportEnabled) {
                try {
                    AuthenticationBackend authenticationBackend;
                    final String authBackendClazz = ads.get("authentication_backend.type", InternalAuthenticationBackend.class.getName());
                    if(authBackendClazz.equals(InternalAuthenticationBackend.class.getName()) //NOSONAR
                            || authBackendClazz.equals("internal")
                            || authBackendClazz.equals("intern")) {
                        authenticationBackend = iab;
                        ReflectionHelper.addLoadedModule(InternalAuthenticationBackend.class);
                    } else {
                        authenticationBackend = newInstance(
                                authBackendClazz,"c",
                                Settings.builder().put(esSettings).put(ads.getAsSettings("authentication_backend.config")).build(), configPath);
                    }
                    
                    String httpAuthenticatorType = ads.get("http_authenticator.type"); //no default
                    HTTPAuthenticator httpAuthenticator = httpAuthenticatorType==null?null:  (HTTPAuthenticator) newInstance(httpAuthenticatorType,"h",
                            Settings.builder().put(esSettings).put(ads.getAsSettings("http_authenticator.config")).build(), configPath);
                    
                    final AuthDomain _ad = new AuthDomain(authenticationBackend, httpAuthenticator,
                            ads.getAsBoolean("http_authenticator.challenge", true), ads.getAsInt("order", 0));
                    
                    if (httpEnabled && _ad.getHttpAuthenticator() != null) {
                        restAuthDomains.add(_ad);
                    }
                    
                    if (transportEnabled) {
                        transportAuthDomains.add(_ad);
                    }
                } catch (final Exception e) {
                    log.error("Unable to initialize auth domain {} due to {}", ad, e.toString(), e);
                }

            }
        }
        
        //SG6 no default authc
        initialized = !restAuthDomains.isEmpty() || anonymousAuthEnabled;
    }

    public User authenticate(final TransportRequest request, final String sslPrincipal, final Task task) {
        
        final User origPKIUser = new User(sslPrincipal);        
        if(adminDns.isAdmin(origPKIUser.getName())) {
            auditLog.logSucceededLogin(origPKIUser.getName(), true, null, request, task);
            return origPKIUser;
        }
        
        final String authorizationHeader = threadPool.getThreadContext().getHeader("Authorization");        
        //Use either impersonation OR credentials authentication
        //if both is supplied credentials authentication win
        final AuthCredentials creds = HTTPHelper.extractCredentials(authorizationHeader, log);
        
        User impersonatedTransportUser = null;
        
        if(creds != null) {
            if(log.isDebugEnabled())  {
                log.debug("User {} submitted also basic credentials: {}", origPKIUser.getName(), creds);
            }
        }
        
        //loop over all transport auth domains
        for (final AuthDomain authDomain: transportAuthDomains) {

            User authenticatedUser = null;
            
            if(creds == null) {
                //no credentials submitted
                //impersonation possible
                impersonatedTransportUser = impersonate(request, origPKIUser);
                authenticatedUser = checkExistsAndAuthz(userCacheTransport, impersonatedTransportUser==null?origPKIUser:impersonatedTransportUser, authDomain, transportAuthorizers);
            } else {
                 //auth credentials submitted
                //impersonation not possible, if requested it will be ignored
                authenticatedUser = authcz(authenticatedUserCacheTransport, creds, authDomain, transportAuthorizers);
            }
            
            if(authenticatedUser == null) {
                if(log.isDebugEnabled()) {
                    log.debug("Cannot authenticate user {} (or add roles) with authdomain {}/{}, try next", creds==null?(impersonatedTransportUser==null?origPKIUser.getName():impersonatedTransportUser.getName()):creds.getUsername(), authDomain.getBackend().getType(), authDomain.getOrder());
                }
                continue;
            }
            
            if(adminDns.isAdmin(authenticatedUser.getName())) {
                log.error("Cannot authenticate user because admin user is not permitted to login");
                auditLog.logFailedLogin(authenticatedUser.getName(), true, null, request, task);
                return null;
            }
     
            if(log.isDebugEnabled()) {
                log.debug("User '{}' is authenticated", authenticatedUser);
            }
            
            auditLog.logSucceededLogin(authenticatedUser.getName(), false, impersonatedTransportUser==null?null:origPKIUser.getName(), request, task);
            
            return authenticatedUser;            
        }//end looping auth domains
        
        
        //auditlog
        if(creds == null) {
            auditLog.logFailedLogin(impersonatedTransportUser==null?origPKIUser.getName():impersonatedTransportUser.getName(), false, impersonatedTransportUser==null?null:origPKIUser.getName(), request, task);
        } else {
            auditLog.logFailedLogin(creds.getUsername(), false, null, request, task);
        }
        
        log.warn("Transport authentication finally failed for {}", creds == null ? impersonatedTransportUser==null?origPKIUser.getName():impersonatedTransportUser.getName():creds.getUsername());
        
        return null;
    }

    
    /**
     * 
     * @param request
     * @param channel
     * @return The authenticated user, null means another roundtrip
     * @throws ElasticsearchSecurityException
     */
    public boolean authenticate(final RestRequest request, final RestChannel channel, final ThreadContext threadContext) {

        final String sslPrincipal = (String) threadPool.getThreadContext().getTransient(ConfigConstants.SG_SSL_PRINCIPAL);

        if(adminDns.isAdmin(sslPrincipal)) {
            //PKI authenticated REST call
            threadPool.getThreadContext().putTransient(ConfigConstants.SG_USER, new User(sslPrincipal));
            auditLog.logSucceededLogin(sslPrincipal, true, null, request);
            return true;
        }
        
        if (!isInitialized()) {
            log.error("Not yet initialized (you may need to run sgadmin)");
            channel.sendResponse(new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, "Search Guard not initialized (SG11). See https://github.com/floragunncom/search-guard-docs/blob/master/sgadmin.md"));
            return false;
        }
        
        threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, xffResolver.resolve(request));
        
        boolean authenticated = false;
        
        User authenticatedUser = null;
        
        AuthCredentials authCredenetials = null;
        
        HTTPAuthenticator firstChallengingHttpAuthenticator = null;
        
        //loop over all http/rest auth domains
        for (final AuthDomain authDomain: restAuthDomains) {
            
            final HTTPAuthenticator httpAuthenticator = authDomain.getHttpAuthenticator();
            
            if(authDomain.isChallenge() && firstChallengingHttpAuthenticator == null) {
                firstChallengingHttpAuthenticator = httpAuthenticator;
            }

            if(log.isDebugEnabled()) {
                log.debug("Try to extract auth creds from {} http authenticator", httpAuthenticator.getType());
            }
            final AuthCredentials ac;
            try {
                ac = httpAuthenticator.extractCredentials(request, threadContext);
            } catch (Exception e1) {
                if(log.isDebugEnabled()) {
                    log.debug("'{}' extracting credentials from {} http authenticator", e1.toString(), httpAuthenticator.getType(), e1);    
                }
                continue;
            }
            authCredenetials = ac;
            
            if (ac == null) {
                //no credentials found in request
                if(anonymousAuthEnabled) {
                    continue;
                }
                        
                if(authDomain.isChallenge() && httpAuthenticator.reRequestAuthentication(channel, null)) {
                    //auditLog.logFailedLogin(null, false, null, request);
                    return false;
                } else {
                    //no reRequest possible
                    continue;
                }      
            } else if (!ac.isComplete()) {
                //credentials found in request but we need another client challenge
                if(httpAuthenticator.reRequestAuthentication(channel, ac)) {
                    //auditLog.logFailedLogin(ac.getUsername()+" <incomplete>", request); --noauditlog
                    return false;
                } else {
                    //no reRequest possible
                    continue;
                }
              
            }

            //http completed
            
            authenticatedUser = authcz(userCache, ac, authDomain, restAuthorizers);
     
            if(authenticatedUser == null) {
                if(log.isDebugEnabled()) {
                    log.debug("Cannot authenticate user {} (or add roles) with authdomain {}/{}, try next", ac.getUsername(), authDomain.getBackend().getType(), authDomain.getOrder());
                }
                continue;
            }

            if(adminDns.isAdmin(authenticatedUser.getName())) {
                log.error("Cannot authenticate user because admin user is not permitted to login via HTTP");
                auditLog.logFailedLogin(authenticatedUser.getName(), true, null, request);
                channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, "Cannot authenticate user because admin user is not permitted to login via HTTP"));
                return false;
            }
            
            final String tenant = Utils.coalesce(request.header("sgtenant"), request.header("sg_tenant"));
            
            if(log.isDebugEnabled()) {
                log.debug("User '{}' is authenticated", authenticatedUser);
                log.debug("sgtenant '{}'", tenant);
            }

            authenticatedUser.setRequestedTenant(tenant);
            final User impersonatedUser = impersonate(request, authenticatedUser, authDomain);
            threadContext.putTransient(ConfigConstants.SG_USER, impersonatedUser==null?authenticatedUser:impersonatedUser);
            
            auditLog.logSucceededLogin((impersonatedUser==null?authenticatedUser:impersonatedUser).getName(), false, authenticatedUser.getName(), request);
            authenticated = true;
            break;
        }//end looping auth domains
        

        if(!authenticated) {        
            if(log.isDebugEnabled()) {
                log.debug("User still not authenticated after checking {} auth domains", restAuthDomains.size());
            }
            
            if(authCredenetials == null && anonymousAuthEnabled) {
            	threadContext.putTransient(ConfigConstants.SG_USER, User.ANONYMOUS);
            	auditLog.logSucceededLogin(User.ANONYMOUS.getName(), false, null, request);
                if(log.isDebugEnabled()) {
                    log.debug("Anonymous User is authenticated");
                }
                return true;
            }
            
            if(firstChallengingHttpAuthenticator != null) {
                
                if(log.isDebugEnabled()) {
                    log.debug("Rerequest with {}", firstChallengingHttpAuthenticator.getClass());
                }
                
                if(firstChallengingHttpAuthenticator.reRequestAuthentication(channel, null)) {                    
                    if(log.isDebugEnabled()) {
                        log.debug("Rerequest {} failed", firstChallengingHttpAuthenticator.getClass());
                    }
                    
                    log.warn("Authentication finally failed for {}", authCredenetials == null ? null:authCredenetials.getUsername());
                    auditLog.logFailedLogin(authCredenetials == null ? null:authCredenetials.getUsername(), false, null, request);
                    return false;
                }
            }
            
            log.warn("Authentication finally failed for {}", authCredenetials == null ? null:authCredenetials.getUsername());
            auditLog.logFailedLogin(authCredenetials == null ? null:authCredenetials.getUsername(), false, null, request);
            channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED, "Authentication finally failed"));
            return false;
        }

        return authenticated;
    }

    /**
     * no auditlog, throw no exception, does also authz for all authorizers
     * 
     * @param cache
     * @param ac
     * @param authDomain
     * @return null if user cannot b authenticated
     */
    private User checkExistsAndAuthz(final Cache<String, User> cache, final User user, final AuthDomain authDomain, final Set<AuthorizationBackend> authorizers) {
        if(user == null) {
            return null;
        }

        try {
            return cache.get(user.getName(), new Callable<User>() {
                @Override
                public User call() throws Exception {
                    if(log.isDebugEnabled()) {
                        log.debug(user.getName()+" not cached, return from "+authDomain.getBackend().getType()+" backend directly");
                    }
                    if(authDomain.getBackend().exists(user)) {
                        for (final AuthorizationBackend ab : authorizers) {
                            try {
                                ab.fillRoles(user, new AuthCredentials(user.getName()));
                            } catch (Exception e) {
                                log.error("Cannot retrieve roles for {} from {} due to {}", user.getName(), ab.getType(), e.toString(), e);
                            }
                        }
                        
                    return user;
                    
                    }

                    if(log.isDebugEnabled()) {
                        log.debug("User "+user.getName()+" does not exist in "+authDomain.getBackend().getType());
                    }
                    return null;
                }
            });
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Can not check and authorize "+user.getName()+" due to "+e.toString(), e);
            }
            return null;
        }
    }
    /**
     * no auditlog, throw no exception, does also authz for all authorizers
     * 
     * @param cache
     * @param ac
     * @param authDomain
     * @return null if user cannot b authenticated
     */
    private User authcz(final Cache<AuthCredentials, User> cache, final AuthCredentials ac, final AuthDomain authDomain, final Set<AuthorizationBackend> authorizers) {
        if(ac == null) {
            return null;
        }

        try {
            return cache.get(ac, new Callable<User>() {
                @Override
                public User call() throws Exception {
                    if(log.isDebugEnabled()) {
                        log.debug(ac.getUsername()+" not cached, return from "+authDomain.getBackend().getType()+" backend directly");
                    }
                    final User authenticatedUser = authDomain.getBackend().authenticate(ac);
                    for (final AuthorizationBackend ab : authorizers) {
                        try {
                            ab.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName()));
                        } catch (Exception e) {
                            log.error("Cannot retrieve roles for {} from {} due to {}", authenticatedUser, ab.getType(), e.toString(), e);
                        }
                    }

                    return authenticatedUser;
                }
            });
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Can not authenticate "+ac.getUsername()+" due to "+e.toString(), e);
            }
            return null;
        } finally {
            ac.clearSecrets();
        }
    }

    private User impersonate(final TransportRequest tr, final User origPKIuser) throws ElasticsearchSecurityException {

        final String impersonatedUser = threadPool.getThreadContext().getHeader("sg_impersonate_as");
        
        if(Strings.isNullOrEmpty(impersonatedUser)) {
            return null; //nothing to do
        }
        
        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Could not check for impersonation because Search Guard is not yet initialized");
        }

        if (origPKIuser == null) {
            throw new ElasticsearchSecurityException("no original PKI user found");
        }

        User aU = origPKIuser;

        if (adminDns.isAdmin(impersonatedUser)) {
            throw new ElasticsearchSecurityException("'"+origPKIuser.getName() + "' is not allowed to impersonate as an adminuser  '" + impersonatedUser+"'");
        }
        
        try {
            if (impersonatedUser != null && !adminDns.isTransportImpersonationAllowed(new LdapName(origPKIuser.getName()), impersonatedUser)) {
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

        return aU;
    }
    
    private User impersonate(final RestRequest request, final User originalUser, final AuthDomain authDomain) throws ElasticsearchSecurityException {

        final String impersonatedUserHeader = request.header("sg_impersonate_as");

        if (Strings.isNullOrEmpty(impersonatedUserHeader) || originalUser == null) {
            return null; // nothing to do
        }

        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Could not check for impersonation because Search Guard is not yet initialized");
        }

        if (adminDns.isAdmin(impersonatedUserHeader)) {
            throw new ElasticsearchSecurityException("It is not allowed to impersonate as an adminuser  '" + impersonatedUserHeader + "'",
                    RestStatus.FORBIDDEN);
        }

        if (!adminDns.isRestImpersonationAllowed(originalUser.getName(), impersonatedUserHeader)) {
            throw new ElasticsearchSecurityException("'" + originalUser.getName() + "' is not allowed to impersonate as '" + impersonatedUserHeader
                    + "'", RestStatus.FORBIDDEN);
        } else {
            final User impersonatedUser = checkExistsAndAuthz(restImpersonationCache, new User(impersonatedUserHeader), authDomain, restAuthorizers);
            
            if(impersonatedUser == null) {
                log.debug("Unable to impersonate rest user from '{}' to '{}' because the impersonated user does not exists in {}", originalUser.getName(), impersonatedUserHeader, authDomain.getBackend().getType());
                throw new ElasticsearchSecurityException("No such user:" + impersonatedUserHeader, RestStatus.FORBIDDEN);
            }
            
            if (log.isDebugEnabled()) {
                log.debug("Impersonate rest user from '{}' to '{}'", originalUser.getName(), impersonatedUserHeader);
            }
            return impersonatedUser;
        }

    }
    
    private <T> T newInstance(final String clazzOrShortcut, String type, final Settings settings, final Path configPath) {
        
        String clazz = clazzOrShortcut;
        boolean isEnterprise = false;
        
        if(authImplMap.containsKey(clazz+"_"+type)) {
            clazz = authImplMap.get(clazz+"_"+type);
        } else {
            isEnterprise = true;
        }
        
        if(ReflectionHelper.isEnterpriseAAAModule(clazz)) {
            isEnterprise = true;
        }
        
        return ReflectionHelper.instantiateAAA(clazz, settings, configPath, isEnterprise);
    }
}
