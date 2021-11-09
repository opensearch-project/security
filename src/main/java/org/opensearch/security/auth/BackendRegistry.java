/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.auth;


import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.blocking.ClientBlockRegistry;
import org.opensearch.security.auth.internal.NoOpAuthenticationBackend;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.ssl.util.Utils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HTTPHelper;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;
import org.greenrobot.eventbus.Subscribe;

import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;
import com.google.common.collect.Multimap;

public class BackendRegistry {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private SortedSet<AuthDomain> restAuthDomains;
    private Set<AuthorizationBackend> restAuthorizers;
    private SortedSet<AuthDomain> transportAuthDomains;
    private Set<AuthorizationBackend> transportAuthorizers;

    private List<AuthFailureListener> ipAuthFailureListeners;
    private Multimap<String, AuthFailureListener> authBackendFailureListeners;
    private List<ClientBlockRegistry<InetAddress>> ipClientBlockRegistries;
    private Multimap<String, ClientBlockRegistry<String>> authBackendClientBlockRegistries;

    private volatile boolean initialized;
    private volatile boolean injectedUserEnabled = false;
    private final AdminDNs adminDns;
    private final XFFResolver xffResolver;
    private volatile boolean anonymousAuthEnabled = false;
    private final Settings opensearchSettings;
    //private final InternalAuthenticationBackend iab;
    private final AuditLog auditLog;
    private final ThreadPool threadPool;
    private final UserInjector userInjector;
    private final int ttlInMin;
    private Cache<AuthCredentials, User> userCache; //rest standard
    private Cache<String, User> restImpersonationCache; //used for rest impersonation
    private Cache<String, User> userCacheTransport; //transport no creds, possibly impersonated
    private Cache<AuthCredentials, User> authenticatedUserCacheTransport; //transport creds, no impersonation

    private Cache<User, Set<String>> transportRoleCache; //
    private Cache<User, Set<String>> restRoleCache; //
    private Cache<String, User> transportImpersonationCache; //used for transport impersonation

    private volatile String transportUsernameAttribute = null;
    
    private void createCaches() {
        userCache = CacheBuilder.newBuilder().expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<AuthCredentials, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                    }
                }).build();

        userCacheTransport = CacheBuilder.newBuilder().expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<String, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<String, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();

        authenticatedUserCacheTransport = CacheBuilder.newBuilder().expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<AuthCredentials, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                    }
                }).build();

        restImpersonationCache = CacheBuilder.newBuilder().expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<String, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<String, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();

        transportRoleCache = CacheBuilder.newBuilder().expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<User, Set<String>>() {
                    @Override
                    public void onRemoval(RemovalNotification<User, Set<String>> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();

        restRoleCache = CacheBuilder.newBuilder().expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<User, Set<String>>() {
                    @Override
                    public void onRemoval(RemovalNotification<User, Set<String>> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();

        transportImpersonationCache = CacheBuilder.newBuilder().expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<String, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<String, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();

    }

    public BackendRegistry(final Settings settings, final AdminDNs adminDns,
            final XFFResolver xffResolver, final AuditLog auditLog, final ThreadPool threadPool) {
        this.adminDns = adminDns;
        this.opensearchSettings = settings;
        this.xffResolver = xffResolver;
        this.auditLog = auditLog;
        this.threadPool = threadPool;
        this.userInjector = new UserInjector(settings, threadPool, auditLog, xffResolver);


        this.ttlInMin = settings.getAsInt(ConfigConstants.SECURITY_CACHE_TTL_MINUTES, 60);

        // This is going to be defined in the opensearch.yml, so it's best suited to be initialized once.
        this.injectedUserEnabled = opensearchSettings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED,false);

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
        restRoleCache.invalidateAll();
        transportRoleCache.invalidateAll();
        transportImpersonationCache.invalidateAll();
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {

        invalidateCache();
        transportUsernameAttribute = dcm.getTransportUsernameAttribute();// config.dynamic.transport_userrname_attribute;
        anonymousAuthEnabled = dcm.isAnonymousAuthenticationEnabled()//config.dynamic.http.anonymous_auth_enabled
                && !opensearchSettings.getAsBoolean(ConfigConstants.SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false);

        restAuthDomains = Collections.unmodifiableSortedSet(dcm.getRestAuthDomains());
        transportAuthDomains = Collections.unmodifiableSortedSet(dcm.getTransportAuthDomains());
        restAuthorizers = Collections.unmodifiableSet(dcm.getRestAuthorizers());
        transportAuthorizers = Collections.unmodifiableSet(dcm.getTransportAuthorizers());

        ipAuthFailureListeners = dcm.getIpAuthFailureListeners();
        authBackendFailureListeners = dcm.getAuthBackendFailureListeners();
        ipClientBlockRegistries = dcm.getIpClientBlockRegistries();
        authBackendClientBlockRegistries = dcm.getAuthBackendClientBlockRegistries();

        //OpenSearch Security no default authc
        initialized = !restAuthDomains.isEmpty() || anonymousAuthEnabled  || injectedUserEnabled;
    }

    public User authenticate(final TransportRequest request, final String sslPrincipal, final Task task, final String action) {
        final boolean isDebugEnabled = log.isDebugEnabled();
        if(isDebugEnabled && request.remoteAddress() != null) {
            log.debug("Transport authentication request from {}", request.remoteAddress());
        }

        if (request.remoteAddress() != null && isBlocked(request.remoteAddress().address().getAddress())) {
            if (isDebugEnabled) {
                log.debug("Rejecting transport request because of blocked address: {}", request.remoteAddress());
            }
            return null;
        }

        User injectedUser = userInjector.getInjectedUser();

        if(injectedUser != null) {
            auditLog.logSucceededLogin(injectedUser.getName(), true, null, request, action, task);
            return injectedUser;
        }

        if(sslPrincipal == null) {
            return null;
        }
        
        User origPKIUser = new User(sslPrincipal);
        
        if(adminDns.isAdmin(origPKIUser)) {
            auditLog.logSucceededLogin(origPKIUser.getName(), true, null, request, action, task);
            return origPKIUser;
        }

        if (!isInitialized()) {
            log.error("Not yet initialized (you may need to run securityadmin)");
            return null;
        }

        final String authorizationHeader = threadPool.getThreadContext().getHeader("Authorization");
        //Use either impersonation OR credentials authentication
        //if both is supplied credentials authentication win
        final AuthCredentials creds = HTTPHelper.extractCredentials(authorizationHeader, log);

        User impersonatedTransportUser = null;

        if(creds != null) {
            if (isDebugEnabled)  {
                log.debug("User {} submitted also basic credentials: {}", origPKIUser.getName(), creds);
            }
        }

        //loop over all transport auth domains
        for (final AuthDomain authDomain: transportAuthDomains) {

            if (isDebugEnabled) {
                log.debug("Check transport authdomain {}/{} or {} in total", authDomain.getBackend().getType(), authDomain.getOrder(), transportAuthDomains.size());
            }
            
            User authenticatedUser = null;

            if(creds == null) {
                //no credentials submitted
                //impersonation possible
                impersonatedTransportUser = impersonate(request, origPKIUser);
                origPKIUser = resolveTransportUsernameAttribute(origPKIUser);
                authenticatedUser = checkExistsAndAuthz(userCacheTransport,
                        impersonatedTransportUser == null ? origPKIUser : impersonatedTransportUser, authDomain.getBackend(), transportAuthorizers);
            } else {
                 //auth credentials submitted
                //impersonation not possible, if requested it will be ignored
                authenticatedUser = authcz(authenticatedUserCacheTransport, transportRoleCache, creds, authDomain.getBackend(), transportAuthorizers);
            }

            if (authenticatedUser == null) {
                for (AuthFailureListener authFailureListener : authBackendFailureListeners.get(authDomain.getBackend().getClass().getName())) {
                    authFailureListener.onAuthFailure(request.remoteAddress() != null ? request.remoteAddress().address().getAddress() : null, creds,
                            request);
                }

                if (isDebugEnabled) {
                    log.debug("Cannot authenticate transport user {} (or add roles) with authdomain {}/{} of {}, try next", creds==null?(impersonatedTransportUser==null?origPKIUser.getName():impersonatedTransportUser.getName()):creds.getUsername(), authDomain.getBackend().getType(), authDomain.getOrder(), transportAuthDomains.size());
                }
                continue;
            }

            if(adminDns.isAdmin(authenticatedUser)) {
                log.error("Cannot authenticate transport user because admin user is not permitted to login");
                auditLog.logFailedLogin(authenticatedUser.getName(), true, null, request, task);
                return null;
            }

            if (isDebugEnabled) {
                log.debug("Transport user '{}' is authenticated", authenticatedUser);
            }

            auditLog.logSucceededLogin(authenticatedUser.getName(), false, impersonatedTransportUser == null ? null : origPKIUser.getName(), request,
                    action, task);

            return authenticatedUser;
        }//end looping auth domains


        //auditlog
        if(creds == null) {
            auditLog.logFailedLogin(impersonatedTransportUser == null ? origPKIUser.getName() : impersonatedTransportUser.getName(), false,
                    impersonatedTransportUser == null ? null : origPKIUser.getName(), request, task);
        } else {
            auditLog.logFailedLogin(creds.getUsername(), false, null, request, task);
        }

        log.warn("Transport authentication finally failed for {} from {}",
                creds == null ? impersonatedTransportUser == null ? origPKIUser.getName() : impersonatedTransportUser.getName() : creds.getUsername(),
                request.remoteAddress());

        notifyIpAuthFailureListeners(request.remoteAddress() != null ? request.remoteAddress().address().getAddress() : null, creds, request);

        return null;
    }

    /**
     *
     * @param request
     * @param channel
     * @return The authenticated user, null means another roundtrip
     * @throws OpenSearchSecurityException
     */
    public boolean authenticate(final RestRequest request, final RestChannel channel, final ThreadContext threadContext) {
        final boolean isDebugEnabled = log.isDebugEnabled();
        if (request.getHttpChannel().getRemoteAddress() instanceof InetSocketAddress && isBlocked(((InetSocketAddress) request.getHttpChannel().getRemoteAddress()).getAddress())) {
            if (isDebugEnabled) {
                log.debug("Rejecting REST request because of blocked address: {}", request.getHttpChannel().getRemoteAddress());
            }
            
            channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED, "Authentication finally failed"));

            return false;
        }

        final String sslPrincipal = (String) threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);

        if(adminDns.isAdminDN(sslPrincipal)) {
            //PKI authenticated REST call
            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User(sslPrincipal));
            auditLog.logSucceededLogin(sslPrincipal, true, null, request);
            return true;
        }

        if (userInjector.injectUser(request)) {
            // ThreadContext injected user
            return true;
        }
        
        if (!isInitialized()) {
            log.error("Not yet initialized (you may need to run securityadmin)");
            channel.sendResponse(new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE,
                    "OpenSearch Security not initialized."));
            return false;
        }
        
        final TransportAddress remoteAddress = xffResolver.resolve(request);
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("Rest authentication request from {} [original: {}]", remoteAddress, request.getHttpChannel().getRemoteAddress());
    	}

        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, remoteAddress);

        boolean authenticated = false;

        User authenticatedUser = null;

        AuthCredentials authCredenetials = null;

        HTTPAuthenticator firstChallengingHttpAuthenticator = null;

        //loop over all http/rest auth domains
        for (final AuthDomain authDomain: restAuthDomains) {
            if (isDebugEnabled) {
                log.debug("Check authdomain for rest {}/{} or {} in total", authDomain.getBackend().getType(), authDomain.getOrder(), restAuthDomains.size());
            }

            final HTTPAuthenticator httpAuthenticator = authDomain.getHttpAuthenticator();

            if(authDomain.isChallenge() && firstChallengingHttpAuthenticator == null) {
                firstChallengingHttpAuthenticator = httpAuthenticator;
            }

            if (isTraceEnabled) {
                log.trace("Try to extract auth creds from {} http authenticator", httpAuthenticator.getType());
            }
            final AuthCredentials ac;
            try {
                ac = httpAuthenticator.extractCredentials(request, threadContext);
            } catch (Exception e1) {
                if (isDebugEnabled) {
                    log.debug("'{}' extracting credentials from {} http authenticator", e1.toString(), httpAuthenticator.getType(), e1);
                }
                continue;
            }

            if (ac != null && isBlocked(authDomain.getBackend().getClass().getName(), ac.getUsername())) {
                if (isDebugEnabled) {
                    log.debug("Rejecting REST request because of blocked user: {}, authDomain: {}", ac.getUsername(), authDomain);
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
                    auditLog.logFailedLogin("<NONE>", false, null, request);
                    log.trace("No 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
                    return false;
                } else {
                    //no reRequest possible
                    if (isTraceEnabled) {
                        log.trace("No 'Authorization' header, send 403");
                    }
                    continue;
                }
            } else {
                org.apache.logging.log4j.ThreadContext.put("user", ac.getUsername());
                if (!ac.isComplete()) {
                    //credentials found in request but we need another client challenge
                    if(httpAuthenticator.reRequestAuthentication(channel, ac)) {
                        //auditLog.logFailedLogin(ac.getUsername()+" <incomplete>", request); --noauditlog
                        return false;
                    } else {
                        //no reRequest possible
                        continue;
                    }

                }
            }

            //http completed       
            authenticatedUser = authcz(userCache, restRoleCache, ac, authDomain.getBackend(), restAuthorizers);

            if(authenticatedUser == null) {
                if (isDebugEnabled) {
                    log.debug("Cannot authenticate rest user {} (or add roles) with authdomain {}/{} of {}, try next", ac.getUsername(), authDomain.getBackend().getType(), authDomain.getOrder(), restAuthDomains);
                }
                for (AuthFailureListener authFailureListener : this.authBackendFailureListeners.get(authDomain.getBackend().getClass().getName())) {
                    authFailureListener.onAuthFailure(
                            (request.getHttpChannel().getRemoteAddress() instanceof InetSocketAddress) ? ((InetSocketAddress) request.getHttpChannel().getRemoteAddress()).getAddress()
                                    : null,
                            ac, request);
                }
                continue;
            }

            if(adminDns.isAdmin(authenticatedUser)) {
                log.error("Cannot authenticate rest user because admin user is not permitted to login via HTTP");
                auditLog.logFailedLogin(authenticatedUser.getName(), true, null, request);
                channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN,
                        "Cannot authenticate user because admin user is not permitted to login via HTTP"));
                return false;
            }

            final String tenant = Utils.coalesce(request.header("securitytenant"), request.header("security_tenant"));

            if (isDebugEnabled) {
                log.debug("Rest user '{}' is authenticated", authenticatedUser);
                log.debug("securitytenant '{}'", tenant);
            }

            authenticatedUser.setRequestedTenant(tenant);
            authenticated = true;
            break;
        }//end looping auth domains

        if(authenticated) {
            final User impersonatedUser = impersonate(request, authenticatedUser);
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, impersonatedUser==null?authenticatedUser:impersonatedUser);
            auditLog.logSucceededLogin((impersonatedUser == null ? authenticatedUser : impersonatedUser).getName(), false,
                    authenticatedUser.getName(), request);
        } else {
            if (isDebugEnabled) {
                log.debug("User still not authenticated after checking {} auth domains", restAuthDomains.size());
            }

            if(authCredenetials == null && anonymousAuthEnabled) {
            	threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, User.ANONYMOUS);
            	auditLog.logSucceededLogin(User.ANONYMOUS.getName(), false, null, request);
                if (isDebugEnabled) {
                    log.debug("Anonymous User is authenticated");
                }
                return true;
            }

            if(firstChallengingHttpAuthenticator != null) {

                if (isDebugEnabled) {
                    log.debug("Rerequest with {}", firstChallengingHttpAuthenticator.getClass());
                }

                if(firstChallengingHttpAuthenticator.reRequestAuthentication(channel, null)) {
                    if (isDebugEnabled) {
                        log.debug("Rerequest {} failed", firstChallengingHttpAuthenticator.getClass());
                    }

                    log.warn("Authentication finally failed for {} from {}", authCredenetials == null ? null:authCredenetials.getUsername(), remoteAddress);
                    auditLog.logFailedLogin(authCredenetials == null ? null:authCredenetials.getUsername(), false, null, request);
                    return false;
                }
            }

            log.warn("Authentication finally failed for {} from {}", authCredenetials == null ? null : authCredenetials.getUsername(),
                    remoteAddress);
            auditLog.logFailedLogin(authCredenetials == null ? null:authCredenetials.getUsername(), false, null, request);

            notifyIpAuthFailureListeners(request, authCredenetials);

            channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED, "Authentication finally failed"));
            return false;
        }

        return authenticated;
    }

    private void notifyIpAuthFailureListeners(RestRequest request, AuthCredentials authCredentials) {
        notifyIpAuthFailureListeners(
                (request.getHttpChannel().getRemoteAddress() instanceof InetSocketAddress) ? ((InetSocketAddress) request.getHttpChannel().getRemoteAddress()).getAddress() : null,
                authCredentials, request);
    }

    private void notifyIpAuthFailureListeners(InetAddress remoteAddress, AuthCredentials authCredentials, Object request) {
        for (AuthFailureListener authFailureListener : this.ipAuthFailureListeners) {
            authFailureListener.onAuthFailure(remoteAddress, authCredentials, request);
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
    private User checkExistsAndAuthz(final Cache<String, User> cache, final User user, final AuthenticationBackend authenticationBackend,
                                     final Set<AuthorizationBackend> authorizers) {
        if(user == null) {
            return null;
        }

        final boolean isDebugEnabled = log.isDebugEnabled();
        final boolean isTraceEnabled = log.isTraceEnabled();

        try {
            return cache.get(user.getName(), new Callable<User>() { //no cache miss in case of noop
                @Override
                public User call() throws Exception {
                    if (isTraceEnabled) {
                        log.trace("Credentials for user {} not cached, return from {} backend directly", user.getName(), authenticationBackend.getType());
                    }
                    if(authenticationBackend.exists(user)) {
                        authz(user, null, authorizers); //no role cache because no miss here in case of noop
                        return user;
                    }

                    if (isDebugEnabled) {
                        log.debug("User {} does not exist in {}", user.getName(), authenticationBackend.getType());
                    }
                    return null;
                }
            });
        } catch (Exception e) {
            if (isDebugEnabled) {
                log.debug("Can not check and authorize {} due to ", user.getName(), e);
            }
            return null;
        }
    }
    private void authz(User authenticatedUser, Cache<User, Set<String>> roleCache, final Set<AuthorizationBackend> authorizers) {

        if(authenticatedUser == null) {
            return;
        }

        if(roleCache != null) {

            final Set<String> cachedBackendRoles = roleCache.getIfPresent(authenticatedUser);

            if(cachedBackendRoles != null) {
                authenticatedUser.addRoles(new HashSet<String>(cachedBackendRoles));
                return;
            }
        }

        if(authorizers == null || authorizers.isEmpty()) {
            return;
        }

        final boolean isTraceEnabled = log.isTraceEnabled();
        for (final AuthorizationBackend ab : authorizers) {
            try {
                if (isTraceEnabled) {
                    log.trace("Backend roles for {} not cached, return from {} backend directly", authenticatedUser.getName(), ab.getType());
                }
                ab.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName()));
            } catch (Exception e) {
                log.error("Cannot retrieve roles for {} from {} due to {}", authenticatedUser, ab.getType(), e.toString(), e);
            }
        }

        if(roleCache != null) {
            roleCache.put(authenticatedUser, new HashSet<String>(authenticatedUser.getRoles()));
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
    private User authcz(final Cache<AuthCredentials, User> cache, Cache<User, Set<String>> roleCache, final AuthCredentials ac,
                        final AuthenticationBackend authBackend, final Set<AuthorizationBackend> authorizers) {
        if(ac == null) {
            return null;
        }
        try {
            
            //noop backend configured and no authorizers
            //that mean authc and authz was completely done via HTTP (like JWT or PKI)
            if(authBackend.getClass() == NoOpAuthenticationBackend.class && authorizers.isEmpty()) {
                //no cache
                return authBackend.authenticate(ac);
            }

            return cache.get(ac, new Callable<User>() {
                @Override
                public User call() throws Exception {
                    if (log.isTraceEnabled()) {
                        log.trace("Credentials for user {} not cached, return from {} backend directly", ac.getUsername(), authBackend.getType());
                    }
                    final User authenticatedUser = authBackend.authenticate(ac);
                    authz(authenticatedUser, roleCache, authorizers);
                    return authenticatedUser;
                }
            });
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Can not authenticate {} due to exception", ac.getUsername(), e);
            }
            return null;
        } finally {
            ac.clearSecrets();
        }
    }

    private User impersonate(final TransportRequest tr, final User origPKIuser) throws OpenSearchSecurityException {

        final String impersonatedUser = threadPool.getThreadContext().getHeader("opendistro_security_impersonate_as");

        if(Strings.isNullOrEmpty(impersonatedUser)) {
            return null; //nothing to do
        }

        if (!isInitialized()) {
            throw new OpenSearchSecurityException("Could not check for impersonation because OpenSearch Security is not yet initialized");
        }

        if (origPKIuser == null) {
            throw new OpenSearchSecurityException("no original PKI user found");
        }

        User aU = origPKIuser;

        if (adminDns.isAdminDN(impersonatedUser)) {
            throw new OpenSearchSecurityException(
                    "'" + origPKIuser.getName() + "' is not allowed to impersonate as an adminuser  '" + impersonatedUser + "'");
        }

        try {
            if (impersonatedUser != null && !adminDns.isTransportImpersonationAllowed(new LdapName(origPKIuser.getName()), impersonatedUser)) {
                throw new OpenSearchSecurityException(
                        "'"+origPKIuser.getName() + "' is not allowed to impersonate as '" + impersonatedUser+"'");
            } else if (impersonatedUser != null) {
                final boolean isDebugEnabled = log.isDebugEnabled();
                //loop over all transport auth domains
                for (final AuthDomain authDomain : transportAuthDomains) {
                    final AuthenticationBackend authenticationBackend = authDomain.getBackend();
                    final User impersonatedUserObject = checkExistsAndAuthz(transportImpersonationCache, new User(impersonatedUser),
                            authenticationBackend, transportAuthorizers);

                    if (impersonatedUserObject == null) {
                        log.debug(
                                "Unable to impersonate transport user from '{}' to '{}' because the impersonated user does not exists in {}, try next ...",
                                origPKIuser.getName(), impersonatedUser, authenticationBackend.getType());
                        continue;
                    }

                    if (isDebugEnabled) {
                        log.debug("Impersonate transport user from '{}' to '{}'", origPKIuser.getName(), impersonatedUser);
                    }
                    return impersonatedUserObject;
                }

                log.debug("Unable to impersonate transport user from '{}' to '{}' because the impersonated user does not exists",
                        origPKIuser.getName(), impersonatedUser);
                throw new OpenSearchSecurityException("No such transport user: " + impersonatedUser, RestStatus.FORBIDDEN);
            }
        } catch (final InvalidNameException e1) {
            throw new OpenSearchSecurityException("PKI does not have a valid name ('" + origPKIuser.getName() + "'), should never happen", e1);
        }

        return aU;
    }

    private User impersonate(final RestRequest request, final User originalUser) throws OpenSearchSecurityException {

        final String impersonatedUserHeader = request.header("opendistro_security_impersonate_as");

        if (Strings.isNullOrEmpty(impersonatedUserHeader) || originalUser == null) {
            return null; // nothing to do
        }

        if (!isInitialized()) {
            throw new OpenSearchSecurityException("Could not check for impersonation because OpenSearch Security is not yet initialized");
        }

        if (adminDns.isAdminDN(impersonatedUserHeader)) {
            throw new OpenSearchSecurityException("It is not allowed to impersonate as an adminuser  '" + impersonatedUserHeader + "'",
                    RestStatus.FORBIDDEN);
        }

        if (!adminDns.isRestImpersonationAllowed(originalUser.getName(), impersonatedUserHeader)) {
            throw new OpenSearchSecurityException(
                    "'" + originalUser.getName() + "' is not allowed to impersonate as '" + impersonatedUserHeader + "'", RestStatus.FORBIDDEN);
        } else {
            final boolean isDebugEnabled = log.isDebugEnabled();
            //loop over all http/rest auth domains
            for (final AuthDomain authDomain: restAuthDomains) {
                final AuthenticationBackend authenticationBackend = authDomain.getBackend();
                final User impersonatedUser = checkExistsAndAuthz(restImpersonationCache, new User(impersonatedUserHeader), authenticationBackend,
                        restAuthorizers);

                if(impersonatedUser == null) {
                    log.debug("Unable to impersonate rest user from '{}' to '{}' because the impersonated user does not exists in {}, try next ...",
                            originalUser.getName(), impersonatedUserHeader, authenticationBackend.getType());
                    continue;
                }

                if (isDebugEnabled) {
                    log.debug("Impersonate rest user from '{}' to '{}'", originalUser.toStringWithAttributes(), impersonatedUser.toStringWithAttributes());
                }
                
                impersonatedUser.setRequestedTenant(originalUser.getRequestedTenant());
                return impersonatedUser;
            }

            log.debug("Unable to impersonate rest user from '{}' to '{}' because the impersonated user does not exists", originalUser.getName(),
                    impersonatedUserHeader);
            throw new OpenSearchSecurityException("No such user:" + impersonatedUserHeader, RestStatus.FORBIDDEN);
        }

    }

    private User resolveTransportUsernameAttribute(User pkiUser) {
    	//#547
        if(transportUsernameAttribute != null && !transportUsernameAttribute.isEmpty()) {
	    	try {
				final LdapName sslPrincipalAsLdapName = new LdapName(pkiUser.getName());
				for(final Rdn rdn: sslPrincipalAsLdapName.getRdns()) {
					if(rdn.getType().equals(transportUsernameAttribute)) {
						return new User((String) rdn.getValue());
					}
				}
			} catch (InvalidNameException e) {
				//cannot happen
			}
        }
        
        return pkiUser;
    }

    private boolean isBlocked(InetAddress address) {
        if (this.ipClientBlockRegistries == null || this.ipClientBlockRegistries.isEmpty()) {
            return false;
        }

        for (ClientBlockRegistry<InetAddress> clientBlockRegistry : ipClientBlockRegistries) {
            if (clientBlockRegistry.isBlocked(address)) {
                return true;
            }
        }

        return false;
    }

    private boolean isBlocked(String authBackend, String userName) {

        if (this.authBackendClientBlockRegistries == null) {
            return false;
        }

        Collection<ClientBlockRegistry<String>> clientBlockRegistries = this.authBackendClientBlockRegistries.get(authBackend);

        if (clientBlockRegistries.isEmpty()) {
            return false;
        }

        for (ClientBlockRegistry<String> clientBlockRegistry : clientBlockRegistries) {
            if (clientBlockRegistry.isBlocked(userName)) {
                return true;
            }
        }

        return false;
    }

}
