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
import java.util.Iterator;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

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
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.ConfigChangeListener;
import com.floragunn.searchguard.filter.SearchGuardRestFilter;
import com.floragunn.searchguard.http.XFFResolver;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class BackendRegistry implements ConfigChangeListener {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final SortedSet<AuthDomain> authDomains = new TreeSet<AuthDomain>();
    private volatile boolean initialized;
    private final ClusterService cse;
    private final TransportConfigUpdateAction tcua;
    private final AdminDNs adminDns;
    private final XFFResolver xffResolver;

    //TODO multiple auth domains
    
    @Inject
    public BackendRegistry(final RestController controller, final TransportConfigUpdateAction tcua, final ClusterService cse,
            final AdminDNs adminDns, final XFFResolver xffResolver) {
        tcua.addConfigChangeListener("config", this);
        controller.registerFilter(new SearchGuardRestFilter(this));
        this.cse = cse;
        this.tcua = tcua;
        this.adminDns = adminDns;
        this.xffResolver = xffResolver;
    }

    private <T> T newInstance(final String clazz, final Settings settings) throws ClassNotFoundException, NoSuchMethodException,
            SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
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

        final Map<String, Settings> dyn = settings.getGroups("searchguard.dynamic.authcz");

        for (final String ad : dyn.keySet()) {
            final Settings ads = dyn.get(ad);
            if (ads.getAsBoolean("enabled", true)) {
                try {
                    final AuthenticationBackend authenticationBackend = newInstance(
                            ads.get("authentication_backend.type", "com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend"),
                            ads);
                    final AuthorizationBackend authorizationBackend = newInstance(
                            ads.get("authorization_backend.type", "com.floragunn.searchguard.auth.internal.NoOpAuthorizationBackend"),
                            ads);
                    final HTTPAuthenticator httpAuthenticator = newInstance(
                            ads.get("http_authenticator.type", "com.floragunn.searchguard.http.HTTPBasicAuthenticator"),
                            ads);
                    authDomains.add(new AuthDomain(authenticationBackend, authorizationBackend, httpAuthenticator,
                            ads.getAsInt("order", 0), ads.getAsBoolean("roles_only", false)));
                } catch (final Exception e) {
                    log.error("Unable to initialize auth domain {} due to {}", ad, e.toString());
                }

            }

        }

        initialized = true;
    }

    @Override
    public void validate(final String event, final Settings settings) throws ElasticsearchSecurityException {
        // TODO Auto-generated method stub

    }

    /**
     * 
     * @param request
     * @param channel
     * @return The authenticated user, null means another roundtrip
     * @throws ElasticsearchSecurityException
     */
    public boolean authenticate(final RestRequest request, final RestChannel channel) throws ElasticsearchSecurityException {

        if (!isInitialized()) {
            log.warn("Not yet initialized");
            channel.sendResponse(new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, "Search Guard not initialized (SG11)"));
            return false;
        }

        request.putInContext("_sg_remote_address", xffResolver.resolve(request));

        User authenticatedUser = null;
        while (authenticatedUser == null) {
            final AuthDomain authDomain = new TreeSet<AuthDomain>(authDomains).first();// (AuthDomain)
                                                                                       // iterator.next();
            log.debug("Try to authenticate with authDomain {}, authenticatedUser so far is {}", authDomain.getOrder(), authenticatedUser);

            AuthCredentials ac = null;
            if (authenticatedUser == null) {

                log.debug("Challenge client with {}", authDomain.getHttpAuthenticator().getClass());

                ac = authDomain.getHttpAuthenticator().authenticate(request, channel);

                log.debug("Authentication token is: {}", ac);

                if (ac == null) {
                    // roundtrip
                    // count?
                    return false;
                }
            }

            try {
                log.debug("Try to authenticate token with {}", authDomain.getBackend().getClass());
                authenticatedUser = authDomain.getBackend().authenticate(ac);
                authenticatedUser.addRoles(ac.getBackendRoles());
                log.debug("User '{}' is authenticated", authenticatedUser);
                request.putInContext("_sg_user", authenticatedUser);
                authDomain.getAbackend().fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(),(Object) null));
                return true;

            } catch (final ElasticsearchSecurityException e) {
                log.info("Cannot authenticate user with ad {} due to {}, try next", authDomain.getOrder(), e.toString());
                authDomain.getHttpAuthenticator().requestAuthentication(channel);
                return false;
            }
            // TODO check if anonymous access is allowed
        }
        return true;
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

        for (final Iterator iterator = new TreeSet<AuthDomain>(authDomains).iterator(); iterator.hasNext();) {

            final AuthDomain authDomain = (AuthDomain) iterator.next();
            if (!authDomain.isRolesOnly()) {
                // continue;
            }

            try {
                authDomain.getAbackend().fillRoles(aU, new AuthCredentials(aU.getName(), (Object) null));
            } catch (final ElasticsearchSecurityException e) {
                log.info("Cannot add roles for user with ad {}, try next", authDomain.getOrder());
                continue;
            }
        }

        return true;
    }

}
