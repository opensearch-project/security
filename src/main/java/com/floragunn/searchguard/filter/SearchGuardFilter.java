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

package com.floragunn.searchguard.filter;

import java.net.InetSocketAddress;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.LogHelper;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;

public class SearchGuardFilter implements ActionFilter {

    // "internal:*",
    // "indices:monitor/*",
    // "cluster:monitor/*",
    // "cluster:admin/reroute",
    // "indices:admin/mapping/put"

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Provider<PrivilegesEvaluator> evalp;
    private final Settings settings;
    private final AdminDNs adminDns;

    @Inject
    public SearchGuardFilter(final Settings settings, final Provider<PrivilegesEvaluator> evalp, final AdminDNs adminDns,
            final Provider<BackendRegistry> backendRegistry) {
        this.settings = settings;
        this.evalp = evalp;
        this.adminDns = adminDns;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public void apply(final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        //System.out.println(":-- "+action);
        
       
        
        
        if (log.isTraceEnabled()) {
            log.trace("Action {} from {}/{}", action, request.remoteAddress(), listener.getClass().getSimpleName());
            log.trace("Context {}", request.getContext());
            log.trace("Header {}", request.getHeaders());

        }
        
        
        if (action.startsWith("internal:")) {
            if (log.isTraceEnabled()) {
                log.trace("INTERNAL:");
            }

            chain.proceed(action, request, listener);
            return;
        }

        LogHelper.logUserTrace("--> Action {} from {}/{}", action, request.remoteAddress(), listener.getClass().getSimpleName());
        LogHelper.logUserTrace("--> Context {}", request.getContext());
        LogHelper.logUserTrace("--> Header {}", request.getHeaders());

        // user fortführen ..... in context etc

        final TransportAddress transportAddressFromHeader = getRemoteAddressFromHeader(request);

        if (transportAddressFromHeader != null) {
            LogHelper.logUserTrace("--> Put address {} in context (from header)", transportAddressFromHeader);
            request.putInContext("_sg_remote_address", transportAddressFromHeader);
        } else {
            if (request.getFromContext("_sg_remote_address") == null) {
                LogHelper.logUserTrace("--> Put address {} in context (initial)", request.remoteAddress());
                request.putInContext("_sg_remote_address", request.remoteAddress());
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("remote address: {}", request.getFromContext("_sg_remote_address"));
        }

        if (isIntraNodeRequest(request)) {
            if (log.isTraceEnabled()) {
                log.trace("INTRANODE_REQUEST");
            }

            chain.proceed(action, request, listener);
            return;
        }

        if (action.equalsIgnoreCase("cluster:admin/searchguard/config/update")) {

            if (log.isTraceEnabled()) {
                log.trace("CONFIG UPDATE");
            }

            chain.proceed(action, request, listener);
            return;

        }

        if (isUserFromHeaderOrContextAdmin(adminDns, request)) {
            if (log.isTraceEnabled()) {
                log.trace("Admin user request, allow all");
            }
            chain.proceed(action, request, listener);
            return;
        }

        /*final String transportPrincipal = (String) request.getFromContext("_sg_ssl_transport_principal");

            if (transportPrincipal != null && adminDns.isAdmin(transportPrincipal)) {

                if (log.isTraceEnabled()) {
                    log.trace("Admin user request, allow all");
                }
                chain.proceed(action, request, listener);
                return;
            }
         */

        User user = getUserFromHeader(request);

        if (user != null) {
            if (log.isTraceEnabled()) {
                log.trace("User {} already authenticated from another node", user.getName());
            }
        } else {

            user = request.getFromContext("_sg_user");
        }

        if (user == null || isInterClusterRequest(request)) {

            /* if (user == null && request.getFromContext("_sg_ssl_transport_intercluster_request") == Boolean.TRUE) {

                 final String transportPrincipalAsBase64 =  OBSOLETE request.getHeader("_sg_ssl_transport_principal_internode");

                 if (!Strings.isNullOrEmpty(transportPrincipalAsBase64)) {
                     final String interNodeTransportPrincipal = (String) Base64Helper.deserializeObject(transportPrincipalAsBase64);


                         if (interNodeTransportPrincipal != null && adminDns.isAdmin(interNodeTransportPrincipal)) {

                             if (log.isTraceEnabled()) {
                                 log.trace("Admin user request, allow all");
                             }
                             request.putInContext("_sg_ssl_transport_principal", interNodeTransportPrincipal);
                             chain.proceed(action, request, listener);
                             return;
                         }
                     
                 }

                 // get user from request header
                 final String userObjectAsBase64 = request.getHeader("_sg_user_header");

                 if (!Strings.isNullOrEmpty(userObjectAsBase64)) {
                     user = (User) Base64Helper.deserializeObject(userObjectAsBase64);
                     request.putInContext("_sg_user", user);
                     if (log.isTraceEnabled()) {
                         log.trace("Got user from intercluster request header: {}", user.getName());
                     }
                 }
             }
            */
            //@formatter:off
            if (action.startsWith("internal:gateway")
                    ||
                    action.startsWith("cluster:monitor/")
                    || action.startsWith("indices:monitor/")
                    || action.startsWith("cluster:admin/reroute")
                    || action.startsWith("indices:admin/mapping/put")) {

                if (log.isTraceEnabled()) {
                    log.trace("No user, will allow only standard discovery and monitoring actions");
                }

                chain.proceed(action, request, listener);
                return;
            } else if(user == null){
                listener.onFailure(new ElasticsearchException("unauthenticated request "+action +" for user "+user, RestStatus.FORBIDDEN));
            }
            //@formatter:on

        }

        // PKI
        /*if (user == null && transportPrincipal != null) {
            user = new User(transportPrincipal);
            request.putInContext("_sg_user", user);

            if (log.isDebugEnabled()) {
                log.debug("PKI authenticated user {}", transportPrincipal);
            }
        }*/

        //System.out.println("User:"+ user);
        
        final PrivilegesEvaluator eval = evalp.get();

        if (!eval.isInitialized()) {
            listener.onFailure(new ElasticsearchException("Search Guard not initialized (SG11) for " + action, RestStatus.SERVICE_UNAVAILABLE));
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Evaluate permissions for user: {}", user.getName());
        }

        if (eval.evaluate(user, action, request)) {
            chain.proceed(action, request, listener);
            return;
        } else {
            listener.onFailure(new ElasticsearchSecurityException("no permissions for " + action, RestStatus.FORBIDDEN));
            return;
        }

        // log.error("unauthenticated request {} from {}", action,
        // request.getFromContext("_sg_remote_address"));
        // listener.onFailure(new
        // ElasticsearchException("unauthenticated request"));
        // return;

    }

    @Override
    public void apply(final String action, final ActionResponse response, final ActionListener listener, final ActionFilterChain chain) {
        chain.proceed(action, response, listener);
    }

    /**
     * 
     * @param request
     * @return true if request comes from a node with a server certificate
     */
    private static boolean isInterClusterRequest(final ActionRequest request) {
        return request.getFromContext("_sg_ssl_transport_intercluster_request") == Boolean.TRUE;
    }

    /**
     * 
     * @param request
     * @return the User from header if request is InterClusterRequest and
     *         contains a user header, otherwise null
     */
    private static User getUserFromHeader(final ActionRequest request) {
        if (isInterClusterRequest(request)) {
            final String userObjectAsBase64 = request.getHeader("_sg_user_header");

            if (!Strings.isNullOrEmpty(userObjectAsBase64)) {
                return (User) Base64Helper.deserializeObject(userObjectAsBase64);
                /*request.putInContext("_sg_user", user);
                if (log.isTraceEnabled()) {
                    log.trace("Got user from intercluster request header: {}", user.getName());
                }*/
            }
        }

        return null;
    }

    /**
     * 
     * @param request
     * @return the User from header if request is InterClusterRequest and
     *         contains a user header, otherwise null
     */
    private static boolean isUserFromHeaderOrContextAdmin(final AdminDNs adminDns, final ActionRequest request) {

        final String transportPrincipal = (String) request.getFromContext("_sg_ssl_transport_principal");

        if (transportPrincipal != null && adminDns.isAdmin(transportPrincipal)) {
            return true;
        }

        final User user = getUserFromHeader(request);

        if (user == null) {
            return false;
        }

        return adminDns.isAdmin(user.getName());
    }

    /**
     * @param request
     * @return the TransportAddress from header if request is
     *         InterClusterRequest and contains a user header, otherwise null
     */
    private static TransportAddress getRemoteAddressFromHeader(final ActionRequest request) {
        if (isInterClusterRequest(request)) {
            final String addressObjectAsBase64 = request.getHeader("_sg_remote_address_header");

            if (!Strings.isNullOrEmpty(addressObjectAsBase64)) {
                return new InetSocketTransportAddress((InetSocketAddress) Base64Helper.deserializeObject(addressObjectAsBase64));
                /*request.putInContext("_sg_user", user);
                if (log.isTraceEnabled()) {
                    log.trace("Got user from intercluster request header: {}", user.getName());
                }*/
            }
        }

        return null;
    }

    /**
     * @param request
     * @return true if the sender is our own node
     */
    private static boolean isIntraNodeRequest(final ActionRequest request) {
        if (request.getFromContext("_sg_internal_request") == Boolean.TRUE) {
            return true;
        }

        return false;
    }

}
