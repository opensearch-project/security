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
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.tasks.Task;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.DlsFlsRequestValve;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;

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
    private Provider<DlsFlsRequestValve> dlsFlsValve;
    private final AuditLog auditLog;

    @Inject
    public SearchGuardFilter(final Settings settings, final Provider<PrivilegesEvaluator> evalp, final AdminDNs adminDns,
            final Provider<BackendRegistry> backendRegistry, Provider<DlsFlsRequestValve> dlsFlsValve, AuditLog auditLog) {
        this.settings = settings;
        this.evalp = evalp;
        this.adminDns = adminDns;
        this.dlsFlsValve = dlsFlsValve;
        this.auditLog = auditLog;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public void apply(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        // - types testen
        // - remote address testn
        
        if (log.isTraceEnabled()) {
            log.trace("Action {} from {}/{}", action, request.remoteAddress(), listener.getClass().getSimpleName());
            log.trace("Context {}", request.getContext());
            log.trace("Header {}", request.getHeaders());

        }
        
        User user = request.getFromContext(ConfigConstants.SG_USER);
        
        if(user == null && request.remoteAddress() == null) {
            user = User.SG_INTERNAL;
        }

        //LogHelper.logUserTrace("--> Action {} from {}/{}", action, request.remoteAddress(), listener.getClass().getSimpleName());
        //LogHelper.logUserTrace("--> Context {}", request.getContext());
        //LogHelper.logUserTrace("--> Header {}", request.getHeaders());

        if (log.isTraceEnabled()) {
            log.trace("remote address: {}", request.getFromContext(ConfigConstants.SG_REMOTE_ADDRESS));
        }

        
        
        if(isUserAdmin(user, adminDns) 
                || isInterClusterRequest(request) 
                || "true".equals(HeaderHelper.getSafeFromHeader(request, ConfigConstants.SG_CONF_REQUEST_HEADER))){
            
            if(!dlsFlsValve.get().invoke(request, listener)) {
                return;
            }
            
            chain.proceed(task, action, request, listener);
            return;
        }

        if(User.SG_INTERNAL.equals(user)) {
        
            //@formatter:off
            if (       action.startsWith("internal:gateway")
                    || action.startsWith("cluster:monitor/")
                    || action.startsWith("indices:monitor/")
                    || action.startsWith("cluster:admin/reroute")
                    || action.startsWith("indices:admin/mapping/put")
                    || action.startsWith("internal:cluster/nodes/indices/shard/store")
                    || action.startsWith("indices:admin/exists")
                    || action.startsWith("internal:indices/admin/upgrade")
               ) {

                if (log.isTraceEnabled()) {
                    log.trace("No user, will allow only standard discovery and monitoring actions");
                }

                chain.proceed(task, action, request, listener);
                return;
            } else {
                log.debug("unauthenticated request {} for user {}", action, user);
                auditLog.logFailedLogin(user.getName(), request);
                listener.onFailure(new ElasticsearchSecurityException("unauthenticated request "+action +" for user "+user, RestStatus.FORBIDDEN));
                return;
            }
            //@formatter:on
        }
        
        final PrivilegesEvaluator eval = evalp.get();

        if (!eval.isInitialized()) {
            log.error("Search Guard not initialized (SG11) for {}", action);
            listener.onFailure(new ElasticsearchSecurityException("Search Guard not initialized (SG11) for " + action, RestStatus.SERVICE_UNAVAILABLE));
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Evaluate permissions for user: {}", user.getName());
        }

        if (eval.evaluate(user, action, request)) {
            if(!dlsFlsValve.get().invoke(request, listener)) {
                return;
            }
            auditLog.logAuthenticatedRequest(request, action);
            chain.proceed(task, action, request, listener);
            return;
        } else {
            auditLog.logMissingPrivileges(action, request);
            log.debug("no permissions for {}", action);
            listener.onFailure(new ElasticsearchSecurityException("no permissions for " + action, RestStatus.FORBIDDEN));
            return;
        }
        
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
        return request.getFromContext(ConfigConstants.SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST) == Boolean.TRUE;
    }

    /**
     * 
     * @param request
     * @return the User from header if request is InterClusterRequest and
     *         contains a user header, otherwise null
     */
    
    private static boolean isUserAdmin(User user, final AdminDNs adminDns) {
        if (user != null && adminDns.isAdmin(user.getName())) {
            return true;
        }

        return false;
    }

}
