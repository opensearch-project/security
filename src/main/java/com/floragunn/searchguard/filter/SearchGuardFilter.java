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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

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

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Provider<PrivilegesEvaluator> evalp;
    private final Settings settings;
    private final AdminDNs adminDns;
    private Provider<DlsFlsRequestValve> dlsFlsValve;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    
    @Inject
    public SearchGuardFilter(final Settings settings, final Provider<PrivilegesEvaluator> evalp, final AdminDNs adminDns,
            final Provider<BackendRegistry> backendRegistry, Provider<DlsFlsRequestValve> dlsFlsValve, AuditLog auditLog, ThreadPool threadPool) {
        this.settings = settings;
        this.evalp = evalp;
        this.adminDns = adminDns;
        this.dlsFlsValve = dlsFlsValve;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public void apply(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        // - types test
        // - remote address test
        
        User user = threadContext.getTransient(ConfigConstants.SG_USER);
        
        if(user == null && request.remoteAddress() == null) {
            user = User.SG_INTERNAL;
        }
        
        if(isUserAdmin(user, adminDns) 
                || HeaderHelper.isInterClusterRequest(threadContext) 
                || "true".equals(HeaderHelper.getSafeFromHeader(threadContext, ConfigConstants.SG_CONF_REQUEST_HEADER))){
            
            if(!dlsFlsValve.get().invoke(request, listener, threadContext)) {
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
                    //|| action.startsWith("internal:indices/admin/upgrade")
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
            listener.onFailure(new ElasticsearchSecurityException("Search Guard not initialized (SG11) for " 
            + action+". See https://github.com/floragunncom/search-guard-docs/blob/master/sgadmin.md", RestStatus.SERVICE_UNAVAILABLE));
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Evaluate permissions for user: {}", user.getName());
        }

        if (eval.evaluate(user, action, request)) {
            auditLog.logAuthenticatedRequest(request, action);
            if(!dlsFlsValve.get().invoke(request, listener, threadContext)) {
                return;
            }
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
    
    private static boolean isUserAdmin(User user, final AdminDNs adminDns) {
        if (user != null && adminDns.isAdmin(user.getName())) {
            return true;
        }

        return false;
    }

}
