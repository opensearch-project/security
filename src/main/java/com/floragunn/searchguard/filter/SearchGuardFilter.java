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

import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteAction;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.action.update.UpdateAction;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.action.licenseinfo.LicenseInfoAction;
import com.floragunn.searchguard.action.whoami.WhoAmIAction;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.AuditLog.Origin;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.DlsFlsRequestValve;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;

public class SearchGuardFilter implements ActionFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Logger actionTrace = LogManager.getLogger("sg_action_trace");
    private final PrivilegesEvaluator evalp;
    private final Settings settings;
    private final AdminDNs adminDns;
    private DlsFlsRequestValve dlsFlsValve;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final ClusterService cs;
    
    public SearchGuardFilter(final Settings settings, final PrivilegesEvaluator evalp, final AdminDNs adminDns,
            DlsFlsRequestValve dlsFlsValve, AuditLog auditLog, ThreadPool threadPool, ClusterService cs) {
        this.settings = settings;
        this.evalp = evalp;
        this.adminDns = adminDns;
        this.dlsFlsValve = dlsFlsValve;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
        this.cs = cs;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(Task task, final String action, Request request,
            ActionListener<Response> listener, ActionFilterChain<Request, Response> chain) {
        try {
            
            if(threadContext.getTransient(ConfigConstants.SG_ORIGIN) == null) {
                threadContext.putTransient(ConfigConstants.SG_ORIGIN, Origin.LOCAL.toString());
            }
            
            final User user = threadContext.getTransient(ConfigConstants.SG_USER);
            final boolean userIsAdmin = isUserAdmin(user, adminDns);
            final boolean interClusterRequest = HeaderHelper.isInterClusterRequest(threadContext);
            //final boolean trustedClusterRequest = HeaderHelper.isTrustedClusterRequest(threadContext);
            final boolean conRequest = "true".equals(HeaderHelper.getSafeFromHeader(threadContext, ConfigConstants.SG_CONF_REQUEST_HEADER));
            final boolean passThroughRequest = action.equals(LicenseInfoAction.NAME) 
                    || action.startsWith("indices:admin/seq_no")
                    || action.equals(WhoAmIAction.NAME);
            
            final boolean internalRequest = 
                    (interClusterRequest || HeaderHelper.isDirectRequest(threadContext))
                    && action.startsWith("internal:") 
                    && !action.startsWith("internal:transport/proxy");
            
            if(actionTrace.isTraceEnabled()) {
                actionTrace.trace("Node "+cs.localNode().getName()+" -> "+action+": userIsAdmin="+userIsAdmin+"/conRequest="+conRequest+"/internalRequest="+internalRequest
                        +"origin="+threadContext.getTransient(ConfigConstants.SG_ORIGIN)+"/directRequest="+HeaderHelper.isDirectRequest(threadContext)+"/remoteAddress="+request.remoteAddress());
            }
            
            /*if(log.isTraceEnabled()) {
                log.trace("Node "+cs.localNode().getName()+" -> "+action+": userIsAdmin="+userIsAdmin+"/conRequest="+conRequest+"/internalRequest="+internalRequest
                        +"origin="+threadContext.getTransient(ConfigConstants.SG_ORIGIN)+"/directRequest="+HeaderHelper.isDirectRequest(threadContext)+"/remoteAddress="+request.remoteAddress());
            }*/
            
            if(userIsAdmin 
                    || conRequest 
                    || internalRequest 
                    || passThroughRequest){
    
                if(userIsAdmin && !conRequest && !internalRequest && !passThroughRequest) {
                    auditLog.logGrantedPrivileges(action, request, task);
                }
    
                if(!dlsFlsValve.invoke(request, listener, threadContext)) {
                    return;
                }
                chain.proceed(task, action, request, listener);
                return;
            }


            if(Origin.LOCAL.toString().equals((String)threadContext.getTransient(ConfigConstants.SG_ORIGIN)) 
                    && HeaderHelper.isDirectRequest(threadContext)
                    && request.remoteAddress() == null
                    && !action.contains("[")) {
               
                //TODO SG6 CONFIG OPTION TO DENY THIS
   
                //"indices:monitor/*", 
                //"cluster:admin/reroute", 
                //"indices:admin/mapping/put"), 
                
                //~"internal:transport/proxy/*"
    
                if(!dlsFlsValve.invoke(request, listener, threadContext)) {
                    return;
                }
                chain.proceed(task, action, request, listener);
                return;
            }
            
            if(user == null) {
                
                if(action.startsWith("cluster:monitor/") || action.startsWith("indices:monitor/stats")) {
                    if(!dlsFlsValve.invoke(request, listener, threadContext)) {
                        return;
                    }
                    chain.proceed(task, action, request, listener);
                    return;
                }

                log.error("No user found for "+ action+" from "+request.remoteAddress()+" "+threadContext.getTransient(ConfigConstants.SG_ORIGIN)+" "+threadContext.getHeaders());
                listener.onFailure(new ElasticsearchSecurityException("No user found for "+action, RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }
           
            final PrivilegesEvaluator eval = evalp;
    
            if (!eval.isInitialized()) {
                log.error("Search Guard not initialized (SG11) for {}", action);
                listener.onFailure(new ElasticsearchSecurityException("Search Guard not initialized (SG11) for " 
                + action+". See https://github.com/floragunncom/search-guard-docs/blob/master/sgadmin.md", RestStatus.SERVICE_UNAVAILABLE));
                return;
            }
    
            if (log.isTraceEnabled()) {
                log.trace("Evaluate permissions for user: {}", user.getName());
            }

            if (eval.evaluate(user, action, request, task)) {
                auditLog.logGrantedPrivileges(action, request, task);
                if(!dlsFlsValve.invoke(request, listener, threadContext)) {
                    return;
                }
                chain.proceed(task, action, request, listener);
                return;
            } else {
                auditLog.logMissingPrivileges(action, request, task);
                log.debug("no permissions for {}", action);
                listener.onFailure(new ElasticsearchSecurityException("no permissions for " + action+" and "+user, RestStatus.FORBIDDEN));
                return;
            }
        } catch (Throwable e) {
            log.error("Unexpected exception "+e, e);
            listener.onFailure(new ElasticsearchSecurityException("Unexpected exception " + action, RestStatus.INTERNAL_SERVER_ERROR));
            return;
        }
    }
    
    private static boolean isUserAdmin(User user, final AdminDNs adminDns) {
        if (user != null && adminDns.isAdmin(user.getName())) {
            return true;
        }

        return false;
    }

}
