/*
 * Copyright 2015-2017 floragunn GmbH
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

import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.DocWriteRequest.OpType;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.close.CloseIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexRequest;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.index.reindex.DeleteByQueryRequest;
import org.elasticsearch.index.reindex.UpdateByQueryRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.action.licenseinfo.LicenseInfoAction;
import com.floragunn.searchguard.action.whoami.WhoAmIAction;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.AuditLog.Origin;
import com.floragunn.searchguard.compliance.ComplianceConfig;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.CompatConfig;
import com.floragunn.searchguard.configuration.DlsFlsRequestValve;
import com.floragunn.searchguard.privileges.PrivilegesEvaluator;
import com.floragunn.searchguard.privileges.PrivilegesEvaluatorResponse;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.support.SourceFieldsContext;
import com.floragunn.searchguard.user.User;

public class SearchGuardFilter implements ActionFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Logger actionTrace = LogManager.getLogger("sg_action_trace");
    private final PrivilegesEvaluator evalp;
    private final AdminDNs adminDns;
    private DlsFlsRequestValve dlsFlsValve;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final ClusterService cs;
    private final ComplianceConfig complianceConfig;
    private final CompatConfig compatConfig;

    public SearchGuardFilter(final PrivilegesEvaluator evalp, final AdminDNs adminDns,
            DlsFlsRequestValve dlsFlsValve, AuditLog auditLog, ThreadPool threadPool, ClusterService cs,
            ComplianceConfig complianceConfig, final CompatConfig compatConfig) {
        this.evalp = evalp;
        this.adminDns = adminDns;
        this.dlsFlsValve = dlsFlsValve;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
        this.cs = cs;
        this.complianceConfig = complianceConfig;
        this.compatConfig = compatConfig;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(Task task, final String action, Request request,
            ActionListener<Response> listener, ActionFilterChain<Request, Response> chain) {
        try (StoredContext ctx = threadContext.newStoredContext(true)){
            org.apache.logging.log4j.ThreadContext.clearAll();
            apply0(task, action, request, listener, chain);
        }
    }
    

    private <Request extends ActionRequest, Response extends ActionResponse> void apply0(Task task, final String action, Request request,
            ActionListener<Response> listener, ActionFilterChain<Request, Response> chain) {
        
        try {

            if(threadContext.getTransient(ConfigConstants.SG_ORIGIN) == null) {
                threadContext.putTransient(ConfigConstants.SG_ORIGIN, Origin.LOCAL.toString());
            }
            
            if(complianceConfig != null && complianceConfig.isEnabled()) {
                attachSourceFieldContext(request);
            }

            final User user = threadContext.getTransient(ConfigConstants.SG_USER);
            final boolean userIsAdmin = isUserAdmin(user, adminDns);
            final boolean interClusterRequest = HeaderHelper.isInterClusterRequest(threadContext);
            final boolean trustedClusterRequest = HeaderHelper.isTrustedClusterRequest(threadContext);
            final boolean confRequest = "true".equals(HeaderHelper.getSafeFromHeader(threadContext, ConfigConstants.SG_CONF_REQUEST_HEADER));
            final boolean passThroughRequest = action.equals(LicenseInfoAction.NAME)
                    || action.startsWith("indices:admin/seq_no")
                    || action.equals(WhoAmIAction.NAME);

            final boolean internalRequest =
                    (interClusterRequest || HeaderHelper.isDirectRequest(threadContext))
                    && action.startsWith("internal:")
                    && !action.startsWith("internal:transport/proxy");

            if (user != null) {
                org.apache.logging.log4j.ThreadContext.put("user", user.getName());    
            }
                        
            if(actionTrace.isTraceEnabled()) {

                String count = "";
                if(request instanceof BulkRequest) {
                    count = ""+((BulkRequest) request).requests().size();
                }

                if(request instanceof MultiGetRequest) {
                    count = ""+((MultiGetRequest) request).getItems().size();
                }

                if(request instanceof MultiSearchRequest) {
                    count = ""+((MultiSearchRequest) request).requests().size();
                }

                actionTrace.trace("Node "+cs.localNode().getName()+" -> "+action+" ("+count+"): userIsAdmin="+userIsAdmin+"/conRequest="+confRequest+"/internalRequest="+internalRequest
                        +"origin="+threadContext.getTransient(ConfigConstants.SG_ORIGIN)+"/directRequest="+HeaderHelper.isDirectRequest(threadContext)+"/remoteAddress="+request.remoteAddress());


                threadContext.putHeader("_sg_trace"+System.currentTimeMillis()+"#"+UUID.randomUUID().toString(), Thread.currentThread().getName()+" FILTER -> "+"Node "+cs.localNode().getName()+" -> "+action+" userIsAdmin="+userIsAdmin+"/conRequest="+confRequest+"/internalRequest="+internalRequest
                        +"origin="+threadContext.getTransient(ConfigConstants.SG_ORIGIN)+"/directRequest="+HeaderHelper.isDirectRequest(threadContext)+"/remoteAddress="+request.remoteAddress()+" "+threadContext.getHeaders().entrySet().stream().filter(p->!p.getKey().startsWith("_sg_trace")).collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue())));


            }


            if(userIsAdmin
                    || confRequest
                    || internalRequest
                    || passThroughRequest){

                if(userIsAdmin && !confRequest && !internalRequest && !passThroughRequest) {
                    auditLog.logGrantedPrivileges(action, request, task);
                }

                chain.proceed(task, action, request, listener);
                return;
            }
            
            
            if(complianceConfig != null && complianceConfig.isEnabled()) {
            
                boolean isImmutable = false;
                
                if(request instanceof BulkShardRequest) {
                    for(BulkItemRequest bsr: ((BulkShardRequest) request).items()) {
                        isImmutable = checkImmutableIndices(bsr.request(), listener);
                        if(isImmutable) {
                            break;
                        }
                    }
                } else {
                    isImmutable = checkImmutableIndices(request, listener);
                }
    
                if(isImmutable) {
                    return;
                }

            }

            if(Origin.LOCAL.toString().equals(threadContext.getTransient(ConfigConstants.SG_ORIGIN))
                    && (interClusterRequest || HeaderHelper.isDirectRequest(threadContext))
                    ) {

                chain.proceed(task, action, request, listener);
                return;
            }

            if(user == null) {

                if(action.startsWith("cluster:monitor/state")) {
                    chain.proceed(task, action, request, listener);
                    return;
                }

                if((interClusterRequest || trustedClusterRequest || request.remoteAddress() == null) && !compatConfig.transportInterClusterAuthEnabled()) {
                    chain.proceed(task, action, request, listener);
                    return;
                }

                log.error("No user found for "+ action+" from "+request.remoteAddress()+" "+threadContext.getTransient(ConfigConstants.SG_ORIGIN)+" via "+threadContext.getTransient(ConfigConstants.SG_CHANNEL_TYPE)+" "+threadContext.getHeaders());
                listener.onFailure(new ElasticsearchSecurityException("No user found for "+action, RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }

            final PrivilegesEvaluator eval = evalp;

            if (!eval.isInitialized()) {
                log.error("Search Guard not initialized (SG11) for {}", action);
                listener.onFailure(new ElasticsearchSecurityException("Search Guard not initialized (SG11) for "
                + action+". See http://docs.search-guard.com/v6/sgadmin", RestStatus.SERVICE_UNAVAILABLE));
                return;
            }

            if (log.isTraceEnabled()) {
                log.trace("Evaluate permissions for user: {}", user.getName());
            }

            final PrivilegesEvaluatorResponse pres = eval.evaluate(user, action, request, task);
            
            if (log.isDebugEnabled()) {
                log.debug(pres);
            }
            
            if (pres.isAllowed()) {
                auditLog.logGrantedPrivileges(action, request, task);
                if(!dlsFlsValve.invoke(request, listener, pres.getAllowedFlsFields(), pres.getMaskedFields(), pres.getQueries())) {
                    return;
                }
                chain.proceed(task, action, request, listener);
                return;
            } else {
                auditLog.logMissingPrivileges(action, request, task);
                log.debug("no permissions for {}", pres.getMissingPrivileges());
                listener.onFailure(new ElasticsearchSecurityException("no permissions for " + pres.getMissingPrivileges()+" and "+user, RestStatus.FORBIDDEN));
                return;
            }
        } catch (Throwable e) {
            log.error("Unexpected exception "+e, e);
            listener.onFailure(new ElasticsearchSecurityException("Unexpected exception " + action, RestStatus.INTERNAL_SERVER_ERROR));
            return;
        }
    }

    private static boolean isUserAdmin(User user, final AdminDNs adminDns) {
        if (user != null && adminDns.isAdmin(user)) {
            return true;
        }

        return false;
    }

    private void attachSourceFieldContext(ActionRequest request) {
        
        if(request instanceof SearchRequest && SourceFieldsContext.isNeeded((SearchRequest) request)) {            
            if(threadContext.getHeader("_sg_source_field_context") == null) {
                final String serializedSourceFieldContext = Base64Helper.serializeObject(new SourceFieldsContext((SearchRequest) request));
                threadContext.putHeader("_sg_source_field_context", serializedSourceFieldContext);
            }
        } else if (request instanceof GetRequest && SourceFieldsContext.isNeeded((GetRequest) request)) {
            if(threadContext.getHeader("_sg_source_field_context") == null) {
                final String serializedSourceFieldContext = Base64Helper.serializeObject(new SourceFieldsContext((GetRequest) request));
                threadContext.putHeader("_sg_source_field_context", serializedSourceFieldContext);
            }
        }
    }
    
    @SuppressWarnings("rawtypes")
    private boolean checkImmutableIndices(Object request, ActionListener listener) {

        if(        request instanceof DeleteRequest 
                || request instanceof UpdateRequest 
                || request instanceof UpdateByQueryRequest 
                || request instanceof DeleteByQueryRequest
                || request instanceof DeleteIndexRequest
                || request instanceof RestoreSnapshotRequest
                || request instanceof CloseIndexRequest
                || request instanceof IndicesAliasesRequest //TODO only remove index
                ) {
            
            if(complianceConfig != null && complianceConfig.isIndexImmutable(request)) {
                //auditLog.log
                
                //check index for type = remove index
                //IndicesAliasesRequest iar = (IndicesAliasesRequest) request;
                //for(AliasActions aa: iar.getAliasActions()) {
                //    if(aa.actionType() == Type.REMOVE_INDEX) {
                        
                //    }
                //}
                
                
                
                listener.onFailure(new ElasticsearchSecurityException("Index is immutable", RestStatus.FORBIDDEN));
                return true;
            }
        }
        
        if(request instanceof IndexRequest) {
            if(complianceConfig != null && complianceConfig.isIndexImmutable(request)) {
                ((IndexRequest) request).opType(OpType.CREATE);
            }
        }
        
        return false;
    }

}