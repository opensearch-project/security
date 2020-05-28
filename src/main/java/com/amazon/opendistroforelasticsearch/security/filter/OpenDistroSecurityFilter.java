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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.filter;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
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

import com.amazon.opendistroforelasticsearch.security.action.whoami.WhoAmIAction;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog.Origin;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.CompatConfig;
import com.amazon.opendistroforelasticsearch.security.configuration.DlsFlsRequestValve;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluatorResponse;
import com.amazon.opendistroforelasticsearch.security.support.Base64Helper;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.HeaderHelper;
import com.amazon.opendistroforelasticsearch.security.support.SourceFieldsContext;
import com.amazon.opendistroforelasticsearch.security.user.User;

public class OpenDistroSecurityFilter implements ActionFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Logger actionTrace = LogManager.getLogger("opendistro_security_action_trace");
    private final PrivilegesEvaluator evalp;
    private final AdminDNs adminDns;
    private DlsFlsRequestValve dlsFlsValve;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final ClusterService cs;
    private final CompatConfig compatConfig;
    private final IndexResolverReplacer indexResolverReplacer;

    public OpenDistroSecurityFilter(final PrivilegesEvaluator evalp, final AdminDNs adminDns,
            DlsFlsRequestValve dlsFlsValve, AuditLog auditLog, ThreadPool threadPool, ClusterService cs,
            final CompatConfig compatConfig, final IndexResolverReplacer indexResolverReplacer) {
        this.evalp = evalp;
        this.adminDns = adminDns;
        this.dlsFlsValve = dlsFlsValve;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
        this.cs = cs;
        this.compatConfig = compatConfig;
        this.indexResolverReplacer = indexResolverReplacer;
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

            if(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN) == null) {
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.LOCAL.toString());
            }

            final ComplianceConfig complianceConfig = auditLog.getComplianceConfig();
            if (complianceConfig != null && complianceConfig.isEnabled()) {
                attachSourceFieldContext(request);
            }

            final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            final boolean userIsAdmin = isUserAdmin(user, adminDns);
            final boolean interClusterRequest = HeaderHelper.isInterClusterRequest(threadContext);
            final boolean trustedClusterRequest = HeaderHelper.isTrustedClusterRequest(threadContext);
            final boolean confRequest = "true".equals(HeaderHelper.getSafeFromHeader(threadContext, ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER));
            final boolean passThroughRequest = action.startsWith("indices:admin/seq_no")
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
                        +"origin="+threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN)+"/directRequest="+HeaderHelper.isDirectRequest(threadContext)+"/remoteAddress="+request.remoteAddress());


                threadContext.putHeader("_opendistro_security_trace"+System.currentTimeMillis()+"#"+UUID.randomUUID().toString(), Thread.currentThread().getName()+" FILTER -> "+"Node "+cs.localNode().getName()+" -> "+action+" userIsAdmin="+userIsAdmin+"/conRequest="+confRequest+"/internalRequest="+internalRequest
                        +"origin="+threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN)+"/directRequest="+HeaderHelper.isDirectRequest(threadContext)+"/remoteAddress="+request.remoteAddress()+" "+threadContext.getHeaders().entrySet().stream().filter(p->!p.getKey().startsWith("_opendistro_security_trace")).collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue())));


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
            
            
            if(complianceConfig != null && complianceConfig.isEnabled() && complianceConfig.getImmutableIndicesMatcher() != WildcardMatcher.NONE) {
            
                boolean isImmutable = false;
                
                if(request instanceof BulkShardRequest) {
                    for(BulkItemRequest bsr: ((BulkShardRequest) request).items()) {
                        isImmutable = checkImmutableIndices(bsr.request(), listener, complianceConfig);
                        if(isImmutable) {
                            break;
                        }
                    }
                } else {
                    isImmutable = checkImmutableIndices(request, listener, complianceConfig);
                }
    
                if(isImmutable) {
                    return;
                }

            }

            if(Origin.LOCAL.toString().equals(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN))
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

                log.error("No user found for "+ action+" from "+request.remoteAddress()+" "+threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN)+" via "+threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_CHANNEL_TYPE)+" "+threadContext.getHeaders());
                listener.onFailure(new ElasticsearchSecurityException("No user found for "+action, RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }

            final PrivilegesEvaluator eval = evalp;

            if (!eval.isInitialized()) {
                log.error("Open Distro Security not initialized for {}", action);
                listener.onFailure(new ElasticsearchSecurityException("Open Distro Security not initialized for "
                + action, RestStatus.SERVICE_UNAVAILABLE));
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
                listener.onFailure(new ElasticsearchSecurityException("no permissions for " + pres.getMissingPrivileges()+ " and "+user, RestStatus.FORBIDDEN));
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
            if(threadContext.getHeader("_opendistro_security_source_field_context") == null) {
                final String serializedSourceFieldContext = Base64Helper.serializeObject(new SourceFieldsContext((SearchRequest) request));
                threadContext.putHeader("_opendistro_security_source_field_context", serializedSourceFieldContext);
            }
        } else if (request instanceof GetRequest && SourceFieldsContext.isNeeded((GetRequest) request)) {
            if(threadContext.getHeader("_opendistro_security_source_field_context") == null) {
                final String serializedSourceFieldContext = Base64Helper.serializeObject(new SourceFieldsContext((GetRequest) request));
                threadContext.putHeader("_opendistro_security_source_field_context", serializedSourceFieldContext);
            }
        }
    }
    
    @SuppressWarnings("rawtypes")
    private boolean checkImmutableIndices(Object request, ActionListener listener, final ComplianceConfig complianceConfig) {
        final boolean isModifyIndexRequest = request instanceof DeleteRequest
                || request instanceof UpdateRequest
                || request instanceof UpdateByQueryRequest
                || request instanceof DeleteByQueryRequest
                || request instanceof DeleteIndexRequest
                || request instanceof RestoreSnapshotRequest
                || request instanceof CloseIndexRequest
                || request instanceof IndicesAliasesRequest;

        if (isModifyIndexRequest && isRequestIndexImmutable(request, complianceConfig)) {
            listener.onFailure(new ElasticsearchSecurityException("Index is immutable", RestStatus.FORBIDDEN));
            return true;
        }
        
        if ((request instanceof IndexRequest) && isRequestIndexImmutable(request, complianceConfig)) {
            ((IndexRequest) request).opType(OpType.CREATE);
        }
        
        return false;
    }

    private boolean isRequestIndexImmutable(Object request, final ComplianceConfig complianceConfig) {
        final IndexResolverReplacer.Resolved resolved = indexResolverReplacer.resolveRequest(request);
        final Set<String> allIndices = resolved.getAllIndices();

        return complianceConfig.getImmutableIndicesMatcher().matchAny(allIndices);
    }
}
