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

package org.opensearch.security.filter;

import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.opensearch.security.auth.RolesInjector;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.support.WildcardMatcher;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
import org.opensearch.security.auth.BackendRegistry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionResponse;
import org.opensearch.action.DocWriteRequest.OpType;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.close.CloseIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.logging.LoggerMessageFormat;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.index.reindex.UpdateByQueryRequest;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.action.whoami.WhoAmIAction;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.configuration.DlsFlsRequestValve;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.support.SourceFieldsContext;
import org.opensearch.security.user.User;

import static org.opensearch.security.OpenSearchSecurityPlugin.isActionTraceEnabled;
import static org.opensearch.security.OpenSearchSecurityPlugin.traceAction;

public class SecurityFilter implements ActionFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evalp;
    private final AdminDNs adminDns;
    private DlsFlsRequestValve dlsFlsValve;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final ClusterService cs;
    private final CompatConfig compatConfig;
    private final IndexResolverReplacer indexResolverReplacer;
    private final WildcardMatcher immutableIndicesMatcher;
    private final RolesInjector rolesInjector;
    private final Client client;
    private final BackendRegistry backendRegistry;

    public SecurityFilter(final Client client, final Settings settings, final PrivilegesEvaluator evalp, final AdminDNs adminDns,
                          DlsFlsRequestValve dlsFlsValve, AuditLog auditLog, ThreadPool threadPool, ClusterService cs,
                          final CompatConfig compatConfig, final IndexResolverReplacer indexResolverReplacer, BackendRegistry backendRegistry) {
        this.client = client;
        this.evalp = evalp;
        this.adminDns = adminDns;
        this.dlsFlsValve = dlsFlsValve;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
        this.cs = cs;
        this.compatConfig = compatConfig;
        this.indexResolverReplacer = indexResolverReplacer;
        this.immutableIndicesMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList()));
        this.rolesInjector = new RolesInjector();
        this.backendRegistry = backendRegistry;
        log.info("{} indices are made immutable.", immutableIndicesMatcher);
    }

    @VisibleForTesting
    WildcardMatcher getImmutableIndicesMatcher() {
        return immutableIndicesMatcher;
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

    private static Set<String> alias2Name(Set<Alias> aliases) {
        return aliases.stream().map(a -> a.name()).collect(ImmutableSet.toImmutableSet());
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
            final Set<String> injectedRoles = rolesInjector.injectUserAndRoles(threadContext);
            boolean enforcePrivilegesEvaluation = false;
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            if(user == null && (user = backendRegistry.authenticate(request, null, task, action)) != null) {
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
                enforcePrivilegesEvaluation = true;
            }

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
                        
            if (isActionTraceEnabled()) {

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

                traceAction("Node "+cs.localNode().getName()+" -> "+action+" ("+count+"): userIsAdmin="+userIsAdmin+"/conRequest="+confRequest+"/internalRequest="+internalRequest
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
                    auditLog.logIndexEvent(action, request, task);
                }

                chain.proceed(task, action, request, listener);
                return;
            }
            
            
            if(immutableIndicesMatcher != WildcardMatcher.NONE) {
            
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

            if(Origin.LOCAL.toString().equals(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN))
                    && (interClusterRequest || HeaderHelper.isDirectRequest(threadContext))
                    && (injectedRoles == null)
                    && !enforcePrivilegesEvaluation
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
                listener.onFailure(new OpenSearchSecurityException("No user found for "+action, RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }

            final PrivilegesEvaluator eval = evalp;

            if (!eval.isInitialized()) {
                log.error("OpenSearch Security not initialized for {}", action);
                listener.onFailure(new OpenSearchSecurityException("OpenSearch Security not initialized for "
                + action, RestStatus.SERVICE_UNAVAILABLE));
                return;
            }

            if (log.isTraceEnabled()) {
                log.trace("Evaluate permissions for user: {}", user.getName());
            }

            final PrivilegesEvaluatorResponse pres = eval.evaluate(user, action, request, task, injectedRoles);
            
            if (log.isDebugEnabled()) {
                log.debug(pres);
            }

            if (pres.isAllowed()) {
                auditLog.logGrantedPrivileges(action, request, task);
                auditLog.logIndexEvent(action, request, task);
                if(!dlsFlsValve.invoke(request, listener, pres.getAllowedFlsFields(), pres.getMaskedFields(), pres.getQueries())) {
                    return;
                }
                final CreateIndexRequestBuilder createIndexRequestBuilder = pres.getCreateIndexRequestBuilder();
                if (createIndexRequestBuilder == null) {
                    chain.proceed(task, action, request, listener);
                } else {
                    CreateIndexRequest createIndexRequest = createIndexRequestBuilder.request();
                    log.info("Request {} requires new tenant index {} with aliases {}",
                        request.getClass().getSimpleName(), createIndexRequest.index(), alias2Name(createIndexRequest.aliases()));
                    createIndexRequestBuilder.execute(new ActionListener<CreateIndexResponse>() {
                        @Override
                        public void onResponse(CreateIndexResponse createIndexResponse) {
                            if (createIndexResponse.isAcknowledged()) {
                                log.debug("Request to create index {} with aliases {} acknowledged, proceeding with {}",
                                    createIndexRequest.index(), alias2Name(createIndexRequest.aliases()), request.getClass().getSimpleName());
                                chain.proceed(task, action, request, listener);
                            } else {
                                String message = LoggerMessageFormat.format("Request to create index {} with aliases {} was not acknowledged, failing {}",
                                    createIndexRequest.index(), alias2Name(createIndexRequest.aliases()), request.getClass().getSimpleName());
                                log.error(message);
                                listener.onFailure(new OpenSearchException(message));
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            Throwable cause = ExceptionsHelper.unwrapCause(e);
                            if (cause instanceof ResourceAlreadyExistsException) {
                                log.warn("Request to create index {} with aliases {} failed as the resource already exists, proceeding with {}",
                                    createIndexRequest.index(), alias2Name(createIndexRequest.aliases()), request.getClass().getSimpleName(), e);
                                chain.proceed(task, action, request, listener);
                            } else {
                                log.error("Request to create index {} with aliases {} failed, failing {}",
                                    createIndexRequest.index(), alias2Name(createIndexRequest.aliases()), request.getClass().getSimpleName(), e);
                                listener.onFailure(e);
                            }
                        }
                    });
                }
            } else {
                auditLog.logMissingPrivileges(action, request, task);
                String err = (injectedRoles == null) ?
                        String.format("no permissions for %s and %s", pres.getMissingPrivileges(), user) :
                        String.format("no permissions for %s and associated roles %s", pres.getMissingPrivileges(), injectedRoles);
                log.debug(err);
                listener.onFailure(new OpenSearchSecurityException(err, RestStatus.FORBIDDEN));
            }
        } catch (OpenSearchException e) {
            if (task != null) {
                log.debug("Failed to apply filter. Task id: {} ({}). Action: {}", task.getId(), task.getDescription(), action, e);
            } else {
                log.debug("Failed to apply filter. Action: {}", action, e);
            }
            listener.onFailure(e);
        } catch (Throwable e) {
            log.error("Unexpected exception "+e, e);
            listener.onFailure(new OpenSearchSecurityException("Unexpected exception " + action, RestStatus.INTERNAL_SERVER_ERROR));
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
    private boolean checkImmutableIndices(Object request, ActionListener listener) {
        final boolean isModifyIndexRequest = request instanceof DeleteRequest
                || request instanceof UpdateRequest
                || request instanceof UpdateByQueryRequest
                || request instanceof DeleteByQueryRequest
                || request instanceof DeleteIndexRequest
                || request instanceof RestoreSnapshotRequest
                || request instanceof CloseIndexRequest
                || request instanceof IndicesAliasesRequest;

        if (isModifyIndexRequest && isRequestIndexImmutable(request)) {
            listener.onFailure(new OpenSearchSecurityException("Index is immutable", RestStatus.FORBIDDEN));
            return true;
        }
        
        if ((request instanceof IndexRequest) && isRequestIndexImmutable(request)) {
            ((IndexRequest) request).opType(OpType.CREATE);
        }
        
        return false;
    }

    private boolean isRequestIndexImmutable(Object request) {
        final IndexResolverReplacer.Resolved resolved = indexResolverReplacer.resolveRequest(request);
        final Set<String> allIndices = resolved.getAllIndices();

        return immutableIndicesMatcher.matchAny(allIndices);
    }
}
