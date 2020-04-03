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

package com.amazon.opendistroforelasticsearch.security.transport;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.admin.cluster.shards.ClusterSearchShardsAction;
import org.elasticsearch.action.admin.cluster.shards.ClusterSearchShardsResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.search.SearchAction;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport.Connection;
import org.elasticsearch.transport.TransportException;
import org.elasticsearch.transport.TransportInterceptor.AsyncSender;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;

import com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog.Origin;
import com.amazon.opendistroforelasticsearch.security.auth.BackendRegistry;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.ssl.SslExceptionHandler;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.Base64Helper;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import com.google.common.collect.Maps;

public class OpenDistroSecurityInterceptor {

    protected final Logger actionTrace = LogManager.getLogger("opendistro_security_action_trace");
    protected final Logger log = LogManager.getLogger(getClass());
    private BackendRegistry backendRegistry;
    private AuditLog auditLog;
    private final ThreadPool threadPool;
    private final PrincipalExtractor principalExtractor;
    private final InterClusterRequestEvaluator requestEvalProvider;
    private final ClusterService cs;
    private final Settings settings;
    private final SslExceptionHandler sslExceptionHandler;
    private final ClusterInfoHolder clusterInfoHolder;

    public OpenDistroSecurityInterceptor(final Settings settings,
            final ThreadPool threadPool, final BackendRegistry backendRegistry,
            final AuditLog auditLog, final PrincipalExtractor principalExtractor,
            final InterClusterRequestEvaluator requestEvalProvider,
            final ClusterService cs,
            final SslExceptionHandler sslExceptionHandler,
            final ClusterInfoHolder clusterInfoHolder) {
        this.backendRegistry = backendRegistry;
        this.auditLog = auditLog;
        this.threadPool = threadPool;
        this.principalExtractor = principalExtractor;
        this.requestEvalProvider = requestEvalProvider;
        this.cs = cs;
        this.settings = settings;
        this.sslExceptionHandler = sslExceptionHandler;
        this.clusterInfoHolder = clusterInfoHolder;
    }

    public <T extends TransportRequest> OpenDistroSecurityRequestHandler<T> getHandler(String action,
            TransportRequestHandler<T> actualHandler) {
        return new OpenDistroSecurityRequestHandler<T>(action, actualHandler, threadPool, backendRegistry, auditLog,
                principalExtractor, requestEvalProvider, cs, sslExceptionHandler);
    }


    public <T extends TransportResponse> void sendRequestDecorate(AsyncSender sender, Connection connection, String action,
            TransportRequest request, TransportRequestOptions options, TransportResponseHandler<T> handler) {

        final Map<String, String> origHeaders0 = getThreadContext().getHeaders();
        final User user0 = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final String origin0 = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);
        final Object remoteAddress0 = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        final String origCCSTransientDls = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_CCS);
        final String origCCSTransientFls = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_CCS);
        final String origCCSTransientMf = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_CCS);

        try (ThreadContext.StoredContext stashedContext = getThreadContext().stashContext()) {
            final TransportResponseHandler<T> restoringHandler = new RestoringTransportResponseHandler<T>(handler, stashedContext);
            getThreadContext().putHeader("_opendistro_security_remotecn", cs.getClusterName().value());

            final Map<String, String> headerMap = new HashMap<>(Maps.filterKeys(origHeaders0, k->k!=null && (
                    k.equals(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER)
                            || (k.equals("_opendistro_security_source_field_context") && ! (request instanceof SearchRequest) && !(request instanceof GetRequest))
                            || k.startsWith("_opendistro_security_trace")
                            || k.startsWith(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER)
            )));

            if (OpenDistroSecurityPlugin.GuiceHolder.getRemoteClusterService().isCrossClusterSearchEnabled()
                    && clusterInfoHolder.isInitialized()
                    && (action.equals(ClusterSearchShardsAction.NAME)
                    || action.equals(SearchAction.NAME)
            )
                    && !clusterInfoHolder.hasNode(connection.getNode())) {
                if (log.isDebugEnabled()) {
                    log.debug("remove dls/fls/mf because we sent a ccs request to a remote cluster");
                }
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER);
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER);
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER);
            }

            if (OpenDistroSecurityPlugin.GuiceHolder.getRemoteClusterService().isCrossClusterSearchEnabled()
                    && clusterInfoHolder.isInitialized()
                    && !action.startsWith("internal:")
                    && !action.equals(ClusterSearchShardsAction.NAME)
                    && !clusterInfoHolder.hasNode(connection.getNode())) {

                if (log.isDebugEnabled()) {
                    log.debug("add dls/fls/mf from transient");
                }

                if (origCCSTransientDls != null && !origCCSTransientDls.isEmpty()) {
                    headerMap.put(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, origCCSTransientDls);
                }
                if (origCCSTransientMf != null && !origCCSTransientMf.isEmpty()) {
                    headerMap.put(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, origCCSTransientMf);
                }
                if (origCCSTransientFls != null && !origCCSTransientFls.isEmpty()) {
                    headerMap.put(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, origCCSTransientFls);
                }
            }

            getThreadContext().putHeader(headerMap);

            ensureCorrectHeaders(remoteAddress0, user0, origin0);

            if(actionTrace.isTraceEnabled()) {
                getThreadContext().putHeader("_opendistro_security_trace"+System.currentTimeMillis()+"#"+UUID.randomUUID().toString(), Thread.currentThread().getName()+" IC -> "+action+" "+getThreadContext().getHeaders().entrySet().stream().filter(p->!p.getKey().startsWith("_opendistro_security_trace")).collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue())));
            }

            sender.sendRequest(connection, action, request, options, restoringHandler);
        }
    }

    private void ensureCorrectHeaders(final Object remoteAdr, final User origUser, final String origin) {
        // keep original address

        if(origin != null && !origin.isEmpty() /*&& !Origin.LOCAL.toString().equalsIgnoreCase(origin)*/ && getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER) == null) {
            getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER, origin);
        }

        if(origin == null && getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER) == null) {
            getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER, Origin.LOCAL.toString());
        }

        if (remoteAdr != null && remoteAdr instanceof TransportAddress) {

            String remoteAddressHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER);

            if(remoteAddressHeader == null) {
                getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER, Base64Helper.serializeObject(((TransportAddress) remoteAdr).address()));
            }
        }

        if(origUser != null) {
            String userHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);

            if(userHeader == null) {
                getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER, Base64Helper.serializeObject(origUser));
            }
        }
    }

    private ThreadContext getThreadContext() {
        return threadPool.getThreadContext();
    }

    //based on
    //org.elasticsearch.transport.TransportService.ContextRestoreResponseHandler<T>
    //which is private scoped
    private class RestoringTransportResponseHandler<T extends TransportResponse> implements TransportResponseHandler<T> {

        private final ThreadContext.StoredContext contextToRestore;
        private final TransportResponseHandler<T> innerHandler;

        private RestoringTransportResponseHandler(TransportResponseHandler<T> innerHandler, ThreadContext.StoredContext contextToRestore) {
            this.contextToRestore = contextToRestore;
            this.innerHandler = innerHandler;
        }

        @Override
        public T read(StreamInput in) throws IOException {
            return innerHandler.read(in);
        }

        @Override
        public void handleResponse(T response) {
            final List<String> flsResponseHeader = getThreadContext().getResponseHeaders().get(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER);
            final List<String> dlsResponseHeader = getThreadContext().getResponseHeaders().get(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER);
            final List<String> maskedFieldsResponseHeader = getThreadContext().getResponseHeaders().get(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER);

            contextToRestore.restore();

            if (response instanceof ClusterSearchShardsResponse && flsResponseHeader != null && !flsResponseHeader.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("add flsResponseHeader as transient");
                }
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_CCS, flsResponseHeader.get(0));
            }

            if (response instanceof ClusterSearchShardsResponse && dlsResponseHeader != null && !dlsResponseHeader.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("add dlsResponseHeader as transient");
                }
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_CCS, dlsResponseHeader.get(0));

            }

            if (response instanceof ClusterSearchShardsResponse && maskedFieldsResponseHeader != null && !maskedFieldsResponseHeader.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("add maskedFieldsResponseHeader as transient");
                }
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_CCS, maskedFieldsResponseHeader.get(0));
            }

            innerHandler.handleResponse(response);
        }

        @Override
        public void handleException(TransportException e) {
            contextToRestore.restore();
            innerHandler.handleException(e);
        }

        @Override
        public String executor() {
            return innerHandler.executor();
        }
    }

}
