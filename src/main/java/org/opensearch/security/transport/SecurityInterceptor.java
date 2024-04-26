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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.transport;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsAction;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.transport.TransportResponse;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.support.SerializationFormat;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Transport.Connection;
import org.opensearch.transport.TransportException;
import org.opensearch.transport.TransportInterceptor.AsyncSender;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;
import org.opensearch.transport.TransportRequestOptions;
import org.opensearch.transport.TransportResponseHandler;

public class SecurityInterceptor {

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
    private final SSLConfig SSLConfig;
    private final Supplier<Boolean> actionTraceEnabled;

    public SecurityInterceptor(
        final Settings settings,
        final ThreadPool threadPool,
        final BackendRegistry backendRegistry,
        final AuditLog auditLog,
        final PrincipalExtractor principalExtractor,
        final InterClusterRequestEvaluator requestEvalProvider,
        final ClusterService cs,
        final SslExceptionHandler sslExceptionHandler,
        final ClusterInfoHolder clusterInfoHolder,
        final SSLConfig SSLConfig,
        final Supplier<Boolean> actionTraceSupplier
    ) {
        this.backendRegistry = backendRegistry;
        this.auditLog = auditLog;
        this.threadPool = threadPool;
        this.principalExtractor = principalExtractor;
        this.requestEvalProvider = requestEvalProvider;
        this.cs = cs;
        this.settings = settings;
        this.sslExceptionHandler = sslExceptionHandler;
        this.clusterInfoHolder = clusterInfoHolder;
        this.SSLConfig = SSLConfig;
        this.actionTraceEnabled = actionTraceSupplier;
    }

    public <T extends TransportRequest> SecurityRequestHandler<T> getHandler(String action, TransportRequestHandler<T> actualHandler) {
        return new SecurityRequestHandler<T>(
            action,
            actualHandler,
            threadPool,
            auditLog,
            principalExtractor,
            requestEvalProvider,
            cs,
            SSLConfig,
            sslExceptionHandler
        );
    }

    public <T extends TransportResponse> void sendRequestDecorate(
        AsyncSender sender,
        Connection connection,
        String action,
        TransportRequest request,
        TransportRequestOptions options,
        TransportResponseHandler<T> handler,
        DiscoveryNode localNode
    ) {
        final Map<String, String> origHeaders0 = getThreadContext().getHeaders();
        final User user0 = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final String injectedUserString = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER);
        final String injectedRolesString = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES);
        final String injectedRolesValidationString = getThreadContext().getTransient(
            ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION
        );
        final String origin0 = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);
        final Object remoteAddress0 = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        final String origCCSTransientDls = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_CCS);
        final String origCCSTransientFls = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_CCS);
        final String origCCSTransientMf = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_CCS);

        final boolean isDebugEnabled = log.isDebugEnabled();

        final var serializationFormat = SerializationFormat.determineFormat(connection.getVersion());
        final boolean isSameNodeRequest = localNode != null && localNode.equals(connection.getNode());

        try (ThreadContext.StoredContext stashedContext = getThreadContext().stashContext()) {
            final TransportResponseHandler<T> restoringHandler = new RestoringTransportResponseHandler<T>(handler, stashedContext);
            getThreadContext().putHeader("_opendistro_security_remotecn", cs.getClusterName().value());

            final Map<String, String> headerMap = new HashMap<>(
                Maps.filterKeys(
                    origHeaders0,
                    k -> k != null
                        && (k.equals(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER)
                            || k.equals(ConfigConstants.OPENDISTRO_SECURITY_DLS_FILTER_LEVEL_QUERY_HEADER)
                            || (k.equals("_opendistro_security_source_field_context")
                                && !(request instanceof SearchRequest)
                                && !(request instanceof GetRequest))
                            || k.startsWith("_opendistro_security_trace")
                            || k.startsWith(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER))
                )
            );

            if (OpenSearchSecurityPlugin.GuiceHolder.getRemoteClusterService().isCrossClusterSearchEnabled()
                && clusterInfoHolder.isInitialized()
                && (action.equals(ClusterSearchShardsAction.NAME) || action.equals(SearchAction.NAME))
                && !clusterInfoHolder.hasNode(connection.getNode())) {
                if (isDebugEnabled) {
                    log.debug("remove dls/fls/mf because we sent a ccs request to a remote cluster");
                }
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER);
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER);
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER);
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER);
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE);
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_DLS_FILTER_LEVEL_QUERY_HEADER);
                headerMap.remove(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER);
            }

            if (OpenSearchSecurityPlugin.GuiceHolder.getRemoteClusterService().isCrossClusterSearchEnabled()
                && clusterInfoHolder.isInitialized()
                && !action.startsWith("internal:")
                && !action.equals(ClusterSearchShardsAction.NAME)
                && !clusterInfoHolder.hasNode(connection.getNode())) {

                if (isDebugEnabled) {
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

            if (StringUtils.isNotEmpty(injectedRolesValidationString)
                && OpenSearchSecurityPlugin.GuiceHolder.getRemoteClusterService().isCrossClusterSearchEnabled()
                && !clusterInfoHolder.hasNode(connection.getNode())
                && getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION_HEADER) == null) {
                // Sending roles validation for only cross cluster requests
                getThreadContext().putHeader(
                    ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION_HEADER,
                    injectedRolesValidationString
                );
            }

            try {
                if (serializationFormat == SerializationFormat.JDK) {
                    Map<String, String> jdkSerializedHeaders = new HashMap<>();
                    HeaderHelper.getAllSerializedHeaderNames()
                        .stream()
                        .filter(k -> headerMap.get(k) != null)
                        .forEach(k -> jdkSerializedHeaders.put(k, Base64Helper.ensureJDKSerialized(headerMap.get(k))));
                    headerMap.putAll(jdkSerializedHeaders);
                }
                getThreadContext().putHeader(headerMap);
            } catch (IllegalArgumentException iae) {
                log.debug("Failed to add headers information onto on thread context", iae);
            }

            ensureCorrectHeaders(
                remoteAddress0,
                user0,
                origin0,
                injectedUserString,
                injectedRolesString,
                isSameNodeRequest,
                serializationFormat
            );

            if (actionTraceEnabled.get()) {
                getThreadContext().putHeader(
                    "_opendistro_security_trace" + System.currentTimeMillis() + "#" + UUID.randomUUID().toString(),
                    Thread.currentThread().getName()
                        + " IC -> "
                        + action
                        + " "
                        + getThreadContext().getHeaders()
                            .entrySet()
                            .stream()
                            .filter(p -> !p.getKey().startsWith("_opendistro_security_trace"))
                            .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()))
                );
            }

            sender.sendRequest(connection, action, request, options, restoringHandler);
        }
    }

    private void ensureCorrectHeaders(
        final Object remoteAdr,
        final User origUser,
        final String origin,
        final String injectedUserString,
        final String injectedRolesString,
        final boolean isSameNodeRequest,
        final SerializationFormat format
    ) {
        // keep original address

        if (origin != null
            && !origin.isEmpty() /*&& !Origin.LOCAL.toString().equalsIgnoreCase(origin)*/
            && getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER) == null) {
            getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER, origin);
        }

        if (origin == null && getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER) == null) {
            getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER, Origin.LOCAL.toString());
        }

        TransportAddress transportAddress = null;
        if (remoteAdr != null && remoteAdr instanceof TransportAddress) {
            String remoteAddressHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER);
            if (remoteAddressHeader == null) {
                transportAddress = (TransportAddress) remoteAdr;
            }
        }

        // we put headers as transient for same node requests
        if (isSameNodeRequest) {
            if (transportAddress != null) {
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, transportAddress);
            }

            if (origUser != null) {
                // if request is going to be handled by same node, we directly put transient value as the thread context is not going to be
                // stah.
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, origUser);
            } else if (StringUtils.isNotEmpty(injectedRolesString)) {
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, injectedRolesString);
            } else if (StringUtils.isNotEmpty(injectedUserString)) {
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, injectedUserString);
            }
        } else {
            final var useJDKSerialization = format == SerializationFormat.JDK;
            if (transportAddress != null) {
                getThreadContext().putHeader(
                    ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER,
                    Base64Helper.serializeObject(transportAddress.address(), useJDKSerialization)
                );
            }

            final String userHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
            if (userHeader == null) {
                // put as headers for other requests
                if (origUser != null) {
                    getThreadContext().putHeader(
                        ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER,
                        Base64Helper.serializeObject(origUser, useJDKSerialization)
                    );
                } else if (StringUtils.isNotEmpty(injectedRolesString)) {
                    getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_HEADER, injectedRolesString);
                } else if (StringUtils.isNotEmpty(injectedUserString)) {
                    getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER_HEADER, injectedUserString);
                }
            }
        }
    }

    private ThreadContext getThreadContext() {
        return threadPool.getThreadContext();
    }

    // based on
    // org.opensearch.transport.TransportService.ContextRestoreResponseHandler<T>
    // which is private scoped
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

            ThreadContext threadContext = getThreadContext();
            Map<String, List<String>> responseHeaders = threadContext.getResponseHeaders();

            List<String> flsResponseHeader = responseHeaders.get(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER);
            List<String> dlsResponseHeader = responseHeaders.get(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER);
            List<String> maskedFieldsResponseHeader = responseHeaders.get(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER);

            contextToRestore.restore();

            final boolean isDebugEnabled = log.isDebugEnabled();
            if (response instanceof ClusterSearchShardsResponse) {
                if (flsResponseHeader != null && !flsResponseHeader.isEmpty()) {
                    if (isDebugEnabled) {
                        log.debug("add flsResponseHeader as transient");
                    }
                    threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_CCS, flsResponseHeader.get(0));
                }

                if (dlsResponseHeader != null && !dlsResponseHeader.isEmpty()) {
                    if (isDebugEnabled) {
                        log.debug("add dlsResponseHeader as transient");
                    }
                    threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_CCS, dlsResponseHeader.get(0));
                }

                if (maskedFieldsResponseHeader != null && !maskedFieldsResponseHeader.isEmpty()) {
                    if (isDebugEnabled) {
                        log.debug("add maskedFieldsResponseHeader as transient");
                    }
                    threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_CCS, maskedFieldsResponseHeader.get(0));
                }
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
