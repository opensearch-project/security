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

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import com.google.common.base.Strings;

import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.support.replication.TransportReplicationAction.ConcreteShardRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.extensions.ExtensionsManager;
import org.opensearch.search.internal.ShardSearchRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.privileges.dlsfls.DlsRequestHeadersUtil;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.ssl.transport.SecuritySSLRequestHandler;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.user.UserFactory;
import org.opensearch.security.util.ParentChildrenQueryDetector;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;

import tools.jackson.core.type.TypeReference;

import static org.opensearch.security.OpenSearchSecurityPlugin.isActionTraceEnabled;

public class SecurityRequestHandler<T extends TransportRequest> extends SecuritySSLRequestHandler<T> {

    private final AuditLog auditLog;
    private final InterClusterRequestEvaluator requestEvalProvider;
    private final ClusterService cs;
    private final UserFactory userFactory;
    private final RemoteClusterIdentityPolicy remoteClusterIdentityPolicy;

    SecurityRequestHandler(
        String action,
        final TransportRequestHandler<T> actualHandler,
        final ThreadPool threadPool,
        final AuditLog auditLog,
        final PrincipalExtractor principalExtractor,
        final InterClusterRequestEvaluator requestEvalProvider,
        final ClusterService cs,
        final SSLConfig SSLConfig,
        final SslExceptionHandler sslExceptionHandler,
        final UserFactory userFactory,
        final RemoteClusterIdentityPolicy remoteClusterIdentityPolicy
    ) {
        super(action, actualHandler, threadPool, principalExtractor, SSLConfig, sslExceptionHandler);
        this.auditLog = auditLog;
        this.requestEvalProvider = requestEvalProvider;
        this.cs = cs;
        this.userFactory = userFactory;
        this.remoteClusterIdentityPolicy = remoteClusterIdentityPolicy;
    }

    @Override
    protected void messageReceivedDecorate(
        final T request,
        final TransportRequestHandler<T> handler,
        final TransportChannel transportChannel,
        Task task
    ) throws Exception {
        String resolvedActionClass = request.getClass().getSimpleName();

        if (request instanceof BulkShardRequest) {
            if (((BulkShardRequest) request).items().length == 1) {
                resolvedActionClass = ((BulkShardRequest) request).items()[0].request().getClass().getSimpleName();
            }
        }

        if (request instanceof ConcreteShardRequest) {
            resolvedActionClass = ((ConcreteShardRequest<?>) request).getRequest().getClass().getSimpleName();
        }

        String initialActionClassValue = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER);

        final ThreadContext.StoredContext sgContext = getThreadContext().newStoredContext(false);

        TransportIdentityContext.restoreOrigin(getThreadContext());

        // restore headers used for DLS
        final var dlsRequestHeadersAsString = getThreadContext().getHeader(ConfigConstants.OPENSEARCH_SECURITY_DLS_REQUEST_HEADERS);
        if (!Strings.isNullOrEmpty(dlsRequestHeadersAsString)) {
            final List<DlsRequestHeadersUtil.DlsRequestHeader> dlsRequestHeaders = DefaultObjectMapper.readValue(
                dlsRequestHeadersAsString,
                new TypeReference<>() {
                }
            );
            getThreadContext().putTransient(ConfigConstants.OPENSEARCH_SECURITY_DLS_REQUEST_HEADERS, dlsRequestHeaders);
        }

        try {

            if (transportChannel.getChannelType() == null) {
                throw new RuntimeException("Can not determine channel type (null)");
            }

            String channelType = transportChannel.getChannelType();

            getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_CHANNEL_TYPE, channelType);
            getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ACTION_NAME, task.getAction());

            if (request instanceof ShardSearchRequest) {
                ShardSearchRequest sr = ((ShardSearchRequest) request);
                if (sr.source() != null && sr.source().suggest() != null) {
                    getThreadContext().putTransient("_opendistro_security_issuggest", Boolean.TRUE);
                }
                if (sr.source() != null && sr.source().query() != null) {
                    if (ParentChildrenQueryDetector.hasParentOrChildQuery(sr.source().query())) {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_CONTAIN_PARENT_CHILD_QUERY, Boolean.TRUE);
                    }
                }
            }

            // bypass non-netty requests
            if (TransportIdentityContext.hasTransientIdentity(getThreadContext())) {
                TransportIdentityContext.restoreRolesValidation(getThreadContext());

                if (isActionTraceEnabled()) {
                    getThreadContext().putHeader(
                        "_opendistro_security_trace" + System.currentTimeMillis() + "#" + UUID.randomUUID().toString(),
                        Thread.currentThread().getName()
                            + " DIR -> "
                            + transportChannel.getChannelType()
                            + " "
                            + getThreadContext().getHeaders()
                    );
                }

                putInitialActionClassHeader(initialActionClassValue, resolvedActionClass);
            } else {
                TransportIdentityContext.restoreSerializedIdentity(
                    getThreadContext(),
                    request.remoteAddress(),
                    userFactory,
                    remoteClusterIdentityPolicy
                );
            }

            if (channelType.equals("direct")) {
                super.messageReceivedDecorate(request, handler, transportChannel, task);
                return;
            }

            if (channelType.equals("stream-transport")) {
                super.messageReceivedDecorate(request, handler, transportChannel, task);
                return;
            }

            boolean skipSecurityIfDualMode = getThreadContext().getTransient(
                ConfigConstants.SECURITY_SSL_DUAL_MODE_SKIP_SECURITY
            ) == Boolean.TRUE;

            if (skipSecurityIfDualMode) {
                if (getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS) == null) {
                    getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, request.remoteAddress());
                }

                if (getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN) == null) {
                    getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.TRANSPORT.toString());
                }

                if (getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST) == null) {
                    getThreadContext().putTransient(
                        ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST,
                        Boolean.TRUE
                    );
                }

                super.messageReceivedDecorate(request, handler, transportChannel, task);
                return;
            }

            // if the incoming request is an internal:* or a shard request allow only if request was sent by a server node
            // if transport channel is not a netty channel but a direct or local channel (e.g. send via network) then allow it (regardless
            // of beeing a internal: or shard request)
            // also allow when issued from a remote cluster for cross cluster search
            if (!HeaderHelper.isLocalClusterNodeRequest(getThreadContext())
                && !HeaderHelper.isRemoteClusterNodeRequest(getThreadContext())
                && !HeaderHelper.isExtensionRequest(getThreadContext())
                && !task.getAction().equals("internal:transport/handshake")
                && (task.getAction().startsWith("internal:") || task.getAction().contains("["))) {

                auditLog.logMissingPrivileges(task.getAction(), request, task);
                log.error(
                    "Internal or shard requests ("
                        + task.getAction()
                        + ") not allowed from a non-server node for transport type "
                        + transportChannel.getChannelType()
                );
                transportChannel.sendResponse(
                    new OpenSearchSecurityException(
                        "Internal or shard requests not allowed from a non-server node for transport type "
                            + transportChannel.getChannelType()
                    )
                );
                return;
            }

            String principal = null;

            if ((principal = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL)) == null) {
                Exception ex = new OpenSearchSecurityException(
                    "No SSL client certificates found for transport type "
                        + transportChannel.getChannelType()
                        + ". OpenSearch Security needs the OpenSearch Security SSL plugin to be installed"
                );
                auditLog.logSSLException(request, ex, task.getAction(), task);
                log.error(
                    "No SSL client certificates found for transport type "
                        + transportChannel.getChannelType()
                        + ". OpenSearch Security needs the OpenSearch Security SSL plugin to be installed"
                );
                transportChannel.sendResponse(ex);
                return;
            } else {
                if (getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN) == null) {
                    getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.TRANSPORT.toString());
                }

                // local cluster node request or cross-cluster request
                if (!(HeaderHelper.isLocalClusterNodeRequest(getThreadContext())
                    || HeaderHelper.isRemoteClusterNodeRequest(getThreadContext())
                    || HeaderHelper.isExtensionRequest(getThreadContext()))) {
                    final OpenSearchException exception = ExceptionUtils.clusterWrongNodeCertConfigException(principal);
                    log.error(exception.toString());
                    transportChannel.sendResponse(exception);
                    return;
                }

                if (isActionTraceEnabled()) {
                    getThreadContext().putHeader(
                        "_opendistro_security_trace" + System.currentTimeMillis() + "#" + UUID.randomUUID().toString(),
                        Thread.currentThread().getName()
                            + " NETTI -> "
                            + transportChannel.getChannelType()
                            + " "
                            + getThreadContext().getHeaders()
                                .entrySet()
                                .stream()
                                .filter(p -> !p.getKey().startsWith("_opendistro_security_trace"))
                                .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()))
                    );
                }

                putInitialActionClassHeader(initialActionClassValue, resolvedActionClass);
            }
            super.messageReceivedDecorate(request, handler, transportChannel, task);
        } finally {

            if (isActionTraceEnabled()) {
                getThreadContext().putHeader(
                    "_opendistro_security_trace" + System.currentTimeMillis() + "#" + UUID.randomUUID().toString(),
                    Thread.currentThread().getName()
                        + " FIN -> "
                        + transportChannel.getChannelType()
                        + " "
                        + getThreadContext().getHeaders()
                );
            }

            if (sgContext != null) {
                sgContext.close();
            }
        }
    }

    private void putInitialActionClassHeader(String initialActionClassValue, String resolvedActionClass) {
        if (initialActionClassValue == null) {
            if (getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER) == null) {
                getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER, resolvedActionClass);
            }
        } else {
            if (getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER) == null) {
                getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER, initialActionClassValue);
            }
        }

    }

    @Override
    protected void addAdditionalContextValues(
        final String action,
        final TransportRequest request,
        final X509Certificate[] localCerts,
        final X509Certificate[] peerCerts,
        final String principal
    ) throws Exception {

        boolean isNodeCertificateRequest = requestEvalProvider.isInterClusterRequest(request, localCerts, peerCerts, principal);
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isNodeCertificateRequest) {
            if (cs.getClusterName().value().equals(getThreadContext().getHeader("_opendistro_security_remotecn"))) {

                if (isTraceEnabled && !action.startsWith("internal:")) {
                    log.trace("Is local cluster node request ({}/{}/{})", action, request.getClass(), request.remoteAddress());
                }

                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_INTERCLUSTER_REQUEST, Boolean.TRUE);
            } else {
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST, Boolean.TRUE);
            }

        } else {
            if (isTraceEnabled) {
                log.trace("Is not a node certificate request");
            }
        }

        String extensionUniqueId = getThreadContext().getHeader("extension_unique_id");
        if (extensionUniqueId != null) {
            ExtensionsManager extManager = OpenSearchSecurityPlugin.GuiceHolder.getExtensionsManager();
            if (extManager.lookupExtensionSettingsById(extensionUniqueId).isPresent()) {
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_EXTENSION_REQUEST, Boolean.TRUE);
            }
        }

        super.addAdditionalContextValues(action, request, localCerts, peerCerts, principal);
    }
}
