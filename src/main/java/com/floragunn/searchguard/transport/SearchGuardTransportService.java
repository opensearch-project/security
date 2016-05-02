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

package com.floragunn.searchguard.transport;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;
import org.elasticsearch.transport.netty.NettyTransportChannel;

import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLTransportService;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.LogHelper;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;

public class SearchGuardTransportService extends SearchGuardSSLTransportService {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Provider<BackendRegistry> backendRegistry;

    @Inject
    public SearchGuardTransportService(final Settings settings, final Transport transport, final ThreadPool threadPool,
            final Provider<BackendRegistry> backendRegistry) {
        super(settings, transport, threadPool);
        this.backendRegistry = backendRegistry;
    }

    @Override
    public <T extends TransportResponse> void sendRequest(final DiscoveryNode node, final String action, final TransportRequest request,
            final TransportResponseHandler<T> handler) {
        copyUserHeader(action, request);
        LogHelper.logUserTrace("<-- Send {} to {} with {}/{}", action, node.getName(), request.getContext(), request.getHeaders());
        super.sendRequest(node, action, request, handler);
    }

    @Override
    public <T extends TransportResponse> void sendRequest(final DiscoveryNode node, final String action, final TransportRequest request,
            final TransportRequestOptions options, final TransportResponseHandler<T> handler) {
        copyUserHeader(action, request);
        LogHelper.logUserTrace("<-- Send {} to {} with {}/{}", action, node.getName(), request.getContext(), request.getHeaders());
        super.sendRequest(node, action, request, options, handler);
    }

    private void copyUserHeader(final String action, final TransportRequest request) {
        
        final User user = request.getFromContext("_sg_user");

        if (request.getFromContext("_sg_internal_request") == Boolean.TRUE) {
            request.putHeader("_sg_internal_request", "true");
        }

        // keep original address
        final Object remoteAdr = request.getFromContext("_sg_remote_address");
        if (remoteAdr != null) {
            request.putHeader("_sg_remote_address_header", Base64Helper.serializeObject(((InetSocketTransportAddress) remoteAdr).address()));
            LogHelper.logUserTrace("<-- Put remote address {} in header (from _sg_remote_address ctx)", remoteAdr);
        }

        if(log.isTraceEnabled()) {
            log.trace("sendRequest {}", LogHelper.toString(request));
        }
        
        if (user != null) {
            if (log.isTraceEnabled()) {
                log.trace("Copy user header for user {}", user);
            }

            LogHelper.logUserTrace("<-- Put user {} in header (from _sg_user ctx)", user.getName());
            request.putHeader("_sg_user_header", Base64Helper.serializeObject(user));
        } else if (Strings.isNullOrEmpty((String) request.getHeader("_sg_user_header"))) {

            //https://github.com/floragunncom/search-guard/issues/103
            if (!action.startsWith("internal:") && request.remoteAddress() != null) {
                throw new ElasticsearchSecurityException("user must not be null here for " + action + " "
                        + LogHelper.toString(request));
            }
        } else if (!Strings.isNullOrEmpty((String) request.getHeader("_sg_user_header"))) {
            if (log.isTraceEnabled()) {
                try {
                    log.trace("User {} is multihopped", Base64Helper.deserializeObject((String) request.getHeader("_sg_user_header")));
                } catch (Exception e) {
                    log.trace(e.toString(), e);
                }
            }
        }

    }

    @Override
    protected void addAdditionalContextValues(final String action, final TransportRequest request, final X509Certificate[] certs)
            throws Exception {

        boolean isInterClusterRequest = false;
        final Collection<List<?>> ianList = certs[0].getSubjectAlternativeNames();

        if (ianList != null) {
            final StringBuilder sb = new StringBuilder();

            for (final List<?> ian : ianList) {

                if (ian == null) {
                    continue;
                }

                for (final Iterator iterator = ian.iterator(); iterator.hasNext();) {
                    final int id = (int) iterator.next();
                    if (id == 8) { //id 8 = OID, id 1 = name (as string or ASN.1 encoded byte[])
                        Object value = iterator.next();
                        
                        if(value == null) {
                           continue;
                        }
                        
                        if(value instanceof String) {
                            sb.append(id + "::" + value);
                        } else if(value instanceof byte[]) {
                            log.error("Unable to handle OID san {} with value {} of type byte[] (ASN.1 DER not supported here)", id, Arrays.toString((byte[]) value));
                        } else {
                            log.error("Unable to handle OID san {} with value {} of type {}", id, value, value.getClass());
                        }
                    } else {
                        iterator.next();
                    }
                }
            }

            if (/*sb.indexOf("0::_sg_is_server_node") >= 0 || */sb.indexOf("8::1.2.3.4.5.5") >= 0) {
                isInterClusterRequest = true;
            }

        } else {
            if (log.isTraceEnabled()) {
                log.trace("No issuer alternative names (san) found");
            }
        }

        if (isInterClusterRequest) {
            if (log.isTraceEnabled() && !action.startsWith("internal:")) {
                log.trace("Is inter cluster request ({}/{}/{})", action, request.getClass(), request.remoteAddress());
            }
            request.putInContext("_sg_ssl_transport_intercluster_request", Boolean.TRUE);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Is not an inter cluster request");
            }
        }
        super.addAdditionalContextValues(action, request, certs);
    }

    @Override
    protected void messageReceivedDecorate(final TransportRequest request, final TransportRequestHandler handler,
            final TransportChannel transportChannel, Task task) throws Exception {
        try {
            final com.floragunn.searchguard.configuration.RequestHolder context = new com.floragunn.searchguard.configuration.RequestHolder(
                    request);
            com.floragunn.searchguard.configuration.RequestHolder.setCurrent(context);

            // TODO support or forbid LocalTransport

            if (transportChannel.action().startsWith("internal:") || transportChannel.action().contains("[")) {

                if (isInterClusterRequest(request)) {
                    super.messageReceivedDecorate(request, handler, transportChannel, task);
                    return;
                } else if (transportChannel instanceof NettyTransportChannel) {
                    transportChannel.sendResponse(new ElasticsearchSecurityException(
                            "Internal or shard requests not allowed from a client node"));
                    return;
                } else {
                    super.messageReceivedDecorate(request, handler, transportChannel, task);
                    return;
                }
            }

            String principal = null;
            LogHelper.logUserTrace("Received {} from {} via {}", transportChannel.action(), request.remoteAddress(),
                    transportChannel.getClass());
            LogHelper.logUserTrace("CTX/H {}/{}", request.getContext(), request.getHeaders());

            if ((principal = request.getFromContext("_sg_ssl_transport_principal")) == null) {
                transportChannel.sendResponse(new ElasticsearchSecurityException(
                        "No SSL client certificates found. Search Guards needs the Search Guard SSL plugin to be installed"));
                return;
            } else
            {
                request.putInContext("_sg_user", new User(principal));
                // impersonation of transport requests
                try {
                    if (!backendRegistry.get().authenticate(request, transportChannel)) {
                        return; //TODO what does that mean? currently this gets not executed because auth() always true
                    }
                } catch (final Exception e) {
                    transportChannel.sendResponse(e);
                    return;
                }

                LogHelper.logUserTrace("--> Put user {} in context (from _sg_ssl_transport_principal)", principal);

            }

            LogHelper.logUserTrace(">>>> TransportService for {}", transportChannel.action());

            super.messageReceivedDecorate(request, handler, transportChannel, task);
        } finally {
            LogHelper.logUserTrace("<<<< TransportService {}", transportChannel.action());
            com.floragunn.searchguard.configuration.RequestHolder.removeCurrent();
        }
    }

    /**
     * 
     * @param request
     * @return true if request comes from a node with a server certificate
     */
    private static boolean isInterClusterRequest(final TransportRequest request) {
        return request.getFromContext("_sg_ssl_transport_intercluster_request") == Boolean.TRUE;
    }
}
