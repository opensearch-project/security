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
import java.util.Objects;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLTransportService;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.support.LogHelper;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;

public class SearchGuardTransportService extends SearchGuardSSLTransportService {
    
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Provider<BackendRegistry> backendRegistry;
    private final AuditLog auditLog;
    private final String certOid;

    @Inject
    public SearchGuardTransportService(final Settings settings, final Transport transport, final ThreadPool threadPool,
            final Provider<BackendRegistry> backendRegistry, AuditLog auditLog) {
        super(settings, transport, threadPool);
        this.backendRegistry = backendRegistry;
        this.auditLog = auditLog;
        this.certOid = settings.get("searchguard.cert.oid", "1.2.3.4.5.5");
    }

    @Override
    public <T extends TransportResponse> void sendRequest(final DiscoveryNode node, final String action, final TransportRequest request,
            final TransportResponseHandler<T> handler) {
        attachHeaders(action, request);
        //LogHelper.logUserTrace("<-- Send {} to {} with {}/{}", action, node.getName(), request.getContext(), request.getHeaders());
        super.sendRequest(node, action, request, handler);
    }

    @Override
    public <T extends TransportResponse> void sendRequest(final DiscoveryNode node, final String action, final TransportRequest request,
            final TransportRequestOptions options, final TransportResponseHandler<T> handler) {
        attachHeaders(action, request);
        //LogHelper.logUserTrace("<-- Send {} to {} with {}/{}", action, node.getName(), request.getContext(), request.getHeaders());
        super.sendRequest(node, action, request, options, handler);
    }

    private void attachHeaders(final String action, final TransportRequest request) {

        // keep original address
        final Object remoteAdr = request.getFromContext(ConfigConstants.SG_REMOTE_ADDRESS);
        if (remoteAdr != null && remoteAdr instanceof InetSocketTransportAddress) {
            request.putHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER, Base64Helper.serializeObject(((InetSocketTransportAddress) remoteAdr).address()));
            //LogHelper.logUserTrace("<-- Put remote address {} in header (from sg_remote_address ctx)", remoteAdr);
        }

        /*if(log.isTraceEnabled()) {
            log.trace("sendRequest {}", LogHelper.toString(request));
        }*/
        
        User user = request.getFromContext(ConfigConstants.SG_USER);
                
        if(user == null /* && action.startsWith("internal:")*/ && request.remoteAddress() == null) {
            user = user.SG_INTERNAL;
        }
        
        if(user != null) {
            request.putHeader(ConfigConstants.SG_USER_HEADER, Base64Helper.serializeObject(user));
        } else {
            throw new ElasticsearchSecurityException("user must not be null here for " + action + " "
                    + LogHelper.toString(request));
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

            if (sb.indexOf("8::" + this.certOid) >= 0) {
                isInterClusterRequest = true;
            }

        } else {
            if (log.isTraceEnabled()) {
                log.trace("No subject alternative names (san) found");
            }
        }

        if (isInterClusterRequest) {
            if (log.isTraceEnabled() && !action.startsWith("internal:")) {
                log.trace("Is inter cluster request ({}/{}/{})", action, request.getClass(), request.remoteAddress());
            }
            request.putInContext(ConfigConstants.SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST, Boolean.TRUE);
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
            
            request.putInContext(ConfigConstants.SG_CHANNEL_TYPE, transportChannel.getChannelType());
            
            //bypass non-netty requests
            if(transportChannel.getChannelType().equals("local") || transportChannel.getChannelType().equals("direct")) {
                super.messageReceivedDecorate(request, handler, transportChannel, task);
                return;
            }
            
            //if the incoming request is an internal:* or a shard request allow only if request was sent by a server node
            //if transport channel is not a netty channel but a direct or local channel (e.g. send via network) then allow it (regardless of beeing a internal: or shard request)
            if (!isInterClusterRequest(request) 
                    && (transportChannel.action().startsWith("internal:") || transportChannel.action().contains("["))) {
                auditLog.logMissingPrivileges(transportChannel.action(), request);
                log.error("Internal or shard requests not allowed from a non-server node for transport type "+transportChannel.getChannelType());
                transportChannel.sendResponse(new ElasticsearchSecurityException(
                        "Internal or shard requests not allowed from a non-server node for transport type "+transportChannel.getChannelType()));
                return;
            }
            
            
            String principal = null;
            //LogHelper.logUserTrace("Received {} from {} via {}", transportChannel.action(), request.remoteAddress(),
            //        transportChannel.getClass());
            //LogHelper.logUserTrace("CTX/H {}/{}", request.getContext(), request.getHeaders());

            if ((principal = request.getFromContext(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL)) == null) {
                Exception ex = new ElasticsearchSecurityException(
                        "No SSL client certificates found for transport type "+transportChannel.getChannelType()+". Search Guard needs the Search Guard SSL plugin to be installed");
                auditLog.logSSLException(request, ex, transportChannel.action());
                log.error("No SSL client certificates found for transport type "+transportChannel.getChannelType()+". Search Guard needs the Search Guard SSL plugin to be installed");
                transportChannel.sendResponse(ex);
                return;
            } else {
                
                if(isInterClusterRequest(request)) {
                    
                    String userHeader = request.getHeader(ConfigConstants.SG_USER_HEADER);
                    
                    if(Strings.isNullOrEmpty(userHeader)) {
                        //user can be null when a node client wants connect
                        request.putInContext(ConfigConstants.SG_USER, User.SG_INTERNAL);               
                    } else {
                        request.putInContext(ConfigConstants.SG_USER, Objects.requireNonNull((User) Base64Helper.deserializeObject(userHeader)));
                    }
                    
                    String originalRemoteAddress = request.getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER);
                    
                    if(!Strings.isNullOrEmpty(originalRemoteAddress)) {
                        request.putInContext(ConfigConstants.SG_REMOTE_ADDRESS, Base64Helper.deserializeObject(originalRemoteAddress));
                    }
                    
                } else {
                    
                    //this is a netty request from a non-server node (maybe also be internal: or a shard request)
                    //and therefore issued by a transport client
                    
                    try {
                        HeaderHelper.checkSGHeader(request);
                    } catch (Exception e) {
                        auditLog.logBadHeaders(request);
                        log.error("Error validating headers "+e, e);
                        transportChannel.sendResponse(ExceptionsHelper.convertToElastic(e));
                        return;
                    }
                    
                    request.putInContext(ConfigConstants.SG_USER, new User(principal));
                    
                    try {
                        if(!backendRegistry.get().authenticate(request, transportChannel)) {
                            log.error("Cannot authenticate {}", request.getFromContext(ConfigConstants.SG_USER));
                            transportChannel.sendResponse(new ElasticsearchSecurityException("Cannot authenticate "+request.getFromContext(ConfigConstants.SG_USER)));
                            return;
                        }
                    } catch (Exception e) {
                        log.error("Error authentication transport user "+e, e);
                        auditLog.logFailedLogin(principal, request);
                        transportChannel.sendResponse(ExceptionsHelper.convertToElastic(e));
                        return;
                    }
                    
                    
                    TransportAddress originalRemoteAddress = request.remoteAddress();
                    
                    if(originalRemoteAddress != null && (originalRemoteAddress instanceof InetSocketTransportAddress)) {
                        request.putInContext(ConfigConstants.SG_REMOTE_ADDRESS, originalRemoteAddress);
                    } else {
                        log.error("Request has no proper remote address {}", originalRemoteAddress);
                        transportChannel.sendResponse(new ElasticsearchException("Request has no proper remote address"));
                        return;
                    }
                }
                
                super.messageReceivedDecorate(request, handler, transportChannel, task);
                //LogHelper.logUserTrace("--> Put user {} in context (from sg_ssl_transport_principal)", principal);
            }

            //LogHelper.logUserTrace(">>>> TransportService for {}", transportChannel.action());

            
            
        } finally {
            //LogHelper.logUserTrace("<<<< TransportService {}", transportChannel.action());
            com.floragunn.searchguard.configuration.RequestHolder.removeCurrent();
        }
    }
    
    @Override
    protected void errorThrown(Throwable t, final TransportRequest request, String action) {
        auditLog.logSSLException(request, t, action);
    }

    /**
     * 
     * @param request
     * @return true if request comes from a node with a server certificate
     */
    private static boolean isInterClusterRequest(final TransportRequest request) {
        return request.getFromContext(ConfigConstants.SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST) == Boolean.TRUE;
    }
}
