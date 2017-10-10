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

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;

import com.floragunn.searchguard.action.whoami.WhoAmIAction;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.AuditLog.Origin;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLRequestHandler;
import com.floragunn.searchguard.ssl.util.ExceptionUtils;
import com.floragunn.searchguard.ssl.util.SSLRequestHelper;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;

public class SearchGuardRequestHandler<T extends TransportRequest> extends SearchGuardSSLRequestHandler<T> {

    private final BackendRegistry backendRegistry;
    private final AuditLog auditLog;
    private final InterClusterRequestEvaluator requestEvalProvider;
    private final ClusterService cs;
    
    SearchGuardRequestHandler(String action, 
            TransportRequestHandler<T> actualHandler, 
            ThreadPool threadPool,
            BackendRegistry backendRegistry,
            AuditLog auditLog,
            final PrincipalExtractor principalExtractor,
            InterClusterRequestEvaluator requestEvalProvider,
            final ClusterService cs) {
        super(action, actualHandler, threadPool, principalExtractor);
        this.backendRegistry = backendRegistry;
        this.auditLog = auditLog;
        this.requestEvalProvider = requestEvalProvider;
        this.cs = cs;
    }
    
    @Override
    protected void messageReceivedDecorate(final T request, final TransportRequestHandler<T> handler,
            final TransportChannel transportChannel, Task task) throws Exception {

        final ThreadContext.StoredContext sgContext = getThreadContext().newStoredContext(false);
        
        final String originHeader = getThreadContext().getHeader(ConfigConstants.SG_ORIGIN_HEADER);
        
        if(!Strings.isNullOrEmpty(originHeader)) {
            getThreadContext().putTransient(ConfigConstants.SG_ORIGIN, originHeader);  
        }
        
        try {

           final String ct = (String) getThreadContext().getTransient(ConfigConstants.SG_CHANNEL_TYPE);
           
           if(transportChannel.getChannelType()==null) {
               throw new RuntimeException("Can not determine channel type (null)");
           }
                       
           getThreadContext().putTransient(ConfigConstants.SG_ACTION_NAME, transportChannel.action());
           
            if(ct == null) {
                 getThreadContext().putTransient(ConfigConstants.SG_CHANNEL_TYPE, transportChannel.getChannelType());
            } else if(!ct.equals(transportChannel.getChannelType())) {
                 throw new RuntimeException("channel type mismtach "+ct+"!="+transportChannel.getChannelType());
            }
            
            //bypass non-netty requests
            if(transportChannel.getChannelType().equals("local") || transportChannel.getChannelType().equals("direct")) {
                final String userHeader = getThreadContext().getHeader(ConfigConstants.SG_USER_HEADER);
                
                if(!Strings.isNullOrEmpty(userHeader)) {
                    getThreadContext().putTransient(ConfigConstants.SG_USER, Objects.requireNonNull((User) Base64Helper.deserializeObject(userHeader)));  
                }
                
                final String originalRemoteAddress = getThreadContext().getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER);          
                
                if(!Strings.isNullOrEmpty(originalRemoteAddress)) {
                    getThreadContext().putTransient(ConfigConstants.SG_REMOTE_ADDRESS, new TransportAddress((InetSocketAddress) Base64Helper.deserializeObject(originalRemoteAddress)));
                }
                                
                super.messageReceivedDecorate(request, handler, transportChannel, task);
                return;
            }
            
            //if the incoming request is an internal:* or a shard request allow only if request was sent by a server node
            //if transport channel is not a netty channel but a direct or local channel (e.g. send via network) then allow it (regardless of beeing a internal: or shard request)
            //also allow when issued from a remote cluster for cross cluster search
            if ( !HeaderHelper.isInterClusterRequest(getThreadContext()) 
                    && !HeaderHelper.isTrustedClusterRequest(getThreadContext()) 
                    && !transportChannel.action().equals("internal:transport/handshake") 
                    && (transportChannel.action().startsWith("internal:") || transportChannel.action().contains("["))) {

                auditLog.logMissingPrivileges(transportChannel.action(), request, task);
                log.error("Internal or shard requests ("+transportChannel.action()+") not allowed from a non-server node for transport type "+transportChannel.getChannelType());
                transportChannel.sendResponse(new ElasticsearchSecurityException(
                        "Internal or shard requests not allowed from a non-server node for transport type "+transportChannel.getChannelType()));
                return;
            }
            
            
            String principal = null;

            if ((principal = getThreadContext().getTransient(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL)) == null) {
                Exception ex = new ElasticsearchSecurityException(
                        "No SSL client certificates found for transport type "+transportChannel.getChannelType()+". Search Guard needs the Search Guard SSL plugin to be installed");
                auditLog.logSSLException(request, ex, transportChannel.action(), task);
                log.error("No SSL client certificates found for transport type "+transportChannel.getChannelType()+". Search Guard needs the Search Guard SSL plugin to be installed");
                transportChannel.sendResponse(ex);
                return;
            } else {
                
                if(getThreadContext().getTransient(ConfigConstants.SG_ORIGIN) == null) {
                    getThreadContext().putTransient(ConfigConstants.SG_ORIGIN, Origin.TRANSPORT.toString());
                }
                
                //network intercluster request or cross search cluster request
                if(HeaderHelper.isInterClusterRequest(getThreadContext()) 
                        || HeaderHelper.isTrustedClusterRequest(getThreadContext())) {
                    
                    final String userHeader = getThreadContext().getHeader(ConfigConstants.SG_USER_HEADER);
                    
                    if(Strings.isNullOrEmpty(userHeader)) {
                        //user can be null when a node client wants connect
                        //getThreadContext().putTransient(ConfigConstants.SG_USER, User.SG_INTERNAL);               
                    } else {
                        getThreadContext().putTransient(ConfigConstants.SG_USER, Objects.requireNonNull((User) Base64Helper.deserializeObject(userHeader)));
                    }
                    
                    String originalRemoteAddress = getThreadContext().getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER);
                    
                    if(!Strings.isNullOrEmpty(originalRemoteAddress)) {
                        getThreadContext().putTransient(ConfigConstants.SG_REMOTE_ADDRESS, new TransportAddress((InetSocketAddress) Base64Helper.deserializeObject(originalRemoteAddress)));
                    } else {
                        getThreadContext().putTransient(ConfigConstants.SG_REMOTE_ADDRESS, (TransportAddress)request.remoteAddress());
                    }
                    
                } else {
                    
                    //this is a netty request from a non-server node (maybe also be internal: or a shard request)
                    //and therefore issued by a transport client
                    
                    if(SSLRequestHelper.containsBadHeader(getThreadContext(), ConfigConstants.SG_CONFIG_PREFIX)) {
                        final ElasticsearchException exception = ExceptionUtils.createBadHeaderException();
                        auditLog.logBadHeaders(request, transportChannel.action(), task);
                        log.error("Error validating headers");
                        transportChannel.sendResponse(exception);
                        return;
                    }
                    
                    //TODO SG6 exception handling, introduce authexception
                    
                    User user;
                    //try {
                        if((user = backendRegistry.authenticate(request, principal, task)) == null) {
                            
                            if(transportChannel.action().equals(WhoAmIAction.NAME)) {
                                super.messageReceivedDecorate(request, handler, transportChannel, task);
                                return;
                            }
                            
                            if(transportChannel.action().equals("cluster:monitor/nodes/liveness")
                                    || transportChannel.action().equals("internal:transport/handshake")) {
                                super.messageReceivedDecorate(request, handler, transportChannel, task);
                                return;
                            }
                            
                            
                            log.error("Cannot authenticate {} for {}", (User) getThreadContext().getTransient(ConfigConstants.SG_USER), transportChannel.action());
                            transportChannel.sendResponse(new ElasticsearchSecurityException("Cannot authenticate "+getThreadContext().getTransient(ConfigConstants.SG_USER)));
                            return;
                        }
                    //} catch (Exception e) {
                        //    log.error("Error authentication transport user "+e, e);
                        //auditLog.logFailedLogin(principal, false, null, request);
                        //transportChannel.sendResponse(ExceptionsHelper.convertToElastic(e));
                        //return;
                        //}
                    
                    getThreadContext().putTransient(ConfigConstants.SG_USER, user);
                    TransportAddress originalRemoteAddress = request.remoteAddress();
                    
                    if(originalRemoteAddress != null && (originalRemoteAddress instanceof TransportAddress)) {
                        getThreadContext().putTransient(ConfigConstants.SG_REMOTE_ADDRESS, originalRemoteAddress);
                    } else {
                        log.error("Request has no proper remote address {}", originalRemoteAddress);
                        transportChannel.sendResponse(new ElasticsearchException("Request has no proper remote address"));
                        return;
                    }
                }
                
                super.messageReceivedDecorate(request, handler, transportChannel, task);
            }
        } finally {
            if(sgContext != null) {
                sgContext.close();
            } 
        }
    }
   
    @Override
    protected void addAdditionalContextValues(final String action, final TransportRequest request, final X509Certificate[] localCerts, final X509Certificate[] peerCerts, final String principal)
            throws Exception {

        boolean isInterClusterRequest = requestEvalProvider.isInterClusterRequest(request, localCerts, peerCerts, principal);

        if (isInterClusterRequest) {
            boolean fromTn = Boolean.parseBoolean(getThreadContext().getHeader("_sg_header_tn"));
            if(fromTn || cs.getClusterName().value().equals((String) getThreadContext().getHeader("_sg_remotecn"))) {
            
                if (log.isTraceEnabled() && !action.startsWith("internal:")) {
                    log.trace("Is inter cluster request ({}/{}/{})", action, request.getClass(), request.remoteAddress());
                }
                
                getThreadContext().putTransient(ConfigConstants.SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST, Boolean.TRUE);
            } else {
                getThreadContext().putTransient(ConfigConstants.SG_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST, Boolean.TRUE);
            }

        } else {
            if (log.isTraceEnabled()) {
                log.trace("Is not an inter cluster request");
            }
        }

        super.addAdditionalContextValues(action, request, localCerts, peerCerts, principal);
    }
    
    @Override
    protected void errorThrown(Throwable t, final TransportRequest request, String action, Task task) {
        auditLog.logSSLException(request, t, action, task);
    }
}
