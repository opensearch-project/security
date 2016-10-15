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
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLRequestHandler;
import com.floragunn.searchguard.ssl.util.SSLRequestHelper;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;

public class SearchGuardRequestHandler<T extends TransportRequest> extends SearchGuardSSLRequestHandler<T> {

    private Provider<BackendRegistry> backendRegistry;
    private Provider<AuditLog> auditLog;
    private final String certOid;
    
    SearchGuardRequestHandler(String action, 
            TransportRequestHandler<T> actualHandler, 
            ThreadPool threadPool,
            Provider<BackendRegistry> backendRegistry,
            Provider<AuditLog> auditLog,
            final String certOid) {
        super(action, actualHandler, threadPool);
        this.backendRegistry = backendRegistry;
        this.auditLog = auditLog;
        this.certOid = certOid;
    }
    
    @Override
    protected void messageReceivedDecorate(final T request, final TransportRequestHandler<T> handler,
            final TransportChannel transportChannel, Task task) throws Exception {
        
        final ThreadContext.StoredContext sgContext = getThreadContext().newStoredContext();
        
        try {

            String ct = (String) getThreadContext().getTransient(ConfigConstants.SG_CHANNEL_TYPE);
           
           if(transportChannel.getChannelType()==null) {
               throw new RuntimeException("Can not determine channel type (null)");
           }
                       
            if(ct == null)
                 getThreadContext().putTransient(ConfigConstants.SG_CHANNEL_TYPE, transportChannel.getChannelType());
            else
                if(!ct.equals(transportChannel.getChannelType())) 
                    throw new RuntimeException("channel type mismtach "+ct+"!="+transportChannel.getChannelType());
            
            //bypass non-netty requests
            if(transportChannel.getChannelType().equals("local") || transportChannel.getChannelType().equals("direct")) {
                super.messageReceivedDecorate(request, handler, transportChannel, task);
                return;
            }
            
            //if the incoming request is an internal:* or a shard request allow only if request was sent by a server node
            //if transport channel is not a netty channel but a direct or local channel (e.g. send via network) then allow it (regardless of beeing a internal: or shard request)
            if (!HeaderHelper.isInterClusterRequest(getThreadContext()) 
                    && (transportChannel.action().startsWith("internal:") || transportChannel.action().contains("["))) {
                auditLog.get().logMissingPrivileges(transportChannel.action(), request);
                log.error("Internal or shard requests not allowed from a non-server node for transport type "+transportChannel.getChannelType());
                transportChannel.sendResponse(new ElasticsearchSecurityException(
                        "Internal or shard requests not allowed from a non-server node for transport type "+transportChannel.getChannelType()));
                return;
            }
            
            
            String principal = null;

            if ((principal = getThreadContext().getTransient(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL)) == null) {
                Exception ex = new ElasticsearchSecurityException(
                        "No SSL client certificates found for transport type "+transportChannel.getChannelType()+". Search Guard needs the Search Guard SSL plugin to be installed");
                auditLog.get().logSSLException(request, ex, transportChannel.action());
                log.error("No SSL client certificates found for transport type "+transportChannel.getChannelType()+". Search Guard needs the Search Guard SSL plugin to be installed");
                transportChannel.sendResponse(ex);
                return;
            } else {
                
                if(HeaderHelper.isInterClusterRequest(getThreadContext())) {
                    
                    String userHeader = getThreadContext().getHeader(ConfigConstants.SG_USER_HEADER);
                    
                    if(Strings.isNullOrEmpty(userHeader)) {
                        //user can be null when a node client wants connect
                       getThreadContext().putTransient(ConfigConstants.SG_USER, User.SG_INTERNAL);               
                    } else {
                        getThreadContext().putTransient(ConfigConstants.SG_USER, Objects.requireNonNull((User) Base64Helper.deserializeObject(userHeader)));
                    }
                    
                    String originalRemoteAddress = getThreadContext().getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER);
                    
                    if(!Strings.isNullOrEmpty(originalRemoteAddress)) {
                        getThreadContext().putTransient(ConfigConstants.SG_REMOTE_ADDRESS, new InetSocketTransportAddress((InetSocketAddress) Base64Helper.deserializeObject(originalRemoteAddress)));
                    }
                    
                } else {
                    
                    //this is a netty request from a non-server node (maybe also be internal: or a shard request)
                    //and therefore issued by a transport client
                    
                    if(SSLRequestHelper.containsBadHeader(getThreadContext(), ConfigConstants.SG_CONFIG_PREFIX)) {
                        final ElasticsearchException exception = new ElasticsearchException("bad header found");      
                        auditLog.get().logBadHeaders(request);
                        log.error("Error validating headers");
                        transportChannel.sendResponse(exception);
                        return;
                    }
                    
                    User user;
                    try {
                        if((user = backendRegistry.get().authenticate(request, transportChannel, principal)) == null) {
                            log.error("Cannot authenticate {}", (User) getThreadContext().getTransient(ConfigConstants.SG_USER));
                            transportChannel.sendResponse(new ElasticsearchSecurityException("Cannot authenticate "+getThreadContext().getTransient(ConfigConstants.SG_USER)));
                            return;
                        }
                    } catch (Exception e) {
                        log.error("Error authentication transport user "+e, e);
                        auditLog.get().logFailedLogin(principal, request);
                        transportChannel.sendResponse(ExceptionsHelper.convertToElastic(e));
                        return;
                    }
                    
                    getThreadContext().putTransient(ConfigConstants.SG_USER, user);
                    TransportAddress originalRemoteAddress = request.remoteAddress();
                    
                    if(originalRemoteAddress != null && (originalRemoteAddress instanceof InetSocketTransportAddress)) {
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
            
            getThreadContext().putTransient(ConfigConstants.SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST, Boolean.TRUE);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Is not an inter cluster request");
            }
        }
        super.addAdditionalContextValues(action, request, certs);
    }
    
    @Override
    protected void errorThrown(Throwable t, final TransportRequest request, String action) {
        auditLog.get().logSSLException(request, t, action);
    }
}
