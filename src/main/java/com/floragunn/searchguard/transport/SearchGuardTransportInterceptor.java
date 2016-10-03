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
import java.util.Map;
import java.util.Objects;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.inject.Guice;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Injector;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportException;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.ssl.SearchGuardSSLPlugin.Holder;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLTransportInterceptor;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;

public class SearchGuardTransportInterceptor extends SearchGuardSSLTransportInterceptor {
    
    private Provider<BackendRegistry> backendRegistry;
    private Provider<AuditLog> auditLog;
    private final String certOid;
    
    @Inject
    public SearchGuardTransportInterceptor(final Settings settings, ThreadPool threadPool, Provider<BackendRegistry> backendRegistry, Provider<AuditLog> auditLog) {
        super(settings, threadPool);
        this.backendRegistry = backendRegistry;
        this.auditLog = auditLog;
        //injector = Guice.createInjector(module);
        this.certOid = settings.get("searchguard.cert.oid", "1.2.3.4.5.5");
    }

    @Override
    protected <T extends TransportResponse> void sendRequestDecorate(AsyncSender sender, DiscoveryNode node, String action,
            TransportRequest request, TransportRequestOptions options, TransportResponseHandler<T> handler) {
        
        //backendRegistry = injector.getProvider(BackendRegistry.class);
        //auditLog = injector.getProvider(AuditLog.class);
      //transient -> header
        //System.out.println("<<< send "+action+" from "+this.nodeName()+"->"+node.getName());
 
        final Map<String, String> origHeaders = getThreadContext().getHeaders();  
        User user = getThreadContext().getTransient(ConfigConstants.SG_USER);
        Object remoteAdress = getThreadContext().getTransient(ConfigConstants.SG_REMOTE_ADDRESS);

        ThreadContext.StoredContext storedContext = getThreadContext().newStoredContext();
        //this.threadContext.putHeader(Maps.filterKeys(origHeaders, k->k.equals(ConfigConstants.SG_CONF_REQUEST_HEADER)));
        
        try (ThreadContext.StoredContext newCtx = getThreadContext().stashAndMergeHeaders(Maps.filterKeys(origHeaders, k->k.equals(ConfigConstants.SG_CONF_REQUEST_HEADER)))) {
            RestoringTransportResponseHandler restoringHandler = new RestoringTransportResponseHandler(handler, storedContext);

            getThreadContext().putTransient(ConfigConstants.SG_USER, user);
            getThreadContext().putTransient(ConfigConstants.SG_REMOTE_ADDRESS, remoteAdress);

            attachHeaders(action);
            // LogHelper.logUserTrace("<-- Send {} to {} with {}/{}", action,
            // node.getName(), request.getContext(), request.getHeaders());
            super.sendRequestDecorate(sender, node, action, request, options, restoringHandler);
        }
    }
    
    private void attachHeaders(String action) { 
        // keep original address
        
        final Object remoteAdr = getThreadContext().getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
        if (remoteAdr != null && remoteAdr instanceof InetSocketTransportAddress) {
            
            String rHeader = getThreadContext().getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER);
           
            if(rHeader == null)
                getThreadContext().putHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER, Base64Helper.serializeObject(((InetSocketTransportAddress) remoteAdr).address()));
            else
                if(!((InetSocketAddress)Base64Helper.deserializeObject(rHeader)).equals(((InetSocketTransportAddress) remoteAdr).address())) {
                    throw new RuntimeException("remote address mismatch "+Base64Helper.deserializeObject(rHeader)+"!="+((InetSocketTransportAddress) remoteAdr).address());
                }
            
            //LogHelper.logUserTrace("<-- Put remote address {} in header (from sg_remote_address ctx)", remoteAdr);
        }
        
        User user = getThreadContext().getTransient(ConfigConstants.SG_USER);
        
        //System.out.println("<<< send user: "+user);
        
      //TODO check remoteAddress
        //if(user == null /* && action.startsWith("internal:")  && request.remoteAddress() == null */) {
        if(user == null /* && action.startsWith("internal:") */ && getThreadContext().getTransient(ConfigConstants.SG_CHANNEL_TYPE) == null) {
            user = User.SG_INTERNAL;
        }
        
        if(user != null) {
            //log.error(Thread.currentThread().getName()+" put h: "+ConfigConstants.SG_USER_HEADER+" "+action+"/"+request.remoteAddress());
            
            String userHeader = getThreadContext().getHeader(ConfigConstants.SG_USER_HEADER);
            
            if(userHeader == null) {
                getThreadContext().putHeader(ConfigConstants.SG_USER_HEADER, Base64Helper.serializeObject(user));
                //System.out.println("<<< send put: "+user);
            }
            else {
                if(!((User)Base64Helper.deserializeObject(userHeader)).getName().equals(user.getName())) {
                    throw new RuntimeException("user mismatch "+Base64Helper.deserializeObject(userHeader)+"!="+user);
                }
            }
        } else {
            throw new ElasticsearchSecurityException("user must not be null here for " + action);
        }
    }

    private ThreadContext getThreadContext() {
        return threadPool.getThreadContext();
    }

    
    @Override
    protected void messageReceivedDecorate(final TransportRequest request, final TransportRequestHandler handler,
            final TransportChannel transportChannel, Task task) throws Exception {
        //backendRegistry = injector.getProvider(BackendRegistry.class);
        //auditLog = injector.getProvider(AuditLog.class);
        //System.out.println("-I- "+transportChannel.action()+" via "+transportChannel.getChannelType());
        
        final ThreadContext.StoredContext sgContext = getThreadContext().newStoredContext();
        try {
            
            //TODO RequestHolder not longer needed?
           // final com.floragunn.searchguard.configuration.RequestHolder context = new com.floragunn.searchguard.configuration.RequestHolder(
            //         request);
            // com.floragunn.searchguard.configuration.RequestHolder.setCurrent(context);

           String ct = (String) getThreadContext().getTransient(ConfigConstants.SG_CHANNEL_TYPE);
           
           if(transportChannel.getChannelType()==null) {
               throw new RuntimeException("ct null");
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
            if (!isInterClusterRequest(request) 
                    && (transportChannel.action().startsWith("internal:") || transportChannel.action().contains("["))) {
                auditLog.get().logMissingPrivileges(transportChannel.action(), request);
                log.error("Internal or shard requests not allowed from a non-server node for transport type "+transportChannel.getChannelType());
                transportChannel.sendResponse(new ElasticsearchSecurityException(
                        "Internal or shard requests not allowed from a non-server node for transport type "+transportChannel.getChannelType()));
                return;
            }
            
            
            String principal = null;
            //LogHelper.logUserTrace("Received {} from {} via {}", transportChannel.action(), request.remoteAddress(),
            //        transportChannel.getClass());
            //LogHelper.logUserTrace("CTX/H {}/{}", request.getContext(), request.getHeaders());

            if ((principal = getThreadContext().getTransient(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL)) == null) {
                Exception ex = new ElasticsearchSecurityException(
                        "No SSL client certificates found for transport type "+transportChannel.getChannelType()+". Search Guard needs the Search Guard SSL plugin to be installed");
                auditLog.get().logSSLException(request, ex, transportChannel.action());
                log.error("No SSL client certificates found for transport type "+transportChannel.getChannelType()+". Search Guard needs the Search Guard SSL plugin to be installed");
                transportChannel.sendResponse(ex);
                return;
            } else {
                
                if(isInterClusterRequest(request)) {
                    
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
                    
                    try {
                        HeaderHelper.checkSGHeader(getThreadContext());
                    } catch (Exception e) {
                        auditLog.get().logBadHeaders(request);
                        log.error("Error validating headers "+e, e);
                        transportChannel.sendResponse(ExceptionsHelper.convertToElastic(e));
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
                //LogHelper.logUserTrace("--> Put user {} in context (from sg_ssl_transport_principal)", principal);
            }

            //LogHelper.logUserTrace(">>>> TransportService for {}", transportChannel.action());

            
            
        } finally {
            //LogHelper.logUserTrace("<<<< TransportService {}", transportChannel.action());
            
            if(sgContext != null) {
                sgContext.close();
            } 
            
            //TODO RequestHolder no longer needed
            //com.floragunn.searchguard.configuration.RequestHolder.removeCurrent();
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
    
    private boolean isInterClusterRequest(final TransportRequest request) {
        return getThreadContext().getTransient(ConfigConstants.SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST) == Boolean.TRUE;
    }
    
  //based on
    //org.elasticsearch.transport.TransportService.ContextRestoreResponseHandler<T>
    //which is private scoped
    private static class RestoringTransportResponseHandler<T extends TransportResponse> implements TransportResponseHandler<T> {

        private final ThreadContext.StoredContext contextToRestore;
        private final TransportResponseHandler<T> innerHandler;

        private RestoringTransportResponseHandler(TransportResponseHandler<T> innerHandler, ThreadContext.StoredContext contextToRestore) {
            this.contextToRestore = contextToRestore;
            this.innerHandler = innerHandler;
        }

        public T newInstance() {
            return innerHandler.newInstance();
        }

        public void handleResponse(T response) {
            contextToRestore.restore();
            innerHandler.handleResponse(response);
        }

        public void handleException(TransportException e) {
            contextToRestore.restore();
            innerHandler.handleException(e);
        }

        public String executor() {
            return innerHandler.executor();
        }
    }

}
