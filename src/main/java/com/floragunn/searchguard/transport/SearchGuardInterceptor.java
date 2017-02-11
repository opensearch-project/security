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
import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportException;
import org.elasticsearch.transport.TransportInterceptor.AsyncSender;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.configuration.InstanceId;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;
import com.google.common.collect.Maps;

public class SearchGuardInterceptor {
    
    private Provider<BackendRegistry> backendRegistry;
    private Provider<AuditLog> auditLog;
    private final String certOid;
    private final ThreadPool threadPool;
    private final PrincipalExtractor principalExtractor;
    private final Provider<InterClusterRequestEvaluator> requestEvalProvider;
    private static Map<String, SearchGuardInterceptor> instancemap = new HashMap<String, SearchGuardInterceptor>(); 
    
    @Inject
    public SearchGuardInterceptor(final InstanceId id, final Settings settings, 
            final ThreadPool threadPool, final Provider<BackendRegistry> backendRegistry, 
            final Provider<AuditLog> auditLog, final PrincipalExtractor principalExtractor,
            final Provider<InterClusterRequestEvaluator> requestEvalProvider) {
        this.backendRegistry = backendRegistry;
        this.auditLog = auditLog;
        this.certOid = settings.get("searchguard.cert.oid", "1.2.3.4.5.5");
        this.threadPool = threadPool;
        this.principalExtractor = principalExtractor;
        this.requestEvalProvider = requestEvalProvider;
        
        synchronized(SearchGuardInterceptor.class) {
            instancemap.put(id.getId(), this);
        }
    }
    
    public static SearchGuardInterceptor getSearchGuardInterceptor(String id) {
        return instancemap.get(id);
    }
    
    public <T extends TransportRequest> SearchGuardRequestHandler<T> getHandler(String action, 
            TransportRequestHandler<T> actualHandler) {
        return new SearchGuardRequestHandler<T>(action, actualHandler, threadPool, backendRegistry, auditLog, principalExtractor, requestEvalProvider);
    }

    public <T extends TransportResponse> void sendRequestDecorate(AsyncSender sender, DiscoveryNode node, String action,
            TransportRequest request, TransportRequestOptions options, TransportResponseHandler<T> handler) {
 
        final Map<String, String> origHeaders = getThreadContext().getHeaders();  
        final User user = getThreadContext().getTransient(ConfigConstants.SG_USER);
        final Object remoteAdress = getThreadContext().getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
        
        ThreadContext.StoredContext storedContext = getThreadContext().newStoredContext();
        
        try (ThreadContext.StoredContext newCtx = getThreadContext().stashAndMergeHeaders(Maps.filterKeys(origHeaders, k->k.equals(ConfigConstants.SG_CONF_REQUEST_HEADER)))) {
            RestoringTransportResponseHandler<T> restoringHandler = new RestoringTransportResponseHandler<T>(handler, storedContext);
            getThreadContext().putTransient(ConfigConstants.SG_USER, user);
            getThreadContext().putTransient(ConfigConstants.SG_REMOTE_ADDRESS, remoteAdress);
            attachHeaders(action, remoteAdress, user);
            sender.sendRequest(node, action, request, options, restoringHandler);
        }
    }
    
    private void attachHeaders(final String action, final Object remoteAdr, final User origUser) { 
        // keep original address

        if (remoteAdr != null && remoteAdr instanceof InetSocketTransportAddress) {
            
            String remoteAddressHeader = getThreadContext().getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER);
           
            if(remoteAddressHeader == null) {
                getThreadContext().putHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER, Base64Helper.serializeObject(((InetSocketTransportAddress) remoteAdr).address()));
            } else {
                if(!((InetSocketAddress)Base64Helper.deserializeObject(remoteAddressHeader)).equals(((InetSocketTransportAddress) remoteAdr).address())) {
                    throw new RuntimeException("remote address mismatch "+Base64Helper.deserializeObject(remoteAddressHeader)+"!="+((InetSocketTransportAddress) remoteAdr).address());
                }   
            }
        }

        User user = origUser;
        
        //we originate the request, so no user here to forward
        if(user == null && remoteAdr == null && getThreadContext().getTransient(ConfigConstants.SG_CHANNEL_TYPE) == null) {
            user = User.SG_INTERNAL;
        }
        
        if(user != null) {            
            String userHeader = getThreadContext().getHeader(ConfigConstants.SG_USER_HEADER);
            
            if(userHeader == null) {
                getThreadContext().putHeader(ConfigConstants.SG_USER_HEADER, Base64Helper.serializeObject(user));
            } else {
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
