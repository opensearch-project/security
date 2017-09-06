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
import java.util.Map;

import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport.Connection;
import org.elasticsearch.transport.TransportException;
import org.elasticsearch.transport.TransportInterceptor.AsyncSender;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;
import com.google.common.collect.Maps;

public class SearchGuardInterceptor {
    
    private BackendRegistry backendRegistry;
    private AuditLog auditLog;
    private final ThreadPool threadPool;
    private final PrincipalExtractor principalExtractor;
    private final InterClusterRequestEvaluator requestEvalProvider;
    private final ClusterService cs;
    private final Settings settings;

    public SearchGuardInterceptor(final Settings settings, 
            final ThreadPool threadPool, final BackendRegistry backendRegistry, 
            final AuditLog auditLog, final PrincipalExtractor principalExtractor,
            final InterClusterRequestEvaluator requestEvalProvider,
            final ClusterService cs) {
        this.backendRegistry = backendRegistry;
        this.auditLog = auditLog;
        this.threadPool = threadPool;
        this.principalExtractor = principalExtractor;
        this.requestEvalProvider = requestEvalProvider;
        this.cs = cs;
        this.settings = settings;
    }

    public <T extends TransportRequest> SearchGuardRequestHandler<T> getHandler(String action, 
            TransportRequestHandler<T> actualHandler) {
        return new SearchGuardRequestHandler<T>(action, actualHandler, threadPool, backendRegistry, auditLog, principalExtractor, requestEvalProvider, cs);
    }

    
    public <T extends TransportResponse> void sendRequestDecorate(AsyncSender sender, Connection connection, String action,
            TransportRequest request, TransportRequestOptions options, TransportResponseHandler<T> handler) {
 
        final Map<String, String> origHeaders0 = getThreadContext().getHeaders();  
        final User user0 = getThreadContext().getTransient(ConfigConstants.SG_USER);
        final Object remoteAdress0 = getThreadContext().getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
        
        try (ThreadContext.StoredContext stashedContext = getThreadContext().stashContext()) {
            final RestoringTransportResponseHandler<T> restoringHandler = new RestoringTransportResponseHandler<T>(handler, stashedContext);
            //getThreadContext().putHeader("_sg_remotecn", cs.getClusterName().value());
            getThreadContext().putHeader("_sg_remotecn", settings.get("searchguard.tribe.clustername", cs.getClusterName().value()));
            
            if(settings.getAsBoolean("action.master.force_local", false) 
                    && settings.getByPrefix("tribe").getAsMap().size() > 0) {
                getThreadContext().putHeader("_sg_header_tn", "true");
            }
            
            //add conf request header if any
            getThreadContext().putHeader(
                    Maps.filterKeys(origHeaders0, k->k!=null && (
                            k.equals(ConfigConstants.SG_CONF_REQUEST_HEADER)
                            || k.equals(ConfigConstants.SG_REMOTE_ADDRESS_HEADER)
                            || k.equals(ConfigConstants.SG_USER_HEADER)
                            || k.equals(ConfigConstants.SG_DLS_QUERY)
                            || k.equals(ConfigConstants.SG_FLS_FIELDS)
                            )));
            ensureCorrectHeaders(action, remoteAdress0, user0);
            sender.sendRequest(connection, action, request, options, restoringHandler);
        }
    }

    private void ensureCorrectHeaders(final String action, final Object remoteAdr, final User origUser) { 
        // keep original address

        if (remoteAdr != null && remoteAdr instanceof TransportAddress) {
            
            String remoteAddressHeader = getThreadContext().getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER);
           
            if(remoteAddressHeader == null) {
                getThreadContext().putHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER, Base64Helper.serializeObject(((TransportAddress) remoteAdr).address()));
            } else {
                if(!((InetSocketAddress)Base64Helper.deserializeObject(remoteAddressHeader)).equals(((TransportAddress) remoteAdr).address())) {
                    throw new RuntimeException("remote address mismatch "+Base64Helper.deserializeObject(remoteAddressHeader)+"!="+((TransportAddress) remoteAdr).address());
                }   
            }
        }
        
        if(origUser != null) {            
            String userHeader = getThreadContext().getHeader(ConfigConstants.SG_USER_HEADER);
            
            if(userHeader == null) {
                getThreadContext().putHeader(ConfigConstants.SG_USER_HEADER, Base64Helper.serializeObject(origUser));
            } else {
                if(!((User)Base64Helper.deserializeObject(userHeader)).getName().equals(origUser.getName())) {
                    throw new RuntimeException("user mismatch "+Base64Helper.deserializeObject(userHeader)+"!="+origUser);
                }
            }
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
