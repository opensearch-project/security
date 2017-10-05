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

package com.floragunn.searchguard.filter;

import java.nio.file.Path;

import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.AuditLog.Origin;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.ssl.util.ExceptionUtils;
import com.floragunn.searchguard.ssl.util.SSLRequestHelper;
import com.floragunn.searchguard.ssl.util.SSLRequestHelper.SSLInfo;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HTTPHelper;

public class SearchGuardRestFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final BackendRegistry registry;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final PrincipalExtractor principalExtractor;
    private final Settings settings;
    private final Path configPath;

    public SearchGuardRestFilter(final BackendRegistry registry, final AuditLog auditLog,
            final ThreadPool threadPool, final PrincipalExtractor principalExtractor,
            final Settings settings, final Path configPath) {
        super();
        this.registry = registry;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
        this.principalExtractor = principalExtractor;
        this.settings = settings;
        this.configPath = configPath;
    }
    
    public RestHandler wrap(RestHandler original) {
        return new RestHandler() {
            
            @Override
            public void handleRequest(RestRequest request, RestChannel channel, NodeClient client) throws Exception {
                if(!checkAndAuthenticateRequest(request, channel, client)) {
                    original.handleRequest(request, channel, client);
                }
            }
        };
    }

    private boolean checkAndAuthenticateRequest(RestRequest request, RestChannel channel, NodeClient client) throws Exception {

        threadContext.putTransient(ConfigConstants.SG_ORIGIN, Origin.REST.toString());
        
        if(HTTPHelper.containsBadHeader(request)) {
            log.error("bad http header found");
            auditLog.logBadHeaders(request);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, ExceptionUtils.createBadHeaderException()));
            return true;
        }
        
        if(SSLRequestHelper.containsBadHeader(threadContext, ConfigConstants.SG_CONFIG_PREFIX)) {
            log.error("bad http header found");
            auditLog.logBadHeaders(request);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, ExceptionUtils.createBadHeaderException()));
            return true;
        }

        final SSLInfo sslInfo;
        try {
            if((sslInfo = SSLRequestHelper.getSSLInfo(settings, configPath, request, principalExtractor)) != null) {
                if(sslInfo.getPrincipal() != null) {
                    threadContext.putTransient("_sg_ssl_principal", sslInfo.getPrincipal());
                }
                
                if(sslInfo.getX509Certs() != null) {
                     threadContext.putTransient("_sg_ssl_peer_certificates", sslInfo.getX509Certs());
                }
                threadContext.putTransient("_sg_ssl_protocol", sslInfo.getProtocol());
                threadContext.putTransient("_sg_ssl_cipher", sslInfo.getCipher());
            }
        } catch (SSLPeerUnverifiedException e) {
            log.error("No ssl info", e);
            auditLog.logSSLException(request, e);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, e));
            return true;
        }

        if(request.method() != Method.OPTIONS 
                && !"/_searchguard/license".equals(request.path())) {
            if (!registry.authenticate(request, channel, threadContext)) {
                // another roundtrip
                return true;
            }
        }
        
        return false;
    }
}
