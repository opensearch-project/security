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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.http;

import java.net.InetSocketAddress;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.netty4.Netty4HttpRequest;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationChangeListener;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

public class XFFResolver implements ConfigurationChangeListener {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile boolean enabled;
    private volatile RemoteIpDetector detector;
    private final ThreadContext threadContext;
        
    public XFFResolver(final ThreadPool threadPool) {
        super();
        this.threadContext = threadPool.getThreadContext();
    }

    public TransportAddress resolve(final RestRequest request) throws ElasticsearchSecurityException {
        
        if(log.isTraceEnabled()) {
            log.trace("resolve {}", request.getRemoteAddress());
        }
        
        if(enabled && request.getRemoteAddress() instanceof InetSocketAddress && request instanceof Netty4HttpRequest) {

            final InetSocketAddress isa = new InetSocketAddress(detector.detect((Netty4HttpRequest) request, threadContext), ((InetSocketAddress)request.getRemoteAddress()).getPort());
        
            if(isa.isUnresolved()) {           
                throw new ElasticsearchSecurityException("Cannot resolve address "+isa.getHostString());
            }
                
             
            if(log.isTraceEnabled()) {
                if(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE) == Boolean.TRUE) {
                    log.trace("xff resolved {} to {}", request.getRemoteAddress(), isa);
                } else {
                    log.trace("no xff done for {}",request.getClass());
                }
            }
            return new TransportAddress(isa);
        } else if(request.getRemoteAddress() instanceof InetSocketAddress){
            
            if(log.isTraceEnabled()) {
                log.trace("no xff done (enabled or no netty request) {},{},{},{}",enabled, request.getClass());

            }
            return new TransportAddress((InetSocketAddress)request.getRemoteAddress());
        } else {
            throw new ElasticsearchSecurityException("Cannot handle this request. Remote address is "+request.getRemoteAddress()+" with request class "+request.getClass());
        }
    }

    @Override
    public void onChange(final Settings settings) {
        enabled = settings.getAsBoolean("opendistro_security.dynamic.http.xff.enabled", true);
        if(enabled) {
            detector = new RemoteIpDetector();
            detector.setInternalProxies(settings.get("opendistro_security.dynamic.http.xff.internalProxies", detector.getInternalProxies()));
            detector.setProxiesHeader(settings.get("opendistro_security.dynamic.http.xff.proxiesHeader", detector.getProxiesHeader()));
            detector.setRemoteIpHeader(settings.get("opendistro_security.dynamic.http.xff.remoteIpHeader", detector.getRemoteIpHeader()));
            detector.setTrustedProxies(settings.get("opendistro_security.dynamic.http.xff.trustedProxies", detector.getTrustedProxies()));
        } else {
            detector = null;
        }
    }
}
