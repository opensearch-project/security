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
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.netty4.Netty4HttpChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;
import org.greenrobot.eventbus.Subscribe;

import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigModel;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

public class XFFResolver {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile boolean enabled;
    private volatile RemoteIpDetector detector;
    private final ThreadContext threadContext;
        
    public XFFResolver(final ThreadPool threadPool) {
        super();
        this.threadContext = threadPool.getThreadContext();
    }

    public TransportAddress resolve(final RestRequest request) throws ElasticsearchSecurityException {
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("resolve {}", request.getHttpChannel().getRemoteAddress());
        }
        
        if(enabled && request.getHttpChannel().getRemoteAddress() instanceof InetSocketAddress && request.getHttpChannel() instanceof Netty4HttpChannel) {

            final InetSocketAddress isa = new InetSocketAddress(detector.detect(request, threadContext), ((InetSocketAddress)request.getHttpChannel().getRemoteAddress()).getPort());
        
            if(isa.isUnresolved()) {           
                throw new ElasticsearchSecurityException("Cannot resolve address "+isa.getHostString());
            }
                
             
            if (isTraceEnabled) {
                if(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE) == Boolean.TRUE) {
                    log.trace("xff resolved {} to {}", request.getHttpChannel().getRemoteAddress(), isa);
                } else {
                    log.trace("no xff done for {}",request.getClass());
                }
            }
            return new TransportAddress(isa);
        } else if(request.getHttpChannel().getRemoteAddress() instanceof InetSocketAddress){
            
            if (isTraceEnabled) {
                log.trace("no xff done (enabled or no netty request) {},{},{},{}",enabled, request.getClass());

            }
            return new TransportAddress((InetSocketAddress)request.getHttpChannel().getRemoteAddress());
        } else {
            throw new ElasticsearchSecurityException("Cannot handle this request. Remote address is "+request.getHttpChannel().getRemoteAddress()+" with request class "+request.getClass());
        }
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        enabled = dcm.isXffEnabled();
        if(enabled) {
            detector = new RemoteIpDetector();
            detector.setInternalProxies(dcm.getInternalProxies());
            detector.setRemoteIpHeader(dcm.getRemoteIpHeader());
        } else {
            detector = null;
        }
    }
}
