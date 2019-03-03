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

package com.amazon.opendistroforelasticsearch.security.test.plugin;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.http.HttpServerTransport.Dispatcher;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

/**
 * Mimics the behavior of system integrators that run their own plugins (i.e. server transports)
 * in front of Open Distro Security. This transport just copies the user string from the
 * REST headers to the ThreadContext to test user injection.
 * @author jkressin
 */
public class UserInjectorPlugin extends Plugin implements NetworkPlugin {
    
    Settings settings;
    ThreadPool threadPool;
    
    public UserInjectorPlugin(final Settings settings, final Path configPath) {        
        this.settings = settings;
    }

    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry,
            NamedXContentRegistry xContentRegistry, NetworkService networkService, Dispatcher dispatcher) {

        Map<String, Supplier<HttpServerTransport>> httpTransports = new HashMap<String, Supplier<HttpServerTransport>>(1);
        final UserInjectingDispatcher validatingDispatcher = new UserInjectingDispatcher(dispatcher);
        httpTransports.put("com.amazon.opendistroforelasticsearch.security.http.UserInjectingServerTransport", () -> new UserInjectingServerTransport(settings, networkService, bigArrays, threadPool, xContentRegistry, validatingDispatcher));        
        return httpTransports;
    }
    
    class UserInjectingServerTransport extends Netty4HttpServerTransport {
        
        public UserInjectingServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
                final ThreadPool threadPool, final NamedXContentRegistry namedXContentRegistry, final Dispatcher dispatcher) {
            super(settings, networkService, bigArrays, threadPool, namedXContentRegistry, dispatcher);                        
        }
    }
    
    class UserInjectingDispatcher implements Dispatcher {
        
        private Dispatcher originalDispatcher;

        public UserInjectingDispatcher(final Dispatcher originalDispatcher) {
            super();
            this.originalDispatcher = originalDispatcher;
        }

        @Override
        public void dispatchRequest(RestRequest request, RestChannel channel, ThreadContext threadContext) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, request.header(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER));
            originalDispatcher.dispatchRequest(request, channel, threadContext);
            
        }

        @Override
        public void dispatchBadRequest(RestRequest request, RestChannel channel, ThreadContext threadContext,
                Throwable cause) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, request.header(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER));
            originalDispatcher.dispatchBadRequest(request, channel, threadContext, cause);
            
        }
    }
    
}
