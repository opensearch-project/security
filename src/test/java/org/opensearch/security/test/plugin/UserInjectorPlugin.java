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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.test.plugin;

import java.nio.file.Path;
import java.util.Map;
import java.util.function.Supplier;

import org.opensearch.common.network.NetworkService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.common.util.PageCacheRecycler;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.http.HttpServerTransport;
import org.opensearch.http.HttpServerTransport.Dispatcher;
import org.opensearch.http.netty4.Netty4HttpServerTransport;
import org.opensearch.indices.breaker.CircuitBreakerService;
import org.opensearch.plugins.NetworkPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.SharedGroupFactory;

import com.google.common.collect.ImmutableMap;

/**
 * Mimics the behavior of system integrators that run their own plugins (i.e. server transports)
 * in front of OpenSearch Security. This transport just copies the user string from the
 * REST headers to the ThreadContext to test user injection.
 * @author jkressin
 */
public class UserInjectorPlugin extends Plugin implements NetworkPlugin {
    
    Settings settings;
    private final SharedGroupFactory sharedGroupFactory;
    ThreadPool threadPool;
    
    public UserInjectorPlugin(final Settings settings, final Path configPath) {        
        this.settings = settings;
        sharedGroupFactory = new SharedGroupFactory(settings);
    }

    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            PageCacheRecycler pageCacheRecycler, CircuitBreakerService circuitBreakerService, NamedXContentRegistry xContentRegistry,
            NetworkService networkService, Dispatcher dispatcher, ClusterSettings clusterSettings) {

        final UserInjectingDispatcher validatingDispatcher = new UserInjectingDispatcher(dispatcher);
        return ImmutableMap.of("org.opensearch.security.http.UserInjectingServerTransport",
                () -> new UserInjectingServerTransport(settings, networkService, bigArrays, threadPool, xContentRegistry, validatingDispatcher, clusterSettings, sharedGroupFactory));
    }
    
    class UserInjectingServerTransport extends Netty4HttpServerTransport {
        
        public UserInjectingServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
                                            final ThreadPool threadPool, final NamedXContentRegistry namedXContentRegistry, final Dispatcher dispatcher, ClusterSettings clusterSettings, SharedGroupFactory sharedGroupFactory) {
            super(settings, networkService, bigArrays, threadPool, namedXContentRegistry, dispatcher, clusterSettings, sharedGroupFactory);
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
        public void dispatchBadRequest(RestChannel channel, ThreadContext threadContext, Throwable cause) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, channel.request().header(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER));
            originalDispatcher.dispatchBadRequest(channel, threadContext, cause);
        }
    }

}
