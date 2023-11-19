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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.http;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;

import io.netty.channel.ChannelInboundHandlerAdapter;
import org.opensearch.common.network.NetworkService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.http.HttpHandlingSettings;
import org.opensearch.http.netty4.Netty4HttpServerTransport;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.ssl.http.netty.Netty4ConditionalDecompressor;
import org.opensearch.security.ssl.http.netty.Netty4HttpRequestHeaderVerifier;
import org.opensearch.telemetry.tracing.Tracer;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.SharedGroupFactory;

public class SecurityNonSslHttpServerTransport extends Netty4HttpServerTransport {

    private final ChannelInboundHandlerAdapter headerVerifier;

    public SecurityNonSslHttpServerTransport(
        final Settings settings,
        final NetworkService networkService,
        final BigArrays bigArrays,
        final ThreadPool threadPool,
        final NamedXContentRegistry namedXContentRegistry,
        final Dispatcher dispatcher,
        final ClusterSettings clusterSettings,
        final SharedGroupFactory sharedGroupFactory,
        final Tracer tracer,
        final SecurityRestFilter restFilter
    ) {
        super(
            settings,
            networkService,
            bigArrays,
            threadPool,
            namedXContentRegistry,
            dispatcher,
            clusterSettings,
            sharedGroupFactory,
            tracer
        );
        headerVerifier = new Netty4HttpRequestHeaderVerifier(restFilter, threadPool, settings);
    }

    @Override
    public ChannelHandler configureServerChannelHandler() {
        return new NonSslHttpChannelHandler(this, handlingSettings);
    }

    protected class NonSslHttpChannelHandler extends Netty4HttpServerTransport.HttpChannelHandler {

        protected NonSslHttpChannelHandler(Netty4HttpServerTransport transport, final HttpHandlingSettings handlingSettings) {
            super(transport, handlingSettings);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
        }
    }

    @Override
    protected ChannelInboundHandlerAdapter createHeaderVerifier() {
        return headerVerifier;
    }

    @Override
    protected ChannelInboundHandlerAdapter createDecompressor() {
        return new Netty4ConditionalDecompressor();
    }
}
