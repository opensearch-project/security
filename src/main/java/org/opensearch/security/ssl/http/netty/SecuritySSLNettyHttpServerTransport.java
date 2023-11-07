/*
 * Copyright 2015-2017 floragunn GmbH
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

package org.opensearch.security.ssl.http.netty;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.network.NetworkService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.http.HttpChannel;
import org.opensearch.http.HttpHandlingSettings;
import org.opensearch.http.netty4.Netty4HttpServerTransport;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.telemetry.tracing.Tracer;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.SharedGroupFactory;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandler;

public class SecuritySSLNettyHttpServerTransport extends Netty4HttpServerTransport {

    private static final Logger logger = LogManager.getLogger(SecuritySSLNettyHttpServerTransport.class);
    private final SecurityKeyStore sks;
    private final SslExceptionHandler errorHandler;
    private final ChannelInboundHandlerAdapter headerVerifier;

    public SecuritySSLNettyHttpServerTransport(
        final Settings settings,
        final NetworkService networkService,
        final BigArrays bigArrays,
        final ThreadPool threadPool,
        final SecurityKeyStore sks,
        final NamedXContentRegistry namedXContentRegistry,
        final ValidatingDispatcher dispatcher,
        final SslExceptionHandler errorHandler,
        ClusterSettings clusterSettings,
        SharedGroupFactory sharedGroupFactory,
        Tracer tracer,
        SecurityRestFilter restFilter
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
        this.sks = sks;
        this.errorHandler = errorHandler;
        headerVerifier = new Netty4HttpRequestHeaderVerifier(restFilter, threadPool, settings);
    }

    @Override
    public ChannelHandler configureServerChannelHandler() {
        return new SSLHttpChannelHandler(this, handlingSettings, sks);
    }

    @Override
    public void onException(HttpChannel channel, Exception cause0) {
        Throwable cause = cause0;

        if (cause0 instanceof DecoderException && cause0 != null) {
            cause = cause0.getCause();
        }

        errorHandler.logError(cause, true);
        logger.error("Exception during establishing a SSL connection: " + cause, cause);

        super.onException(channel, cause0);
    }

    protected class SSLHttpChannelHandler extends Netty4HttpServerTransport.HttpChannelHandler {

        protected SSLHttpChannelHandler(
            Netty4HttpServerTransport transport,
            final HttpHandlingSettings handlingSettings,
            final SecurityKeyStore odsks
        ) {
            super(transport, handlingSettings);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            final SslHandler sslHandler = new SslHandler(SecuritySSLNettyHttpServerTransport.this.sks.createHTTPSSLEngine());
            ch.pipeline().addFirst("ssl_http", sslHandler);
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
