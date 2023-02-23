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

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.network.NetworkService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.http.HttpChannel;
import org.opensearch.http.HttpHandlingSettings;
import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.http.netty4.Netty4HttpServerTransport;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.SharedGroupFactory;

public class SecuritySSLNettyHttpServerTransport extends Netty4HttpServerTransport {
    private static final Logger logger = LogManager.getLogger(SecuritySSLNettyHttpServerTransport.class);
    private final SecurityKeyStore sks;
    private final SslExceptionHandler errorHandler;
    
    public SecuritySSLNettyHttpServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
                                               final ThreadPool threadPool, final SecurityKeyStore sks, final NamedXContentRegistry namedXContentRegistry, final ValidatingDispatcher dispatcher,
                                               final SslExceptionHandler errorHandler, ClusterSettings clusterSettings, SharedGroupFactory sharedGroupFactory) {
        super(settings, networkService, bigArrays, threadPool, namedXContentRegistry, dispatcher, clusterSettings, sharedGroupFactory);
        this.sks = sks;
        this.errorHandler = errorHandler;
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
        /**
         * Application negotiation handler to select either HTTP 1.1 or HTTP 2 protocol, based
         * on client/server ALPN negotiations.
         */
        private class Http2OrHttpHandler extends ApplicationProtocolNegotiationHandler {
            protected Http2OrHttpHandler() {
                super(ApplicationProtocolNames.HTTP_1_1);
            }

            @Override
            protected void configurePipeline(ChannelHandlerContext ctx, String protocol) throws Exception {
                if (ApplicationProtocolNames.HTTP_2.equals(protocol)) {
                    configureDefaultHttp2Pipeline(ctx.pipeline());
                } else if (ApplicationProtocolNames.HTTP_1_1.equals(protocol)) {
                    configureDefaultHttpPipeline(ctx.pipeline());
                } else {
                    throw new IllegalStateException("Unknown application protocol: " + protocol);
                }
            }
            
            @Override
            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                super.exceptionCaught(ctx, cause);
                Netty4HttpChannel channel = ctx.channel().attr(HTTP_CHANNEL_KEY).get();
                if (channel != null) {
                    if (cause instanceof Error) {
                        onException(channel, new Exception(cause));
                    } else {
                        onException(channel, (Exception) cause);
                    }
                }
            }
        }

        protected SSLHttpChannelHandler(Netty4HttpServerTransport transport, final HttpHandlingSettings handlingSettings, final SecurityKeyStore odsks) {
            super(transport, handlingSettings);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            final SslHandler sslHandler = new SslHandler(SecuritySSLNettyHttpServerTransport.this.sks.createHTTPSSLEngine());
            ch.pipeline().addFirst("ssl_http", sslHandler);
        }
        
        @Override
        protected void configurePipeline(Channel ch) {
            ch.pipeline().addLast(new Http2OrHttpHandler());
        }
    }
}
