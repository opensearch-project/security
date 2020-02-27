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

package com.amazon.opendistroforelasticsearch.security.ssl.http.netty;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.NotSslRecordException;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.SslExceptionHandler;

public class OpenDistroSecuritySSLNettyHttpServerTransport extends Netty4HttpServerTransport {

    private static final Logger logger = LogManager.getLogger(OpenDistroSecuritySSLNettyHttpServerTransport.class);
    private final OpenDistroSecurityKeyStore odks;
    private final ThreadContext threadContext;
    private final SslExceptionHandler errorHandler;
    
    public OpenDistroSecuritySSLNettyHttpServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
            final ThreadPool threadPool, final OpenDistroSecurityKeyStore odks, final NamedXContentRegistry namedXContentRegistry, final ValidatingDispatcher dispatcher,
            final SslExceptionHandler errorHandler) {
        super(settings, networkService, bigArrays, threadPool, namedXContentRegistry, dispatcher);
        this.odks = odks;
        this.threadContext = threadPool.getThreadContext();
        this.errorHandler = errorHandler;
    }

    @Override
    public ChannelHandler configureServerChannelHandler() {
        return new SSLHttpChannelHandler(this, odks);
    }

    @Override
    protected final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if(this.lifecycle.started()) {
            
            if(cause instanceof DecoderException && cause != null) {
                cause = cause.getCause();
            }
            
            errorHandler.logError(cause, true);
            
            if(cause instanceof NotSslRecordException) {
                logger.warn("Someone ({}) speaks http plaintext instead of ssl, will close the channel", ctx.channel().remoteAddress());
                ctx.channel().close();
                return;
            } else if (cause instanceof SSLException) {
                logger.error("SSL Problem "+cause.getMessage(),cause);
                ctx.channel().close();
                return;
            } else if (cause instanceof SSLHandshakeException) {
                logger.error("Problem during handshake "+cause.getMessage());
                ctx.channel().close();
                return;
            }
            
        }
        
        super.exceptionCaught(ctx, cause);
    }

    protected class SSLHttpChannelHandler extends Netty4HttpServerTransport.HttpChannelHandler {
        
        protected SSLHttpChannelHandler(Netty4HttpServerTransport transport, final OpenDistroSecurityKeyStore odks) {
            super(transport, OpenDistroSecuritySSLNettyHttpServerTransport.this.detailedErrorsEnabled, OpenDistroSecuritySSLNettyHttpServerTransport.this.threadContext);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            final SslHandler sslHandler = new SslHandler(OpenDistroSecuritySSLNettyHttpServerTransport.this.odks.createHTTPSSLEngine());
            ch.pipeline().addFirst("ssl_http", sslHandler);
        }
    }
}
