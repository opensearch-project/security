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

package com.amazon.opendistroforelasticsearch.security.ssl.transport;

import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConnectionTestResult;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConnectionTestUtil;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.PageCacheRecycler;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.SharedGroupFactory;
import org.elasticsearch.transport.TcpChannel;
import org.elasticsearch.transport.netty4.Netty4Transport;

import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.SslExceptionHandler;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandler;

public class OpenDistroSecuritySSLNettyTransport extends Netty4Transport {

    private static final Logger logger = LogManager.getLogger(OpenDistroSecuritySSLNettyTransport.class);
    private final OpenDistroSecurityKeyStore odsks;
    private final SslExceptionHandler errorHandler;
    private final OpenDistroSSLConfig openDistroSSLConfig;

    public OpenDistroSecuritySSLNettyTransport(final Settings settings, final Version version, final ThreadPool threadPool, final NetworkService networkService,
            final PageCacheRecycler pageCacheRecycler, final NamedWriteableRegistry namedWriteableRegistry,
            final CircuitBreakerService circuitBreakerService, final OpenDistroSecurityKeyStore odsks, final SslExceptionHandler errorHandler, SharedGroupFactory sharedGroupFactory,
            final OpenDistroSSLConfig openDistroSSLConfig) {
        super(settings, version, threadPool, networkService, pageCacheRecycler, namedWriteableRegistry, circuitBreakerService, sharedGroupFactory);

        this.odsks = odsks;
        this.errorHandler = errorHandler;
        this.openDistroSSLConfig = openDistroSSLConfig;
    }

    @Override
    public void onException(TcpChannel channel, Exception e) {

        Throwable cause = e;

        if (e instanceof DecoderException && e != null) {
            cause = e.getCause();
        }

        errorHandler.logError(cause, false);
        logger.error("Exception during establishing a SSL connection: " + cause, cause);

        super.onException(channel, e);
    }

    @Override
    protected ChannelHandler getServerChannelInitializer(String name) {
        return new SSLServerChannelInitializer(name);
    }
    
    @Override
    protected ChannelHandler getClientChannelInitializer(DiscoveryNode node) {
        return new SSLClientChannelInitializer(node);
    }

    protected class SSLServerChannelInitializer extends Netty4Transport.ServerChannelInitializer {

        public SSLServerChannelInitializer(String name) {
            super(name);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);

            boolean dualModeEnabled = openDistroSSLConfig.isDualModeEnabled();
            if (dualModeEnabled) {
                logger.info("SSL Dual mode enabled, using port unification handler");
                final ChannelHandler portUnificationHandler = new DualModeSSLHandler(odsks);
                ch.pipeline().addFirst("port_unification_handler", portUnificationHandler);
            } else {
                final SslHandler sslHandler = new SslHandler(odsks.createServerTransportSSLEngine());
                ch.pipeline().addFirst("ssl_server", sslHandler);
            }
        }
        
        @Override
        public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if (cause instanceof DecoderException && cause != null) {
                cause = cause.getCause();
            }

            errorHandler.logError(cause, false);
            logger.error("Exception during establishing a SSL connection: " + cause, cause);

            super.exceptionCaught(ctx, cause);
        }
    }

    protected static class ClientSSLHandler extends ChannelOutboundHandlerAdapter {
        private final Logger log = LogManager.getLogger(this.getClass());
        private final OpenDistroSecurityKeyStore odsks;
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;
        private final SslExceptionHandler errorHandler;
        

        private ClientSSLHandler(final OpenDistroSecurityKeyStore odsks, final boolean hostnameVerificationEnabled,
                final boolean hostnameVerificationResovleHostName, final SslExceptionHandler errorHandler) {
            this.odsks = odsks;
            this.hostnameVerificationEnabled = hostnameVerificationEnabled;
            this.hostnameVerificationResovleHostName = hostnameVerificationResovleHostName;
            this.errorHandler = errorHandler;
        }
        

        @Override
        public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if (cause instanceof DecoderException && cause != null) {
                cause = cause.getCause();
            }
            
            errorHandler.logError(cause, false);
            logger.error("Exception during establishing a SSL connection: " + cause, cause);

            super.exceptionCaught(ctx, cause);
        }

        @Override
        public void connect(ChannelHandlerContext ctx, SocketAddress remoteAddress, SocketAddress localAddress, ChannelPromise promise) throws Exception {
            SSLEngine engine = null;
            try {
                if (hostnameVerificationEnabled) {
                    final InetSocketAddress inetSocketAddress = (InetSocketAddress) remoteAddress;
                    String hostname = null;
                    if (hostnameVerificationResovleHostName) {
                        hostname = inetSocketAddress.getHostName();
                    } else {
                        hostname = inetSocketAddress.getHostString();
                    }

                    if(log.isDebugEnabled()) {
                        log.debug("Hostname of peer is {} ({}/{}) with hostnameVerificationResovleHostName: {}", hostname, inetSocketAddress.getHostName(), inetSocketAddress.getHostString(), hostnameVerificationResovleHostName);
                    }
                    
                    engine = odsks.createClientTransportSSLEngine(hostname, inetSocketAddress.getPort());
                } else {
                    engine = odsks.createClientTransportSSLEngine(null, -1);
                }
            } catch (final SSLException e) {
                throw ExceptionsHelper.convertToElastic(e);
            }
            final SslHandler sslHandler = new SslHandler(engine);
            ctx.pipeline().replace(this, "ssl_client", sslHandler);
            super.connect(ctx, remoteAddress, localAddress, promise);
        }
    }

    protected class SSLClientChannelInitializer extends Netty4Transport.ClientChannelInitializer {
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;
        private final DiscoveryNode node;
        private SSLConnectionTestResult connectionTestResult;

        public SSLClientChannelInitializer(DiscoveryNode node) {
            this.node = node;
            hostnameVerificationEnabled = settings.getAsBoolean(
                    SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true);
            hostnameVerificationResovleHostName = settings.getAsBoolean(
                    SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true);

            connectionTestResult = SSLConnectionTestResult.SSL_AVAILABLE;
            if (openDistroSSLConfig.isDualModeEnabled()) {
                SSLConnectionTestUtil sslConnectionTestUtil = new SSLConnectionTestUtil(node.getAddress().getAddress(), node.getAddress().getPort());
                connectionTestResult = AccessController.doPrivileged((PrivilegedAction<SSLConnectionTestResult>) sslConnectionTestUtil::testConnection);
            }
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);

            if(connectionTestResult == SSLConnectionTestResult.ES_PING_FAILED) {
                logger.error("SSL dual mode is enabled but dual mode handshake and ES ping has failed during client connection setup, closing channel");
                ch.close();
                return;
            }

            if (connectionTestResult == SSLConnectionTestResult.SSL_AVAILABLE) {
                logger.debug("Connection to {} needs to be ssl, adding ssl handler to the client channel ", node.getHostName());
                ch.pipeline().addFirst("client_ssl_handler", new ClientSSLHandler(odsks, hostnameVerificationEnabled,
                        hostnameVerificationResovleHostName, errorHandler));
            } else {
                logger.debug("Connection to {} needs to be non ssl", node.getHostName());
            }
        }
        
        @Override
        public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if (cause instanceof DecoderException && cause != null) {
                cause = cause.getCause();
            }


            errorHandler.logError(cause, false);
            logger.error("Exception during establishing a SSL connection: " + cause, cause);
            
            super.exceptionCaught(ctx, cause);
        }
    }
}
