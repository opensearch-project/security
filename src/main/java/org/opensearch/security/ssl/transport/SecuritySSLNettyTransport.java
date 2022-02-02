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

package org.opensearch.security.ssl.transport;

import org.opensearch.security.ssl.util.SSLConnectionTestResult;
import org.opensearch.security.ssl.util.SSLConnectionTestUtil;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.Version;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.common.io.stream.NamedWriteableRegistry;
import org.opensearch.common.network.NetworkService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.PageCacheRecycler;
import org.opensearch.indices.breaker.CircuitBreakerService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.SharedGroupFactory;
import org.opensearch.transport.TcpChannel;
import org.opensearch.transport.netty4.Netty4Transport;

import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.util.SSLConfigConstants;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandler;

public class SecuritySSLNettyTransport extends Netty4Transport {

    private static final Logger logger = LoggerFactory.getLogger(SecuritySSLNettyTransport.class);
    private final SecurityKeyStore ossks;
    private final SslExceptionHandler errorHandler;
    private final SSLConfig SSLConfig;

    public SecuritySSLNettyTransport(final Settings settings, final Version version, final ThreadPool threadPool, final NetworkService networkService,
                                     final PageCacheRecycler pageCacheRecycler, final NamedWriteableRegistry namedWriteableRegistry,
                                     final CircuitBreakerService circuitBreakerService, final SecurityKeyStore ossks, final SslExceptionHandler errorHandler, SharedGroupFactory sharedGroupFactory,
                                     final SSLConfig SSLConfig) {
        super(settings, version, threadPool, networkService, pageCacheRecycler, namedWriteableRegistry, circuitBreakerService, sharedGroupFactory);

        this.ossks = ossks;
        this.errorHandler = errorHandler;
        this.SSLConfig = SSLConfig;
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

            boolean dualModeEnabled = SSLConfig.isDualModeEnabled();
            if (dualModeEnabled) {
                logger.info("SSL Dual mode enabled, using port unification handler");
                final ChannelHandler portUnificationHandler = new DualModeSSLHandler(ossks);
                ch.pipeline().addFirst("port_unification_handler", portUnificationHandler);
            } else {
                final SslHandler sslHandler = new SslHandler(ossks.createServerTransportSSLEngine());
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
        private final Logger log = LoggerFactory.getLogger(this.getClass());
        private final SecurityKeyStore sks;
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;
        private final SslExceptionHandler errorHandler;
        

        private ClientSSLHandler(final SecurityKeyStore sks, final boolean hostnameVerificationEnabled,
                                 final boolean hostnameVerificationResovleHostName, final SslExceptionHandler errorHandler) {
            this.sks = sks;
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
                    
                    engine = sks.createClientTransportSSLEngine(hostname, inetSocketAddress.getPort());
                } else {
                    engine = sks.createClientTransportSSLEngine(null, -1);
                }
            } catch (final SSLException e) {
                throw ExceptionsHelper.convertToOpenSearchException(e);
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
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true);
            hostnameVerificationResovleHostName = settings.getAsBoolean(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true);

            connectionTestResult = SSLConnectionTestResult.SSL_AVAILABLE;
            if (SSLConfig.isDualModeEnabled()) {
                SSLConnectionTestUtil sslConnectionTestUtil = new SSLConnectionTestUtil(node.getAddress().getAddress(), node.getAddress().getPort());
                connectionTestResult = AccessController.doPrivileged((PrivilegedAction<SSLConnectionTestResult>) sslConnectionTestUtil::testConnection);
            }
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);

            if(connectionTestResult == SSLConnectionTestResult.OPENSEARCH_PING_FAILED) {
                logger.error("SSL dual mode is enabled but dual mode handshake and OpenSearch ping has failed during client connection setup, closing channel");
                ch.close();
                return;
            }

            if (connectionTestResult == SSLConnectionTestResult.SSL_AVAILABLE) {
                logger.debug("Connection to {} needs to be ssl, adding ssl handler to the client channel ", node.getHostName());
                ch.pipeline().addFirst("client_ssl_handler", new ClientSSLHandler(ossks, hostnameVerificationEnabled,
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
