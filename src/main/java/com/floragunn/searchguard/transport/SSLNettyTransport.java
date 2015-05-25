/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.transport;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.elasticsearch.Version;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.netty.channel.ChannelHandlerContext;
import org.elasticsearch.common.netty.channel.ChannelStateEvent;
import org.elasticsearch.common.netty.channel.SimpleChannelHandler;
import org.elasticsearch.common.netty.handler.ssl.SslHandler;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.netty.NettyTransport;

import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

public class SSLNettyTransport extends SearchGuardNettyTransport {

    @Inject
    public SSLNettyTransport(final Settings settings, final ThreadPool threadPool, final NetworkService networkService,
            final BigArrays bigArrays, final Version version) {
        super(settings, threadPool, networkService, bigArrays, version);

    }

    @Override
    public org.elasticsearch.common.netty.channel.ChannelPipelineFactory configureClientChannelPipelineFactory() {
        logger.debug("Node client configured for SSL");
        return new SSLClientChannelPipelineFactory(this, this.settings);
    }

    @Override
    public org.elasticsearch.common.netty.channel.ChannelPipelineFactory configureServerChannelPipelineFactory(final String name,
            final Settings settings) {
        logger.debug("Node server configured for SSL");
        return new SSLServerChannelPipelineFactory(this, name, settings, this.settings);
    }

    protected static class SSLServerChannelPipelineFactory extends ServerChannelPipelineFactory {

        private final String keystoreType;
        private final String keystoreFilePath;
        private final String keystorePassword;
        private final boolean enforceClientAuth;

        private final String truststoreType;
        private final String truststoreFilePath;
        private final String truststorePassword;

        public SSLServerChannelPipelineFactory(final NettyTransport nettyTransport, final String name, final Settings sslsettings,
                final Settings essettings) {
            super(nettyTransport, name, sslsettings);

            keystoreType = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_TYPE, "JKS");
            keystoreFilePath = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH, null);
            keystorePassword = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD, "changeit");
            enforceClientAuth = essettings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENFORCE_CLIENTAUTH, true);
            truststoreType = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE, "JKS");
            truststoreFilePath = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH, null);
            truststorePassword = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD, "changeit");
        }

        @Override
        public org.elasticsearch.common.netty.channel.ChannelPipeline getPipeline() throws Exception {
            final org.elasticsearch.common.netty.channel.ChannelPipeline pipeline = super.getPipeline();

            TrustManagerFactory tmf = null;

            if (enforceClientAuth) {

                final KeyStore ts = KeyStore.getInstance(truststoreType);
                ts.load(new FileInputStream(new File(truststoreFilePath)), truststorePassword.toCharArray());

                tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ts);
            }

            final KeyStore ks = KeyStore.getInstance(keystoreType);
            ks.load(new FileInputStream(new File(keystoreFilePath)), keystorePassword.toCharArray());

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, keystorePassword.toCharArray());

            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(kmf.getKeyManagers(), tmf == null ? null : tmf.getTrustManagers(), null);
            final SSLEngine engine = serverContext.createSSLEngine();
            final SSLParameters sslParams = new SSLParameters();
            sslParams.setCipherSuites(SecurityUtil.ENABLED_SSL_CIPHERS);
            sslParams.setProtocols(SecurityUtil.ENABLED_SSL_PROTOCOLS);
            sslParams.setNeedClientAuth(enforceClientAuth);
            engine.setSSLParameters(sslParams);
            engine.setUseClientMode(false);

            final SslHandler sslHandler = new SslHandler(engine);
            sslHandler.setEnableRenegotiation(false);
            pipeline.addFirst("ssl_server", sslHandler);

            return pipeline;
        }

    }

    protected static class ClientSslHandler extends SimpleChannelHandler {
        private final SSLContext serverContext;
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;

        private ClientSslHandler(final SSLContext serverContext, final boolean hostnameVerificationEnabled,
                final boolean hostnameVerificationResovleHostName) {
            this.hostnameVerificationEnabled = hostnameVerificationEnabled;
            this.hostnameVerificationResovleHostName = hostnameVerificationResovleHostName;
            this.serverContext = serverContext;
        }

        @Override
        public void connectRequested(final ChannelHandlerContext ctx, final ChannelStateEvent event) {
            SSLEngine engine = null;
            final SSLParameters sslParams = new SSLParameters();
            sslParams.setCipherSuites(SecurityUtil.ENABLED_SSL_CIPHERS);
            sslParams.setProtocols(SecurityUtil.ENABLED_SSL_PROTOCOLS);

            if (hostnameVerificationEnabled) {
                final InetSocketAddress inetSocketAddress = (InetSocketAddress) event.getValue();

                String hostname = null;
                if (hostnameVerificationResovleHostName) {
                    hostname = inetSocketAddress.getHostName();
                } else {
                    hostname = inetSocketAddress.getHostString();
                }

                engine = serverContext.createSSLEngine(hostname, inetSocketAddress.getPort());
                sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            } else {
                engine = serverContext.createSSLEngine();
            }

            engine.setSSLParameters(sslParams);
            engine.setUseClientMode(true);

            final SslHandler sslHandler = new SslHandler(engine);
            sslHandler.setEnableRenegotiation(false);
            ctx.getPipeline().replace(this, "ssl_client", sslHandler);

            ctx.sendDownstream(event);
        }
    }

    protected static class SSLClientChannelPipelineFactory extends ClientChannelPipelineFactory {

        private final String keystoreType;
        private final String keystoreFilePath;
        private final String keystorePassword;
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;
        private final String truststoreType;
        private final String truststoreFilePath;
        private final String truststorePassword;

        public SSLClientChannelPipelineFactory(final NettyTransport nettyTransport, final Settings settings) {
            super(nettyTransport);

            keystoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_TYPE, "JKS");
            keystoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH, null);
            keystorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD, "changeit");
            truststoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE, "JKS");
            truststoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH, null);
            truststorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD, "changeit");
            hostnameVerificationEnabled = settings.getAsBoolean(
                    ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION, true);
            hostnameVerificationResovleHostName = settings.getAsBoolean(
                    ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true);
        }

        @Override
        public org.elasticsearch.common.netty.channel.ChannelPipeline getPipeline() throws Exception {
            final org.elasticsearch.common.netty.channel.ChannelPipeline pipeline = super.getPipeline();

            //## Truststore ##
            final KeyStore ts = KeyStore.getInstance(truststoreType);
            ts.load(new FileInputStream(new File(truststoreFilePath)), truststorePassword.toCharArray());

            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            //## Keystore ##
            final KeyStore ks = KeyStore.getInstance(keystoreType);
            ks.load(new FileInputStream(new File(keystoreFilePath)), keystorePassword.toCharArray());

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, keystorePassword.toCharArray());

            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            pipeline.addFirst("client_ssl_handler", new ClientSslHandler(serverContext, hostnameVerificationEnabled,
                    hostnameVerificationResovleHostName));

            return pipeline;
        }

    }
}
