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

import java.io.IOException;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportException;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.netty.NettyTransport;

import com.floragunn.searchguard.service.SearchGuardService;
import com.floragunn.searchguard.util.SecurityUtil;

public class SearchGuardNettyTransport extends NettyTransport {

    @Inject
    public SearchGuardNettyTransport(final Settings settings, final ThreadPool threadPool, final NetworkService networkService,
            final BigArrays bigArrays, final Version version) {
        super(settings, threadPool, networkService, bigArrays, version);

    }

    @Override
    public org.elasticsearch.common.netty.channel.ChannelPipelineFactory configureClientChannelPipelineFactory() {
        return new SearchGuardClientChannelPipelineFactory(this);
    }

    @Override
    public org.elasticsearch.common.netty.channel.ChannelPipelineFactory configureServerChannelPipelineFactory(final String name,
            final Settings settings) {
        return new SearchGuardServerChannelPipelineFactory(this, name, settings);
    }

    protected boolean isClient() {
        return false;
    }

    @Override
    public void sendRequest(final DiscoveryNode node, final long requestId, final String action, final TransportRequest request,
            final TransportRequestOptions options) throws IOException, TransportException {

        if (!isClient()) {
            logger.debug("send " + action + " from " + this.nodeName() + " to " + node.getName());

            request.putHeader("searchguard_authenticated_transport_request",
                    SecurityUtil.encryptAndSerializeObject("authorized", SearchGuardService.getSecretKey()));
        } else {
            logger.debug("send (client mode without inter auth header) " + action + " from " + this.nodeName() + " to " + node.getName());
        }

        super.sendRequest(node, requestId, action, request, options);
    }

    protected static class SearchGuardServerChannelPipelineFactory extends ServerChannelPipelineFactory {

        protected final NettyTransport nettyTransport;
        protected static final ESLogger log = Loggers.getLogger(SearchGuardServerChannelPipelineFactory.class);

        public SearchGuardServerChannelPipelineFactory(final NettyTransport nettyTransport, final String name, final Settings settings) {
            super(nettyTransport, name, settings);
            this.nettyTransport = nettyTransport;
        }

        @Override
        public org.elasticsearch.common.netty.channel.ChannelPipeline getPipeline() throws Exception {
            final org.elasticsearch.common.netty.channel.ChannelPipeline pipeline = super.getPipeline();
            pipeline.replace("dispatcher", "dispatcher", new SearchGuardMessageChannelHandler(nettyTransport, log));
            return pipeline;
        }
    }

    protected static class SearchGuardClientChannelPipelineFactory extends ClientChannelPipelineFactory {

        protected final NettyTransport nettyTransport;
        protected static final ESLogger log = Loggers.getLogger(SearchGuardClientChannelPipelineFactory.class);

        public SearchGuardClientChannelPipelineFactory(final NettyTransport nettyTransport) {
            super(nettyTransport);
            this.nettyTransport = nettyTransport;
        }

        @Override
        public org.elasticsearch.common.netty.channel.ChannelPipeline getPipeline() throws Exception {
            final org.elasticsearch.common.netty.channel.ChannelPipeline pipeline = super.getPipeline();
            pipeline.replace("dispatcher", "dispatcher", new SearchGuardMessageChannelHandler(nettyTransport, log));
            return pipeline;
        }

    }
}
