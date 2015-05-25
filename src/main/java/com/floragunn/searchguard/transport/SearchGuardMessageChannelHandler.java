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
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.netty.channel.Channel;
import org.elasticsearch.common.netty.channel.ChannelFuture;
import org.elasticsearch.common.netty.channel.ChannelFutureListener;
import org.elasticsearch.common.netty.channel.ChannelHandlerContext;
import org.elasticsearch.common.netty.channel.ChannelStateEvent;
import org.elasticsearch.common.netty.channel.MessageEvent;
import org.elasticsearch.common.netty.handler.ssl.SslHandler;
import org.elasticsearch.transport.TransportResponseHandler;
import org.elasticsearch.transport.netty.MessageChannelHandler;
import org.elasticsearch.transport.netty.NettyTransport;

public class SearchGuardMessageChannelHandler extends MessageChannelHandler {

    public SearchGuardMessageChannelHandler(final NettyTransport transport, final ESLogger logger) {
        super(transport, logger, ""); //TODO check profileName
    }

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) throws Exception {
        super.messageReceived(ctx, e);
    }

    @Override
    protected void handleResponse(final Channel channel, final StreamInput buffer, final TransportResponseHandler handler) {
        super.handleResponse(channel, buffer, handler);
    }

    @Override
    protected String handleRequest(final Channel channel, final StreamInput buffer, final long requestId, final Version version)
            throws IOException {
        final String action = super.handleRequest(channel, buffer, requestId, version);
        return action;
    }

    @Override
    public void channelConnected(final ChannelHandlerContext ctx, final ChannelStateEvent e) {
        //prevent javax.net.ssl.SSLException: Received close_notify during handshake
        final SslHandler sslHandler = ctx.getPipeline().get(SslHandler.class);

        if (sslHandler == null) {
            return;
        }

        final ChannelFuture handshakeFuture = sslHandler.handshake();
        handshakeFuture.addListener(new ChannelFutureListener() {

            @Override
            public void operationComplete(final ChannelFuture future) throws Exception {
                if (logger.isTraceEnabled()) {
                    logger.trace("Node to Node encryption cipher is {}/{}", sslHandler.getEngine().getSession().getProtocol(), sslHandler
                            .getEngine().getSession().getCipherSuite());
                }
                ctx.sendUpstream(e);
            }
        });
    }

}
