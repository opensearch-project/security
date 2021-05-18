/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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


import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.util.SSLConnectionTestUtil;
import org.opensearch.security.ssl.util.TLSUtil;
import com.google.common.annotations.VisibleForTesting;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.ssl.SslHandler;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLException;
import java.util.List;

/**
 * Modifies the current pipeline dynamically to enable TLS
 */
public class DualModeSSLHandler extends ByteToMessageDecoder {

    private static final Logger logger = LogManager.getLogger(DualModeSSLHandler.class);
    private final SecurityKeyStore securityKeyStore;

    private final SslHandler providedSSLHandler;

    public DualModeSSLHandler(SecurityKeyStore securityKeyStore) {
        this(securityKeyStore, null);
    }

    @VisibleForTesting
    protected DualModeSSLHandler(SecurityKeyStore securityKeyStore, SslHandler providedSSLHandler) {
        this.securityKeyStore = securityKeyStore;
        this.providedSSLHandler = providedSSLHandler;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        // Will use the first six bytes to detect a protocol.
        if (in.readableBytes() < 6) {
            return;
        }
        int offset = in.readerIndex();
        if (in.getCharSequence(offset, 6, StandardCharsets.UTF_8).equals(SSLConnectionTestUtil.DUAL_MODE_CLIENT_HELLO_MSG)) {
            logger.debug("Received DualSSL Client Hello message");
            ByteBuf responseBuffer = Unpooled.buffer(6);
            responseBuffer.writeCharSequence(SSLConnectionTestUtil.DUAL_MODE_SERVER_HELLO_MSG, StandardCharsets.UTF_8);
            ctx.writeAndFlush(responseBuffer).addListener(ChannelFutureListener.CLOSE);
            return;
        }

        if (TLSUtil.isTLS(in)) {
            logger.debug("Identified request as SSL request");
            enableSsl(ctx);
        } else {
            logger.debug("Identified request as non SSL request, running in HTTP mode as dual mode is enabled");
            ctx.pipeline().remove(this);
        }
    }

    private void enableSsl(ChannelHandlerContext ctx) throws SSLException {
        SslHandler sslHandler;
        if (providedSSLHandler != null) {
            sslHandler = providedSSLHandler;
        } else {
            sslHandler = new SslHandler(securityKeyStore.createServerTransportSSLEngine());
        }
        ChannelPipeline p = ctx.pipeline();
        p.addAfter("port_unification_handler", "ssl_server", sslHandler);
        p.remove(this);
        logger.debug("Removed port unification handler and added SSL handler as incoming request is SSL");
    }
}
