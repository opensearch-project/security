/*
 * Portions Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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


import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLUtil;
import com.google.common.annotations.VisibleForTesting;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLException;
import java.util.List;

/**
 * Manipulates the current pipeline dynamically to enable
 * TLS
 */
public class OpenDistroPortUnificationHandler extends ByteToMessageDecoder {

    private final OpenDistroSecurityKeyStore odsks;
    private static final Logger logger = LogManager.getLogger(OpenDistroPortUnificationHandler.class);

    private SslHandler providedSSLHandler;
    private SSLUtil sslUtils;

    public OpenDistroPortUnificationHandler(OpenDistroSecurityKeyStore odsks, SSLUtil sslUtils) {
        this(odsks, null, sslUtils);
    }

    @VisibleForTesting
    protected OpenDistroPortUnificationHandler(OpenDistroSecurityKeyStore odsks, SslHandler providedSSLHandler,
                                               SSLUtil sslUtils) {
        this.odsks = odsks;
        this.providedSSLHandler = providedSSLHandler;
        this.sslUtils = sslUtils;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        // Will use the first five bytes to detect a protocol.
        if (in.readableBytes() < 5) {
            return;
        }
        logger.debug("Checking if dual ssl mode or not");
        if (this.sslUtils.isTLS(in)) {
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
            sslHandler = new SslHandler(odsks.createServerTransportSSLEngine());
        }
        ChannelPipeline p = ctx.pipeline();
        p.addAfter("port_unification_handler", "ssl_server", sslHandler);
        p.remove(this);
        logger.debug("Removed port unification handler and added SSL handler as incoming request is SSL");
    }
}