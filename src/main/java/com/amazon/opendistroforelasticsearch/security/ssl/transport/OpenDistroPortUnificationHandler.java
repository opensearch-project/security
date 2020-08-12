package com.amazon.opendistroforelasticsearch.security.ssl.transport;


import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLUtil;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import javax.net.ssl.SSLException;
import java.util.List;

/**
 * Manipulates the current pipeline dynamically to enable
 * TLS
 */
public class OpenDistroPortUnificationHandler extends ByteToMessageDecoder {

    private final OpenDistroSecurityKeyStore odsks;
    private final Settings settings;
    private static final Logger logger = LogManager.getLogger(OpenDistroPortUnificationHandler.class);

    public OpenDistroPortUnificationHandler(final Settings settings, OpenDistroSecurityKeyStore odsks) {
        this.odsks = odsks;
        this.settings = settings;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        // Will use the first five bytes to detect a protocol.
        if (in.readableBytes() < 5) {
            return;
        }
        logger.info("dual mode from settings {}",
                OpenDistroSSLDualModeConfig.getInstance().isIsDualModeEnabled());
        logger.info("Checking if dual ssl mode or not for request from {}", ctx.channel().remoteAddress());
        if (OpenDistroSSLMode.isDualSSLMode()) {
            if (isTLS(in)) {
                logger.info("Identified request as SSL request");
                enableSsl(ctx);
            } else {
                logger.info("Identified request as non SSL request, running in HTTP mode as dual mode is enabled");
                ctx.pipeline().remove(this);
            }
        } else {
            enableSsl(ctx);
        }

    }

    private boolean isTLS(ByteBuf buf) {
        logger.info("First byte is {}", buf.getUnsignedByte(buf.readerIndex()));
        return SSLUtil.isTLS(buf);
    }

    private void enableSsl(ChannelHandlerContext ctx) throws SSLException {
        final SslHandler sslHandler = new SslHandler(odsks.createServerTransportSSLEngine());
        ChannelPipeline p = ctx.pipeline();
        p.addAfter("port_unification_handler", "ssl_server", sslHandler);
        p.remove(this);
        logger.info("Removed port unification handler and added SSL handler as incoming request is SSL");
    }
}