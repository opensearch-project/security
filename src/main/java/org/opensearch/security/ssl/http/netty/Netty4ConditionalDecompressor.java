package org.opensearch.security.ssl.http.netty;

import io.netty.channel.ChannelHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.HttpContentDecompressor;

import static org.opensearch.security.ssl.http.netty.Netty4HttpRequestHeaderVerifier.IS_AUTHENTICATED;

@ChannelHandler.Sharable
public class Netty4ConditionalDecompressor extends HttpContentDecompressor {
    @Override
    protected EmbeddedChannel newContentDecoder(String contentEncoding) throws Exception {
        if (Boolean.FALSE.equals(ctx.channel().attr(IS_AUTHENTICATED).get())) {
            return super.newContentDecoder("identity");
        }
        return super.newContentDecoder(contentEncoding);
    }
}
