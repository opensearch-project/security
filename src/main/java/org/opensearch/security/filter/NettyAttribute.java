package org.opensearch.security.filter;

import java.util.Optional;

import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.rest.RestRequest;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;

public class NettyAttribute {

    /**
     * Gets an attribute value from the request context and clears it from that context
     */
    public static <T> Optional<T> popFrom(final RestRequest request, final AttributeKey<T> attribute) {
        if (request.getHttpChannel() instanceof Netty4HttpChannel) {
            Channel nettyChannel = ((Netty4HttpChannel) request.getHttpChannel()).getNettyChannel();
            return Optional.ofNullable(nettyChannel.attr(attribute).getAndSet(null));
        }
        return Optional.empty();
    }

    /**
     * Gets an attribute value from the channel handler context and clears it from that context
     */
    public static <T> Optional<T> popFrom(final ChannelHandlerContext ctx, final AttributeKey<T> attribute) {
        return Optional.ofNullable(ctx.channel().attr(attribute).getAndSet(null));
    }

    /**
     * Gets an attribute value from the channel handler context
     */
    public static <T> Optional<T> peekFrom(final ChannelHandlerContext ctx, final AttributeKey<T> attribute) {
        return Optional.ofNullable(ctx.channel().attr(attribute).get());
    }

    /**
     * Clears an attribute value from the channel handler context
     */
    public static <T> void clearAttribute(final RestRequest request, final AttributeKey<T> attribute) {
        if (request.getHttpChannel() instanceof Netty4HttpChannel) {
            Channel nettyChannel = ((Netty4HttpChannel) request.getHttpChannel()).getNettyChannel();
            nettyChannel.attr(attribute).set(null);
        }
    }

}
