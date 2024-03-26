/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.filter;

import java.util.Optional;

import org.opensearch.http.HttpChannel;
import org.opensearch.rest.RestRequest;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;

public class NettyAttribute {

    /**
     * Gets an attribute value from the request context and clears it from that context
     */
    public static <T> Optional<T> popFrom(final RestRequest request, final AttributeKey<T> attribute) {
        final HttpChannel httpChannel = request.getHttpChannel();
        if (httpChannel != null) {
            return httpChannel.get("channel", Channel.class).map(channel -> channel.attr(attribute).getAndSet(null));
        } else {
            return Optional.empty();
        }
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
        final HttpChannel httpChannel = request.getHttpChannel();
        if (httpChannel != null) {
            httpChannel.get("channel", Channel.class).ifPresent(channel -> channel.attr(attribute).set(null));
        }
    }

}
