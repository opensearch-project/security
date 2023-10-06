package org.opensearch.security.filter;

import java.util.Optional;

import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.rest.RestRequest;

import io.netty.channel.Channel;
import io.netty.util.AttributeKey;

public class NettyAttribute {

    /**
     * Gets an attribute value from the request context and clears it from the context
     */
    public static <T> Optional<T> popFrom(final RestRequest request, final AttributeKey<T> attribute) {
        if (request.getHttpChannel() instanceof Netty4HttpChannel) {
            Channel nettyChannel = ((Netty4HttpChannel) request.getHttpChannel()).getNettyChannel();
            // final Optional<SecurityResponse> maybeSavedResponse = Optional.ofNullable(EARLY_RESPONSE).getAndSet(null));
            return Optional.ofNullable(nettyChannel.attr(attribute).getAndSet(null));
        }
        return Optional.empty();
    }

}
