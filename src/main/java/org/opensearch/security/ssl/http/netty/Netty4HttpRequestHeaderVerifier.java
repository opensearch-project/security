/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.http.netty;

import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.util.ReferenceCountUtil;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.http.AbstractHttpServerTransport;

import io.netty.channel.ChannelHandlerContext;
import org.opensearch.http.HttpHandlingSettings;
import org.opensearch.http.netty4.Netty4DefaultHttpRequest;
import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.http.netty4.Netty4HttpServerTransport;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.http.InterceptingRestChannel;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.http.netty4.Netty4HttpServerTransport.CONTEXT_TO_RESTORE;
import static org.opensearch.http.netty4.Netty4HttpServerTransport.EARLY_RESPONSE;
import static org.opensearch.http.netty4.Netty4HttpServerTransport.SHOULD_DECOMPRESS;

public class Netty4HttpRequestHeaderVerifier extends SimpleChannelInboundHandler<DefaultHttpRequest> {
    private final SecurityRestFilter restFilter;
    private final ThreadPool threadPool;
    private final NamedXContentRegistry xContentRegistry;
    private final HttpHandlingSettings handlingSettings;

    public Netty4HttpRequestHeaderVerifier(
        SecurityRestFilter restFilter,
        NamedXContentRegistry xContentRegistry,
        ThreadPool threadPool,
        HttpHandlingSettings handlingSettings
    ) {
        this.restFilter = restFilter;
        this.xContentRegistry = xContentRegistry;
        this.threadPool = threadPool;
        this.handlingSettings = handlingSettings;
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, DefaultHttpRequest msg) throws Exception {
        // DefaultHttpRequest should always be first and contain headers
        ReferenceCountUtil.retain(msg);
        if (HttpMethod.OPTIONS.equals(msg.method())) {
            // skip header verifier for pre-flight request. CORS Handler later in the pipeline will send early response
            ctx.fireChannelRead(msg);
            return;
        }

        final Netty4HttpChannel httpChannel = ctx.channel().attr(Netty4HttpServerTransport.HTTP_CHANNEL_KEY).get();
        final Netty4DefaultHttpRequest httpRequest = new Netty4DefaultHttpRequest(msg);
        RestRequest restRequest = AbstractHttpServerTransport.createRestRequest(xContentRegistry, httpRequest, httpChannel);

        InterceptingRestChannel interceptingRestChannel = new InterceptingRestChannel(
            restRequest,
            handlingSettings.getDetailedErrorsEnabled()
        );
        ThreadContext threadContext = threadPool.getThreadContext();
        try (ThreadContext.StoredContext ignore = threadPool.getThreadContext().stashContext()) {
            boolean isUnauthenticated = restFilter.checkAndAuthenticateRequest(restRequest, interceptingRestChannel, threadContext);

            ThreadContext.StoredContext contextToRestore = threadPool.getThreadContext().newStoredContext(false);

            ctx.channel().attr(EARLY_RESPONSE).set(interceptingRestChannel.getInterceptedResponse());
            ctx.channel().attr(CONTEXT_TO_RESTORE).set(contextToRestore);

            if (isUnauthenticated) {
                ctx.channel().attr(SHOULD_DECOMPRESS).set(Boolean.FALSE);
            } else {
                ctx.channel().attr(SHOULD_DECOMPRESS).set(Boolean.TRUE);
            }
        } finally {
            ctx.fireChannelRead(msg);
        }
    }
}
