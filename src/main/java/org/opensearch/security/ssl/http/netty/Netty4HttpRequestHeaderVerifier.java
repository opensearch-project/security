/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.http.netty;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.http.netty4.Netty4HttpServerTransport;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.filter.SecurityRequestChannelUnsupported;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.filter.SecurityRestUtils;
import org.opensearch.security.ssl.OpenSearchSecuritySSLPlugin;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.util.ReferenceCountUtil;

import static org.opensearch.security.http.SecurityHttpServerTransport.CONTEXT_TO_RESTORE;
import static org.opensearch.security.http.SecurityHttpServerTransport.EARLY_RESPONSE;
import static org.opensearch.security.http.SecurityHttpServerTransport.IS_AUTHENTICATED;
import static org.opensearch.security.http.SecurityHttpServerTransport.SHOULD_DECOMPRESS;
import static org.opensearch.security.http.SecurityHttpServerTransport.UNCONSUMED_PARAMS;

@Sharable
public class Netty4HttpRequestHeaderVerifier extends SimpleChannelInboundHandler<DefaultHttpRequest> {
    private final SecurityRestFilter restFilter;
    private final ThreadPool threadPool;
    private final SSLConfig sslConfig;
    private final boolean injectUserEnabled;
    private final boolean passthrough;

    public Netty4HttpRequestHeaderVerifier(SecurityRestFilter restFilter, ThreadPool threadPool, Settings settings) {
        this.restFilter = restFilter;
        this.threadPool = threadPool;

        this.injectUserEnabled = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false);
        boolean disabled = settings.getAsBoolean(ConfigConstants.SECURITY_DISABLED, false);
        if (disabled) {
            sslConfig = new SSLConfig(false, false);
        } else {
            sslConfig = new SSLConfig(settings);
        }
        boolean client = !"node".equals(settings.get(OpenSearchSecuritySSLPlugin.CLIENT_TYPE));
        this.passthrough = client || disabled || sslConfig.isSslOnlyMode();
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, DefaultHttpRequest msg) throws Exception {
        // DefaultHttpRequest should always be first and contain headers
        ReferenceCountUtil.retain(msg);

        if (passthrough) {
            ctx.fireChannelRead(msg);
            return;
        }

        // Start by setting this value to false, only requests that meet all the criteria will be decompressed
        ctx.channel().attr(SHOULD_DECOMPRESS).set(Boolean.FALSE);
        ctx.channel().attr(IS_AUTHENTICATED).set(Boolean.FALSE);

        final Netty4HttpChannel httpChannel = ctx.channel().attr(Netty4HttpServerTransport.HTTP_CHANNEL_KEY).get();

        final SecurityRequestChannel requestChannel = SecurityRequestFactory.from(msg, httpChannel);
        ThreadContext threadContext = threadPool.getThreadContext();
        try (ThreadContext.StoredContext ignore = threadPool.getThreadContext().stashContext()) {
            injectUser(msg, threadContext);

            // If request channel is completed and a response is sent, then there was a failure during authentication
            restFilter.checkAndAuthenticateRequest(requestChannel);

            ctx.channel().attr(UNCONSUMED_PARAMS).set(requestChannel.getUnconsumedParams());

            ThreadContext.StoredContext contextToRestore = threadPool.getThreadContext().newStoredContext(false);
            ctx.channel().attr(CONTEXT_TO_RESTORE).set(contextToRestore);

            requestChannel.getQueuedResponse().ifPresent(response -> ctx.channel().attr(EARLY_RESPONSE).set(response));

            boolean shouldSkipAuthentication = SecurityRestUtils.shouldSkipAuthentication(requestChannel);
            boolean shouldDecompress = !shouldSkipAuthentication && requestChannel.getQueuedResponse().isEmpty();

            if (requestChannel.getQueuedResponse().isEmpty() || shouldSkipAuthentication) {
                // Only allow decompression on authenticated requests that also aren't one of those ^
                ctx.channel().attr(SHOULD_DECOMPRESS).set(Boolean.valueOf(shouldDecompress));
                ctx.channel().attr(IS_AUTHENTICATED).set(Boolean.TRUE);
            }
        } catch (final OpenSearchSecurityException e) {
            final SecurityResponse earlyResponse = new SecurityResponse(ExceptionsHelper.status(e).getStatus(), e);
            ctx.channel().attr(EARLY_RESPONSE).set(earlyResponse);
        } catch (final SecurityRequestChannelUnsupported srcu) {
            // Use defaults for unsupported channels
        } finally {
            ctx.fireChannelRead(msg);
        }
    }

    private void injectUser(HttpRequest request, ThreadContext threadContext) {
        if (this.injectUserEnabled) {
            threadContext.putTransient(
                ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER,
                request.headers().get(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER)
            );
        }
    }
}
