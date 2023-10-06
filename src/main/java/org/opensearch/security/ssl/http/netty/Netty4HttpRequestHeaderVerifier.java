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
import io.netty.handler.codec.http.HttpRequest;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;
import org.opensearch.ExceptionsHelper;
import org.opensearch.common.util.concurrent.ThreadContext;

import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.rest.RestUtils;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.filter.SecurityRequestChannelUnsupported;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.filter.SecurityRestUtils;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.ssl.OpenSearchSecuritySSLPlugin;
import org.opensearch.common.settings.Settings;
import org.opensearch.OpenSearchSecurityException;

import java.util.regex.Matcher;

import static com.amazon.dlic.auth.http.saml.HTTPSamlAuthenticator.API_AUTHTOKEN_SUFFIX;
import static org.opensearch.security.filter.SecurityRestFilter.HEALTH_SUFFIX;
import static org.opensearch.security.filter.SecurityRestFilter.PATTERN_PATH_PREFIX;
import static org.opensearch.security.filter.SecurityRestFilter.WHO_AM_I_SUFFIX;
import static org.opensearch.security.http.SecurityHttpServerTransport.CONTEXT_TO_RESTORE;
import static org.opensearch.security.http.SecurityHttpServerTransport.EARLY_RESPONSE;
import static org.opensearch.security.http.SecurityHttpServerTransport.SHOULD_DECOMPRESS;
import static org.opensearch.security.http.SecurityHttpServerTransport.IS_AUTHENTICATED;

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

        // TODO: GET PROPER MAVEN BUILD
        // final Netty4HttpChannel httpChannel = ctx.channel().attr(Netty4HttpServerTransport.HTTP_CHANNEL_KEY).get();
        final Netty4HttpChannel httpChannel = ctx.channel().attr(AttributeKey.<Netty4HttpChannel>valueOf("opensearch-http-channel")).get();
        String rawPath = SecurityRestUtils.path(msg.uri());
        String path = RestUtils.decodeComponent(rawPath);
        Matcher matcher = PATTERN_PATH_PREFIX.matcher(path);
        final String suffix = matcher.matches() ? matcher.group(2) : null;
        if (API_AUTHTOKEN_SUFFIX.equals(suffix)) {
            // TODO: I think this is going to create problems - we should have a sensible size limit, not prevention of
            // TODO_CONTINUED: decompression - it will prevent valid response bodies that are gzip'ed from being usable no?
            ctx.fireChannelRead(msg);
            return;
        }

        final SecurityRequestChannel requestChannel = SecurityRequestFactory.from(msg, httpChannel);
        ThreadContext threadContext = threadPool.getThreadContext();
        try (ThreadContext.StoredContext ignore = threadPool.getThreadContext().stashContext()) {
            injectUser(msg, threadContext);

            boolean shouldSkipAuthentication = HttpMethod.OPTIONS.equals(msg.method())
                || HEALTH_SUFFIX.equals(suffix)
                || WHO_AM_I_SUFFIX.equals(suffix);

            if (!shouldSkipAuthentication) {
                // If request channel is completed and a response is sent, then there was a failure during authentication
                restFilter.checkAndAuthenticateRequest(requestChannel);
            }

            ThreadContext.StoredContext contextToRestore = threadPool.getThreadContext().newStoredContext(false);
            ctx.channel().attr(CONTEXT_TO_RESTORE).set(contextToRestore);

            requestChannel.getQueuedResponse().ifPresent(response -> ctx.channel().attr(EARLY_RESPONSE).set(response));

            boolean shouldDecompress = !shouldSkipAuthentication && requestChannel.getQueuedResponse().isEmpty();

            if (requestChannel.getQueuedResponse().isEmpty() || shouldSkipAuthentication) {
                // Only allow decompression on authenticated requests that also aren't one of those ^
                ctx.channel().attr(SHOULD_DECOMPRESS).set(Boolean.valueOf(shouldDecompress));
                ctx.channel().attr(IS_AUTHENTICATED).set(Boolean.TRUE);
            }
        } catch (final OpenSearchSecurityException e) {
            final SecurityResponse earlyResponse = new SecurityResponse(ExceptionsHelper.status(e).getStatus(), null, e.getMessage());
            ctx.channel().attr(EARLY_RESPONSE).set(earlyResponse);
        } catch (final SecurityRequestChannelUnsupported srcu) {
            // TODO: Move handling for ACS Endpoint here?
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
