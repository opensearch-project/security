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
import org.opensearch.security.filter.NettyRequestChannel;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.http.InterceptingRestChannel;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.ssl.OpenSearchSecuritySSLPlugin;
import org.opensearch.common.settings.Settings;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestResponse;

import java.util.regex.Matcher;

import static com.amazon.dlic.auth.http.saml.HTTPSamlAuthenticator.API_AUTHTOKEN_SUFFIX;
import static org.opensearch.security.filter.SecurityRestFilter.HEALTH_SUFFIX;
import static org.opensearch.security.filter.SecurityRestFilter.PATTERN_PATH_PREFIX;
import static org.opensearch.security.filter.SecurityRestFilter.WHO_AM_I_SUFFIX;
import static org.opensearch.security.http.SecurityHttpServerTransport.CONTEXT_TO_RESTORE;
import static org.opensearch.security.http.SecurityHttpServerTransport.EARLY_RESPONSE;
import static org.opensearch.security.http.SecurityHttpServerTransport.SHOULD_DECOMPRESS;

public class Netty4HttpRequestHeaderVerifier extends SimpleChannelInboundHandler<DefaultHttpRequest> {
    private final SecurityRestFilter restFilter;
    private final ThreadPool threadPool;
    private final NamedXContentRegistry xContentRegistry;
    private final HttpHandlingSettings handlingSettings;
    private final Settings settings;
    private final SSLConfig sslConfig;
    private final boolean injectUserEnabled;
    private final boolean passthrough;

    public Netty4HttpRequestHeaderVerifier(
        SecurityRestFilter restFilter,
        NamedXContentRegistry xContentRegistry,
        ThreadPool threadPool,
        HttpHandlingSettings handlingSettings,
        Settings settings
    ) {
        this.restFilter = restFilter;
        this.xContentRegistry = xContentRegistry;
        this.threadPool = threadPool;
        this.handlingSettings = handlingSettings;
        this.settings = settings;

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

        final Netty4HttpChannel httpChannel = ctx.channel().attr(Netty4HttpServerTransport.HTTP_CHANNEL_KEY).get();
        final Netty4DefaultHttpRequest httpRequest = new Netty4DefaultHttpRequest(msg);
        RestRequest restRequest = AbstractHttpServerTransport.createRestRequest(xContentRegistry, httpRequest, httpChannel);
        InterceptingRestChannel interceptingRestChannel = new InterceptingRestChannel(
            restRequest,
            handlingSettings.getDetailedErrorsEnabled()
        );
        final NettyRequestChannel requestChannel = (NettyRequestChannel) SecurityRequestFactory.from(msg, interceptingRestChannel);
        Matcher matcher = PATTERN_PATH_PREFIX.matcher(restRequest.path());
        final String suffix = matcher.matches() ? matcher.group(2) : null;
        if (API_AUTHTOKEN_SUFFIX.equals(suffix)) {
            ctx.channel().attr(SHOULD_DECOMPRESS).set(Boolean.FALSE);
            ctx.fireChannelRead(msg);
            return;
        }

        ThreadContext threadContext = threadPool.getThreadContext();
        try (ThreadContext.StoredContext ignore = threadPool.getThreadContext().stashContext()) {
            injectUser(restRequest, threadContext);
            // If request channel gets completed and a response is sent, then there was a failure during authentication
            restFilter.checkAndAuthenticateRequest(requestChannel);

            ThreadContext.StoredContext contextToRestore = threadPool.getThreadContext().newStoredContext(false);

            ctx.channel().attr(EARLY_RESPONSE).set(interceptingRestChannel.getInterceptedResponse());
            ctx.channel().attr(CONTEXT_TO_RESTORE).set(contextToRestore);

            if (requestChannel.hasCompleted()
                || HttpMethod.OPTIONS.equals(msg.method())
                || HEALTH_SUFFIX.equals(suffix)
                || WHO_AM_I_SUFFIX.equals(suffix)) {
                // skip header verifier for pre-flight request. CORS Handler later in the pipeline will send early response
                ctx.channel().attr(SHOULD_DECOMPRESS).set(Boolean.FALSE);
            } else {
                ctx.channel().attr(SHOULD_DECOMPRESS).set(Boolean.TRUE);
            }
        } catch (OpenSearchSecurityException e) {
            RestResponse earlyResponse = new BytesRestResponse(interceptingRestChannel, e);
            ctx.channel().attr(EARLY_RESPONSE).set(earlyResponse);
            ctx.channel().attr(SHOULD_DECOMPRESS).set(Boolean.FALSE);
        } finally {
            ctx.fireChannelRead(msg);
        }
    }

    private void injectUser(RestRequest request, ThreadContext threadContext) {
        if (this.injectUserEnabled) {
            threadContext.putTransient(
                ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER,
                request.header(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER)
            );
        }
    }
}
