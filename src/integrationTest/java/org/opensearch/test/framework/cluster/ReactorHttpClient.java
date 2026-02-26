/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.test.framework.cluster;

import java.io.Closeable;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.http.netty4.http3.Http3Utils;
import org.opensearch.security.support.FipsMode;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.EmptyHttpHeaders;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http2.HttpConversionUtil;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.resolver.DefaultAddressResolverGroup;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.ParallelFlux;
import reactor.netty.http.Http11SslContextSpec;
import reactor.netty.http.Http2SslContextSpec;
import reactor.netty.http.Http3SslContextSpec;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.client.HttpClient;

import static org.opensearch.http.HttpTransportSettings.SETTING_HTTP_MAX_CONTENT_LENGTH;

/**
 * Tiny helper to send http requests over netty.
 */
public class ReactorHttpClient implements Closeable {
    private static final Logger LOG = LogManager.getLogger(ReactorHttpClient.class);
    private static final java.util.Random RAND = new java.util.Random();

    private final boolean compression;
    private final boolean secure;
    private final HttpProtocol protocol;
    private final Settings settings;
    private final InetSocketAddress remoteAddress;
    private final boolean fipsMode;

    public ReactorHttpClient(boolean compression, boolean secure, Settings settings, InetSocketAddress remoteAddress, boolean fipsMode) {
        this(compression, secure, selectSupportedProtocol(secure), settings, remoteAddress, fipsMode);
    }

    public ReactorHttpClient(
        boolean compression,
        boolean secure,
        HttpProtocol protocol,
        Settings settings,
        InetSocketAddress remoteAddress,
        boolean fipsMode
    ) {
        this.compression = compression;
        this.secure = secure;
        this.protocol = protocol;
        this.settings = settings;
        this.remoteAddress = remoteAddress;
        this.fipsMode = fipsMode;
    }

    public final Collection<FullHttpResponse> post(List<Tuple<String, byte[]>> urisAndBodies, int parallelism) {
        return processRequestsWithBody(HttpMethod.POST, remoteAddress, urisAndBodies, parallelism);
    }

    private List<FullHttpResponse> processRequestsWithBody(
        HttpMethod method,
        InetSocketAddress remoteAddress,
        List<Tuple<String, byte[]>> urisAndBodies,
        int parallelism
    ) {
        List<FullHttpRequest> requests = new ArrayList<>(urisAndBodies.size());
        for (int i = 0; i < urisAndBodies.size(); ++i) {
            final Tuple<String, byte[]> uriAndBody = urisAndBodies.get(i);
            ByteBuf content = Unpooled.copiedBuffer(uriAndBody.v2());
            FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, method, uriAndBody.v1(), content);
            request.headers().add(HttpHeaderNames.HOST, "localhost");
            request.headers().add(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
            request.headers().add(HttpHeaderNames.CONTENT_TYPE, "application/json");
            request.headers().add(HttpHeaderNames.CONTENT_ENCODING, "gzip");
            request.headers().add(HttpConversionUtil.ExtensionHeaderNames.SCHEME.text(), secure ? "https" : "http");
            requests.add(request);
        }
        return sendRequests(remoteAddress, requests, false, parallelism);
    }

    private List<FullHttpResponse> sendRequests(
        final InetSocketAddress remoteAddress,
        final Collection<FullHttpRequest> requests,
        boolean ordered,
        int parallelism
    ) {
        final EventLoopGroup eventLoopGroup = new MultiThreadIoEventLoopGroup(parallelism, NioIoHandler.newFactory());
        try {
            final HttpClient client = createClient(remoteAddress, eventLoopGroup);

            @SuppressWarnings("unchecked")
            final Mono<FullHttpResponse>[] monos = requests.stream()
                .map(
                    request -> client.headers(h -> h.add(request.headers()))
                        .baseUrl(request.uri())
                        .request(request.method())
                        .send(Mono.fromSupplier(() -> request.content()))
                        .responseSingle(
                            (r, body) -> body.switchIfEmpty(Mono.just(Unpooled.EMPTY_BUFFER))
                                .map(
                                    b -> new DefaultFullHttpResponse(
                                        r.version(),
                                        r.status(),
                                        b.retain(),
                                        r.responseHeaders(),
                                        EmptyHttpHeaders.INSTANCE
                                    )
                                )
                        )
                        .doOnError(e -> LOG.warn("Request failed [protocol={}]: {}", protocol, e.getMessage(), e))
                )
                .toArray(Mono[]::new);

            if (ordered == false) {
                return ParallelFlux.from(monos).sequential().collectList().block();
            } else {
                return Flux.concat(monos).flatMapSequential(r -> Mono.just(r)).collectList().block(Duration.ofMinutes(2));
            }
        } finally {
            eventLoopGroup.shutdownGracefully().awaitUninterruptibly();
        }
    }

    private HttpClient createClient(final InetSocketAddress remoteAddress, final EventLoopGroup eventLoopGroup) {
        final HttpClient client = HttpClient.newConnection()
            .resolver(DefaultAddressResolverGroup.INSTANCE)
            .runOn(eventLoopGroup)
            .host(remoteAddress.getHostString())
            .port(remoteAddress.getPort())
            .compress(compression);

        if (secure) {
            if (protocol == HttpProtocol.HTTP11) {
                return client.protocol(protocol)
                    .secure(
                        spec -> spec.sslContext(
                            Http11SslContextSpec.forClient()
                                .configure(s -> s.clientAuth(ClientAuth.NONE).trustManager(InsecureTrustManagerFactory.INSTANCE))
                        ).handshakeTimeout(Duration.ofSeconds(30))
                    );
            } else if (protocol == HttpProtocol.H2) {
                // In FIPS mode: force JDK (BC FIPS/JSSE) instead of native BoringSSL, and advertise
                // only h2 in ALPN — reactor.netty.http.Http2SslContextSpec defaults to native BoringSSL
                // (same bypass as HTTP3) and includes http/1.1 as an ALPN fallback, both of which must be excluded.
                Consumer<SslContextBuilder> h2Configure = fipsMode
                    ? s -> s.sslProvider(SslProvider.JDK)
                        .clientAuth(ClientAuth.NONE)
                        .trustManager(InsecureTrustManagerFactory.INSTANCE)
                        .applicationProtocolConfig(
                            new ApplicationProtocolConfig(
                                Protocol.ALPN,
                                SelectorFailureBehavior.NO_ADVERTISE,
                                SelectedListenerFailureBehavior.ACCEPT,
                                ApplicationProtocolNames.HTTP_2
                            )
                        )
                    : s -> s.clientAuth(ClientAuth.NONE).trustManager(InsecureTrustManagerFactory.INSTANCE);
                HttpProtocol[] h2Protocols = fipsMode
                    ? new HttpProtocol[] { HttpProtocol.H2 }
                    : new HttpProtocol[] { HttpProtocol.HTTP11, HttpProtocol.H2 };
                return client.protocol(h2Protocols)
                    .secure(
                        spec -> spec.sslContext(Http2SslContextSpec.forClient().configure(h2Configure))
                            .handshakeTimeout(Duration.ofSeconds(30))
                    );
            } else {
                return client.protocol(protocol)
                    .secure(
                        spec -> spec.sslContext(
                            Http3SslContextSpec.forClient().configure(s -> s.trustManager(InsecureTrustManagerFactory.INSTANCE))
                        ).handshakeTimeout(Duration.ofSeconds(30))
                    )
                    .http3Settings(
                        spec -> spec.idleTimeout(Duration.ofSeconds(5))
                            .maxData(SETTING_HTTP_MAX_CONTENT_LENGTH.get(settings).getBytes())
                            .maxStreamDataBidirectionalLocal(1000000)
                            .maxStreamDataBidirectionalRemote(1000000)
                            .maxStreamsBidirectional(100L)
                    );
            }
        } else {
            if (protocol == HttpProtocol.HTTP11) {
                return client.protocol(protocol);
            } else {
                return client.protocol(new HttpProtocol[] { HttpProtocol.HTTP11, HttpProtocol.H2C });
            }
        }
    }

    @Override
    public void close() {

    }

    public HttpProtocol protocol() {
        return protocol;
    }

    private static HttpProtocol selectSupportedProtocol(boolean secure) {
        // In FIPS mode only H2 (TLS 1.2/1.3) is a valid test choice:
        // HTTP11: Http11SslContextSpec advertises non-FIPS cipher suites via JSSE; BC FIPS rejects the ClientHello.
        // HTTP3: QUIC crypto is handled by BoringSSL (native). The standard grpc-netty-shaded BoringSSL is NOT
        // built from the FIPS-validated branch (see boringssl/crypto/fipsmodule/FIPS.md), so it is not
        // FIPS-certified. Additionally it bypasses JSSE/BC FIPS entirely, so no enforcement happens.
        // Operators who need FIPS + QUIC can substitute a certified drop-in at the OS level — that is
        // outside the scope of these tests.
        // H2: mandates TLS 1.2+ through JSSE, correctly exercising BC FIPS enforcement.
        if (FipsMode.isEnabled()) {
            if (!secure) {
                throw new IllegalStateException("Plaintext H2C is not permitted in FIPS mode; use a TLS-secured connection");
            }
            return HttpProtocol.H2;
        }

        HttpProtocol[] values = null;

        if (secure) {
            values = Http3Utils.isHttp3Available()
                ? new HttpProtocol[] { HttpProtocol.HTTP11, HttpProtocol.H2, HttpProtocol.HTTP3 }
                : new HttpProtocol[] { HttpProtocol.HTTP11, HttpProtocol.H2 };
        } else {
            values = new HttpProtocol[] { HttpProtocol.HTTP11, HttpProtocol.H2C };
        }

        return values[RAND.nextInt(values.length - 1)];
    }

}
