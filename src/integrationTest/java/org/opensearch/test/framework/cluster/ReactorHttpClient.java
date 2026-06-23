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

import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.http.netty4.http3.Http3Utils;

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
import io.netty.handler.ssl.ClientAuth;
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

import static org.opensearch.http.HttpTransportSettings.SETTING_HTTP_HTTP3_ENABLED;
import static org.opensearch.http.HttpTransportSettings.SETTING_HTTP_MAX_CONTENT_LENGTH;

/**
 * Tiny helper to send http requests over netty.
 */
public class ReactorHttpClient implements Closeable {
    private static final java.util.Random RAND = new java.util.Random();

    private final boolean compression;
    private final boolean secure;
    private final HttpProtocol protocol;
    private final Settings settings;
    private final InetSocketAddress remoteAddress;

    public ReactorHttpClient(boolean compression, boolean secure, Settings settings, InetSocketAddress remoteAddress) {
        this.compression = compression;
        this.secure = secure;
        this.protocol = randomProtocol(secure, settings);
        this.settings = settings;
        this.remoteAddress = remoteAddress;
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
                return client.protocol(new HttpProtocol[] { HttpProtocol.HTTP11, HttpProtocol.H2 })
                    .secure(
                        spec -> spec.sslContext(
                            Http2SslContextSpec.forClient()
                                .configure(s -> s.clientAuth(ClientAuth.NONE).trustManager(InsecureTrustManagerFactory.INSTANCE))
                        ).handshakeTimeout(Duration.ofSeconds(30))
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

    private static HttpProtocol randomProtocol(boolean secure, Settings settings) {
        HttpProtocol[] values = null;

        if (secure) {
            if (Http3Utils.isHttp3Available() && SETTING_HTTP_HTTP3_ENABLED.get(settings).booleanValue() == true) {
                values = new HttpProtocol[] { HttpProtocol.HTTP11, HttpProtocol.H2, HttpProtocol.HTTP3 };
            } else {
                values = new HttpProtocol[] { HttpProtocol.HTTP11, HttpProtocol.H2 };
            }
        } else {
            values = new HttpProtocol[] { HttpProtocol.HTTP11, HttpProtocol.H2C };
        }

        return values[RAND.nextInt(values.length - 1)];
    }

}
