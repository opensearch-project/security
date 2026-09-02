/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.opensearch.test.framework.cluster;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import org.junit.Test;

import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;

import io.netty.handler.codec.http.HttpResponseStatus;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.server.HttpServer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

public class ReactorHttpClientTests {
    @Test
    public void honorsRequestedProtocol() {
        try (
            ReactorHttpClient client = new ReactorHttpClient(
                HttpProtocol.HTTP3,
                true,
                true,
                Settings.EMPTY,
                InetSocketAddress.createUnresolved("localhost", 443)
            )
        ) {
            assertThat(client.protocol(), equalTo(HttpProtocol.HTTP3));
        }
    }

    @Test
    public void limitsConcurrentRequests() {
        AtomicInteger activeRequests = new AtomicInteger();
        AtomicInteger maxActiveRequests = new AtomicInteger();
        DisposableServer server = HttpServer.create().port(0).handle((request, response) -> {
            int active = activeRequests.incrementAndGet();
            maxActiveRequests.accumulateAndGet(active, Math::max);
            return Mono.delay(Duration.ofMillis(20))
                .then(response.status(HttpResponseStatus.UNAUTHORIZED).send())
                .doFinally(signalType -> activeRequests.decrementAndGet());
        }).bindNow();

        try (
            ReactorHttpClient client = new ReactorHttpClient(
                HttpProtocol.HTTP11,
                true,
                false,
                Settings.EMPTY,
                new InetSocketAddress("localhost", server.port())
            )
        ) {
            List<Tuple<String, byte[]>> requests = IntStream.range(0, 20).mapToObj(i -> Tuple.tuple("/", new byte[0])).toList();

            client.post(requests, 2).forEach(response -> {
                assertThat(response.status(), equalTo(HttpResponseStatus.UNAUTHORIZED));
                response.release();
            });
        } finally {
            server.disposeNow();
        }

        assertThat(maxActiveRequests.get(), lessThanOrEqualTo(2));
    }
}
