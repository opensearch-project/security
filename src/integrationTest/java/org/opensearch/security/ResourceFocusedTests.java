/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.GZIPOutputStream;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.test.framework.AsyncActions;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ResourceFocusedTests {
    private final static Logger LOG = LogManager.getLogger(AsyncActions.class);
    private static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);
    private static final User LIMITED_USER = new User("limited_user").roles(
        new TestSecurityConfig.Role("limited-role").clusterPermissions(
            "indices:data/read/mget",
            "indices:data/read/msearch",
            "indices:data/read/scroll",
            "cluster:monitor/state",
            "cluster:monitor/health"
        )
            .indexPermissions(
                "indices:data/read/search",
                "indices:data/read/mget*",
                "indices:monitor/settings/get",
                "indices:monitor/stats"
            )
            .on("*")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, LIMITED_USER)
        .anonymousAuth(false)
        .doNotFailOnForbidden(true)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index("document").source(Map.of("foo", "bar", "abc", "xyz")))
                .actionGet();
        }
    }

    @Test
    public void testUnauthenticatedFewBig() {
        // Tweaks:
        final RequestBodySize size = RequestBodySize.XLarge;
        final String requestPath = "/*/_search";
        final int parrallelism = 5;
        final int totalNumberOfRequests = 100;

        runResourceTest(size, requestPath, parrallelism, totalNumberOfRequests);
    }

    @Test
    public void testUnauthenticatedManyMedium() {
        // Tweaks:
        final RequestBodySize size = RequestBodySize.Medium;
        final String requestPath = "/*/_search";
        final int parrallelism = 20;
        final int totalNumberOfRequests = 10_000;

        runResourceTest(size, requestPath, parrallelism, totalNumberOfRequests);
    }

    @Test
    public void testUnauthenticatedTonsSmall() {
        // Tweaks:
        final RequestBodySize size = RequestBodySize.Small;
        final String requestPath = "/*/_search";
        final int parrallelism = 100;
        final int totalNumberOfRequests = 15_000;

        runResourceTest(size, requestPath, parrallelism, totalNumberOfRequests);
    }

    private void runResourceTest(
        final RequestBodySize size,
        final String requestPath,
        final int parrallelism,
        final int totalNumberOfRequests
    ) {
        final byte[] compressedRequestBody = createCompressedRequestBody(size);
        try (final TestRestClient client = cluster.getRestClient(new BasicHeader("Content-Encoding", "gzip"))) {
            final var requests = AsyncActions.generate(() -> {
                final HttpPost post = new HttpPost(client.getHttpServerUri() + requestPath);
                post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));
                TestRestClient.HttpResponse response = client.executeRequest(post);
                return response.getStatusCode();
            }, parrallelism, totalNumberOfRequests);

            AsyncActions.getAll(requests, 2, TimeUnit.MINUTES).forEach((responseCode) -> {
                assertThat(responseCode, equalTo(HttpStatus.SC_UNAUTHORIZED));
            });
        }
    }

    static enum RequestBodySize {
        Small(1),
        Medium(1_000),
        XLarge(1_000_000);

        public final int elementCount;

        private RequestBodySize(final int elementCount) {
            this.elementCount = elementCount;
        }
    }

    private byte[] createCompressedRequestBody(final RequestBodySize size) {
        final int repeatCount = size.elementCount;
        final String prefix = "{ \"items\": [";
        final String repeatedElement = IntStream.range(0, 20)
            .mapToObj(n -> ('a' + n) + "")
            .map(n -> '"' + n + '"' + ": 123")
            .collect(Collectors.joining(",", "{", "}"));
        final String postfix = "]}";
        long uncompressedBytesSize = 0;

        try (
            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            final GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)
        ) {

            final byte[] prefixBytes = prefix.getBytes(StandardCharsets.UTF_8);
            final byte[] repeatedElementBytes = repeatedElement.getBytes(StandardCharsets.UTF_8);
            final byte[] postfixBytes = postfix.getBytes(StandardCharsets.UTF_8);

            gzipOutputStream.write(prefixBytes);
            uncompressedBytesSize = uncompressedBytesSize + prefixBytes.length;
            for (int i = 0; i < repeatCount; i++) {
                gzipOutputStream.write(repeatedElementBytes);
                uncompressedBytesSize = uncompressedBytesSize + repeatedElementBytes.length;
            }
            gzipOutputStream.write(postfixBytes);
            uncompressedBytesSize = uncompressedBytesSize + postfixBytes.length;
            gzipOutputStream.finish();

            final byte[] compressedRequestBody = byteArrayOutputStream.toByteArray();
            LOG.info(
                String.format(
                    "Original size was %,d bytes, compressed to %,d bytes, ratio %,.2f",
                    uncompressedBytesSize,
                    compressedRequestBody.length,
                    ((double) uncompressedBytesSize / compressedRequestBody.length)
                )
            );
            return compressedRequestBody;
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }
}
