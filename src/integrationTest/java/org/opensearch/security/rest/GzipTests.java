/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.rest;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.GZIPOutputStream;

import static org.junit.Assert.fail;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GzipTests {
    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);
    private static final TestSecurityConfig.User LIMITED_USER = new TestSecurityConfig.User("limited_user").roles(
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
    public void testAuthenticatedGzippedRequests() {
        final String requestPath = "/*/_search";
        final int parrallelism = 10;
        final int totalNumberOfRequests = 100;

        final byte[] compressedRequestBody = createCompressedRequestBody();
        List<TestRestClient> restClients = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            restClients.add(cluster.getRestClient(ADMIN_USER, new BasicHeader("Content-Encoding", "gzip")));
        }
        Random rand = new Random();
        final HttpPost post = new HttpPost(restClients.get(0).getHttpServerUri() + requestPath);
        post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));

        final ForkJoinPool forkJoinPool = new ForkJoinPool(parrallelism);

        final List<CompletableFuture<Void>> waitingOn = IntStream.rangeClosed(1, totalNumberOfRequests)
            .boxed()
            .map(i -> CompletableFuture.runAsync(() -> {
                TestRestClient.HttpResponse response = restClients.get(rand.nextInt(10)).executeRequest(post);
                assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
                assertThat(response.getBody(), not(containsString("json_parse_exception")));
            }, forkJoinPool))
            .collect(Collectors.toList());

        final CompletableFuture<Void> allOfThem = CompletableFuture.allOf(waitingOn.toArray(new CompletableFuture[0]));

        try {
            allOfThem.get(30, TimeUnit.SECONDS);
        } catch (final Exception e) {
            Throwable rootCause = e.getCause();
            if (rootCause instanceof AssertionError) {
                fail("Received exception: " + e.getMessage());
            }
        }
    }

    private byte[] createCompressedRequestBody() {
        final String rawBody = "{ \"query\": { \"match\": { \"foo\": \"bar\" }}}";

        try (
            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            final GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)
        ) {
            gzipOutputStream.write(rawBody.getBytes(StandardCharsets.UTF_8));
            gzipOutputStream.finish();

            final byte[] compressedRequestBody = byteArrayOutputStream.toByteArray();
            return compressedRequestBody;
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }
}
