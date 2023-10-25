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
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.MatcherAssert.assertThat;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.GZIPOutputStream;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.TestRestClientConfiguration.getBasicAuthHeader;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class CompressionTests {
    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .anonymousAuth(false)
        .build();

    @Test
    public void testAuthenticatedGzippedRequests() throws Exception {
        final String requestPath = "/*/_search";
        final int parallelism = 10;
        final int totalNumberOfRequests = 100;

        final String rawBody = "{ \"query\": { \"match\": { \"foo\": \"bar\" }}}";

        final byte[] compressedRequestBody = createCompressedRequestBody(rawBody);
        try (final TestRestClient client = cluster.getRestClient(ADMIN_USER, new BasicHeader("Content-Encoding", "gzip"))) {

            final ForkJoinPool forkJoinPool = new ForkJoinPool(parallelism);

            final List<CompletableFuture<HttpResponse>> waitingOn = IntStream.rangeClosed(1, totalNumberOfRequests)
                .boxed()
                .map(i -> CompletableFuture.supplyAsync(() -> {
                    final HttpPost post = new HttpPost(client.getHttpServerUri() + requestPath);
                    post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));
                    return client.executeRequest(post);
                }, forkJoinPool))
                .collect(Collectors.toList());

            final CompletableFuture<Void> allOfThem = CompletableFuture.allOf(waitingOn.toArray(new CompletableFuture[0]));

            allOfThem.get(30, TimeUnit.SECONDS);

            waitingOn.stream().forEach(future -> {
                try {
                    final HttpResponse response = future.get();
                    response.assertStatusCode(HttpStatus.SC_OK);
                } catch (final Exception ex) {
                    throw new RuntimeException(ex);
                }
            });
            ;
        }
    }

    @Test
    public void testMixOfAuthenticatedAndUnauthenticatedGzippedRequests() throws Exception {
        final String requestPath = "/*/_search";
        final int parallelism = 10;
        final int totalNumberOfRequests = 100;

        final String rawBody = "{ \"query\": { \"match\": { \"foo\": \"bar\" }}}";

        final byte[] compressedRequestBody = createCompressedRequestBody(rawBody);
        try (final TestRestClient client = cluster.getRestClient(new BasicHeader("Content-Encoding", "gzip"))) {

            final ForkJoinPool forkJoinPool = new ForkJoinPool(parallelism);

            final Header basicAuthHeader = getBasicAuthHeader(ADMIN_USER.getName(), ADMIN_USER.getPassword());

            final List<CompletableFuture<HttpResponse>> waitingOn = IntStream.rangeClosed(1, totalNumberOfRequests)
                .boxed()
                .map(i -> CompletableFuture.supplyAsync(() -> {
                    final HttpPost post = new HttpPost(client.getHttpServerUri() + requestPath);
                    post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));
                    return i % 2 == 0 ? client.executeRequest(post) : client.executeRequest(post, basicAuthHeader);
                }, forkJoinPool))
                .collect(Collectors.toList());

            final CompletableFuture<Void> allOfThem = CompletableFuture.allOf(waitingOn.toArray(new CompletableFuture[0]));

            allOfThem.get(30, TimeUnit.SECONDS);

            waitingOn.stream().forEach(future -> {
                try {
                    final HttpResponse response = future.get();
                    assertThat(response.getBody(), not(containsString("json_parse_exception")));
                    assertThat(response.getStatusCode(), anyOf(equalTo(HttpStatus.SC_UNAUTHORIZED), equalTo(HttpStatus.SC_OK)));
                } catch (final Exception ex) {
                    throw new RuntimeException(ex);
                }
            });
            ;
        }
    }

    static byte[] createCompressedRequestBody(final String rawBody) {
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
