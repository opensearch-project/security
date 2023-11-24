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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicHeader;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.AsyncActions;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
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
    public void testAuthenticatedGzippedRequests() {
        final String requestPath = "/*/_search";
        final int parallelism = 10;
        final int totalNumberOfRequests = 100;

        final String rawBody = "{ \"query\": { \"match\": { \"foo\": \"bar\" }}}";

        final byte[] compressedRequestBody = createCompressedRequestBody(rawBody);
        try (final TestRestClient client = cluster.getRestClient(ADMIN_USER, new BasicHeader("Content-Encoding", "gzip"))) {
            final var requests = AsyncActions.generate(() -> {
                final HttpPost post = new HttpPost(client.getHttpServerUri() + requestPath);
                post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));
                return client.executeRequest(post);
            }, parallelism, totalNumberOfRequests);

            AsyncActions.getAll(requests, 30, TimeUnit.SECONDS).forEach((response) -> { response.assertStatusCode(HttpStatus.SC_OK); });
        }
    }

    @Test
    public void testMixOfAuthenticatedAndUnauthenticatedGzippedRequests() throws Exception {
        final String requestPath = "/*/_search";
        final int parallelism = 10;
        final int totalNumberOfRequests = 50;

        final String rawBody = "{ \"query\": { \"match\": { \"foo\": \"bar\" }}}";

        final byte[] compressedRequestBody = createCompressedRequestBody(rawBody);
        try (final TestRestClient client = cluster.getRestClient(new BasicHeader("Content-Encoding", "gzip"))) {
            final CountDownLatch countDownLatch = new CountDownLatch(1);

            final var authorizedRequests = AsyncActions.generate(() -> {
                countDownLatch.await();
                System.err.println("Generation triggered authorizedRequests");
                final HttpPost post = new HttpPost(client.getHttpServerUri() + requestPath);
                post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));
                return client.executeRequest(post, getBasicAuthHeader(ADMIN_USER.getName(), ADMIN_USER.getPassword()));
            }, parallelism, totalNumberOfRequests);

            final var unauthorizedRequests = AsyncActions.generate(() -> {
                countDownLatch.await();
                System.err.println("Generation triggered unauthorizedRequests");
                final HttpPost post = new HttpPost(client.getHttpServerUri() + requestPath);
                post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));
                return client.executeRequest(post);
            }, parallelism, totalNumberOfRequests);

            // Make sure all requests start at the same time
            countDownLatch.countDown();

            AsyncActions.getAll(authorizedRequests, 30, TimeUnit.SECONDS).forEach((response) -> {
                assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
            });
            AsyncActions.getAll(unauthorizedRequests, 30, TimeUnit.SECONDS).forEach((response) -> {
                assertThat(response.getBody(), not(containsString("json_parse_exception")));
                assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            });
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
