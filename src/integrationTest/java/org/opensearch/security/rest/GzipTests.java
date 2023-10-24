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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.GZIPOutputStream;

import static org.junit.Assert.fail;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.TestRestClientConfiguration.getBasicAuthHeader;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GzipTests {
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

            final ForkJoinPool forkJoinPool = new ForkJoinPool(parallelism);

            final List<CompletableFuture<Void>> waitingOn = IntStream.rangeClosed(1, totalNumberOfRequests)
                .boxed()
                .map(i -> CompletableFuture.runAsync(() -> {
                    final HttpPost post = new HttpPost(client.getHttpServerUri() + requestPath);
                    post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));
                    TestRestClient.HttpResponse response = client.executeRequest(post);
                    assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
                    assertThat(response.getBody(), not(containsString("json_parse_exception")));
                }, forkJoinPool))
                .collect(Collectors.toList());

            final CompletableFuture<Void> allOfThem = CompletableFuture.allOf(waitingOn.toArray(new CompletableFuture[0]));

            allOfThem.get(30, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            Throwable rootCause = e.getCause();
            if (rootCause instanceof AssertionError) {
                fail("Received exception: " + e.getMessage());
            }
            // ignore
        } catch (InterruptedException e) {
            // ignore
        } catch (TimeoutException e) {
            // ignore
        }
    }

    @Test
    public void testMixOfAuthenticatedAndUnauthenticatedGzippedRequests() {
        final String requestPath = "/*/_search";
        final int parallelism = 10;
        final int totalNumberOfRequests = 100;

        final String rawBody = "{ \"query\": { \"match\": { \"foo\": \"bar\" }}}";

        final byte[] compressedRequestBody = createCompressedRequestBody(rawBody);
        try (TestRestClient client = cluster.getRestClient(new BasicHeader("Content-Encoding", "gzip"))) {

            final ForkJoinPool forkJoinPool = new ForkJoinPool(parallelism);

            Header basicAuthHeader = getBasicAuthHeader(ADMIN_USER.getName(), ADMIN_USER.getPassword());

            final List<CompletableFuture<Void>> waitingOn = IntStream.rangeClosed(1, totalNumberOfRequests)
                .boxed()
                .map(i -> CompletableFuture.runAsync(() -> {
                    final HttpPost post = new HttpPost(client.getHttpServerUri() + requestPath);
                    post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));
                    TestRestClient.HttpResponse response = i % 2 == 0
                        ? client.executeRequest(post)
                        : client.executeRequest(post, basicAuthHeader);
                    assertThat(response.getStatusCode(), equalTo(i % 2 == 0 ? HttpStatus.SC_UNAUTHORIZED : HttpStatus.SC_OK));
                    assertThat(response.getBody(), not(containsString("json_parse_exception")));
                }, forkJoinPool))
                .collect(Collectors.toList());

            final CompletableFuture<Void> allOfThem = CompletableFuture.allOf(waitingOn.toArray(new CompletableFuture[0]));

            allOfThem.get(30, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            Throwable rootCause = e.getCause();
            if (rootCause instanceof AssertionError) {
                fail("Received exception: " + e.getMessage());
            }
            // ignore
        } catch (InterruptedException e) {
            // ignore
        } catch (TimeoutException e) {
            // ignore
        }
    }

    static byte[] createCompressedRequestBody(String rawBody) {
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
