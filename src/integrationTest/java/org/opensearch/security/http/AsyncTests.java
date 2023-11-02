/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.http;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.nimbusds.jose.util.StandardCharset;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.security.IndexOperationsHelper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.AsyncActions;
import org.opensearch.test.framework.RolesMapping;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import java.util.Collections;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CompletableFuture;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AsyncTests {
    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").backendRoles("admin");

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().singleNode()
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .rolesMapping(new RolesMapping(ALL_ACCESS).backendRoles("admin"))
        .anonymousAuth(false)
        .nodeSettings(Map.of(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of(ALL_ACCESS.getName())))
        .build();

    @Test
    public void testBulkAndCacheInvalidationMixed() throws Exception {
        String indexName = "test-index";
        final String invalidateCachePath = "_plugins/_security/api/cache";
        final String nodesPath = "_nodes";
        final String bulkPath = "/_bulk";
        final String document = ("{ \"index\": { \"_index\": \"" + indexName + "\" }}\n{ \"foo\": \"bar\" }\n").repeat(5);
        final int parallelism = 5;
        final int totalNumberOfRequests = 30;

        try (final TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            IndexOperationsHelper.createIndex(cluster, indexName);

            final CountDownLatch countDownLatch = new CountDownLatch(1);

            List<CompletableFuture<HttpResponse>> allRequests = new ArrayList<CompletableFuture<HttpResponse>>();

            allRequests.addAll(AsyncActions.generate(() -> {
                countDownLatch.await();
                return client.delete(invalidateCachePath);
            }, parallelism, totalNumberOfRequests));

            allRequests.addAll(AsyncActions.generate(() -> {
                countDownLatch.await();
                final HttpPost post = new HttpPost(client.getHttpServerUri() + bulkPath);
                post.setEntity(new ByteArrayEntity(document.getBytes(StandardCharset.UTF_8), ContentType.APPLICATION_JSON));
                return client.executeRequest(post);
            }, parallelism, totalNumberOfRequests));

            allRequests.addAll(AsyncActions.generate(() -> {
                countDownLatch.await();
                return client.get(nodesPath);
            }, parallelism, totalNumberOfRequests));

            // Make sure all requests start at the same time
            countDownLatch.countDown();
            Collections.shuffle(allRequests);

            AsyncActions.getAll(allRequests, 30, TimeUnit.SECONDS).forEach((response) -> { response.assertStatusCode(HttpStatus.SC_OK); });
        }
    }
}