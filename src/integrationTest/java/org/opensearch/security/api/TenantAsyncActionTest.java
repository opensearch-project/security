/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.api;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.AsyncActions;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class TenantAsyncActionTest {

    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

    private static final String TENANT_ENDPOINT = PLUGINS_PREFIX + "/api/tenants/tenant1";

    private static final String TENANT_BODY = "{\"description\":\"create new tenant\"}";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .anonymousAuth(false)
        .nodeSettings(Map.of(SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName())))
        .build();

    @Test
    public void testParallelPutRequests() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {

            final CountDownLatch countDownLatch = new CountDownLatch(1);
            final List<CompletableFuture<TestRestClient.HttpResponse>> conflictingRequests = AsyncActions.generate(() -> {
                return client.putJson(TENANT_ENDPOINT, TENANT_BODY);
            }, 4, 4);

            // Make sure all requests start at the same time
            countDownLatch.countDown();

            AtomicInteger numCreatedResponses = new AtomicInteger();
            AsyncActions.getAll(conflictingRequests, 1, TimeUnit.SECONDS).forEach((response) -> {
                assertThat(response.getStatusCode(), anyOf(equalTo(HttpStatus.SC_CREATED), equalTo(HttpStatus.SC_CONFLICT)));
                if (response.getStatusCode() == HttpStatus.SC_CREATED) numCreatedResponses.getAndIncrement();
            });
            assertThat(numCreatedResponses.get(), equalTo(1)); // should only be one 201

            TestRestClient.HttpResponse getResponse = client.get(TENANT_ENDPOINT); // make sure the one 201 works
            assertThat(getResponse.getBody(), containsString("create new tenant"));
        }
    }
}
