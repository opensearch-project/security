/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.alias;

import java.io.IOException;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Integration tests for GET _alias/{alias} API with scoped credentials.
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GetAliasIntegrationTest {

    private static final String CONCRETE_INDEX = "concrete_index";
    private static final String ALIAS_NAME = "my_alias";

    static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    // User with permissions only on the alias, not the concrete index
    static final User ALIAS_ONLY_USER = new User("alias_user").roles(
        new Role("alias_role").clusterPermissions("*").indexPermissions("*").on(ALIAS_NAME)
    );

    // User with permissions on both alias and concrete index
    static final User ALIAS_PLUS_CONCRETE_INDEX_USER = new User("alias_concrete_user").roles(
        new Role("alias_concrete_role").clusterPermissions("*").indexPermissions("*").on(ALIAS_NAME, CONCRETE_INDEX)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, ALIAS_ONLY_USER, ALIAS_PLUS_CONCRETE_INDEX_USER)
        .build();

    @BeforeClass
    public static void createTestData() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson(CONCRETE_INDEX + "/_doc/1?refresh=true", """
                {"field":"value"}
                """);
            client.postJson("_aliases", """
                {"actions":[{"add":{"index":"%s","alias":"%s"}}]}
                """.formatted(CONCRETE_INDEX, ALIAS_NAME));
        }
    }

    @Test
    public void testGetAlias_WithAliasPermission_ShouldSucceed() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ALIAS_ONLY_USER)) {
            var response = client.get("_alias/" + ALIAS_NAME);

            assertThat(response.getStatusCode(), is(200));
        }
    }

    @Test
    public void testGetAlias_WithoutConcreteIndexPermission_ShouldFail() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ALIAS_ONLY_USER)) {
            var response = client.get("_alias/" + CONCRETE_INDEX);

            assertThat(response.getStatusCode(), is(404));
        }
    }

    @Test
    public void testSearchViaAlias_WithAliasPermission_ShouldSucceed() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ALIAS_ONLY_USER)) {
            var response = client.get(ALIAS_NAME + "/_search");

            assertThat(response.getStatusCode(), is(200));
        }
    }

    // TODO This surprisingly works, but should it?
    @Ignore
    @Test
    public void testSearchConcreteIndex_WithAliasPermission_ShouldFail() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ALIAS_ONLY_USER)) {
            var response = client.get(CONCRETE_INDEX + "/_search");

            assertThat(response.getStatusCode(), is(403));
        }
    }

    @Test
    public void testGetAlias_WithBothPermissions_ShouldSucceed() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ALIAS_PLUS_CONCRETE_INDEX_USER)) {
            var response = client.get("_alias/" + ALIAS_NAME);

            assertThat(response.getStatusCode(), is(200));
        }
    }

    @Test
    public void testSearchViaAlias_WithBothPermissions_ShouldSucceed() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ALIAS_PLUS_CONCRETE_INDEX_USER)) {
            var response = client.get(ALIAS_NAME + "/_search");

            assertThat(response.getStatusCode(), is(200));
        }
    }

    @Test
    public void testSearchConcreteIndex_WithBothPermissions_ShouldSucceed() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ALIAS_PLUS_CONCRETE_INDEX_USER)) {
            var response = client.get(CONCRETE_INDEX + "/_search");

            assertThat(response.getStatusCode(), is(200));
        }
    }
}
