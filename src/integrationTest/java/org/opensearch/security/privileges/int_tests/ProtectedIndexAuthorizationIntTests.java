/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.privileges.int_tests;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestAlias;
import org.opensearch.test.framework.data.TestIndex;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.IndexMatcher;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnResponseIndexMatcher.containsExactly;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.limitedTo;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * This class tests protected indices functionality with different cluster configurations.
 * It uses the following dimensions:
 * <ul>
 *     <li>ClusterConfig: Tests with protected indices enabled and disabled</li>
 *     <li>TestSecurityConfig.User: Different users with different protected index role assignments</li>
 *     <li>Test methods: Different operations (search, create, delete, update, etc.)</li>
 * </ul>
 */
@RunWith(Parameterized.class)
public class ProtectedIndexAuthorizationIntTests {

    // -------------------------------------------------------------------------------------------------------
    // Test indices used by this test suite
    // -------------------------------------------------------------------------------------------------------

    static final TestIndex protected_index1 = TestIndex.name("protected_index1").documentCount(10).seed(1).build();
    static final TestIndex protected_index2 = TestIndex.name("protected_index2").documentCount(10).seed(2).build();
    static final TestIndex unprotected_index = TestIndex.name("unprotected_index").documentCount(10).seed(4).build();

    /**
     * This index is initially not created. Used for index creation tests.
     */
    static final TestIndex protected_index_x = TestIndex.name("protected_index_x").build();

    static final TestAlias alias_protected = new TestAlias("alias_protected").on(protected_index1);

    static final TestSecurityConfig.User.MetadataKey<IndexMatcher> ALLOWED = new TestSecurityConfig.User.MetadataKey<>(
        "allowed",
        IndexMatcher.class
    );

    // -------------------------------------------------------------------------------------------------------
    // Test users with different privilege configurations
    // -------------------------------------------------------------------------------------------------------

    static final TestSecurityConfig.Role PROTECTED_INDEX_ROLE = new TestSecurityConfig.Role("protected_index_role");

    /**
     * User with all index permissions but NOT member of protected index roles.
     * When protected indices are enabled, they should NOT have access to protected indices.
     */
    static final TestSecurityConfig.User NORMAL_USER = new TestSecurityConfig.User("normal_user")//
        .description("all_access but no protected role")//
        .roles(
            new TestSecurityConfig.Role("all_access_role")//
                .clusterPermissions("*")
                .indexPermissions("*")
                .on("*")
        )//
        .reference(ALLOWED, limitedTo(unprotected_index));

    /**
     * User with all index permissions AND member of protected_index_role.
     * When protected indices are enabled, they SHOULD have full access to protected indices.
     */
    static final TestSecurityConfig.User PROTECTED_INDEX_USER = new TestSecurityConfig.User("protected_index_user")//
        .description("all_access with protected role")//
        .roles(
            new TestSecurityConfig.Role("all_access_role")//
                .clusterPermissions("*")
                .indexPermissions("*")
                .on("*")
        )
        .referencedRoles(PROTECTED_INDEX_ROLE)//
        .reference(ALLOWED, limitedTo(protected_index1, protected_index2, unprotected_index));

    static final List<TestSecurityConfig.User> USERS = ImmutableList.of(NORMAL_USER, PROTECTED_INDEX_USER);

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USERS)
            .indices(protected_index1, protected_index2, unprotected_index)
            .aliases(alias_protected)
            .roles(PROTECTED_INDEX_ROLE)
            .nodeSettings(
                Map.of(
                    "plugins.security.protected_indices.enabled",
                    true,
                    "plugins.security.protected_indices.indices",
                    "protected_index*",
                    "plugins.security.protected_indices.roles",
                    "protected_index_role"
                )
            );
    }

    @ClassRule
    public static final ClusterConfig.ClusterInstances clusterInstances = new ClusterConfig.ClusterInstances(
        ProtectedIndexAuthorizationIntTests::clusterBuilder
    );

    final TestSecurityConfig.User user;
    final LocalCluster cluster;
    final ClusterConfig clusterConfig;

    @Test
    public void search_protectedIndex() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String matchAllQuery = "{\"query\": {\"match_all\": {}}}";

            TestRestClient.HttpResponse response = restClient.postJson("protected_index1/_search", matchAllQuery);
            if (user == PROTECTED_INDEX_USER) {
                assertThat(response, isOk());
                assertThat(response, containsExactly(protected_index1).at("hits.hits[*]._index"));
            } else if (clusterConfig.legacyPrivilegeEvaluation) {
                assertThat(response, isOk());
                assertThat(response, containsExactly().at("hits.hits[*]._index"));
            } else {
                // Thew new privilege evaluation just forbids this request; this follows the normal index reduction semantics
                assertThat(response, isForbidden());
            }
        }
    }

    @Test
    public void search_unprotectedIndex() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String matchAllQuery = "{\"query\": {\"match_all\": {}}}";

            TestRestClient.HttpResponse response = restClient.postJson("unprotected_index/_search", matchAllQuery);
            assertThat(response, isOk());
            assertThat(response, containsExactly(unprotected_index).at("hits.hits[*]._index"));
        }
    }

    @Test
    public void search_protectedIndexPattern() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String matchAllQuery = "{\"query\": {\"match_all\": {}}}";

            TestRestClient.HttpResponse response = restClient.postJson("protected_index*/_search?size=100", matchAllQuery);

            if (user == PROTECTED_INDEX_USER) {
                assertThat(response, isOk());
                assertThat(response, containsExactly(protected_index1, protected_index2).at("hits.hits[*]._index"));
            } else {
                assertThat(response, isOk());
                assertThat(response, containsExactly().at("hits.hits[*]._index"));
            }
        }
    }

    @Test
    public void search_aliasContainingProtectedIndices() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String matchAllQuery = "{\"query\": {\"match_all\": {}}}";

            TestRestClient.HttpResponse response = restClient.postJson("alias_protected/_search?size=100", matchAllQuery);

            if (user == PROTECTED_INDEX_USER) {
                assertThat(response, isOk());
                assertThat(response, containsExactly(protected_index1).at("hits.hits[*]._index"));
            } else if (clusterConfig.legacyPrivilegeEvaluation) {
                assertThat(response, isOk());
                assertThat(response, containsExactly().at("hits.hits[*]._index"));
            } else {
                // The new privilege evaluation just forbids this request; this follows the normal index reduction semantics
                assertThat(response, isForbidden());
            }
        }
    }

    @Test
    public void createDocument_protectedIndex() {
        String docId = "protected_index1/_doc/create_test_doc";
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = restClient.put(docId, json("foo", "bar"));
            if (user == PROTECTED_INDEX_USER) {
                assertThat(response, isCreated());
            } else {
                assertThat(response, isForbidden());
            }
        } finally {
            delete(docId);
        }
    }

    @Test
    public void deleteDocument_protectedIndex() {
        String docId = "protected_index1/_doc/create_test_doc";
        try (TestRestClient restClient = cluster.getRestClient(user); TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {

            // Initialization: Create document as admin
            {
                TestRestClient.HttpResponse httpResponse = adminRestClient.put(docId + "?refresh=true", json("foo", "bar"));
                assertThat(httpResponse, isCreated());
            }

            TestRestClient.HttpResponse response = restClient.delete(docId);
            if (user == PROTECTED_INDEX_USER) {
                assertThat(response, isOk());
            } else {
                assertThat(response, isForbidden());
            }
        } finally {
            delete(docId);
        }
    }

    @Test
    public void updateMappings_protectedIndex() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String newMappings = "{\"properties\": {\"user_name\": {\"type\": \"text\"}}}";
            TestRestClient.HttpResponse response = restClient.putJson("protected_index1/_mapping", newMappings);
            if (user == PROTECTED_INDEX_USER) {
                assertThat(response, isOk());
            } else {
                assertThat(response, isForbidden());
            }
        }
    }

    @Test
    public void closeIndex_protectedIndex() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = restClient.post("protected_index2/_close");
            if (user == PROTECTED_INDEX_USER) {
                assertThat(response, isOk());
            } else {
                assertThat(response, isForbidden());
            }
        } finally {
            try (TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {
                adminRestClient.post("protected_index2/_open");
            }
        }
    }

    @Test
    public void updateSettings_protectedIndex() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String indexSettings = "{\"index\": {\"refresh_interval\": \"5s\"}}";
            TestRestClient.HttpResponse response = restClient.putJson("protected_index1/_settings", indexSettings);
            if (user == PROTECTED_INDEX_USER) {
                assertThat(response, isOk());
            } else {
                assertThat(response, isForbidden());
            }
        } finally {
            try (TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {
                adminRestClient.putJson("protected_index1/_settings", "{\"index\": {\"refresh_interval\": null}}");
            }
        }
    }

    @Test
    public void aliasOperations_protectedIndex() {
        String aliasName = "test_alias_protected";
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String addAliasBody = """
                {"actions": [{"add": {"index": "protected_index1", "alias": "%s"}}]}
                """.formatted(aliasName);

            TestRestClient.HttpResponse response = restClient.postJson("_aliases", addAliasBody);

            if (user == PROTECTED_INDEX_USER) {
                assertThat(response, isOk());
            } else {
                assertThat(response, isForbidden());
            }
        } finally {
            // Cleanup - remove alias
            try (TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {
                String removeAliasBody = """
                    {"actions": [{"remove": {"index": "protected_index1", "alias": "%s"}}]}
                    """.formatted(aliasName);
                adminRestClient.postJson("_aliases", removeAliasBody);
            }
        }
    }

    @Parameterized.Parameters(name = "{0}, {2}")
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();

        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            for (TestSecurityConfig.User user : USERS) {
                result.add(new Object[] { clusterConfig, user, user.getDescription() });
            }
        }
        return result;
    }

    public ProtectedIndexAuthorizationIntTests(
        ClusterConfig clusterConfig,
        TestSecurityConfig.User user,
        @SuppressWarnings("unused") String description
    ) {
        this.user = user;
        this.cluster = clusterInstances.get(clusterConfig);
        this.clusterConfig = clusterConfig;
    }

    private void delete(String... paths) {
        try (TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {
            for (String path : paths) {
                TestRestClient.HttpResponse response = adminRestClient.delete(path);
                if (response.getStatusCode() != 200 && response.getStatusCode() != 404) {
                    throw new RuntimeException("Error while deleting " + path + "\n" + response.getBody());
                }
            }
        }
    }
}
