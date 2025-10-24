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

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestComponentTemplate;
import org.opensearch.test.framework.data.TestDataStream;
import org.opensearch.test.framework.data.TestIndex;
import org.opensearch.test.framework.data.TestIndexOrAliasOrDatastream;
import org.opensearch.test.framework.data.TestIndexTemplate;
import org.opensearch.test.framework.matcher.RestIndexMatchers;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.data.TestIndex.openSearchSecurityConfigIndex;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnResponseIndexMatcher.containsExactly;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.limitedTo;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.limitedToNone;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.unlimited;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.unlimitedIncludingOpenSearchSecurityIndex;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * This class defines a huge test matrix for index related access controls. This class is especially for read-only operations on data streams.
 * It uses the following dimensions:
 * <ul>
 *     <li>ClusterConfig: At the moment, we test without and with system index permission enabled. New semantics will follow later.</li>
 *     <li>TestSecurityConfig.User: We have quite a few of different users with different privileges configurations.</li>
 *     <li>The test methods represent different operations with different options that are tested</li>
 * </ul>
 * To cope with the huge space of tests, this class uses test oracles to verify the result of the operations.
 * These are defined with the "indexMatcher()" method of TestSecurityConfig.User. See there and the class IndexApiMatchers.
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DataStreamAuthorizationReadOnlyIntTests {

    // -------------------------------------------------------------------------------------------------------
    // Test data streams and indices used by this test suite. Indices are usually initially created; the only
    // exception is ds_ax, which is referred to in tests, but which does not exist on purpose.
    // -------------------------------------------------------------------------------------------------------

    static TestDataStream ds_a1 = TestDataStream.name("ds_a1").documentCount(100).rolloverAfter(10).seed(1).build();
    static TestDataStream ds_a2 = TestDataStream.name("ds_a2").documentCount(110).rolloverAfter(10).seed(2).build();
    static TestDataStream ds_a3 = TestDataStream.name("ds_a3").documentCount(120).rolloverAfter(10).seed(3).build();
    static TestDataStream ds_ax = TestDataStream.name("ds_ax").build(); // Not existing data stream
    static TestDataStream ds_b1 = TestDataStream.name("ds_b1").documentCount(51).rolloverAfter(10).seed(4).build();
    static TestDataStream ds_b2 = TestDataStream.name("ds_b2").documentCount(52).rolloverAfter(10).seed(5).build();
    static TestDataStream ds_b3 = TestDataStream.name("ds_b3").documentCount(53).rolloverAfter(10).seed(6).build();
    static TestIndex index_c1 = TestIndex.name("index_c1").documentCount(5).seed(7).build();

    static final List<TestIndexOrAliasOrDatastream> ALL_INDICES = List.of(
        ds_a1,
        ds_a2,
        ds_a3,
        ds_b1,
        ds_b2,
        ds_b3,
        index_c1,
        openSearchSecurityConfigIndex()
    );

    static final List<TestIndexOrAliasOrDatastream> ALL_INDICES_EXCEPT_SYSTEM_INDICES = List.of(
        ds_a1,
        ds_a2,
        ds_a3,
        ds_b1,
        ds_b2,
        ds_b3,
        index_c1
    );

    static final List<TestIndexOrAliasOrDatastream> ALL_DATA_STREAMS = List.of(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3);

    /**
     * This key identifies assertion reference data for index search/read permissions of individual users.
     */
    static final TestSecurityConfig.User.MetadataKey<RestIndexMatchers.IndexMatcher> READ = new TestSecurityConfig.User.MetadataKey<>(
        "read",
        RestIndexMatchers.IndexMatcher.class
    );

    // -------------------------------------------------------------------------------------------------------
    // Test users with which the tests will be executed; the users need to be added to the list USERS below
    // The users have two redundant versions or privilege configuration, which needs to be kept in sync:
    // - The standard role configuration defined with .roles()
    // - IndexMatchers which act as test oracles, defined with the indexMatcher() methods
    // -------------------------------------------------------------------------------------------------------

    /**
     * A simple user that can read from ds_a*
     */
    static TestSecurityConfig.User LIMITED_USER_A = new TestSecurityConfig.User("limited_user_A")//
        .description("ds_a*")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")//
                .indexPermissions(
                    "read",
                    "indices_monitor",
                    "indices:admin/analyze",
                    "indices:admin/data_stream/get",
                    "indices:monitor/data_stream/stats"
                )
                .on("ds_a*")
        )//
        .reference(READ, limitedTo(ds_a1, ds_a2, ds_a3, ds_ax));

    /**
     * A simple user that can read from ds_b*
     */
    static TestSecurityConfig.User LIMITED_USER_B = new TestSecurityConfig.User("limited_user_B")//
        .description("ds_b*")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")//
                .indexPermissions(
                    "read",
                    "indices_monitor",
                    "indices:admin/analyze",
                    "indices:admin/data_stream/get",
                    "indices:monitor/data_stream/stats"
                )
                .on("ds_b*")
        )//
        .reference(READ, limitedTo(ds_b1, ds_b2, ds_b3));

    /**
     * A simple user that can read from ds_b1
     */
    static TestSecurityConfig.User LIMITED_USER_B1 = new TestSecurityConfig.User("limited_user_B1")//
        .description("ds_b1")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")//
                .indexPermissions(
                    "read",
                    "indices_monitor",
                    "indices:admin/analyze",
                    "indices:admin/data_stream/get",
                    "indices:monitor/data_stream/stats"
                )
                .on("ds_b1")
        )//
        .reference(READ, limitedTo(ds_b1));

    /**
     * This user has no privileges for indices that are used in this test. But they have privileges for other indices.
     * This allows them to use actions like _search and receive empty result sets.
     */
    static TestSecurityConfig.User LIMITED_USER_OTHER_PRIVILEGES = new TestSecurityConfig.User("limited_user_other_index_privileges")//
        .description("no privileges for existing indices")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")//
                .indexPermissions(
                    "read",
                    "indices_monitor",
                    "indices:admin/analyze",
                    "indices:admin/data_stream/get",
                    "indices:monitor/data_stream/stats"
                )
                .on("ds_does_not_exist_*")
        )//
        .reference(READ, limitedToNone());

    /**
     * A user with "*" privileges on "*"; as it is a regular user, they are still subject to system index
     * restrictions and similar things.
     */
    static TestSecurityConfig.User UNLIMITED_USER = new TestSecurityConfig.User("unlimited_user")//
        .description("unlimited")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")//
                .indexPermissions("*")
                .on("*")//
        )//
        .reference(READ, unlimited());

    /**
     * The SUPER_UNLIMITED_USER authenticates with an admin cert, which will cause all access control code to be skipped.
     * This serves as a base for comparison with the default behavior.
     */
    static TestSecurityConfig.User SUPER_UNLIMITED_USER = new TestSecurityConfig.User("super_unlimited_user")//
        .description("super unlimited (admin cert)")//
        .adminCertUser()//
        .reference(READ, unlimitedIncludingOpenSearchSecurityIndex());

    static List<TestSecurityConfig.User> USERS = List.of(
        LIMITED_USER_A,
        LIMITED_USER_B,
        LIMITED_USER_B1,
        LIMITED_USER_OTHER_PRIVILEGES,
        UNLIMITED_USER,
        SUPER_UNLIMITED_USER
    );

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USERS)//
            .indexTemplates(new TestIndexTemplate("ds_test", "ds_*").dataStream().composedOf(TestComponentTemplate.DATA_STREAM_MINIMAL))//
            .dataStreams(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3)//
            .indices(index_c1);
    }

    @AfterClass
    public static void stopClusters() {
        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            clusterConfig.shutdown();
        }
    }

    final TestSecurityConfig.User user;
    final LocalCluster cluster;
    final ClusterConfig clusterConfig;

    @Test
    public void search_noPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(ALL_INDICES_EXCEPT_SYSTEM_INDICES).at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_noPattern_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_search?size=1000&expand_wildcards=none");
            if (user == UNLIMITED_USER || user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
            } else {
                assertThat(httpResponse, isForbidden());
            }
        }
    }

    @Test
    public void search_noPattern_allowNoIndicesFalse() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_search?size=1000&allow_no_indices=false");
            if (user != LIMITED_USER_OTHER_PRIVILEGES) {
                assertThat(
                    httpResponse,
                    containsExactly(ALL_INDICES_EXCEPT_SYSTEM_INDICES).at("hits.hits[*]._index")
                        .reducedBy(user.reference(READ))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isNotFound() : isForbidden())
                );
            } else {
                // Due to allow_no_indices=false, we cannot reduce to the empty set for the user without any privileges. Thus we get a 403
                assertThat(httpResponse, isForbidden());
            }
        }
    }

    @Test
    public void search_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_all/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(ALL_INDICES_EXCEPT_SYSTEM_INDICES).at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_all_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_all/_search?size=1000&expand_wildcards=none");
            if (user == UNLIMITED_USER || user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
            } else {
                assertThat(httpResponse, isForbidden());
            }
        }
    }

    @Test
    public void search_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*/_search?size=1000");

            assertThat(
                httpResponse,
                containsExactly(ALL_INDICES_EXCEPT_SYSTEM_INDICES).at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_staticNames_noIgnoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1/_search?size=1000");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // In the old privilege evaluation, data streams with incomplete privileges will be replaced by their member indices
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_b1).at("hits.hits[*]._index").reducedBy(user.reference(READ)).whenEmpty(isForbidden())
                );
            } else {
                // In the new privilege evaluation, data streams with incomplete privileges will lead to a 403 error
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_b1).at("hits.hits[*]._index").butForbiddenIfIncomplete(user.reference(READ))
                );
            }
        }
    }

    @Test
    public void search_staticNames_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1/_search?size=1000&ignore_unavailable=true");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_b1).at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_staticIndicies_negation_backingIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1,-.ds-ds_b1*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_b1).at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a*,ds_b*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_indexPattern_minus() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a*,ds_b*,-ds_b2,-ds_b3/_search?size=1000");
            // OpenSearch does not handle the expression ds_a*,ds_b*,-ds_b2,-ds_b3 in a way that excludes the data streams. See
            // search_indexPattern_minus_backingIndices for an alternative.
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_indexPattern_minus_backingIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a*,ds_b*,-.ds-ds_b2*,-.ds-ds_b3*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1).at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_indexPattern_nonExistingIndex_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(
                "ds_a*,ds_b*,xxx_non_existing/_search?size=1000&ignore_unavailable=true"
            );

            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );

        }
    }

    @Test
    public void search_indexPattern_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(
                "ds_a*,ds_b*/_search?size=1000&expand_wildcards=none&ignore_unavailable=true"
            );
            if (clusterConfig.legacyPrivilegeEvaluation && (user == LIMITED_USER_B1 || user == LIMITED_USER_OTHER_PRIVILEGES)) {
                assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/search]"));
            } else {
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
            }
        }
    }

    @Test
    public void search_nonExisting_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("x_does_not_exist/_search?size=1000");

            if (user == UNLIMITED_USER || user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isNotFound());
            } else {
                assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/search]"));
            }
        }
    }

    @Test
    public void search_nonExisting_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("x_does_not_exist*/_search?size=1000");

            assertThat(httpResponse, isOk());
            assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
        }
    }

    @Test
    public void search_termsAggregation_index() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("_search", """
                {
                  "size": 0,
                  "aggs": {
                    "indices": {
                      "terms": {
                        "field": "_index",
                        "size": 1000
                      }
                    }
                  }
                }""");

            assertThat(
                httpResponse,
                containsExactly(ALL_INDICES_EXCEPT_SYSTEM_INDICES).at("aggregations.indices.buckets[*].key")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isOk())
            );

        }
    }

    @Test
    public void msearch_staticIndices() throws Exception {
        String msearchBody = """
            {"index": "ds_b1"}
            {"size": 10, "query": {"bool":{"must":{"match_all":{}}}}}
            {"index": "ds_b2"}
            {"size": 10, "query": {"bool":{"must":{"match_all":{}}}}}
            """;

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("_msearch", msearchBody);
            assertThat(
                httpResponse,
                containsExactly(ds_b1, ds_b2).at("responses[*].hits.hits[*]._index").reducedBy(user.reference(READ)).whenEmpty(isOk())
            );
        }
    }

    @Test
    public void index_stats_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_stats");
            assertThat(
                httpResponse,
                containsExactly(ALL_INDICES_EXCEPT_SYSTEM_INDICES).at("indices.keys()")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void index_stats_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_b*/_stats");
            assertThat(
                httpResponse,
                containsExactly(ds_b1, ds_b2, ds_b3).at("indices.keys()")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void getDataStream_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // The legacy mode does not support dnfof for indices:admin/data_stream/get
                assertThat(
                    httpResponse,
                    containsExactly(ALL_DATA_STREAMS).at("$.data_streams[*].name").butForbiddenIfIncomplete(user.reference(READ))
                );
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ALL_DATA_STREAMS).at("$.data_streams[*].name").reducedBy(user.reference(READ)).whenEmpty(isOk())
                );
            }
        }
    }

    @Test
    public void getDataStream_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/*");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // The legacy mode does not support dnfof for indices:admin/data_stream/get
                assertThat(
                    httpResponse,
                    containsExactly(ALL_DATA_STREAMS).at("$.data_streams[*].name").butForbiddenIfIncomplete(user.reference(READ))
                );
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ALL_DATA_STREAMS).at("$.data_streams[*].name").reducedBy(user.reference(READ)).whenEmpty(isOk())
                );
            }
        }
    }

    @Test
    public void getDataStream_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_a*");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // The legacy mode does not support dnfof for indices:admin/data_stream/get
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3).at("$.data_streams[*].name").butForbiddenIfIncomplete(user.reference(READ))
                );
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3).at("$.data_streams[*].name").reducedBy(user.reference(READ)).whenEmpty(isOk())
                );
            }
        }
    }

    @Test
    public void getDataStream_pattern_negation() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_*,-ds_b*");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // The legacy mode does not support dnfof for indices:admin/data_stream/get
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3).at("$.data_streams[*].name").butForbiddenIfIncomplete(user.reference(READ))
                );
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3).at("$.data_streams[*].name").reducedBy(user.reference(READ)).whenEmpty(isOk())
                );
            }
        }
    }

    @Test
    public void getDataStream_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_a1,ds_a2");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2).at("$.data_streams[*].name").butForbiddenIfIncomplete(user.reference(READ))
            );
        }
    }

    @Test
    public void getDataStreamStats_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/_stats");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // The legacy mode does not support dnfof for indices:monitor/data_stream/stats
                assertThat(
                    httpResponse,
                    containsExactly(ALL_DATA_STREAMS).at("$.data_streams[*].data_stream").butForbiddenIfIncomplete(user.reference(READ))
                );
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ALL_DATA_STREAMS).at("$.data_streams[*].data_stream").reducedBy(user.reference(READ)).whenEmpty(isOk())
                );
            }
        }
    }

    @Test
    public void getDataStreamStats_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/*/_stats");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // The legacy mode does not support dnfof for indices:monitor/data_stream/stats
                assertThat(
                    httpResponse,
                    containsExactly(ALL_DATA_STREAMS).at("$.data_streams[*].data_stream").butForbiddenIfIncomplete(user.reference(READ))
                );
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ALL_DATA_STREAMS).at("$.data_streams[*].data_stream").reducedBy(user.reference(READ)).whenEmpty(isOk())
                );
            }
        }
    }

    @Test
    public void getDataStreamStats_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_a*/_stats");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // The legacy mode does not support dnfof for indices:monitor/data_stream/stats
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3).at("$.data_streams[*].data_stream").butForbiddenIfIncomplete(user.reference(READ))
                );
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3).at("$.data_streams[*].data_stream")
                        .reducedBy(user.reference(READ))
                        .whenEmpty(isOk())
                );
            }
        }
    }

    @Test
    public void getDataStreamStats_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_a1,ds_a2/_stats");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2).at("$.data_streams[*].data_stream").butForbiddenIfIncomplete(user.reference(READ))
            );
        }
    }

    @Test
    public void resolve_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/*");
            assertThat(
                httpResponse,
                containsExactly(ALL_INDICES_EXCEPT_SYSTEM_INDICES).at("$.*[*].name")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void resolve_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/ds_a*,ds_b*");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("$.*[*].name")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void field_caps_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(ALL_INDICES_EXCEPT_SYSTEM_INDICES).at("indices")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void field_caps_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a*,ds_b*/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("indices")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void field_caps_staticIndices_noIgnoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1/_field_caps?fields=*");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_b1).at("indices").reducedBy(user.reference(READ)).whenEmpty(isForbidden())
                );
            } else {
                assertThat(httpResponse, containsExactly(ds_a1, ds_a2, ds_b1).at("indices").butForbiddenIfIncomplete(user.reference(READ)));
            }
        }
    }

    @Test
    public void field_caps_staticIndices_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1/_field_caps?fields=*&ignore_unavailable=true");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_b1).at("indices")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void field_caps_nonExisting_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("x_does_not_exist/_field_caps?fields=*");

            if (user == UNLIMITED_USER || user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isNotFound());
            } else {
                assertThat(httpResponse.getStatusCode(), is(403));
            }
        }
    }

    @Test
    public void field_caps_nonExisting_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("x_does_not_exist*/_field_caps?fields=*");

            assertThat(httpResponse, containsExactly().at("indices").whenEmpty(isOk()));
        }
    }

    @Test
    public void field_caps_indexPattern_minus() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a*,ds_b*,-ds_b2,-ds_b3/_field_caps?fields=*");
            // does not handle the expression ds_a*,ds_b*,-ds_b2,-ds_b3 in a way that excludes the data streams. See
            // field_caps_indexPattern_minus_backingIndices for an alternative.
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("indices")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void field_caps_indexPattern_minus_backingIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a*,ds_b*,-.ds-ds_b2*,-.ds-ds_b3*/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1).at("indices")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void field_caps_staticIndices_negation_backingIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1,-.ds-ds_b1*/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_b1).at("indices")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @ParametersFactory(shuffle = false, argumentFormatting = "%1$s, %3$s")
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();

        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            for (TestSecurityConfig.User user : USERS) {
                result.add(new Object[] { clusterConfig, user, user.getDescription() });
            }
        }
        return result;
    }

    public DataStreamAuthorizationReadOnlyIntTests(ClusterConfig clusterConfig, TestSecurityConfig.User user, String description)
        throws Exception {
        this.user = user;
        this.cluster = clusterConfig.cluster(DataStreamAuthorizationReadOnlyIntTests::clusterBuilder);
        this.clusterConfig = clusterConfig;
    }
}
