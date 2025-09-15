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

import org.opensearch.test.framework.TestComponentTemplate;
import org.opensearch.test.framework.TestDataStream;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestIndexOrAliasOrDatastream;
import org.opensearch.test.framework.TestIndexTemplate;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.opensearch.test.framework.TestIndex.openSearchSecurityConfigIndex;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnResponseIndexMatcher.containsExactly;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.limitedTo;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.limitedToNone;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.unlimited;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.unlimitedIncludingOpenSearchSecurityIndex;
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

    static TestDataStream ds_a1 = TestDataStream.name("ds_a1").documentCount(100).rolloverAfter(10).seed(1)/*.attr("prefix", "a")*/.build();
    static TestDataStream ds_a2 = TestDataStream.name("ds_a2").documentCount(110).rolloverAfter(10).seed(2)/*.attr("prefix", "a")*/.build();
    static TestDataStream ds_a3 = TestDataStream.name("ds_a3").documentCount(120).rolloverAfter(10).seed(3)/*.attr("prefix", "a")*/.build();
    static TestDataStream ds_ax = TestDataStream.name("ds_ax").build(); // Not existing data stream
    static TestDataStream ds_b1 = TestDataStream.name("ds_b1").documentCount(51).rolloverAfter(10).seed(4)/*.attr("prefix", "b")*/.build();
    static TestDataStream ds_b2 = TestDataStream.name("ds_b2").documentCount(52).rolloverAfter(10).seed(5)/*.attr("prefix", "a")*/.build();
    static TestDataStream ds_b3 = TestDataStream.name("ds_b3").documentCount(53).rolloverAfter(10).seed(6)/*.attr("prefix", "a")*/.build();
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

    static TestSecurityConfig.User LIMITED_USER_A = new TestSecurityConfig.User("limited_user_A")//
        .description("ds_a*")//
        .roles(
            //
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
        .indexMatcher("read", limitedTo(ds_a1, ds_a2, ds_a3, ds_ax))//
        .indexMatcher("read_top_level", limitedTo(ds_a1, ds_a2, ds_a3))//
        .indexMatcher("get_alias", limitedToNone());

    static TestSecurityConfig.User LIMITED_USER_B = new TestSecurityConfig.User("limited_user_B")//
        .description("ds_b*")//
        .roles(
            //
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
        .indexMatcher("read", limitedTo(ds_b1, ds_b2, ds_b3))//
        .indexMatcher("read_top_level", limitedTo(ds_b1, ds_b2, ds_b3))//
        .indexMatcher("get_alias", limitedToNone());

    static TestSecurityConfig.User LIMITED_USER_B1 = new TestSecurityConfig.User("limited_user_B1")//
        .description("ds_b1")//
        .roles(
            //
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
        .indexMatcher("read", limitedTo(ds_b1))//
        .indexMatcher("read_top_level", limitedTo(ds_b1))//
        .indexMatcher("get_alias", limitedToNone());

    static TestSecurityConfig.User LIMITED_USER_NONE = new TestSecurityConfig.User("limited_user_none")//
        .description("no privileges for existing indices")//
        .roles(
            //
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
        .indexMatcher("read", limitedToNone())//
        .indexMatcher("read_top_level", limitedToNone())//
        .indexMatcher("get_alias", limitedToNone());

    static TestSecurityConfig.User UNLIMITED_USER = new TestSecurityConfig.User("unlimited_user")//
        .description("unlimited")//
        .roles(
            //
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")//
                .indexPermissions("*")
                .on("*")//
        )//
        .indexMatcher("read", unlimited())//
        .indexMatcher("read_top_level", unlimited())//
        .indexMatcher("get_alias", unlimited());

    /**
     * The SUPER_UNLIMITED_USER authenticates with an admin cert, which will cause all access control code to be skipped.
     * This serves as a base for comparison with the default behavior.
     */
    static TestSecurityConfig.User SUPER_UNLIMITED_USER = new TestSecurityConfig.User("super_unlimited_user")//
        .description("super unlimited (admin cert)")//
        .adminCertUser()//
        .indexMatcher("read", unlimitedIncludingOpenSearchSecurityIndex())//
        .indexMatcher("read_top_level", unlimitedIncludingOpenSearchSecurityIndex())//
        .indexMatcher("get_alias", unlimitedIncludingOpenSearchSecurityIndex());

    static List<TestSecurityConfig.User> USERS = List.of(
        LIMITED_USER_A,
        LIMITED_USER_B,
        LIMITED_USER_B1,
        LIMITED_USER_NONE,
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
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3, index_c1).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
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
                // The dnfof implementation has the effect that the expand_wildcards=none option is disregarded
                // Additionally, the dnfof implementation has the effect that hidden indices might be included even though not requested
                assertThat(
                    httpResponse,
                    containsExactly(ALL_INDICES).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_noPattern_allowNoIndicesFalse() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_search?size=1000&allow_no_indices=false");

            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3, index_c1).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isNotFound() : isForbidden())
            );
        }
    }

    @Test
    public void search_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_all/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3, index_c1).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
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
                // The dnfof implementation has the effect that the expand_wildcards=none option is disregarded
                // Additionally, the dnfof implementation has the effect that hidden indices might be included even though not requested
                assertThat(
                    httpResponse,
                    containsExactly(ALL_INDICES).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3, index_c1).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_staticNames_noIgnoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1/_search?size=1000");
            // With dnfof data streams with incomplete privileges will be replaced by their member indices
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_b1).at("hits.hits[*]._index").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void search_staticNames_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1/_search?size=1000&ignore_unavailable=true");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_b1).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
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
                    .reducedBy(user.indexMatcher("read"))
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
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_indexPattern_minus() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a*,ds_b*,-ds_b2,-ds_b3/_search?size=1000");
            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                // does not handle the expression ds_a*,ds_b*,-ds_b2,-ds_b3 in a way that excludes the data streams. See
                // search_indexPattern_minus_backingIndices for an alternative.
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else {
                // The IndexResolverReplacer fails to interpret the minus patterns and falls back to interpreting the given index names
                // literally
                // In the logs, this then looks like this:
                // | indices:data/read/search |
                // -ds_b2| MISSING |
                // -ds_b3| MISSING |
                // ds_b* | MISSING |
                // ds_a* | MISSING |
                // This has the effect that granted privileges using wildcards might work, but granted privileges without wildcards won't
                // work
                if (user == LIMITED_USER_B1) {
                    // No wildcard in the index pattern
                    assertThat(httpResponse, isForbidden());
                } else {
                    assertThat(
                        httpResponse,
                        containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("hits.hits[*]._index")
                            .reducedBy(user.indexMatcher("read"))
                            .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                    );
                }
            }
        }
    }

    @Test
    public void search_indexPattern_minus_backingIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a*,ds_b*,-.ds-ds_b2*,-.ds-ds_b3*/_search?size=1000");
            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3, ds_b1).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else {

                // dnfof has the effect that the index expression is interpreted differently and that ds_b2 and ds_b3 get included
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_indexPattern_nonExistingIndex_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(
                "ds_a*,ds_b*,xxx_non_existing/_search?size=1000&ignore_unavailable=true"
            );

            // The presence of a non existing index has the effect that the other patterns are not resolved by IndexResolverReplacer
            // This causes a few more 403 errors where the granted index patterns do not use wildcards

            if (user == LIMITED_USER_B1) {
                assertThat(httpResponse, isForbidden());
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_indexPattern_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(
                "ds_a*,ds_b*/_search?size=1000&expand_wildcards=none&ignore_unavailable=true"
            );
            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
            } else {
                // dnfof makes the expand_wildcards=none option ineffective
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
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

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3, index_c1).at("aggregations.indices.buckets[*].key")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(isOk())
                );
            } else {
                // Users without full privileges will not see hidden indices here; thus on a cluster with only data streams, the result is
                // often just empty
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly().at("aggregations.indices.buckets[*].key"));
            }
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
                containsExactly(ds_b1, ds_b2).at("responses[*].hits.hits[*]._index").reducedBy(user.indexMatcher("read")).whenEmpty(isOk())
            );
        }
    }

    @Test
    public void index_stats_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_stats");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3, index_c1).at("indices.keys()")
                    .reducedBy(user.indexMatcher("read"))
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
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void getDataStream_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream");
            // The legacy mode does not support dnfof for indices:admin/data_stream/get
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("$.data_streams[*].name")
                    .butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void getDataStream_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/*");
            // The legacy mode does not support dnfof for indices:admin/data_stream/get
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("$.data_streams[*].name")
                    .butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void getDataStream_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_a*");
            // The legacy mode does not support dnfof for indices:admin/data_stream/get
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3).at("$.data_streams[*].name").butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void getDataStream_pattern_negation() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_*,-ds_b*");
            // The legacy mode does not support dnfof for indices:admin/data_stream/get
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3).at("$.data_streams[*].name").butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void getDataStream_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_a1,ds_a2");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2).at("$.data_streams[*].name").butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void getDataStreamStats_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/_stats");
            // The legacy mode does not support dnfof for indices:monitor/data_stream/stats
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("$.data_streams[*].data_stream")
                    .butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void getDataStreamStats_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/*/_stats");
            // The legacy mode does not support dnfof for indices:monitor/data_stream/stats
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("$.data_streams[*].data_stream")
                    .butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void getDataStreamStats_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_a*/_stats");
            // The legacy mode does not support dnfof for indices:monitor/data_stream/stats
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3).at("$.data_streams[*].data_stream").butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void getDataStreamStats_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_data_stream/ds_a1,ds_a2/_stats");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2).at("$.data_streams[*].data_stream").butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void resolve_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/*");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3, index_c1).at("$.*[*].name")
                    .reducedBy(user.indexMatcher("read"))
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
                    .reducedBy(user.indexMatcher("read"))
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
                containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3, index_c1).at("indices")
                    .reducedBy(user.indexMatcher("read"))
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
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void field_caps_staticIndices_noIgnoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_b1).at("indices").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden())
            );

        }
    }

    @Test
    public void field_caps_staticIndices_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1/_field_caps?fields=*&ignore_unavailable=true");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_b1).at("indices")
                    .reducedBy(user.indexMatcher("read"))
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
            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                // OpenSearch does not handle the expression ds_a*,ds_b*,-ds_b2,-ds_b3 in a way that excludes the data streams. See
                // field_caps_indexPattern_minus_backingIndices for an alternative.
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("indices")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else {
                if (user == LIMITED_USER_B1) {
                    // No wildcard in the index pattern
                    assertThat(httpResponse, isForbidden());
                } else {
                    assertThat(
                        httpResponse,
                        containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("indices")
                            .reducedBy(user.indexMatcher("read"))
                            .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                    );
                }
            }
        }
    }

    @Test
    public void field_caps_indexPattern_minus_backingIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a*,ds_b*,-.ds-ds_b2*,-.ds-ds_b3*/_field_caps?fields=*");
            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3, ds_b1).at("indices")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else {
                // dnfof has the effect that the index expression is interpreted differently and that ds_b2 and ds_b3 get included
                assertThat(
                    httpResponse,
                    containsExactly(ds_a1, ds_a2, ds_a3, ds_b1, ds_b2, ds_b3).at("indices")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void field_caps_staticIndices_negation_backingIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("ds_a1,ds_a2,ds_b1,-.ds-ds_b1*/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(ds_a1, ds_a2, ds_b1).at("indices")
                    .reducedBy(user.indexMatcher("read"))
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
