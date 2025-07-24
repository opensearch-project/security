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

package org.opensearch.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.collect.ImmutableList;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestAlias;
import org.opensearch.test.framework.TestData;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.IndexApiMatchers.IndexMatcher;
import static org.opensearch.test.framework.IndexApiMatchers.containsExactly;
import static org.opensearch.test.framework.IndexApiMatchers.limitedTo;
import static org.opensearch.test.framework.IndexApiMatchers.limitedToNone;
import static org.opensearch.test.framework.IndexApiMatchers.openSearchIndices;
import static org.opensearch.test.framework.IndexApiMatchers.unlimited;
import static org.opensearch.test.framework.IndexApiMatchers.unlimitedIncludingOpenSearchIndices;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class IndexAuthorizationReadOnlyIntTests {

    static final TestIndex index_a1 = TestIndex.name("index_a1").documentCount(100).seed(1).build();
    static final TestIndex index_a2 = TestIndex.name("index_a2").documentCount(110).seed(2).build();
    static final TestIndex index_a3 = TestIndex.name("index_a3").documentCount(120).seed(3).build();
    static final TestIndex index_ax = TestIndex.name("index_ax").build(); // Not existing index
    static final TestIndex index_b1 = TestIndex.name("index_b1").documentCount(51).seed(4).build();
    static final TestIndex index_b2 = TestIndex.name("index_b2").documentCount(52).seed(5).build();
    static final TestIndex index_b3 = TestIndex.name("index_b3").documentCount(53).seed(6).build();
    static final TestIndex index_c1 = TestIndex.name("index_c1").documentCount(5).seed(7).build();
    static final TestIndex index_hidden = TestIndex.name("index_hidden").hidden().documentCount(1).seed(8).build();
    static final TestIndex index_hidden_dot = TestIndex.name(".index_hidden_dot").hidden().documentCount(1).seed(8).build();

    static final TestAlias alias_ab1 = new TestAlias("alias_ab1", index_a1, index_a2, index_a3, index_b1);
    static final TestAlias alias_c1 = new TestAlias("alias_c1", index_c1);

    static final TestSecurityConfig.User LIMITED_USER_A = new TestSecurityConfig.User("limited_user_A").description("index_a*")
        .roles(
            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_a*")
        )
        .indexMatcher("read", limitedTo(index_a1, index_a2, index_a3, index_ax))
        .indexMatcher("search", limitedTo(index_a1, index_a2, index_a3, index_ax))
        .indexMatcher("get_alias", limitedToNone());

    static final TestSecurityConfig.User LIMITED_USER_B = new TestSecurityConfig.User("limited_user_B").description("index_b*")
        .roles(
            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_b*")
        )
        .indexMatcher("read", limitedTo(index_b1, index_b2, index_b3))
        .indexMatcher("search", limitedTo(index_b1, index_b2, index_b3))
        .indexMatcher("get_alias", limitedToNone());

    static final TestSecurityConfig.User LIMITED_USER_B1 = new TestSecurityConfig.User("limited_user_B1").description("index_b1")
        .roles(
            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_b1")
        )
        .indexMatcher("read", limitedTo(index_b1))
        .indexMatcher("search", limitedTo(index_b1))
        .indexMatcher("get_alias", limitedToNone());

    static final TestSecurityConfig.User LIMITED_USER_C = new TestSecurityConfig.User("limited_user_C").description("index_c*")
        .roles(

            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_c*")
        )
        .indexMatcher("read", limitedTo(index_c1))
        .indexMatcher("search", limitedTo(index_c1))
        .indexMatcher("get_alias", limitedToNone());

    static final TestSecurityConfig.User LIMITED_USER_ALIAS_AB1 = new TestSecurityConfig.User("limited_user_alias_AB1").description(
        "alias_ab1"
    )
        .roles(

            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze", "indices:admin/aliases/get")
                .on("alias_ab1*")
        )
        .indexMatcher("read", limitedTo(index_a1, index_a2, index_a3, index_b1, alias_ab1))
        .indexMatcher("search", limitedTo(index_a1, index_a2, index_a3, index_b1, alias_ab1))
        .indexMatcher("get_alias", limitedTo(index_a1, index_a2, index_a3, index_b1, alias_ab1));

    static final TestSecurityConfig.User LIMITED_USER_ALIAS_C1 = new TestSecurityConfig.User("limited_user_alias_C1").description(
        "alias_c1"
    )
        .roles(

            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("alias_c1")
        )
        .indexMatcher("read", limitedTo(index_c1, alias_c1))
        .indexMatcher("search", limitedTo(index_c1, alias_c1))
        .indexMatcher("get_alias", limitedToNone());

    static final TestSecurityConfig.User LIMITED_USER_A_HIDDEN = new TestSecurityConfig.User("limited_user_A_hidden").description(
        "index_a*, index_hidden*"
    )
        .roles(

            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_a*", "index_hidden*", ".index_hidden*")
        )
        .indexMatcher("read", limitedTo(index_a1, index_a2, index_a3, index_ax, index_hidden, index_hidden_dot))
        .indexMatcher("search", limitedTo(index_a1, index_a2, index_a3, index_ax, index_hidden, index_hidden_dot))
        .indexMatcher("get_alias", limitedToNone());

    static final TestSecurityConfig.User LIMITED_USER_NONE = new TestSecurityConfig.User("limited_user_none").description(
        "no privileges for existing indices"
    )
        .roles(

            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("crud", "indices_monitor", "indices:admin/analyze")
                .on("index_does_not_exist_*")
        )
        .indexMatcher("read", limitedToNone())
        .indexMatcher("search", limitedToNone())
        .indexMatcher("get_alias", limitedToNone());

    static final TestSecurityConfig.User UNLIMITED_USER = new TestSecurityConfig.User("unlimited_user").description("unlimited")
        .roles(

            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("*")
                .on("*")

        )
        .indexMatcher("read", unlimitedIncludingOpenSearchIndices())
        .indexMatcher("search", unlimited())
        .indexMatcher("get_alias", unlimitedIncludingOpenSearchIndices());

    /**
     * The SUPER_UNLIMITED_USER authenticates with an admin cert, which will cause all access control code to be skipped.
     * This serves as a base for comparison with the default behavior.
     */
    static final TestSecurityConfig.User SUPER_UNLIMITED_USER = new TestSecurityConfig.User("super_unlimited_user").description(
        "super unlimited (admin cert)"
    )
        .adminCertUser()
        .indexMatcher("read", unlimitedIncludingOpenSearchIndices())
        .indexMatcher("search", unlimitedIncludingOpenSearchIndices())
        .indexMatcher("get_alias", unlimitedIncludingOpenSearchIndices());

    static final List<TestSecurityConfig.User> USERS = ImmutableList.of(
        LIMITED_USER_A,
        LIMITED_USER_B,
        LIMITED_USER_B1,
        LIMITED_USER_C,
        LIMITED_USER_ALIAS_AB1,
        LIMITED_USER_ALIAS_C1,
        LIMITED_USER_A_HIDDEN,
        LIMITED_USER_NONE,
        UNLIMITED_USER,
        SUPER_UNLIMITED_USER
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().singleNode()
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USERS)
        .indices(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1, index_hidden, index_hidden_dot)
        .aliases(alias_ab1, alias_c1)
        .doNotFailOnForbidden(true)
        .respectRequestIndicesOptions(true)
        .build();

    final TestSecurityConfig.User user;

    @ParametersFactory(shuffle = false)
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();

        for (TestSecurityConfig.User user : USERS) {
            result.add(new Object[] { user, user.getDescription() });
        }

        return result;
    }

    public IndexAuthorizationReadOnlyIntTests(TestSecurityConfig.User user, String description) {
        this.user = user;
    }

    @Test
    public void search_noPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    @Ignore("Fails with an exception java.lang.IllegalArgumentException: Must contain at least one column and at least one row (got []/[indices:data/read/search]) thrown from https://github.com/opensearch-project/security/blob/main/src/main/java/org/opensearch/security/privileges/actionlevel/RuntimeOptimizedActionPrivileges.java#L103")
    public void search_noPattern_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("/_search?size=1000&expand_wildcards=none");
            assertThat(httpResponse, containsExactly().at("hits.hits[*]._index").whenEmpty(200));
        }
    }

    @Test
    public void search_noPattern_allowNoIndicesFalse() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("/_search?size=1000&allow_no_indices=false");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void search_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_all/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    @Ignore("Fails with an exception java.lang.IllegalArgumentException: Must contain at least one column and at least one row (got []/[indices:data/read/search]) thrown by https://github.com/opensearch-project/security/blob/main/src/main/java/org/opensearch/security/privileges/actionlevel/RuntimeOptimizedActionPrivileges.java#L103")
    public void search_all_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_all/_search?size=1000&expand_wildcards=none");
            assertThat(httpResponse, containsExactly().at("hits.hits[*]._index").whenEmpty(200));
        }
    }

    @Test
    public void search_all_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_all/_search?size=1000&expand_wildcards=all");
            assertThat(
                httpResponse,
                containsExactly(
                    index_a1,
                    index_a2,
                    index_a3,
                    index_b1,
                    index_b2,
                    index_b3,
                    index_c1,
                    index_hidden,
                    index_hidden_dot,
                    openSearchIndices()
                ).at("hits.hits[*]._index").but(user.indexMatcher("search")).whenEmpty(403)
            );
        }
    }

    @Test
    public void search_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    @Ignore("Fails with an exception java.lang.IllegalArgumentException: Must contain at least one column and at least one row (got []/[indices:data/read/search]) thrown by https://github.com/opensearch-project/security/blob/main/src/main/java/org/opensearch/security/privileges/actionlevel/RuntimeOptimizedActionPrivileges.java#L103")
    public void search_wildcard_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*/_search?size=1000&expand_wildcards=none");
            assertThat(httpResponse, containsExactly().at("hits.hits[*]._index").whenEmpty(200));
        }
    }

    @Test
    public void search_wildcard_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*/_search?size=1000&expand_wildcards=all");
            assertThat(
                httpResponse,
                containsExactly(
                    index_a1,
                    index_a2,
                    index_a3,
                    index_b1,
                    index_b2,
                    index_b3,
                    index_c1,
                    index_hidden,
                    index_hidden_dot,
                    openSearchIndices()
                ).at("hits.hits[*]._index").but(user.indexMatcher("search")).whenEmpty(403)
            );
        }
    }

    @Test
    public void search_staticIndicies() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a1,index_a2,index_b1/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_b1).at("hits.hits[*]._index").but(user.indexMatcher("search")).whenEmpty(403)
            );
        }
    }

    @Test
    public void search_staticIndicies_nonExisting() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_ax/_search?size=1000");

            if (containsExactly(index_ax).but(user.indexMatcher("search")).isEmpty()) {
                assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/search]"));
            } else {
                assertThat(httpResponse, isNotFound());
            }
        }
    }

    @Test
    public void search_staticIndicies_negation() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            // On static indices, negation does not have an effect
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a1,index_a2,index_b1,-index_b1/_search?size=1000");

            if (httpResponse.getStatusCode() == 404) {
                // A 404 error is also acceptable if we get OS complaining about -index_b1. This will be the case for users with full
                // permissions
                assertThat(httpResponse.getTextFromJsonBody("/error/type"), equalTo("index_not_found_exception"));
                assertThat(httpResponse.getTextFromJsonBody("/error/reason"), containsString("no such index [-index_b1]"));
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_b1).at("hits.hits[*]._index").but(user.indexMatcher("search")).whenEmpty(403)
                );
            }
        }
    }

    @Test
    public void search_staticIndicies_hidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_hidden/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_hidden).at("hits.hits[*]._index").butForbiddenIfIncomplete(user.indexMatcher("search"))
            );
        }
    }

    @Test
    public void search_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a*,index_b*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void search_indexPattern_minus() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a*,index_b*,-index_b2,-index_b3/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void search_indexPattern_nonExistingIndex_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(
                "index_a*,index_b*,xxx_non_existing/_search?size=1000&ignore_unavailable=true"
            );
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void search_indexPattern_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(
                "index_a*,index_b*/_search?size=1000&expand_wildcards=none&ignore_unavailable=true"
            );
            assertThat(httpResponse, containsExactly().at("hits.hits[*]._index").but(user.indexMatcher("search")).whenEmpty(200));
        }
    }

    @Test
    public void search_indexPatternAndStatic_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(
                "index_a*,index_b1/_search?size=1000&expand_wildcards=none&ignore_unavailable=true"
            );
            assertThat(httpResponse, containsExactly(index_b1).at("hits.hits[*]._index").but(user.indexMatcher("search")).whenEmpty(403));
        }
    }

    @Test
    public void search_indexPatternAndStatic_negation() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            // If there is a wildcard, negation will also affect indices specified without a wildcard
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a*,index_b1,index_b2,-index_b2/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void search_alias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab1/_search?size=1000&ignore_unavailable=true");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void search_alias_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab1*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void search_alias_pattern_negation() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_*,-alias_ab1/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_c1).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void search_aliasAndIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab1,index_b2/_search?size=1000&ignore_unavailable=true");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2).at("hits.hits[*]._index")
                    .but(user.indexMatcher("search"))
                    .whenEmpty(403)
            );
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

            assertThat(httpResponse, containsExactly().at("hits.hits[*]._index").whenEmpty(200));
        }
    }

    @Test
    public void search_termsAggregation_index() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson(
                "/_search",
                "{\"size\":0,\"aggs\":{\"indices\":{\"terms\":{\"field\":\"_index\",\"size\":1000}}}}"
            );

            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at(
                    "aggregations.indices.buckets[*].key"
                ).but(user.indexMatcher("search")).whenEmpty(200)
            );
        }
    }

    @Test
    public void search_pit() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.post("index_*/_search/point_in_time?keep_alive=1m");

            IndexMatcher indexMatcher = containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1);

            if (indexMatcher.but(user.indexMatcher("search")).isEmpty()) {
                assertThat(
                    httpResponse,
                    isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/point_in_time/create]")
                );
                return;
            } else {
                assertThat(httpResponse, isOk());
            }

            String pitId = httpResponse.getTextFromJsonBody("/pit_id");
            httpResponse = restClient.postJson("/_search?size=1000", String.format("""
                {
                  "pit": {
                    "id": "%s"
                  }
                }
                """, pitId));
            assertThat(httpResponse, isOk());
            assertThat(httpResponse, indexMatcher.at("hits.hits[*]._index").but(user.indexMatcher("search")));
        }
    }

    @Test
    public void search_pit_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.post("_all/_search/point_in_time?keep_alive=1m");

            IndexMatcher indexMatcher = containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1);

            if (indexMatcher.but(user.indexMatcher("search")).isEmpty()) {
                assertThat(
                    httpResponse,
                    isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/point_in_time/create]")
                );
                return;
            } else {
                assertThat(httpResponse, isOk());
            }

            String pitId = httpResponse.getTextFromJsonBody("/pit_id");
            httpResponse = restClient.postJson("/_search?size=1000", String.format("""
                {
                  "pit": {
                    "id": "%s"
                  }
                }
                """, pitId));
            assertThat(httpResponse, isOk());
            assertThat(httpResponse, indexMatcher.at("hits.hits[*]._index").but(user.indexMatcher("search")));
        }
    }

    @Test
    public void search_pit_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.post("index_a1/_search/point_in_time?keep_alive=1m");

            IndexMatcher indexMatcher = containsExactly(index_a1);

            if (indexMatcher.but(user.indexMatcher("search")).isEmpty()) {
                assertThat(
                    httpResponse,
                    isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/point_in_time/create]")
                );
                return;
            } else {
                assertThat(httpResponse, isOk());
            }

            String pitId = httpResponse.getTextFromJsonBody("/pit_id");
            httpResponse = restClient.postJson("/_search?size=1000", String.format("""
                {
                  "pit": {
                    "id": "%s"
                  }
                }
                """, pitId));
            assertThat(httpResponse, indexMatcher.at("hits.hits[*]._index").but(user.indexMatcher("search")));
        }
    }

    @Test
    public void search_pit_wrongIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.post("index_a*/_search/point_in_time?keep_alive=1m");

            IndexMatcher indexMatcher = containsExactly(index_a1, index_a2, index_a3);

            if (indexMatcher.but(user.indexMatcher("search")).isEmpty()) {
                assertThat(
                    httpResponse,
                    isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/point_in_time/create]")
                );
                return;
            } else {
                assertThat(httpResponse, isOk());
            }

            String pitId = httpResponse.getTextFromJsonBody("/pit_id");
            httpResponse = restClient.postJson("index_b*/_search?size=1000", String.format("""
                {
                  "pit": {
                    "id": "%s"
                  }
                }
                """, pitId));
            assertThat(httpResponse, isBadRequest("/error/root_cause/0/reason", "[indices] cannot be used with point in time"));
        }
    }

    @Test
    public void msearch_staticIndices() throws Exception {
        String msearchBody = """
            {"index":"index_b1"}
            {"size":10, "query":{"bool":{"must":{"match_all":{}}}}}
            {"index":"index_b2"}
            {"size":10, "query":{"bool":{"must":{"match_all":{}}}}}
            """;

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("/_msearch", msearchBody);
            assertThat(
                httpResponse,
                containsExactly(index_b1, index_b2).at("responses[*].hits.hits[*]._index").but(user.indexMatcher("read")).whenEmpty(200)
            );
        }
    }

    @Test
    public void mget() throws Exception {
        TestData.TestDocument testDocumentA1 = index_a1.anyDocument();
        TestData.TestDocument testDocumentB1 = index_b1.anyDocument();
        TestData.TestDocument testDocumentB2 = index_b2.anyDocument();

        String mget = String.format("""
            {
              "docs": [
                { "_index": "index_a1", "_id": "%s" },
                { "_index": "index_b1", "_id": "%s" },
                { "_index": "index_b2", "_id": "%s" }
              ]
            }
            """, testDocumentA1.id(), testDocumentB1.id(), testDocumentB2.id());

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("/_mget", mget);
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_b1, index_b2).at("docs[?(@.found == true)]._index")
                    .but(user.indexMatcher("read"))
                    .whenEmpty(200)
            );
        }
    }

    @Test
    public void mget_alias() throws Exception {
        TestData.TestDocument testDocumentC1a = index_c1.anyDocument();
        TestData.TestDocument testDocumentC1b = index_c1.anyDocument();

        String mget = String.format("""
            {
              "docs": [
                { "_index": "alias_c1", "_id": "%s" },
                { "_index": "alias_c1", "_id": "%s" }
              ]
            }
            """, testDocumentC1a.id(), testDocumentC1b.id());

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("/_mget", mget);
            assertThat(
                httpResponse,
                containsExactly(index_c1).at("docs[?(@.found == true)]._index").but(user.indexMatcher("read")).whenEmpty(200)
            );
        }
    }

    @Test
    public void get() throws Exception {
        TestData.TestDocument testDocumentB1 = index_b1.anyDocument();

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_b1/_doc/" + testDocumentB1.id());
            assertThat(httpResponse, containsExactly(index_b1).at("_index").but(user.indexMatcher("read")).whenEmpty(403));
        }
    }

    @Test
    public void get_alias() throws Exception {
        TestData.TestDocument testDocumentC1 = index_c1.anyDocument();

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_c1/_doc/" + testDocumentC1.id());
            assertThat(httpResponse, containsExactly(index_c1).at("_index").but(user.indexMatcher("read")).whenEmpty(403));
        }
    }

    @Test
    public void cat_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/indices?format=json");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("$[*].index")
                    .but(user.indexMatcher("read"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void cat_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/indices/index_a*?format=json");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3).at("$[*].index").but(user.indexMatcher("read")).whenEmpty(403)
            );
        }
    }

    @Test
    public void cat_all_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/indices?format=json&expand_wildcards=all");
            assertThat(
                httpResponse,
                containsExactly(
                    index_a1,
                    index_a2,
                    index_a3,
                    index_b1,
                    index_b2,
                    index_b3,
                    index_c1,
                    index_hidden,
                    index_hidden_dot,
                    openSearchIndices()
                ).at("$[*].index").but(user.indexMatcher("read")).whenEmpty(403)
            );
        }
    }

    @Test
    public void index_stats_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("/_stats");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("indices.keys()")
                    .but(user.indexMatcher("read"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void index_stats_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_b*/_stats");
            assertThat(
                httpResponse,
                containsExactly(index_b1, index_b2, index_b3).at("indices.keys()").but(user.indexMatcher("read")).whenEmpty(403)
            );
        }
    }

    @Test
    public void getAlias_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_alias");
            assertThat(
                httpResponse,
                containsExactly(alias_ab1, alias_c1).at("$.*.aliases.keys()").but(user.indexMatcher("get_alias")).whenEmpty(403)
            );
            assertThat(
                httpResponse,
                containsExactly(
                    index_a1,
                    index_a2,
                    index_a3,
                    index_b1,
                    index_b2,
                    index_b3,
                    index_c1,
                    index_hidden,
                    index_hidden_dot,
                    openSearchIndices()
                ).at("$.keys()").but(user.indexMatcher("get_alias")).whenEmpty(403)
            );
        }
    }

    @Test
    public void getAlias_staticAlias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_alias/alias_c1");
            if (user == LIMITED_USER_ALIAS_AB1) {
                // RestGetAliasesAction does some further post processing on the results, thus we get 404 errors in case a non wildcard
                // alias was removed
                assertThat(httpResponse, isNotFound());
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(alias_c1).at("$.*.aliases.keys()").but(user.indexMatcher("get_alias")).whenEmpty(403)
                );
                assertThat(httpResponse, containsExactly(index_c1).at("$.keys()").but(user.indexMatcher("get_alias")).whenEmpty(403));
            }
        }
    }

    @Test
    public void getAlias_aliasPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_alias/alias_ab*");
            assertThat(
                httpResponse,
                containsExactly(alias_ab1).at("$.*.aliases.keys()").but(user.indexMatcher("get_alias")).whenEmpty(403)
            );
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("$.keys()").but(user.indexMatcher("get_alias")).whenEmpty(403)
            );
        }
    }

    @Test
    @Ignore("Fails with an exception java.lang.IllegalArgumentException: Must contain at least one column and at least one row (got []/[indices:admin/aliases/get]) thrown by https://github.com/opensearch-project/security/blob/main/src/main/java/org/opensearch/security/privileges/actionlevel/RuntimeOptimizedActionPrivileges.java#L103")
    public void getAlias_aliasPattern_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_alias/alias_ab*?expand_wildcards=none");
            assertThat(httpResponse, isOk());
            assertThat(httpResponse.bodyAsJsonNode().isEmpty(), equalTo(true));
        }
    }

    @Test
    public void getAlias_mixed() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_alias/alias_ab1,alias_c*");

            assertThat(
                httpResponse,
                containsExactly(alias_ab1, alias_c1).at("$.*.aliases.keys()").but(user.indexMatcher("get_alias")).whenEmpty(403)
            );
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_c1).at("$.keys()")
                    .but(user.indexMatcher("get_alias"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    @Ignore("This doesn't work. There were already commented-out tests, e.g. https://github.com/opensearch-project/security/blob/main/src/test/java/org/opensearch/security/HttpIntegrationTests.java#L184")
    public void analyze_noIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("_analyze", "{\"text\": \"sample text\"}");

            if (user.indexMatcher("read").isEmpty()) {
                assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:admin/analyze]"));
            } else {
                assertThat(httpResponse, isOk());
            }
        }
    }

    @Test
    public void analyze_staticIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("index_a1/_analyze", "{\"text\": \"sample text\"}");
            IndexMatcher matcher = containsExactly(index_a1).but(user.indexMatcher("read"));

            if (matcher.isEmpty()) {
                assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:admin/analyze]"));
            } else {
                assertThat(httpResponse, isOk());
            }
        }
    }

    @Test
    public void resolve_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/*");
            if (user == LIMITED_USER_ALIAS_AB1 || user == LIMITED_USER_ALIAS_C1) {
                // request is reduced by dnfof, aliases are not returned
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("$.*[*].name")
                        .but(user.indexMatcher("read"))
                        .whenEmpty(403)
                );
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1, alias_ab1, alias_c1).at(
                        "$.*[*].name"
                    ).but(user.indexMatcher("read")).whenEmpty(403)
                );
            }
        }
    }

    @Test
    public void resolve_wildcard_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/*?expand_wildcards=all");
            if (user == LIMITED_USER_ALIAS_AB1 || user == LIMITED_USER_ALIAS_C1) {
                // request is reduced by dnfof, aliases are not returned
                assertThat(
                    httpResponse,
                    containsExactly(
                        index_a1,
                        index_a2,
                        index_a3,
                        index_b1,
                        index_b2,
                        index_b3,
                        index_c1,
                        index_hidden,
                        index_hidden_dot,
                        openSearchIndices()
                    ).at("$.*[*].name").but(user.indexMatcher("read")).whenEmpty(403)
                );
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(
                        index_a1,
                        index_a2,
                        index_a3,
                        index_b1,
                        index_b2,
                        index_b3,
                        index_c1,
                        alias_ab1,
                        alias_c1,
                        index_hidden,
                        index_hidden_dot,
                        openSearchIndices()
                    ).at("$.*[*].name").but(user.indexMatcher("read")).whenEmpty(403)
                );
            }
        }
    }

    @Test
    public void resolve_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/index_a*,index_b*");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3).at("$.*[*].name")
                    .but(user.indexMatcher("read"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void field_caps_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("indices")
                    .but(user.indexMatcher("read"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void field_caps_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_b*/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(index_b1, index_b2, index_b3).at("indices").but(user.indexMatcher("read")).whenEmpty(403)
            );
        }
    }

    @Test
    public void field_caps_staticIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a1,index_a2,index_b1/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_b1).at("indices").but(user.indexMatcher("read")).whenEmpty(403)
            );
        }
    }

    @Test
    public void field_caps_staticIndices_hidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_hidden/_field_caps?fields=*");
            assertThat(httpResponse, containsExactly(index_hidden).at("indices").butForbiddenIfIncomplete(user.indexMatcher("read")));
        }
    }

    @Test
    public void field_caps_alias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab1/_field_caps?fields=*&ignore_unavailable=true");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("indices").but(user.indexMatcher("read")).whenEmpty(403)
            );
        }
    }

    @Test
    public void field_caps_aliasPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab*/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("indices").but(user.indexMatcher("read")).whenEmpty(403)
            );
        }
    }

    @Test
    public void field_caps_nonExisting_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_ax/_field_caps?fields=*");

            if (containsExactly(index_ax).but(user.indexMatcher("read")).isEmpty()) {
                assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/field_caps]"));
            } else {
                assertThat(httpResponse, isNotFound());
            }
        }
    }

    @Test
    public void field_caps_nonExisting_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("x_does_not_exist*/_field_caps?fields=*");

            assertThat(httpResponse, containsExactly().at("indices").whenEmpty(200));
        }
    }

    @Test
    public void field_caps_aliasAndIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab1,index_b2/_field_caps?fields=*&ignore_unavailable=true");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2).at("indices")
                    .but(user.indexMatcher("read"))
                    .whenEmpty(403)
            );
        }
    }

    @Test
    public void field_caps_staticIndices_negation() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            // On static indices, negation does not have an effect
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a1,index_a2,index_b1,-index_b1/_field_caps?fields=*");

            if (httpResponse.getStatusCode() == 404) {
                // A 404 error is also acceptable if we get ES complaining about -index_b1. This will be the case for users with full
                // permissions
                assertThat(httpResponse.getTextFromJsonBody("/error/type"), equalTo("index_not_found_exception"));
                assertThat(httpResponse.getTextFromJsonBody("/error/reason"), containsString("no such index [-index_b1]"));
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_b1).at("indices").but(user.indexMatcher("read")).whenEmpty(403)
                );
            }
        }
    }

    @Test
    public void field_caps_indexPattern_minus() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a*,index_b*,-index_b2,-index_b3/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("indices").but(user.indexMatcher("read")).whenEmpty(403)
            );
        }
    }
}
