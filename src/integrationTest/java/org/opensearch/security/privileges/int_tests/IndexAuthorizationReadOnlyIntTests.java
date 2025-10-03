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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.collect.ImmutableList;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.SystemIndexPlugin;
import org.opensearch.script.mustache.MustacheModulePlugin;
import org.opensearch.test.framework.TestAlias;
import org.opensearch.test.framework.TestData;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestIndexOrAliasOrDatastream;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.matcher.IndexApiResponseMatchers;

import static java.util.stream.Collectors.joining;
import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestIndex.openSearchSecurityConfigIndex;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.IndexMatcher;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnResponseIndexMatcher.containsExactly;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.limitedTo;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.limitedToNone;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.unlimitedIncludingOpenSearchSecurityIndex;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;
import static org.junit.Assert.assertTrue;

/**
 * This class defines a huge test matrix for index related access controls. This class is especially for read-only operations on indices and aliases.
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
public class IndexAuthorizationReadOnlyIntTests {

    // -------------------------------------------------------------------------------------------------------
    // Test indices used by this test suite. Indices are usually initially created; the only exception is
    // index_ax, which is referred to in tests, but which does not exist on purpose.
    // -------------------------------------------------------------------------------------------------------

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
    static final TestIndex system_index_plugin = TestIndex.name(".system_index_plugin").hidden().documentCount(1).seed(8).build();

    static final TestAlias alias_ab1 = new TestAlias("alias_ab1").on(index_a1, index_a2, index_a3, index_b1);
    static final TestAlias alias_c1 = new TestAlias("alias_c1").on(index_c1);
    static final TestAlias alias_with_system_index = new TestAlias(".alias_with_system_index").hidden().on(system_index_plugin);

    static final List<TestIndexOrAliasOrDatastream> ALL_INDICES_EXCEPT_SYSTEM_INDICES = List.of(
        index_a1,
        index_a2,
        index_a3,
        index_b1,
        index_b2,
        index_b3,
        index_c1,
        index_hidden,
        index_hidden_dot
    );

    static final List<TestIndexOrAliasOrDatastream> ALL_INDICES = List.of(
        index_a1,
        index_a2,
        index_a3,
        index_b1,
        index_b2,
        index_b3,
        index_c1,
        index_hidden,
        index_hidden_dot,
        system_index_plugin,
        openSearchSecurityConfigIndex()
    );

    static final List<TestIndexOrAliasOrDatastream> ALL_INDICES_AND_ALIASES = List.of(
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
        system_index_plugin,
        alias_with_system_index,
        openSearchSecurityConfigIndex()
    );

    static final List<TestIndexOrAliasOrDatastream> ALL_INDICES_AND_ALIASES_EXCEPT_SYSTEM_INDICES = List.of(
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
        index_hidden_dot
    );

    // -------------------------------------------------------------------------------------------------------
    // Test users with which the tests will be executed; the users need to be added to the list USERS below
    // The users have two redundant versions or privilege configuration, which needs to be kept in sync:
    // - The standard role configuration defined with .roles()
    // - IndexMatchers which act as test oracles, defined with the indexMatcher() methods
    // -------------------------------------------------------------------------------------------------------

    /**
     * A simple user that can read from index_a*
     */
    static final TestSecurityConfig.User LIMITED_USER_A = new TestSecurityConfig.User("limited_user_A")//
        .description("index_a*")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_a*")
        )//
        .indexMatcher("read", limitedTo(index_a1, index_a2, index_a3, index_ax))//
        .indexMatcher("get_alias", limitedToNone());

    /**
     * A simple user that can read from index_b*
     */
    static final TestSecurityConfig.User LIMITED_USER_B = new TestSecurityConfig.User("limited_user_B")//
        .description("index_b*")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_b*")
        )//
        .indexMatcher("read", limitedTo(index_b1, index_b2, index_b3))//
        .indexMatcher("get_alias", limitedToNone());

    /**
     * A simple user that can read only from index_b1
     */
    static final TestSecurityConfig.User LIMITED_USER_B1 = new TestSecurityConfig.User("limited_user_B1")//
        .description("index_b1")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_b1")
        )//
        .indexMatcher("read", limitedTo(index_b1))//
        .indexMatcher("get_alias", limitedToNone());

    /**
     * A simple user that can read from index_c*
     */
    static final TestSecurityConfig.User LIMITED_USER_C = new TestSecurityConfig.User("limited_user_C")//
        .description("index_c*")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_c*")
        )//
        .indexMatcher("read", limitedTo(index_c1, alias_c1))//
        .indexMatcher("get_alias", limitedToNone());

    /**
     * A user that has read privileges for alias_ab1*; these privileges are inherited to the member indices.
     * The user has no directly defined privileges on indices.
     */
    static final TestSecurityConfig.User LIMITED_USER_ALIAS_AB1 = new TestSecurityConfig.User("limited_user_alias_AB1")//
        .description("alias_ab1")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze", "indices:admin/aliases/get")
                .on("alias_ab1*")
        )//
        .indexMatcher("read", limitedTo(index_a1, index_a2, index_a3, index_b1, alias_ab1))//
        .indexMatcher("get_alias", limitedTo(index_a1, index_a2, index_a3, index_b1, alias_ab1));

    /**
     * A user that has read privileges for alias_c1; these privileges are inherited to the member indices.
     * The user has no directly defined privileges on indices.
     */
    static final TestSecurityConfig.User LIMITED_USER_ALIAS_C1 = new TestSecurityConfig.User("limited_user_alias_C1")//
        .description("alias_c1")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze", "indices:admin/aliases/get")
                .on("alias_c1")
        )//
        .indexMatcher("read", limitedTo(index_c1, alias_c1))//
        .indexMatcher("get_alias", limitedTo(index_c1, alias_c1));
    /**
     * Same as LIMITED_USER_A with the addition of read privileges for index_hidden* and .index_hidden*
     */
    static final TestSecurityConfig.User LIMITED_USER_A_HIDDEN = new TestSecurityConfig.User("limited_user_A_hidden")//
        .description("index_a*, index_hidden*")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze")
                .on("index_a*", "index_hidden*", ".index_hidden*")
        )//
        .indexMatcher("read", limitedTo(index_a1, index_a2, index_a3, index_ax, index_hidden, index_hidden_dot))//
        .indexMatcher("get_alias", limitedToNone());

    /**
     * Same as LIMITED_USER_C with the addition of read privileges for ".system_index_plugin"; they also have the
     * explicit privilege "system:admin/system_index" that allows them accessing this index.
     */
    static final TestSecurityConfig.User LIMITED_USER_C_WITH_SYSTEM_INDICES = new TestSecurityConfig.User(
        "limited_user_C_with_system_indices"
    )//
        .description("index_c*, .system_index_plugin")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("read", "indices_monitor", "indices:admin/analyze", "indices:admin/aliases/get")
                .on("index_c*", "alias_c1")//
                .indexPermissions(
                    "read",
                    "indices_monitor",
                    "indices:admin/analyze",
                    "indices:admin/aliases/get",
                    "system:admin/system_index"
                )
                .on(".system_index_plugin")
        )//
        .indexMatcher("read", limitedTo(index_c1, alias_c1, system_index_plugin, alias_with_system_index))//
        .indexMatcher("get_alias", limitedTo(index_c1, alias_c1, system_index_plugin, alias_with_system_index));

    /**
     * This user has no privileges for indices that are used in this test. But they have privileges for other indices.
     * This allows them to use actions like _search and receive empty result sets.
     * <p>
     * Compare with LIMITED_USER_NONE, which has no search privileges and will only receive 403 errors.
     */
    static final TestSecurityConfig.User LIMITED_USER_OTHER_PRIVILEGES = new TestSecurityConfig.User("limited_user_other_index_privileges")//
        .description("no privileges for tested indices")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("crud", "indices_monitor", "indices:admin/analyze")
                .on("index_does_not_exist_*")
        )//
        .indexMatcher("read", limitedToNone())//
        .indexMatcher("get_alias", limitedToNone());

    /**
     * This user has no index read privileges at all.
     */
    static final TestSecurityConfig.User LIMITED_USER_NONE = new TestSecurityConfig.User("limited_user_none")//
        .description("no index privileges")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
        )//
        .indexMatcher("read", limitedToNone())//
        .indexMatcher("get_alias", limitedToNone());

    /**
     * A user with "*" privileges on "*"; as it is a regular user, they are still subject to system index
     * restrictions and similar things.
     */
    static final TestSecurityConfig.User UNLIMITED_USER = new TestSecurityConfig.User("unlimited_user")//
        .description("unlimited")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("*")
                .indexPermissions("*")
                .on("*")//

        )//
        .indexMatcher("read", limitedTo(ALL_INDICES_AND_ALIASES_EXCEPT_SYSTEM_INDICES).and(index_ax))//
        .indexMatcher("get_alias", limitedTo(ALL_INDICES_AND_ALIASES_EXCEPT_SYSTEM_INDICES).and(index_ax));

    /**
     * The SUPER_UNLIMITED_USER authenticates with an admin cert, which will cause all access control code to be skipped.
     * This serves as a base for comparison with the default behavior.
     */
    static final TestSecurityConfig.User SUPER_UNLIMITED_USER = new TestSecurityConfig.User("super_unlimited_user")//
        .description("super unlimited (admin cert)")//
        .adminCertUser()//
        .indexMatcher("read", unlimitedIncludingOpenSearchSecurityIndex())//
        .indexMatcher("get_alias", unlimitedIncludingOpenSearchSecurityIndex());

    static final List<TestSecurityConfig.User> USERS = ImmutableList.of(
        LIMITED_USER_A,
        LIMITED_USER_B,
        LIMITED_USER_B1,
        LIMITED_USER_C,
        LIMITED_USER_ALIAS_AB1,
        LIMITED_USER_ALIAS_C1,
        LIMITED_USER_A_HIDDEN,
        LIMITED_USER_C_WITH_SYSTEM_INDICES,
        LIMITED_USER_OTHER_PRIVILEGES,
        LIMITED_USER_NONE,
        UNLIMITED_USER,
        SUPER_UNLIMITED_USER
    );

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USERS)//
            .indices(
                index_a1,
                index_a2,
                index_a3,
                index_b1,
                index_b2,
                index_b3,
                index_c1,
                index_hidden,
                index_hidden_dot,
                system_index_plugin
            )//
            .aliases(alias_ab1, alias_c1, alias_with_system_index)//
            .plugin(SystemIndexTestPlugin.class, MustacheModulePlugin.class);
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

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else {
                // The dnfof implementation has the effect that hidden indices might be included even though not requested
                assertThat(
                    httpResponse,
                    containsExactly(clusterConfig.systemIndexPrivilegeEnabled ? ALL_INDICES : ALL_INDICES_EXCEPT_SYSTEM_INDICES).at(
                        "hits.hits[*]._index"
                    ).reducedBy(user.indexMatcher("read")).whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_noPattern_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_search?size=1000&expand_wildcards=none");

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                // Users with full privileges get an empty result, like expected due to the expand_wildcards=none option
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
            } else {
                // The dnfof implementation has the effect that the expand_wildcards=none option is disregarded
                // Additionally, the dnfof implementation has the effect that hidden indices might be included even though not requested
                assertThat(
                    httpResponse,
                    containsExactly(clusterConfig.systemIndexPrivilegeEnabled ? ALL_INDICES : ALL_INDICES_EXCEPT_SYSTEM_INDICES).at(
                        "hits.hits[*]._index"
                    ).reducedBy(user.indexMatcher("read")).whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_noPattern_allowNoIndicesFalse() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_search?size=1000&allow_no_indices=false");

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(isForbidden())
                );
            } else {
                // The dnfof implementation has the effect that hidden indices might be included even though not requested
                assertThat(
                    httpResponse,
                    containsExactly(clusterConfig.systemIndexPrivilegeEnabled ? ALL_INDICES : ALL_INDICES_EXCEPT_SYSTEM_INDICES).at(
                        "hits.hits[*]._index"
                    ).reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden())
                );
            }
        }
    }

    @Test
    public void search_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_all/_search?size=1000");

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else {
                // The dnfof implementation has the effect that hidden indices might be included even though not requested
                assertThat(
                    httpResponse,
                    containsExactly(clusterConfig.systemIndexPrivilegeEnabled ? ALL_INDICES : ALL_INDICES_EXCEPT_SYSTEM_INDICES).at(
                        "hits.hits[*]._index"
                    ).reducedBy(user.indexMatcher("read")).whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_all_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_all/_search?size=1000&expand_wildcards=none");

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                // Users with full privileges get an empty result, like expected due to the expand_wildcards=none option
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
            } else {
                // The dnfof implementation has the effect that the expand_wildcards=none option is disregarded
                // Additionally, the dnfof implementation has the effect that hidden indices might be included even though not requested
                assertThat(
                    httpResponse,
                    containsExactly(clusterConfig.systemIndexPrivilegeEnabled ? ALL_INDICES : ALL_INDICES_EXCEPT_SYSTEM_INDICES).at(
                        "hits.hits[*]._index"
                    ).reducedBy(user.indexMatcher("read")).whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_all_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_all/_search?size=1000&expand_wildcards=all");

            assertThat(
                httpResponse,
                containsExactly(
                    clusterConfig.systemIndexPrivilegeEnabled || user == SUPER_UNLIMITED_USER
                        ? ALL_INDICES
                        : ALL_INDICES_EXCEPT_SYSTEM_INDICES
                ).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*/_search?size=1000");

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else {
                // The dnfof implementation has the effect that hidden indices might be included even though not requested
                assertThat(
                    httpResponse,
                    containsExactly(clusterConfig.systemIndexPrivilegeEnabled ? ALL_INDICES : ALL_INDICES_EXCEPT_SYSTEM_INDICES).at(
                        "hits.hits[*]._index"
                    ).reducedBy(user.indexMatcher("read")).whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_wildcard_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*/_search?size=1000&expand_wildcards=none");

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                // Users with full privileges get an empty result, like expected due to the expand_wildcards=none option
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
            } else {
                // The dnfof implementation has the effect that the expand_wildcards=none option is disregarded
                // Additionally, the dnfof implementation has the effect that hidden indices might be included even though not requested
                assertThat(
                    httpResponse,
                    containsExactly(clusterConfig.systemIndexPrivilegeEnabled ? ALL_INDICES : ALL_INDICES_EXCEPT_SYSTEM_INDICES).at(
                        "hits.hits[*]._index"
                    ).reducedBy(user.indexMatcher("read")).whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_wildcard_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*/_search?size=1000&expand_wildcards=all");

            assertThat(
                httpResponse,
                containsExactly(
                    clusterConfig.systemIndexPrivilegeEnabled || user == SUPER_UNLIMITED_USER
                        ? ALL_INDICES
                        : ALL_INDICES_EXCEPT_SYSTEM_INDICES
                ).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_staticIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a1/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_a1).at("hits.hits[*]._index").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void search_staticIndices_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a1,index_b1/_search?size=1000&ignore_unavailable=true");

            assertThat(
                httpResponse,
                containsExactly(index_a1, index_b1).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_staticIndices_nonExisting() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_ax/_search?size=1000");

            if (containsExactly(index_ax).reducedBy(user.indexMatcher("read")).isEmpty()) {
                assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/search]"));
            } else {
                assertThat(httpResponse, isNotFound());
            }
        }
    }

    @Test
    public void search_staticIndices_hidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_hidden/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(index_hidden).at("hits.hits[*]._index").butForbiddenIfIncomplete(user.indexMatcher("read"))
            );
        }
    }

    @Test
    public void search_staticIndices_systemIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(".system_index_plugin/_search?size=1000");
            if (clusterConfig.systemIndexPrivilegeEnabled || user == SUPER_UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(system_index_plugin).at("hits.hits[*]._index").butForbiddenIfIncomplete(user.indexMatcher("read"))
                );
            } else {
                // legacy privilege evaluation without system index privilege enabled
                if (user == UNLIMITED_USER || user == LIMITED_USER_C_WITH_SYSTEM_INDICES) {
                    // The legacy evaluation grants access in SystemIndexAccessPrivilegesEvaluator for users with * privileges,
                    // but withholds documents on the DLS level
                    assertThat(httpResponse, isOk());
                    assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
                } else {
                    assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/search]"));
                }
            }
        }
    }

    @Test
    public void search_staticIndices_systemIndex_alias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(".alias_with_system_index/_search?size=1000");

            if (user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly(system_index_plugin).at("hits.hits[*]._index"));
            } else if (clusterConfig == ClusterConfig.LEGACY_PRIVILEGES_EVALUATION) {
                if (user == UNLIMITED_USER || user == LIMITED_USER_C_WITH_SYSTEM_INDICES) {
                    // The legacy evaluation grants access in SystemIndexAccessPrivilegesEvaluator for users with * privileges,
                    // but withholds documents on the DLS level
                    assertThat(httpResponse, isOk());
                    assertThat(httpResponse, containsExactly().at("hits.hits[*]._index"));
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else if (clusterConfig == ClusterConfig.LEGACY_PRIVILEGES_EVALUATION_SYSTEM_INDEX_PERMISSION) {
                assertThat(
                    httpResponse,
                    containsExactly(system_index_plugin).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(isForbidden())
                );
            } else {
                if (user.indexMatcher("read").covers(alias_with_system_index)) {
                    assertThat(httpResponse, isOk());
                    assertThat(httpResponse, containsExactly(system_index_plugin).at("hits.hits[*]._index"));
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        }
    }

    @Test
    public void search_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a*,index_b*/_search?size=1000");

            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
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
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_indexPattern_nonExistingIndex_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(
                "index_a*,index_b*,xxx_non_existing/_search?size=1000&ignore_unavailable=true"
            );

            // The presence of a non existing index has the effect that the other patterns are not resolved by IndexResolverReplacer
            // This causes a few more 403 errors where the granted index patterns do not use wildcards

            if (user == LIMITED_USER_B1 || user == LIMITED_USER_ALIAS_AB1) {
                assertThat(httpResponse, isForbidden());
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void search_indexPattern_noWildcards() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a*,index_b*/_search?size=1000&expand_wildcards=none");
            // We have to specify the users here explicitly because here we need to check privileges for the
            // non-existing (and invalidly named) indices "index_a*" and "index_b*".
            // However: Again, dnfof gets the indices options wrong and ignores the expand_wildcards=none flag when getting active
            if (user == UNLIMITED_USER || user == SUPER_UNLIMITED_USER) {
                // Only these users "get through". Because the indices does not exist, they get a 404
                assertThat(httpResponse, isNotFound());
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }

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
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_indexPattern_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*index*/_search?size=1000&expand_wildcards=all");

            if (user == SUPER_UNLIMITED_USER) {
                // The super admin sees everything
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
                        system_index_plugin
                    ).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else if (!clusterConfig.systemIndexPrivilegeEnabled) {
                // Without system index privileges, the system_index_plugin will be never included
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1, index_hidden, index_hidden_dot)
                        .at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else {
                // Things get buggy here; basically all requests fail with a 403
                if (user == LIMITED_USER_C_WITH_SYSTEM_INDICES) {
                    // This user is supposed to have the system index privilege for the index .system_index_plugin
                    // However, the system index privilege evaluation code only works correct when the system index is the
                    // only requested index. If also non system indices are requested in the same request, it will require
                    // the presence of the system index privilege for all indices. As this is not the case, the request
                    // will be denied with a 403 error.
                    assertThat(httpResponse, isForbidden());
                } else {
                    // The other users do not have privileges for the system index. The dnfof feature promises to filter
                    // out indices without authorization from eligible requests. However, the SystemIndexAccessEvaluator
                    // is not aware of this and just denies all these requests
                    // See also https://github.com/opensearch-project/security/issues/5546
                    assertThat(httpResponse, isForbidden());
                }
            }
        }
    }

    @Test
    public void search_alias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab1/_search?size=1000");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // The legacy privilege evaluation with dnfof enabled can replace aliases by a sub-set of its member indices
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(isForbidden())
                );
            }
        }
    }

    @Test
    public void search_alias_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab1*/_search?size=1000");

            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
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
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void search_alias_pattern_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*alias*/_search?size=1000&expand_wildcards=all");

            if (user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_c1, system_index_plugin).at("hits.hits[*]._index")
                );
            } else if (user != LIMITED_USER_NONE) {
                if (clusterConfig == ClusterConfig.LEGACY_PRIVILEGES_EVALUATION) {
                    assertThat(
                        httpResponse,
                        containsExactly(index_a1, index_a2, index_a3, index_b1, index_c1).at("hits.hits[*]._index")
                            .reducedBy(user.indexMatcher("read"))
                            .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                    );
                } else if (clusterConfig == ClusterConfig.LEGACY_PRIVILEGES_EVALUATION_SYSTEM_INDEX_PERMISSION) {
                    // For all users without the system index permission, SystemIndexAccessEvaluator shuts the door
                    // For the user with the system index permission, that happens as well, as SystemIndexAccessEvaluator expects the
                    // permission for all requested indices, even if they are not system indices
                    assertThat(httpResponse, isForbidden());
                } else {
                    assertThat(
                        httpResponse,
                        containsExactly(index_a1, index_a2, index_a3, index_b1, index_c1, system_index_plugin).at("hits.hits[*]._index")
                            .reducedBy(user.indexMatcher("read"))
                            .whenEmpty(isOk())
                    );
                }
            } else {
                assertThat(httpResponse, isForbidden());
            }
        }
    }

    @Test
    public void search_aliasAndIndex_ignoreUnavailable() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab1,index_b1/_search?size=1000&ignore_unavailable=true");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                // The legacy privilege evaluation with dnfof enabled can replace aliases by a sub-set of its member indices
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1).at("hits.hits[*]._index")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(isForbidden())
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

            assertThat(httpResponse, containsExactly().at("hits.hits[*]._index").whenEmpty(isOk()));
        }
    }

    @Test
    public void search_termsAggregation_index() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("/_search", """
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
                containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at(
                    "aggregations.indices.buckets[*].key"
                ).reducedBy(user.indexMatcher("read")).whenEmpty(isOk())
            );
        }
    }

    @Test
    public void search_pit() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.post("index_a*,index_b*/_search/point_in_time?keep_alive=1m");

            IndexApiResponseMatchers.OnResponseIndexMatcher indexMatcher = containsExactly(
                index_a1,
                index_a2,
                index_a3,
                index_b1,
                index_b2,
                index_b3
            );

            if (indexMatcher.reducedBy(user.indexMatcher("read")).isEmpty()) {
                assertThat(
                    httpResponse,
                    isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/point_in_time/create]")
                );
            } else {
                assertThat(httpResponse, isOk());
                String pitId = httpResponse.getTextFromJsonBody("/pit_id");
                httpResponse = restClient.postJson("/_search?size=1000", String.format("""
                    {
                      "pit": {
                        "id": "%s"
                      }
                    }
                    """, pitId));
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, indexMatcher.at("hits.hits[*]._index").reducedBy(user.indexMatcher("read")));
            }
        }
    }

    @Test
    public void search_pit_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.post("_all/_search/point_in_time?keep_alive=1m");

            IndexApiResponseMatchers.OnResponseIndexMatcher indexMatcher;

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                indexMatcher = containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1);
            } else {
                indexMatcher = containsExactly(
                    index_a1,
                    index_a2,
                    index_a3,
                    index_b1,
                    index_b2,
                    index_b3,
                    index_c1,
                    index_hidden,
                    index_hidden_dot
                );
            }

            if (indexMatcher.reducedBy(user.indexMatcher("read")).isEmpty()) {
                assertThat(
                    httpResponse,
                    isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/point_in_time/create]")
                );
            } else {
                assertThat(httpResponse, isOk());
                String pitId = httpResponse.getTextFromJsonBody("/pit_id");
                httpResponse = restClient.postJson("/_search?size=1000", String.format("""
                    {
                      "pit": {
                        "id": "%s"
                      }
                    }
                    """, pitId));
                if (clusterConfig.systemIndexPrivilegeEnabled && user == LIMITED_USER_C_WITH_SYSTEM_INDICES) {
                    // The current request mixes access to a normal index and a system index.
                    // The current system index permission implementation has the issue that it also
                    // expects the system index permission for the normal issue then.
                    // As this is not present, the request https://github.com/opensearch-project/security/issues/5508
                    assertThat(httpResponse, isForbidden());
                } else {
                    assertThat(httpResponse, isOk());
                    assertThat(httpResponse, indexMatcher.at("hits.hits[*]._index").reducedBy(user.indexMatcher("read")));
                }
            }
        }
    }

    @Test
    public void search_pit_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.post("index_a1/_search/point_in_time?keep_alive=1m");

            IndexApiResponseMatchers.OnResponseIndexMatcher indexMatcher = containsExactly(index_a1);

            if (indexMatcher.reducedBy(user.indexMatcher("read")).isEmpty()) {
                assertThat(
                    httpResponse,
                    isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/point_in_time/create]")
                );
            } else {
                assertThat(httpResponse, isOk());
                String pitId = httpResponse.getTextFromJsonBody("/pit_id");
                httpResponse = restClient.postJson("/_search?size=1000", String.format("""
                    {
                      "pit": {
                        "id": "%s"
                      }
                    }
                    """, pitId));
                assertThat(httpResponse, indexMatcher.at("hits.hits[*]._index").reducedBy(user.indexMatcher("read")));
            }
        }
    }

    @Test
    public void search_pit_wrongIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.post("index_a*/_search/point_in_time?keep_alive=1m");

            if (user.indexMatcher("read").coversAll(index_a1, index_a2, index_a3)) {
                assertThat(httpResponse, isOk());
                String pitId = httpResponse.getTextFromJsonBody("/pit_id");
                httpResponse = restClient.postJson("index_b*/_search?size=1000", String.format("""
                    {
                      "pit": {
                        "id": "%s"
                      }
                    }
                    """, pitId));
                assertThat(httpResponse, isBadRequest("/error/root_cause/0/reason", "[indices] cannot be used with point in time"));

            } else {
                assertThat(
                    httpResponse,
                    isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/point_in_time/create]")
                );
            }
        }
    }

    /**
     * Moved from https://github.com/opensearch-project/security/blob/eb7153d772e9e00d49d9cb5ffafb33b5f02399fc/src/integrationTest/java/org/opensearch/security/privileges/PrivilegesEvaluatorTest.java#L103
     * See also https://github.com/opensearch-project/security/issues/1678
     */
    @Test
    public void search_template_staticIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String params = """
                {
                    "department": [%s]
                }""".formatted(TestData.DEPARTMENTS.stream().map(s -> '"' + s + '"').collect(joining(",")));
            String query = """
                {
                  "query": {
                    "terms": {
                      "attr_text_1": [
                        "{{#department}}",
                        "{{.}}",
                        "{{/department}}"
                      ]
                    }
                  }
                }
                """;

            TestRestClient.HttpResponse httpResponse = restClient.getWithJsonBody("index_a1/_search/template?size=1000", """
                {
                  "params": %s,
                  "source": "%s"
                }""".formatted(params, escapeJson(query)));

            assertThat(
                httpResponse,
                containsExactly(index_a1).at("hits.hits[*]._index").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void msearch_staticIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("/_msearch", """
                {"index":"index_b1"}
                {"size":10, "query":{"bool":{"must":{"match_all":{}}}}}
                {"index":"index_b2"}
                {"size":10, "query":{"bool":{"must":{"match_all":{}}}}}
                """);
            assertThat(
                httpResponse,
                containsExactly(index_b1, index_b2).at("responses[*].hits.hits[*]._index")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(isOk())
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
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(isOk())
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
                containsExactly(index_c1).at("docs[?(@.found == true)]._index").reducedBy(user.indexMatcher("read")).whenEmpty(isOk())
            );
        }
    }

    @Test
    public void get() throws Exception {
        TestData.TestDocument testDocumentB1 = index_b1.anyDocument();

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_b1/_doc/" + testDocumentB1.id());
            assertThat(httpResponse, containsExactly(index_b1).at("_index").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden()));
        }
    }

    @Test
    public void get_alias() throws Exception {
        TestData.TestDocument testDocumentC1 = index_c1.anyDocument();

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_c1/_doc/" + testDocumentC1.id());
            assertThat(httpResponse, containsExactly(index_c1).at("_index").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden()));
        }
    }

    @Test
    public void get_systemIndex() throws Exception {
        TestData.TestDocument testDocument = system_index_plugin.anyDocument();

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get(".system_index_plugin/_doc/" + testDocument.id());

            if (clusterConfig == ClusterConfig.LEGACY_PRIVILEGES_EVALUATION) {
                if (user == SUPER_UNLIMITED_USER) {
                    assertThat(httpResponse, isOk());
                    assertThat(httpResponse, containsExactly(system_index_plugin).at("_index"));
                } else if (user == LIMITED_USER_C_WITH_SYSTEM_INDICES || user == UNLIMITED_USER) {
                    // If the user has a role that grants access to the index, they can
                    // successfully access the index (i.e., they won't get a 403), but
                    // the index will appear empty (i.e., they will get a 404)
                    assertThat(httpResponse, isNotFound());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else if ((clusterConfig.systemIndexPrivilegeEnabled && user == LIMITED_USER_C_WITH_SYSTEM_INDICES)
                || user == SUPER_UNLIMITED_USER) {
                    assertThat(httpResponse, isOk());
                    assertThat(httpResponse, containsExactly(system_index_plugin).at("_index"));
                } else {
                    assertThat(httpResponse, isForbidden());
                }
        }
    }

    @Test
    public void cat_indices_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/indices?format=json");

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("$[*].index")
                        .reducedBy(user.indexMatcher("read"))
                );

            } else {
                // Also here, dnfof might introduce hidden indices even though they were not requested
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
                        index_hidden_dot,
                        index_hidden,
                        system_index_plugin
                    ).at("$[*].index").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden())
                );
            }
        }
    }

    @Test
    public void cat_indices_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/indices/index_a*?format=json");

            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3).at("$[*].index")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void cat_indices_all_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/indices?format=json&expand_wildcards=all");
            if (user == UNLIMITED_USER) {
                assertThat(httpResponse, containsExactly(ALL_INDICES).at("$[*].index"));
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ALL_INDICES).at("$[*].index").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden())
                );
            }
        }
    }

    @Test
    public void cat_aliases_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/aliases?format=json");

            if (clusterConfig.legacyPrivilegeEvaluation && user == UNLIMITED_USER) {
                assertThat(httpResponse, containsExactly(alias_ab1, alias_c1, alias_with_system_index).at("$[*].alias"));
            } else {
                if (!user.indexMatcher("get_alias").isEmpty()) {
                    assertThat(
                        httpResponse,
                        containsExactly(alias_ab1, alias_c1, alias_with_system_index).at("$[*].alias")
                            .reducedBy(user.indexMatcher("get_alias"))
                            .whenEmpty(isOk())
                    );
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        }
    }

    @Test
    public void cat_aliases_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/aliases/alias_a*?format=json");

            if (!user.indexMatcher("get_alias").isEmpty()) {
                assertThat(
                    httpResponse,
                    containsExactly(alias_ab1).at("$[*].alias").reducedBy(user.indexMatcher("get_alias")).whenEmpty(isOk())
                );
            } else {
                assertThat(httpResponse, isForbidden());
            }
        }
    }

    @Test
    public void index_stats_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("/_stats");

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("indices.keys()")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            } else {
                // Also here, dnfof can introduce hidden indices even though they were not requested
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
                        system_index_plugin
                    ).at("indices.keys()")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void index_stats_pattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_b*/_stats");

            assertThat(
                httpResponse,
                containsExactly(index_b1, index_b2, index_b3).at("indices.keys()")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );
        }
    }

    @Test
    public void getAlias_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_alias");
            if (user == UNLIMITED_USER) {
                // The legacy privilege evaluation also allows regular users access to metadata of the security index
                // This is not a security issue, as the metadata are not really security relevant
                assertThat(httpResponse, containsExactly(ALL_INDICES).at("$.keys()"));
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(alias_ab1, alias_c1, alias_with_system_index).at("$.*.aliases.keys()")
                        .reducedBy(user.indexMatcher("get_alias"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
                assertThat(
                    httpResponse,
                    containsExactly(ALL_INDICES).at("$.keys()")
                        .reducedBy(user.indexMatcher("get_alias"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }
        }
    }

    @Test
    public void getAlias_staticAlias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_alias/alias_c1");
            if (user == LIMITED_USER_ALIAS_AB1) {
                if (clusterConfig.legacyPrivilegeEvaluation) {
                    // RestGetAliasesAction does some further post processing on the results, thus we get 404 errors in case a non wildcard
                    // alias was removed
                    assertThat(httpResponse, isNotFound());
                } else {
                    assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:admin/aliases/get]"));
                }
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(alias_c1).at("$.*.aliases.keys()").reducedBy(user.indexMatcher("get_alias")).whenEmpty(isForbidden())
                );
                assertThat(
                    httpResponse,
                    containsExactly(index_c1).at("$.keys()").reducedBy(user.indexMatcher("get_alias")).whenEmpty(isForbidden())
                );
            }
        }
    }

    @Test
    public void getAlias_aliasPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_alias/alias_ab*");

            if (user == LIMITED_USER_ALIAS_AB1 || user == UNLIMITED_USER || user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly(alias_ab1).at("$.*.aliases.keys()").reducedBy(user.indexMatcher("get_alias")));
                assertThat(httpResponse, containsExactly(index_a1, index_a2, index_a3, index_b1).at("$.keys()"));
            } else if (user == LIMITED_USER_ALIAS_C1 || user == LIMITED_USER_C_WITH_SYSTEM_INDICES) {
                // This is also a kind of anomaly in the legacy privilege evaluation: Even though we do not have permissions
                // we get a 200 response with an empty result
                assertThat(httpResponse, isOk());
                assertTrue(httpResponse.getBody(), httpResponse.bodyAsMap().isEmpty());
            } else {
                assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:admin/aliases/get]"));
            }
        }
    }

    @Test
    public void getAlias_indexPattern_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*index*/_alias?expand_wildcards=all");
            if (user == SUPER_UNLIMITED_USER) {
                // The super admin sees everything
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly(alias_ab1, alias_c1, alias_with_system_index).at("$.*.aliases.keys()"));
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
                        system_index_plugin
                    ).at("$.keys()")
                );
            } else if (!clusterConfig.systemIndexPrivilegeEnabled) {
                if (user == UNLIMITED_USER) {
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
                            system_index_plugin
                        ).at("$.keys()")
                    );
                } else {
                    assertThat(
                        httpResponse,
                        containsExactly(alias_ab1, alias_c1, alias_with_system_index).at("$.*.aliases.keys()")
                            .reducedBy(user.indexMatcher("get_alias"))
                            .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                    );
                    assertThat(
                        httpResponse,
                        containsExactly(ALL_INDICES).at("$.keys()")
                            .reducedBy(user.indexMatcher("get_alias"))
                            .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                    );
                }
            } else {
                // If the system index privilege is enabled, we only get 403 errors, as SystemIndexPrivilegeEvaluator
                // is not aware of dnfof; see https://github.com/opensearch-project/security/issues/5546
                assertThat(httpResponse, isForbidden());
            }
        }
    }

    @Test
    public void analyze_noIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("_analyze", "{\"text\": \"sample text\"}");

            // _analyze without index is different from most other operations:
            // Usually, the absence of an index means "all indices". For analyze, however, it means: "no index".
            // However, the IndexResolverReplacer does not get this right; it assumes that all indices are requested.
            // Thus, we get only through to this operation with full privileges for all indices
            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:admin/analyze]"));
            }
        }
    }

    @Test
    public void analyze_staticIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.postJson("index_a1/_analyze", "{\"text\": \"sample text\"}");
            IndexMatcher matcher = containsExactly(index_a1).reducedBy(user.indexMatcher("read"));

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

            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1, alias_ab1, alias_c1).at(
                        "$.*[*].name"
                    ).reducedBy(user.indexMatcher("read")).whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
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
                        index_hidden,
                        index_hidden_dot,
                        system_index_plugin
                    ).at("$.*[*].name")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );
            }

        }
    }

    @Test
    public void resolve_wildcard_includeHidden() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/*?expand_wildcards=all");

            if (user == UNLIMITED_USER || user == SUPER_UNLIMITED_USER) {
                // The legacy privilege evaluation also allows regular users access to metadata of the security index
                // This is not a security issue, as the metadata are not really security relevant
                assertThat(httpResponse, containsExactly(ALL_INDICES_AND_ALIASES).at("$.*[*].name"));
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(ALL_INDICES).at("$.*[*].name").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden())
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
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );

        }
    }

    @Test
    public void field_caps_all() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            if (user == SUPER_UNLIMITED_USER || user == UNLIMITED_USER) {
                TestRestClient.HttpResponse httpResponse = restClient.get("_field_caps?fields=*");
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3, index_c1).at("indices")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );

            } else {
                TestRestClient.HttpResponse httpResponse = restClient.get("_field_caps?fields=*");
                assertThat(
                    httpResponse,
                    containsExactly(ALL_INDICES).at("indices")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
                );

            }

        }
    }

    @Test
    public void field_caps_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_b*/_field_caps?fields=*");

            assertThat(
                httpResponse,
                containsExactly(index_b1, index_b2, index_b3).at("indices").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void field_caps_staticIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a1/_field_caps?fields=*");
            assertThat(httpResponse, containsExactly(index_a1).at("indices").reducedBy(user.indexMatcher("read")).whenEmpty(isForbidden()));
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
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab1/_field_caps?fields=*");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                assertThat(
                    httpResponse,
                    containsExactly(index_a1, index_a2, index_a3, index_b1).at("indices")
                        .reducedBy(user.indexMatcher("read"))
                        .whenEmpty(isForbidden())
                );
            }
        }
    }

    @Test
    public void field_caps_aliasPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("alias_ab*/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("indices")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );

        }
    }

    @Test
    public void field_caps_nonExisting_static() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_ax/_field_caps?fields=*");

            if (containsExactly(index_ax).reducedBy(user.indexMatcher("read")).isEmpty()) {
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

            // As this resolves to an empty set of indices, we are always allowed
            assertThat(httpResponse, containsExactly().at("indices").whenEmpty(isOk()));
        }
    }

    @Test
    public void field_caps_indexPattern_minus() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a*,index_b*,-index_b2,-index_b3/_field_caps?fields=*");

            assertThat(
                httpResponse,
                containsExactly(index_a1, index_a2, index_a3, index_b1).at("indices")
                    .reducedBy(user.indexMatcher("read"))
                    .whenEmpty(clusterConfig.allowsEmptyResultSets ? isOk() : isForbidden())
            );

        }
    }

    @Test
    public void pit_list_all() throws Exception {
        String indexA1pitId = createPit(index_a1);

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_search/point_in_time/_all");

            // At the moment, it is sufficient to have any privileges for any existing index to use the _all API
            // This is clearly a bug; yet, not a severe issue, as we do not have really sensitive things available here.
            // This is caused by the following line which makes PrivilegesEvaluator believe it could reduce the indices
            // to authorized indices, even though it actually could not:
            // https://github.com/opensearch-project/security/blob/aee54a8ca2a6cc596cb1e490be1e9fa240286246/src/main/java/org/opensearch/security/resolver/IndexResolverReplacer.java#L824-L825
            if (user != LIMITED_USER_NONE && user != LIMITED_USER_OTHER_PRIVILEGES) {
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            deletePit(indexA1pitId);
        }
    }

    @Test
    public void pit_delete() throws Exception {
        String indexA1pitId = createPit(index_a1);

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.delete("_search/point_in_time", json("pit_id", List.of(indexA1pitId)));

            if (user.indexMatcher("read").covers(index_a1)) {
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            deletePit(indexA1pitId);
        }
    }

    @Test
    public void pit_catSegments() throws Exception {
        String indexA1pitId = createPit(index_a1);

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/pit_segments", json("pit_id", List.of(indexA1pitId)));

            if (user.indexMatcher("read").covers(index_a1)) {
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            deletePit(indexA1pitId);
        }
    }

    @Test
    public void pit_catSegments_all() throws Exception {
        String indexA1pitId = createPit(index_a1);

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/pit_segments/_all");

            // The user needs to have the privilege for all indices. If it is only granted for a subset of indices, this will be forbidden.
            if (user == UNLIMITED_USER || user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            deletePit(indexA1pitId);
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

    public IndexAuthorizationReadOnlyIntTests(ClusterConfig clusterConfig, TestSecurityConfig.User user, String description)
        throws Exception {
        this.user = user;
        this.cluster = clusterConfig.cluster(IndexAuthorizationReadOnlyIntTests::clusterBuilder);
        this.clusterConfig = clusterConfig;
    }

    public static class SystemIndexTestPlugin extends Plugin implements SystemIndexPlugin {
        @Override
        public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
            return List.of(
                new SystemIndexDescriptor(".system_index_plugin", "for testing system index exclusion"),
                new SystemIndexDescriptor(".system_index_plugin_not_existing", "for testing system index exclusion")
            );
        }
    }

    private String createPit(TestIndex... indices) throws IOException {
        try (TestRestClient client = cluster.getAdminCertRestClient()) {
            TestRestClient.HttpResponse response = client.post(
                Stream.of(indices).map(TestIndex::name).collect(joining(",")) + "/_search/point_in_time?keep_alive=1m"
            );
            assertThat(response, isOk());
            return response.getTextFromJsonBody("/pit_id");
        }
    }

    private void deletePit(String... pitIds) {
        try (TestRestClient client = cluster.getAdminCertRestClient()) {
            TestRestClient.HttpResponse response = client.delete("_search/point_in_time", json("pit_id", Arrays.asList(pitIds)));
            assertThat(response, isOk());
        }
    }
}
