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
import com.google.common.collect.ImmutableList;
import org.junit.AfterClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.data.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.matcher.RestIndexMatchers;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnResponseIndexMatcher.containsExactly;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.limitedTo;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.limitedToNone;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.unlimitedIncludingOpenSearchSecurityIndex;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class CrossClusterAuthorizationIntTests {

    // -------------------------------------------------------------------------------------------------------
    // Test indices used by this test suite
    // -------------------------------------------------------------------------------------------------------

    interface LocalIndices {
        TestIndex index_a1 = TestIndex.name("index_a1").documentCount(10).seed(1).build();
        TestIndex index_a2 = TestIndex.name("index_a2").documentCount(11).seed(2).build();
    }

    interface RemoteIndices {
        TestIndex index_r1 = TestIndex.name("index_r1").documentCount(212).seed(11).build();
        TestIndex index_r2 = TestIndex.name("index_r2").documentCount(213).seed(12).build();
        TestIndex index_r3 = TestIndex.name("index_r3").documentCount(214).seed(13).build();
    }

    /**
     * This key identifies assertion reference data for index search/read permissions of individual users.
     */
    static final TestSecurityConfig.User.MetadataKey<RestIndexMatchers.IndexMatcher> READ = new TestSecurityConfig.User.MetadataKey<>(
        "read",
        RestIndexMatchers.IndexMatcher.class
    );

    // -------------------------------------------------------------------------------------------------------
    // Test users with which the tests will be executed; the users need to be added to the list USERS below
    // Each user comes with one or two additionally defined TestSecurityConfig.Role objects:
    // - If it is two, one is meant for the local cluster, the other is meant for the remote cluster
    // - If it is one, both local and remote cluster must get these roles.
    // These roles must be passed to the test cluster builders via the roles() method
    // -------------------------------------------------------------------------------------------------------

    static final TestSecurityConfig.Role LIMITED_USER_ROLE_A_R = new TestSecurityConfig.Role("limited_user_A_R_role").clusterPermissions(
        "cluster_composite_ops_ro",
        "cluster_monitor"
    ).indexPermissions("read", "indices_monitor").on("index_a*");
    static final TestSecurityConfig.Role LIMITED_USER_ROLE_A_R_REMOTE = new TestSecurityConfig.Role("limited_user_A_R_role")
        .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
        .indexPermissions("read", "indices_monitor", "indices:admin/shards/search_shards")
        .on("index_r*");
    static final TestSecurityConfig.User LIMITED_USER_A_R = new TestSecurityConfig.User("limited_user_A_R")//
        .description("index_a*, index_r*")//
        .roles(LIMITED_USER_ROLE_A_R)//
        .reference(
            READ,
            limitedTo(LocalIndices.index_a1, LocalIndices.index_a2, RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
        );

    static final TestSecurityConfig.Role LIMITED_USER_ROLE_R = new TestSecurityConfig.Role("limited_user_R_role").clusterPermissions(
        "cluster_composite_ops_ro",
        "cluster_monitor"
    );
    static final TestSecurityConfig.Role LIMITED_USER_ROLE_R_REMOTE = new TestSecurityConfig.Role("limited_user_R_role").clusterPermissions(
        "cluster_composite_ops_ro",
        "cluster_monitor"
    ).indexPermissions("read", "indices_monitor", "indices:admin/shards/search_shards").on("index_r*");
    static final TestSecurityConfig.User LIMITED_USER_R = new TestSecurityConfig.User("limited_user_R")//
        .description("index_r*")//
        .roles(LIMITED_USER_ROLE_R)//
        .reference(READ, limitedTo(RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3));

    static final TestSecurityConfig.Role LIMITED_USER_ROLE_R1 = new TestSecurityConfig.Role("limited_user_R1_role").clusterPermissions(
        "cluster_composite_ops_ro",
        "cluster_monitor"
    );
    static final TestSecurityConfig.Role LIMITED_USER_ROLE_R1_REMOTE = new TestSecurityConfig.Role("limited_user_R1_role")
        .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
        .indexPermissions("read", "indices_monitor", "indices:admin/shards/search_shards")
        .on("index_${attr.internal.attr_r1}");
    static final TestSecurityConfig.User LIMITED_USER_R1 = new TestSecurityConfig.User("limited_user_R1")//
        .description("index_r1, with user attribute")//
        .roles(LIMITED_USER_ROLE_R1)//
        .attr("attr_r1", "r1")
        .reference(READ, limitedTo(RemoteIndices.index_r1));

    static final TestSecurityConfig.Role LIMITED_ROLE_NONE = new TestSecurityConfig.Role("limited_role_none").clusterPermissions(
        "cluster_composite_ops_ro",
        "cluster_monitor"
    ).clusterPermissions("cluster_composite_ops_ro", "cluster_monitor");
    static final TestSecurityConfig.User LIMITED_USER_NONE = new TestSecurityConfig.User("limited_user_none")//
        .description("no index privileges")//
        .roles(LIMITED_ROLE_NONE)//
        .reference(READ, limitedToNone());

    static final TestSecurityConfig.Role UNLIMITED_ROLE = new TestSecurityConfig.Role("unlimited_role")//
        .clusterPermissions("*")
        .indexPermissions("*")
        .on("*");

    static final TestSecurityConfig.User UNLIMITED_USER = new TestSecurityConfig.User("unlimited_user")//
        .description("unlimited")//
        .roles(UNLIMITED_ROLE)//
        .reference(
            READ,
            limitedTo(LocalIndices.index_a1, LocalIndices.index_a2, RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
        );

    /**
     * The SUPER_UNLIMITED_USER authenticates with an admin cert, which will cause all access control code to be skipped.
     * This serves as a base for comparison with the default behavior.
     */
    static final TestSecurityConfig.User SUPER_UNLIMITED_USER = new TestSecurityConfig.User("super_unlimited_user")//
        .description("super unlimited (admin cert)")//
        .adminCertUser()//
        .reference(READ, unlimitedIncludingOpenSearchSecurityIndex());

    static final List<TestSecurityConfig.User> USERS = ImmutableList.of(
        LIMITED_USER_A_R,
        LIMITED_USER_R,
        LIMITED_USER_R1,
        LIMITED_USER_NONE,
        UNLIMITED_USER,
        SUPER_UNLIMITED_USER
    );

    static final TestCertificates TEST_CERTIFICATES = new TestCertificates();

    @ClassRule
    public static final LocalCluster remoteCluster = new LocalCluster.Builder().certificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLENODE)
        .clusterName("remote_1")
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .privilegesEvaluationType("next_gen")
        .roles(LIMITED_USER_ROLE_A_R_REMOTE, LIMITED_USER_ROLE_R_REMOTE, LIMITED_USER_ROLE_R1_REMOTE, LIMITED_ROLE_NONE, UNLIMITED_ROLE)
        .indices(RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
        .build();

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().clusterManager(ClusterManager.SINGLE_REMOTE_CLIENT)
            .remote("remote_1", remoteCluster)
            .certificates(TEST_CERTIFICATES)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USERS)//
            .roles(LIMITED_USER_ROLE_A_R, LIMITED_USER_ROLE_R, LIMITED_USER_ROLE_R1, LIMITED_ROLE_NONE, UNLIMITED_ROLE)
            .indices(LocalIndices.index_a1, LocalIndices.index_a2);
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
    public void search_wildcardWildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("*:*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
                    .at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void search_remoteWildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("remote_1:*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
                    .at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void search_remoteWildcard_minimizeRoundtrips() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("remote_1:*/_search?size=1000&ccs_minimize_roundtrips=true");
            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
                    .at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void search_remoteStaticIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("remote_1:index_r1/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1)
                    .at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void search_remoteStaticIndices_minimizeRoundtrips() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("remote_1:index_r1/_search?size=1000&ccs_minimize_roundtrips=true");
            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1)
                    .at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void search_remoteIndexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("remote_1:index_*/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
                    .at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void search_remoteIndexPattern_minimizeRoundtrips() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("remote_1:index_*/_search?size=1000&ccs_minimize_roundtrips=true");
            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
                    .at("hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void search_localStaticIndex_remoteStaticIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_a2,remote_1:index_r1/_search?size=1000");
            assertThat(
                httpResponse,
                containsExactly(LocalIndices.index_a2).andFromRemote("remote_1", RemoteIndices.index_r1)
                    .at("hits.hits[*]._index")
                    .butForbiddenIfIncomplete(user.reference(READ))
            );
        }
    }

    @Test
    public void search_localIndexPattern_remoteIndexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_*,remote_1:index_*/_search?size=1000");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(READ).covers(LocalIndices.index_a1) || user.reference(READ).covers(LocalIndices.index_a2)) {
                    // Only if we have privileges for local indices, we also get through
                    assertThat(
                        httpResponse,
                        containsExactly(LocalIndices.index_a1, LocalIndices.index_a2).andFromRemote(
                            "remote_1",
                            RemoteIndices.index_r1,
                            RemoteIndices.index_r2,
                            RemoteIndices.index_r3
                        ).at("hits.hits[*]._index").reducedBy(user.reference(READ)).whenEmpty(isForbidden())
                    );
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user != LIMITED_USER_NONE) {
                    assertThat(
                        httpResponse,
                        containsExactly(LocalIndices.index_a1, LocalIndices.index_a2).andFromRemote(
                            "remote_1",
                            RemoteIndices.index_r1,
                            RemoteIndices.index_r2,
                            RemoteIndices.index_r3
                        ).at("hits.hits[*]._index").reducedBy(user.reference(READ)).whenEmpty(isOk())
                    );
                } else {
                    // No search permissions anywhere will result in a 403 error
                    assertThat(httpResponse, isForbidden());
                }
            }
        }
    }

    @Test
    public void resolve_wildcardWildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/*:*");

            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
                    .at("$.*[*].name")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isOk())
            );
        }
    }

    @Test
    public void resolve_remoteWildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/remote_1:*");

            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
                    .at("$.*[*].name")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isOk())
            );
        }
    }

    @Test
    public void resolve_localWildcard_remoteWildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/*,remote_1:*");

            assertThat(
                httpResponse,
                containsExactly(LocalIndices.index_a1, LocalIndices.index_a2).andFromRemote(
                    "remote_1",
                    RemoteIndices.index_r1,
                    RemoteIndices.index_r2,
                    RemoteIndices.index_r3
                ).at("$.*[*].name").reducedBy(user.reference(READ)).whenEmpty(isOk())
            );
        }
    }

    @Test
    public void resolve_localIndexPattern_remoteIndexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_resolve/index/index_a1*,remote_1:index_r1*");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(READ).covers(LocalIndices.index_a1)) {
                    // Only if we have privileges for local indices, we also get through
                    assertThat(
                        httpResponse,
                        containsExactly(LocalIndices.index_a1).andFromRemote("remote_1", RemoteIndices.index_r1)
                            .at("$.*[*].name")
                            .reducedBy(user.reference(READ))
                            .whenEmpty(isOk())
                    );
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(LocalIndices.index_a1).andFromRemote("remote_1", RemoteIndices.index_r1)
                        .at("$.*[*].name")
                        .reducedBy(user.reference(READ))
                        .whenEmpty(isOk())
                );
            }
        }
    }

    @Test
    public void field_caps_remoteWildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("remote_1:*/_field_caps?fields=*");
            assertThat(
                httpResponse,
                containsExactly().andFromRemote("remote_1", RemoteIndices.index_r1, RemoteIndices.index_r2, RemoteIndices.index_r3)
                    .at("indices")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isOk())
            );
        }
    }

    @Test
    public void field_caps_localIndexPattern_remoteIndexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("index_*,remote_1:index_*/_field_caps?fields=*");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(READ).covers(LocalIndices.index_a1) || user.reference(READ).covers(LocalIndices.index_a2)) {
                    // Only if we have privileges for local indices, we also get through
                    assertThat(
                        httpResponse,
                        containsExactly(LocalIndices.index_a1, LocalIndices.index_a2).andFromRemote(
                            "remote_1",
                            RemoteIndices.index_r1,
                            RemoteIndices.index_r2,
                            RemoteIndices.index_r3
                        ).at("indices").reducedBy(user.reference(READ)).whenEmpty(isOk())
                    );
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                assertThat(
                    httpResponse,
                    containsExactly(LocalIndices.index_a1, LocalIndices.index_a2).andFromRemote(
                        "remote_1",
                        RemoteIndices.index_r1,
                        RemoteIndices.index_r2,
                        RemoteIndices.index_r3
                    ).at("indices").reducedBy(user.reference(READ)).whenEmpty(isOk())
                );
            }
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

    public CrossClusterAuthorizationIntTests(ClusterConfig clusterConfig, TestSecurityConfig.User user, String description)
        throws Exception {
        this.user = user;
        this.cluster = clusterConfig.cluster(CrossClusterAuthorizationIntTests::clusterBuilder);
        this.clusterConfig = clusterConfig;
    }

}
