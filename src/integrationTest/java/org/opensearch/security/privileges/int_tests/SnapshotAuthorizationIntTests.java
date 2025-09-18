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
import org.apache.hc.core5.http.HttpEntity;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestIndexOrAliasOrDatastream;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnResponseIndexMatcher.containsExactly;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.limitedTo;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.limitedToNone;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.unlimitedIncludingOpenSearchSecurityIndex;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * TODO requests on non master node
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SnapshotAuthorizationIntTests {
    static final TestIndex index_a1 = TestIndex.name("index_ar1").documentCount(10).seed(1).build();
    static final TestIndex index_a2 = TestIndex.name("index_ar2").documentCount(11).seed(2).build();
    static final TestIndex index_a3 = TestIndex.name("index_ar3").documentCount(12).seed(3).build();
    static final TestIndex index_b1 = TestIndex.name("index_br1").documentCount(4).seed(4).build();
    static final TestIndex index_b2 = TestIndex.name("index_br2").documentCount(5).seed(5).build();
    static final TestIndex index_b3 = TestIndex.name("index_br3").documentCount(6).seed(6).build();

    static final TestIndex system_index_plugin_not_existing = TestIndex.name(".system_index_plugin_not_existing")
        .hidden()
        .documentCount(0)
        .build(); // not initially created

    static final TestIndex index_awx1 = TestIndex.name("index_awx1").documentCount(10).seed(11).build(); // not initially created
    static final TestIndex index_awx2 = TestIndex.name("index_awx2").documentCount(10).seed(12).build(); // not initially created

    static final TestIndex index_bwx1 = TestIndex.name("index_bwx1").documentCount(10).seed(13).build(); // not initially created
    static final TestIndex index_bwx2 = TestIndex.name("index_bwx2").documentCount(10).seed(14).build(); // not initially created

    static TestSecurityConfig.User LIMITED_USER_A = new TestSecurityConfig.User("limited_user_A")//
        .description("index_a*")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor", "manage_snapshots")//
                .indexPermissions("read", "indices_monitor", "indices:admin/refresh*")
                .on("index_a*")//
                .indexPermissions("write", "manage")
                .on("index_aw*")
        )//
        .indexMatcher("read", limitedTo(index_a1, index_a2, index_awx1, index_awx2))//
        .indexMatcher("write", limitedTo(index_awx1, index_awx2));

    static TestSecurityConfig.User LIMITED_USER_B = new TestSecurityConfig.User("limited_user_B")//
        .description("index_b*")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor", "manage_snapshots")//
                .indexPermissions("read", "indices_monitor", "indices:admin/refresh*")
                .on("index_b*")//
                .indexPermissions("write", "manage")
                .on("index_bw*")
        )//
        .indexMatcher("read", limitedTo(index_b1, index_b2, index_bwx1, index_bwx2))//
        .indexMatcher("write", limitedTo(index_bwx1, index_bwx2));

    static TestSecurityConfig.User LIMITED_USER_B_SYSTEM_INDEX = new TestSecurityConfig.User("limited_user_B_system_index")//
        .description("index_b*, .system_index_plugin")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor", "manage_snapshots")//
                .indexPermissions("read", "indices_monitor", "indices:admin/refresh*")
                .on("index_b*")//
                .indexPermissions("write", "manage")
                .on("index_bw*")
                .indexPermissions("read", "indices_monitor", "indices:admin/refresh*", "system:admin/system_index")
                .on(".system_index_plugin", ".system_index_plugin_not_existing")
                .indexPermissions("write", "manage", "system:admin/system_index")
                .on(".system_index_plugin_not_existing")

        )//
        .indexMatcher("read", limitedTo(index_b1, index_b2, index_bwx1, index_bwx2))//
        .indexMatcher("write", limitedTo(index_bwx1, index_bwx2, system_index_plugin_not_existing));

    static TestSecurityConfig.User LIMITED_USER_AB = new TestSecurityConfig.User("limited_user_AB")//
        .description("index_a*, index_b*")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor", "manage_snapshots")//
                .indexPermissions("read", "indices_monitor", "indices:admin/refresh*")
                .on("index_a*", "index_b*")//
                .indexPermissions("write", "manage")
                .on("index_aw*", "index_bw*")
        )//
        .indexMatcher("read", limitedTo(index_a1, index_a2, index_awx1, index_awx2, index_b1, index_b2, index_bwx1, index_bwx2))//
        .indexMatcher("write", limitedTo(index_awx1, index_awx2, index_bwx1, index_bwx2));

    static final TestSecurityConfig.User LIMITED_USER_NONE = new TestSecurityConfig.User("limited_user_none")//
        .description("no index privileges")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
        )//
        .indexMatcher("read", limitedToNone())//
        .indexMatcher("write", limitedToNone());

    static final TestSecurityConfig.User UNLIMITED_USER = new TestSecurityConfig.User("unlimited_user")//
        .description("unlimited")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor", "manage_snapshots")
                .indexPermissions("*")
                .on("*")//

        )//
        .indexMatcher(
            "read",
            limitedTo(index_a1, index_a2, index_a3, index_awx1, index_awx2, index_b1, index_b2, index_b3, index_bwx1, index_bwx2)
        )//
        .indexMatcher(
            "write",
            limitedTo(index_a1, index_a2, index_a3, index_awx1, index_awx2, index_b1, index_b2, index_b3, index_bwx1, index_bwx2)
        );

    /**
     * The SUPER_UNLIMITED_USER authenticates with an admin cert, which will cause all access control code to be skipped.
     * This serves as a base for comparison with the default behavior.
     */
    static final TestSecurityConfig.User SUPER_UNLIMITED_USER = new TestSecurityConfig.User("super_unlimited_user")//
        .description("super unlimited (admin cert)")//
        .adminCertUser()//
        .indexMatcher("read", unlimitedIncludingOpenSearchSecurityIndex())//
        .indexMatcher("write", unlimitedIncludingOpenSearchSecurityIndex());

    static final List<TestSecurityConfig.User> USERS = ImmutableList.of(
        LIMITED_USER_A,
        LIMITED_USER_B,
        LIMITED_USER_B_SYSTEM_INDEX,
        LIMITED_USER_AB,
        LIMITED_USER_NONE,
        UNLIMITED_USER,
        SUPER_UNLIMITED_USER
    );

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USERS)//
            .indices(index_a1, index_a2, index_a3, index_b1, index_b2, index_b3)//
            .snapshotRepositories("test_repository")
            .plugin(IndexAuthorizationReadOnlyIntTests.SystemIndexTestPlugin.class);
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
    public void restore_singleIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(index_awx1);
            createInitialTestSnapshot("_snapshot/test_repository/single_index_snapshot", json("indices", "index_awx1"));

            delete(index_awx1);

            TestRestClient.HttpResponse httpResponse = restClient.post(
                "_snapshot/test_repository/single_index_snapshot/_restore?wait_for_completion=true"
            );

            assertThat(
                httpResponse,
                containsExactly(index_awx1).at("snapshot.indices").butForbiddenIfIncomplete(user.indexMatcher("write"))
            );

        } finally {
            delete("_snapshot/test_repository/single_index_snapshot");
            delete(index_awx1);
        }
    }

    @Test
    public void restore_singleIndex_rename1() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(index_awx1);
            createInitialTestSnapshot("_snapshot/test_repository/single_index_snapshot", json("indices", "index_awx1"));

            TestRestClient.HttpResponse httpResponse = restClient.post(
                "_snapshot/test_repository/single_index_snapshot/_restore?wait_for_completion=true",
                json("rename_pattern", "index_(.+)x1", "rename_replacement", "index_$1x2")
            );

            assertThat(
                httpResponse,
                containsExactly(index_awx2).at("snapshot.indices").butForbiddenIfIncomplete(user.indexMatcher("write"))
            );

        } finally {
            delete("_snapshot/test_repository/single_index_snapshot");
            delete(index_awx1, index_awx2);
        }
    }

    @Test
    public void restore_singleIndex_rename2() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(index_awx1);
            createInitialTestSnapshot("_snapshot/test_repository/single_index_snapshot", json("indices", "index_awx1"));

            TestRestClient.HttpResponse httpResponse = restClient.post(
                "_snapshot/test_repository/single_index_snapshot/_restore?wait_for_completion=true",
                json("rename_pattern", "index_a(.*)", "rename_replacement", "index_b$1")
            );

            assertThat(
                httpResponse,
                containsExactly(index_bwx1).at("snapshot.indices").butForbiddenIfIncomplete(user.indexMatcher("write"))
            );

        } finally {
            delete("_snapshot/test_repository/single_index_snapshot");
            delete(index_awx1, index_bwx1);
        }
    }

    @Test
    public void restore_singleIndex_renameToSystemIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(index_awx1);
            createInitialTestSnapshot("_snapshot/test_repository/single_index_snapshot", json("indices", "index_awx1"));

            TestRestClient.HttpResponse httpResponse = restClient.post(
                "_snapshot/test_repository/single_index_snapshot/_restore?wait_for_completion=true",
                json("rename_pattern", "index_awx1", "rename_replacement", system_index_plugin_not_existing.name())
            );

            if (clusterConfig.systemIndexPrivilegeEnabled || user == SUPER_UNLIMITED_USER) {
                assertThat(
                    httpResponse,
                    containsExactly(system_index_plugin_not_existing).at("snapshot.indices")
                        .butForbiddenIfIncomplete(user.indexMatcher("write"))
                );
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            delete("_snapshot/test_repository/single_index_snapshot");
            delete(index_awx1, system_index_plugin_not_existing);
        }
    }

    @Test
    public void restore_singleIndexFromAllIndices() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(index_awx1);
            createInitialTestSnapshot("_snapshot/test_repository/all_index_snapshot", json());

            delete(index_awx1);

            TestRestClient.HttpResponse httpResponse = restClient.post(
                "_snapshot/test_repository/all_index_snapshot/_restore?wait_for_completion=true",
                json("indices", "index_awx1")
            );

            assertThat(
                httpResponse,
                containsExactly(index_awx1).at("snapshot.indices").butForbiddenIfIncomplete(user.indexMatcher("write"))
            );

        } finally {
            delete("_snapshot/test_repository/all_index_snapshot");
            delete(index_awx1);
        }
    }

    @Test
    public void restore_all_globalState() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(index_awx1, index_awx2, index_bwx1, index_bwx2);
            createInitialTestSnapshot("_snapshot/test_repository/all_index_snapshot", json("indices", "index_*w*"));

            delete(index_awx1, index_awx2, index_bwx1, index_bwx2);

            TestRestClient.HttpResponse httpResponse = restClient.post(
                "_snapshot/test_repository/all_index_snapshot/_restore?wait_for_completion=true",
                json("include_global_state", true)
            );

            if (user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isForbidden());
            }

        } finally {
            delete("_snapshot/test_repository/all_index_snapshot");
            delete(index_awx1, index_awx2, index_bwx1, index_bwx2);
        }
    }

    @After
    public void refresh() {
        cluster.getInternalNodeClient().admin().indices().refresh(new RefreshRequest("*")).actionGet();
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

    public SnapshotAuthorizationIntTests(ClusterConfig clusterConfig, TestSecurityConfig.User user, String description) throws Exception {
        this.user = user;
        this.cluster = clusterConfig.cluster(SnapshotAuthorizationIntTests::clusterBuilder);
        this.clusterConfig = clusterConfig;
    }

    private void createInitialTestObjects(TestIndexOrAliasOrDatastream... testIndexLikeArray) {
        TestIndexOrAliasOrDatastream.createInitialTestObjects(cluster, testIndexLikeArray);
    }

    private void createInitialTestSnapshot(String snapshotName, HttpEntity requestBody) {
        try (TestRestClient client = cluster.getAdminCertRestClient()) {
            TestRestClient.HttpResponse httpResponse = client.put(snapshotName + "?wait_for_completion=true", requestBody);
            assertThat(httpResponse, isOk());
        }
    }

    private void delete(TestIndexOrAliasOrDatastream... testIndexLikeArray) {
        TestIndexOrAliasOrDatastream.delete(cluster, testIndexLikeArray);
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
