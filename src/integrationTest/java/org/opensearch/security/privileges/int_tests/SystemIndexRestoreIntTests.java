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

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.SystemIndexPlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * Restoring allowlisted system indices by a security-admin (a holder of a role in
 * {@code plugins.security.restapi.roles_enabled}), for both the legacy and the V4 privilege evaluation.
 */
@RunWith(Parameterized.class)
public class SystemIndexRestoreIntTests {

    static final String ELIGIBLE = ".opendistro-alerting-config";
    static final String NOT_ELIGIBLE = ".opendistro-alerting-alerts";
    static final String REGULAR = "restore_regular_index";
    static final String REPOSITORY = "restore_repository";

    static final TestSecurityConfig.Role ADMIN_ROLE = new TestSecurityConfig.Role("restore_admin")//
        .clusterPermissions("cluster_composite_ops", "cluster_monitor", "manage_snapshots")//
        .indexPermissions("*")
        .on("*");

    static final TestSecurityConfig.User SECURITY_ADMIN = new TestSecurityConfig.User("security_admin").roles(ADMIN_ROLE);

    /**
     * Same privileges as SECURITY_ADMIN, but its role is not listed in plugins.security.restapi.roles_enabled.
     */
    static final TestSecurityConfig.User NOT_SECURITY_ADMIN = new TestSecurityConfig.User("not_security_admin").roles(ADMIN_ROLE);

    static final List<String> SECURITY_ADMIN_ROLES = List.of("user_" + SECURITY_ADMIN.getName() + "__" + ADMIN_ROLE.getName());

    static LocalCluster.Builder clusterBuilder() {
        return defaultClusterBuilder().nodeSettings(
            Map.of(SECURITY_RESTAPI_ROLES_ENABLED, SECURITY_ADMIN_ROLES, SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY, List.of(ELIGIBLE))
        );
    }

    /**
     * Cluster with {@code plugins.security.system_indices.restore.indices} left at its empty default.
     */
    static LocalCluster.Builder defaultClusterBuilder() {
        return new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(SECURITY_ADMIN, NOT_SECURITY_ADMIN)
            .snapshotRepositories(REPOSITORY)
            .nodeSettings(Map.of(SECURITY_RESTAPI_ROLES_ENABLED, SECURITY_ADMIN_ROLES))
            .plugin(RestorableSystemIndexTestPlugin.class);
    }

    @ClassRule
    public static final ClusterConfig.ClusterInstances clusterInstances = new ClusterConfig.ClusterInstances(
        SystemIndexRestoreIntTests::clusterBuilder
    );

    final ClusterConfig clusterConfig;
    final LocalCluster cluster;

    @Test
    public void securityAdmin_restoresExplicitAllowlistedSystemIndex() {
        createIndicesAndSnapshot("snap_eligible", ELIGIBLE, REGULAR);
        try (TestRestClient client = cluster.getRestClient(SECURITY_ADMIN)) {
            TestRestClient.HttpResponse response = client.post(restorePath("snap_eligible"), json("indices", List.of(ELIGIBLE, REGULAR)));
            assertThat(response, isOk());
        } finally {
            cleanup("snap_eligible", ELIGIBLE, REGULAR);
        }
    }

    @Test
    public void notSecurityAdmin_cannotRestoreAllowlistedSystemIndex() {
        createIndicesAndSnapshot("snap_not_admin", ELIGIBLE);
        try (TestRestClient client = cluster.getRestClient(NOT_SECURITY_ADMIN)) {
            TestRestClient.HttpResponse response = client.post(restorePath("snap_not_admin"), json("indices", List.of(ELIGIBLE)));
            assertThat(response, isForbidden());
        } finally {
            cleanup("snap_not_admin", ELIGIBLE);
        }
    }

    @Test
    public void securityAdmin_cannotRestoreNonAllowlistedSystemIndex() {
        createIndicesAndSnapshot("snap_not_eligible", ELIGIBLE, NOT_ELIGIBLE);
        try (TestRestClient client = cluster.getRestClient(SECURITY_ADMIN)) {
            TestRestClient.HttpResponse response = client.post(
                restorePath("snap_not_eligible"),
                json("indices", List.of(ELIGIBLE, NOT_ELIGIBLE))
            );
            assertThat(response, isForbidden());
            assertThat(response.getBody(), containsString("[" + NOT_ELIGIBLE + "] are not eligible for restore"));
            assertThat(response.getBody(), containsString("Restorable system indices: [" + ELIGIBLE));
        } finally {
            cleanup("snap_not_eligible", ELIGIBLE, NOT_ELIGIBLE);
        }
    }

    @Test
    public void securityAdmin_cannotRestoreSystemIndexMatchedByWildcard() {
        createIndicesAndSnapshot("snap_wildcard", ELIGIBLE);
        try (TestRestClient client = cluster.getRestClient(SECURITY_ADMIN)) {
            TestRestClient.HttpResponse response = client.post(
                restorePath("snap_wildcard"),
                json("indices", List.of(".opendistro-alerting-c*"))
            );
            assertThat(response, isForbidden());
            assertThat(response.getBody(), containsString("must be named explicitly"));
        } finally {
            cleanup("snap_wildcard", ELIGIBLE);
        }
    }

    @Test
    public void securityAdmin_cannotRenameIntoSystemIndex() {
        createIndicesAndSnapshot("snap_rename", REGULAR);
        try (TestRestClient client = cluster.getRestClient(SECURITY_ADMIN)) {
            TestRestClient.HttpResponse response = client.post(
                restorePath("snap_rename"),
                json("indices", List.of(REGULAR), "rename_pattern", REGULAR, "rename_replacement", ELIGIBLE)
            );
            assertThat(response, isForbidden());
            assertThat(response.getBody(), containsString("Renaming indices is not allowed"));
        } finally {
            cleanup("snap_rename", REGULAR, ELIGIBLE);
        }
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();
        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            result.add(new Object[] { clusterConfig });
        }
        return result;
    }

    public SystemIndexRestoreIntTests(ClusterConfig clusterConfig) {
        this.clusterConfig = clusterConfig;
        this.cluster = clusterInstances.get(clusterConfig);
    }

    static String restorePath(String snapshot) {
        return "_snapshot/" + REPOSITORY + "/" + snapshot + "/_restore?wait_for_completion=true";
    }

    /**
     * Creates the indices with one document each, snapshots them and deletes them again, so they can be restored.
     */
    private void createIndicesAndSnapshot(String snapshot, String... indices) {
        createIndicesAndSnapshot(cluster, snapshot, indices);
    }

    static void createIndicesAndSnapshot(LocalCluster cluster, String snapshot, String... indices) {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            for (String index : indices) {
                assertThat(admin.put(index + "/_doc/1?refresh=true", json("field", "value")), isCreated());
            }
            assertThat(
                admin.put("_snapshot/" + REPOSITORY + "/" + snapshot + "?wait_for_completion=true", json("indices", List.of(indices))),
                isOk()
            );
            for (String index : indices) {
                assertThat(admin.delete(index), isOk());
            }
        }
    }

    private void cleanup(String snapshot, String... indices) {
        cleanup(cluster, snapshot, indices);
    }

    static void cleanup(LocalCluster cluster, String snapshot, String... indices) {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            admin.delete("_snapshot/" + REPOSITORY + "/" + snapshot);
            for (String index : indices) {
                admin.delete(index);
            }
        }
    }

    public static class RestorableSystemIndexTestPlugin extends Plugin implements SystemIndexPlugin {
        @Override
        public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
            return List.of(
                new SystemIndexDescriptor(ELIGIBLE, "restore-eligible system index for testing"),
                new SystemIndexDescriptor(NOT_ELIGIBLE, "non restore-eligible system index for testing")
            );
        }
    }
}
