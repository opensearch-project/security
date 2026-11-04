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

import java.util.List;

import com.google.common.collect.ImmutableList;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestIndex;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * Integration test for the CCS remote role recomputation setting.
 *
 * Proves:
 * 1. With flag=true, source-propagated securityRoles are stripped (CCS query denied for unmapped user)
 * 2. With flag=true, roles_mapping on the remote still grants access independently (mapped user succeeds)
 * 3. With flag=false, legacy union behavior is preserved (source roles propagate)
 * 4. Dynamic setting update via PUT _cluster/settings works at runtime
 */
public class CcsIgnoreSourceSecurityRolesIntTests {

    private static final String REMOTE_CLUSTER_FLAG_ON = "remote_flag_on";
    private static final String REMOTE_CLUSTER_FLAG_OFF = "remote_flag_off";
    private static final String REMOTE_CLUSTER_DYNAMIC = "remote_dynamic";
    private static final String INDEX_NAME = "index_r1";
    private static final String MAPPED_USER_NAME = "mapped_user";
    private static final String UNMAPPED_USER_NAME = "unmapped_user";
    private static final String UNLIMITED_ROLE_NAME = "unlimited_role";
    private static final String READ_ROLE_REMOTE_NAME = "read_role_remote";

    static final TestIndex REMOTE_INDEX = TestIndex.name(INDEX_NAME).documentCount(10).seed(1).build();

    // Role that grants access to ALL indices (assigned to user on local cluster via securityRoles)
    static final TestSecurityConfig.Role UNLIMITED_ROLE = new TestSecurityConfig.Role(UNLIMITED_ROLE_NAME).clusterPermissions("*")
        .indexPermissions("*")
        .on("*");

    // Role that grants read-only on the remote index (mapped via roles_mapping on remote)
    static final TestSecurityConfig.Role READ_ROLE_REMOTE = new TestSecurityConfig.Role(READ_ROLE_REMOTE_NAME).clusterPermissions(
        "cluster_composite_ops_ro",
        "cluster_monitor"
    ).indexPermissions("read", "indices_monitor", "indices:admin/shards/search_shards").on(INDEX_NAME);

    // User with unlimited access via securityRoles (source cluster), mapped via roles_mapping on remote
    static final TestSecurityConfig.User MAPPED_USER = new TestSecurityConfig.User(MAPPED_USER_NAME).referencedRoles(UNLIMITED_ROLE);

    // Second user: also has unlimited on source, but NO roles_mapping on remote
    static final TestSecurityConfig.User UNMAPPED_USER = new TestSecurityConfig.User(UNMAPPED_USER_NAME).referencedRoles(UNLIMITED_ROLE);

    // Roles mapping on remote: maps "mapped_user" -> "read_role_remote"
    // Note: "unmapped_user" intentionally has NO mapping
    static final TestSecurityConfig.RoleMapping READ_ROLE_MAPPING = new TestSecurityConfig.RoleMapping(READ_ROLE_REMOTE_NAME).users(
        MAPPED_USER_NAME
    );

    static final List<TestSecurityConfig.User> USERS = ImmutableList.of(MAPPED_USER, UNMAPPED_USER);

    static final TestCertificates TEST_CERTIFICATES = new TestCertificates();

    // Remote cluster with flag=TRUE: ignores source securityRoles, uses only its own roles_mapping
    @ClassRule
    public static final LocalCluster remoteClusterFlagOn = new LocalCluster.Builder().certificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLENODE)
        .clusterName(REMOTE_CLUSTER_FLAG_ON)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .privilegesEvaluationType("v4")
        .users(USERS)
        .roles(UNLIMITED_ROLE, READ_ROLE_REMOTE)
        .rolesMapping(READ_ROLE_MAPPING)
        .nodeSetting(ConfigConstants.SECURITY_CCS_IGNORE_SOURCE_SECURITY_ROLES, true)
        .indices(REMOTE_INDEX)
        .build();

    // Remote cluster with flag=FALSE: legacy behavior, source securityRoles propagate through
    @ClassRule
    public static final LocalCluster remoteClusterFlagOff = new LocalCluster.Builder().certificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLENODE)
        .clusterName(REMOTE_CLUSTER_FLAG_OFF)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .privilegesEvaluationType("v4")
        .users(USERS)
        .roles(UNLIMITED_ROLE, READ_ROLE_REMOTE)
        .nodeSetting(ConfigConstants.SECURITY_CCS_IGNORE_SOURCE_SECURITY_ROLES, false)
        .indices(REMOTE_INDEX)
        .build();

    // Dedicated remote cluster for dynamic setting test: starts with flag=FALSE, flipped to TRUE at runtime
    @ClassRule
    public static final LocalCluster remoteClusterDynamic = new LocalCluster.Builder().certificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLENODE)
        .clusterName(REMOTE_CLUSTER_DYNAMIC)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .privilegesEvaluationType("v4")
        .users(USERS)
        .roles(UNLIMITED_ROLE, READ_ROLE_REMOTE)
        .nodeSetting(ConfigConstants.SECURITY_CCS_IGNORE_SOURCE_SECURITY_ROLES, false)
        .indices(REMOTE_INDEX)
        .build();

    // Local cluster: connects to all three remotes
    @ClassRule
    public static final LocalCluster localCluster = new LocalCluster.Builder().certificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLE_REMOTE_CLIENT)
        .remote(REMOTE_CLUSTER_FLAG_ON, remoteClusterFlagOn)
        .remote(REMOTE_CLUSTER_FLAG_OFF, remoteClusterFlagOff)
        .remote(REMOTE_CLUSTER_DYNAMIC, remoteClusterDynamic)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .privilegesEvaluationType("v4")
        .users(USERS)
        .roles(UNLIMITED_ROLE)
        .doNotFailOnForbidden(true)
        .build();

    /**
     * With flag=true: source's unlimited_role is stripped.
     * But remote's roles_mapping maps the user -> read_role_remote (read on index_r1).
     * CCS query should SUCCEED via the remote's own roles_mapping.
     */
    @Test
    public void ccsQuery_withFlagOn_shouldSucceedViaRolesMapping() throws Exception {
        try (TestRestClient restClient = localCluster.getRestClient(MAPPED_USER)) {
            TestRestClient.HttpResponse response = restClient.get(REMOTE_CLUSTER_FLAG_ON + ":" + INDEX_NAME + "/_search");
            assertThat(response, isOk());
        }
    }

    /**
     * With flag=true: source's unlimited_role is stripped.
     * Unmapped user has NO roles_mapping entry on remote.
     * CCS query should be FORBIDDEN — proves source securityRoles are actually stripped.
     */
    @Test
    public void ccsQuery_withFlagOn_shouldBeForbidden_whenNoRolesMapping() throws Exception {
        try (TestRestClient restClient = localCluster.getRestClient(UNMAPPED_USER)) {
            TestRestClient.HttpResponse response = restClient.get(REMOTE_CLUSTER_FLAG_ON + ":" + INDEX_NAME + "/_search");
            assertThat(response, isForbidden());
        }
    }

    /**
     * With flag=false (legacy behavior): source's securityRoles propagate through.
     * Unmapped user has unlimited_role from source — which exists on remote's roles.yml.
     * CCS query should SUCCEED — proves legacy union behavior is preserved.
     */
    @Test
    public void ccsQuery_withFlagOff_shouldSucceed_whenSourceRolesPropagate() throws Exception {
        try (TestRestClient restClient = localCluster.getRestClient(UNMAPPED_USER)) {
            TestRestClient.HttpResponse response = restClient.get(REMOTE_CLUSTER_FLAG_OFF + ":" + INDEX_NAME + "/_search");
            assertThat(response, isOk());
        }
    }

    /**
     * Dynamic setting update on a dedicated cluster: flip flag from false to true at runtime.
     * CCS query that previously succeeded should now be forbidden.
     * Uses a dedicated remote cluster so no other test depends on its state.
     */
    @Test
    public void ccsQuery_withFlagDynamicallyEnabled_shouldBeForbidden() throws Exception {
        // First: confirm CCS works with flag=false (source roles propagate)
        try (TestRestClient restClient = localCluster.getRestClient(UNMAPPED_USER)) {
            TestRestClient.HttpResponse response = restClient.get(REMOTE_CLUSTER_DYNAMIC + ":" + INDEX_NAME + "/_search");
            assertThat(response, isOk());
        }

        // Dynamically enable the flag on the dedicated remote cluster
        try (TestRestClient remoteClient = remoteClusterDynamic.getRestClient(MAPPED_USER)) {
            TestRestClient.HttpResponse updateResponse = remoteClient.putJson(
                "_cluster/settings",
                "{\"transient\": {\"plugins.security.ccs.ignore_source_security_roles\": true}}"
            );
            assertThat(updateResponse, isOk());
        }

        // Now the same CCS query should be forbidden (source roles stripped)
        try (TestRestClient restClient = localCluster.getRestClient(UNMAPPED_USER)) {
            TestRestClient.HttpResponse response = restClient.get(REMOTE_CLUSTER_DYNAMIC + ":" + INDEX_NAME + "/_search");
            assertThat(response, isForbidden());
        }
    }
}
