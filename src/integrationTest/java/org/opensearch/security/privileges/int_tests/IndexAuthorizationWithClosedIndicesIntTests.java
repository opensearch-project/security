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

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import org.opensearch.script.mustache.MustacheModulePlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestIndex;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.IndexMatcher;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.limitedToNone;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * Integration tests for index authorization when all indices are closed.
 * Tests operations that should work even when getAllIndicesResolved() returns empty.
 * This test suite verifies that operations like _cat/recovery can still be authorized
 * correctly when all indices are closed, which results in an empty resolved indices set.
 * <p>
 * We need this dedicated test suite because closing indices triggers cluster state changes,
 * affecting some threads and losing access to the RandomizedContext. Therefore, we isolate
 * these tests to avoid interference with other tests.
 */
@RunWith(Parameterized.class)
public class IndexAuthorizationWithClosedIndicesIntTests {

    private static final Logger log = LogManager.getLogger(IndexAuthorizationWithClosedIndicesIntTests.class);

    // -------------------------------------------------------------------------------------------------------
    // Test indices used by this test suite
    // -------------------------------------------------------------------------------------------------------

    static final TestIndex index_a1 = TestIndex.name("index_a1").documentCount(100).seed(1).build();
    static final TestIndex index_a2 = TestIndex.name("index_a2").documentCount(110).seed(2).build();
    static final TestIndex index_b1 = TestIndex.name("index_b1").documentCount(51).seed(3).build();
    static final TestIndex index_b2 = TestIndex.name("index_b2").documentCount(52).seed(4).build();

    /**
     * This key identifies assertion reference data for index search/read permissions of individual users.
     */
    static final TestSecurityConfig.User.MetadataKey<IndexMatcher> READ = new TestSecurityConfig.User.MetadataKey<>(
        "read",
        IndexMatcher.class
    );

    /**
     * A user with indices:monitor/recovery permission on all indices to verify that it succeeds in case all indices are closed.
     */
    static final TestSecurityConfig.User LIMITED_USER_RECOVERY = new TestSecurityConfig.User("limited_user_recovery").description(
        "indices:monitor/recovery on *"
    )
        .roles(
            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("indices:monitor/recovery")
                .on("*")
        )
        .reference(READ, limitedToNone());

    /**
     * A user with indices:monitor/recovery permission on specific indices (not wildcard) to test empty resolved indices handling.
     * This user is crucial for testing the empty resolved indices scenario because it doesn't have wildcard privileges,
     * which means checkWildcardIndexPrivilegesOnWellKnownActions will return null, forcing execution to reach
     * the CheckTable.create() call with empty allIndicesResolved.
     */
    static final TestSecurityConfig.User LIMITED_USER_RECOVERY_SPECIFIC = new TestSecurityConfig.User("limited_user_recovery_specific")
        .description("indices:monitor/recovery on index_a*")
        .roles(
            new TestSecurityConfig.Role("r1").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
                .indexPermissions("indices:monitor/recovery")
                .on("index_a*")
        )
        .reference(READ, limitedToNone());

    /**
     * A user with "*" privileges on "*"; as it is a regular user, they are still subject to system index
     * restrictions and similar things.
     */
    static final TestSecurityConfig.User UNLIMITED_USER = new TestSecurityConfig.User("unlimited_user")//
        .description("unlimited")
        .roles(new TestSecurityConfig.Role("r1").clusterPermissions("*").indexPermissions("*").on("*"))
        .reference(READ, limitedToNone());

    /**
     * The SUPER_UNLIMITED_USER authenticates with an admin cert, which will cause all access control code to be skipped.
     * This serves as a base for comparison with the default behavior.
     */
    static final TestSecurityConfig.User SUPER_UNLIMITED_USER = new TestSecurityConfig.User("super_unlimited_user")//
        .description("super unlimited (admin cert)")
        .adminCertUser()
        .reference(READ, limitedToNone());

    /**
     * A user with no index privileges to test that operations are properly denied.
     */
    static final TestSecurityConfig.User LIMITED_USER_NONE = new TestSecurityConfig.User("limited_user_none").description(
        "no index privileges"
    )
        .roles(new TestSecurityConfig.Role("r2").clusterPermissions("cluster_composite_ops_ro", "cluster_monitor"))
        .reference(READ, limitedToNone());

    static final List<TestSecurityConfig.User> USERS = ImmutableList.of(
        LIMITED_USER_NONE,
        LIMITED_USER_RECOVERY,
        LIMITED_USER_RECOVERY_SPECIFIC,
        SUPER_UNLIMITED_USER,
        UNLIMITED_USER
    );

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USERS)
            .indices(index_a1, index_a2, index_b1, index_b2)
            .plugin(MustacheModulePlugin.class);
    }

    private final TestSecurityConfig.User user;
    private final LocalCluster cluster;
    private final ClusterConfig clusterConfig;

    @Parameters(name = "{0}, {2}")
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();

        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            for (TestSecurityConfig.User user : USERS) {
                result.add(new Object[] { clusterConfig, user, user.getDescription() });
            }
        }
        return result;
    }

    public IndexAuthorizationWithClosedIndicesIntTests(ClusterConfig clusterConfig, TestSecurityConfig.User user, String description)
        throws Exception {
        this.user = user;
        this.cluster = clusterConfig.cluster(IndexAuthorizationWithClosedIndicesIntTests::clusterBuilder);
        this.clusterConfig = clusterConfig;
    }

    @Before
    public void setup() {
        // In order to test index authorization when all indices are closed, we close all indices, including hidden ones.
        try (TestRestClient adminClient = cluster.getAdminCertRestClient()) {
            TestRestClient.HttpResponse hiddenCloseResponse = adminClient.post("_all/_close?expand_wildcards=all");
            assertThat(hiddenCloseResponse, isOk());
        }
    }

    @After
    public void teardown() {
        try (TestRestClient adminClient = cluster.getAdminCertRestClient()) {
            try {
                adminClient.post("_all/_open?expand_wildcards=all");
            } catch (Exception e) {
                log.warn("Error reopening all indices during teardown", e);
            }
        }
    }

    /**
     * Tests _cat/recovery operation succeeds when all indices are closed. This verifies that
     * the empty resolved indices check in RuntimeOptimizedActionPrivileges works correctly.
     */
    @Test
    public void cat_recovery_allIndicesClosed() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.get("_cat/recovery");

            if (user == UNLIMITED_USER || user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
            } else if (user == LIMITED_USER_RECOVERY) {
                // This user has indices:monitor/recovery on wildcard "*".
                // checkWildcardIndexPrivilegesOnWellKnownActions() == null should handle this.
                assertThat(httpResponse, isOk());
            } else if (user == LIMITED_USER_RECOVERY_SPECIFIC) {
                // This user has indices:monitor/recovery on index_a* but not wildcard.
                // When all indices are closed, getAllIndicesResolved() returns empty,
                // then we must ensure that the empty resolved indices case is handled correctly.
                assertThat(httpResponse, isOk());
            } else if (user == LIMITED_USER_NONE) {
                // This user has no permission at the same time as all indices are closed.
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isOk());
            }
        }
    }
}
