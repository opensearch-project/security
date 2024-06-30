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

package org.opensearch.security.privileges;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.user.User;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import com.github.noconnor.junitperf.JUnitPerfRule;
import com.github.noconnor.junitperf.JUnitPerfTest;
import com.github.noconnor.junitperf.JUnitPerfTestRequirement;
import com.github.noconnor.junitperf.reporting.providers.ConsoleReportGenerator;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.junit.Assert.assertTrue;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PrivilegesEvaluatorPerformanceTest {

    final static TestSecurityConfig.User FULL_PRIVILEGES_TEST_USER = new TestSecurityConfig.User("full_privileges").roles(
        new TestSecurityConfig.Role("full_privileges_role").indexPermissions("*").on("*").clusterPermissions("*")
    );

    final static User FULL_PRIVILEGES_USER = user(FULL_PRIVILEGES_TEST_USER);

    final static TestSecurityConfig.User INDEX_A_READ_TEST_USER = new TestSecurityConfig.User("index_a_read").roles(
        new TestSecurityConfig.Role("index_a_read_role").indexPermissions("read").on("index_a*").clusterPermissions("cluster_composite_ops")
    );

    final static User INDEX_A_READ_USER = user(INDEX_A_READ_TEST_USER);

    final static TestSecurityConfig.User INDEX_A_READ_REGEX_TEST_USER = new TestSecurityConfig.User("index_a_read_regex").roles(
        new TestSecurityConfig.Role("index_a_read_regex_role").indexPermissions("read")
            .on("/^index_a.*/")
            .clusterPermissions("cluster_composite_ops")
    );

    final static User INDEX_A_READ_REGEX_USER = user(INDEX_A_READ_REGEX_TEST_USER);

    final static TestSecurityConfig.User INDEX_A_READ_ATTR_TEST_USER = new TestSecurityConfig.User("index_a_read_attr").attr("attr_a", "a")
        .roles(
            new TestSecurityConfig.Role("index_a_read_attr_role").indexPermissions("read")
                .on("index_${attr_internal_attr_a}*")
                .clusterPermissions("cluster_composite_ops")
        );

    final static User INDEX_A_READ_ATTR_USER = user(INDEX_A_READ_ATTR_TEST_USER);

    final static TestSecurityConfig.User INDEX_A_READ_ATTR_REGEX_TEST_USER = new TestSecurityConfig.User("index_a_read_attr").attr(
        "attr_a",
        "a"
    )
        .roles(
            new TestSecurityConfig.Role("index_a_read_attr_regex_role").indexPermissions("read")
                .on("/^index_${attr_internal_attr_a}.*/")
                .clusterPermissions("cluster_composite_ops")
        );

    final static User INDEX_A_READ_ATTR_REGEX_USER = user(INDEX_A_READ_ATTR_REGEX_TEST_USER);

    final static SearchRequest SEARCH_REQUEST = new SearchRequest("index_a*");

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(
            FULL_PRIVILEGES_TEST_USER,
            INDEX_A_READ_TEST_USER,
            INDEX_A_READ_REGEX_TEST_USER,
            INDEX_A_READ_ATTR_TEST_USER,
            INDEX_A_READ_ATTR_REGEX_TEST_USER
        )
        .indices(testIndices())
        .build();

    @Rule
    public JUnitPerfRule perfTestRule = new JUnitPerfRule(new ConsoleReportGenerator());

    static PrivilegesEvaluator privilegesEvaluator;

    @BeforeClass
    public static void setUp() {
        privilegesEvaluator = cluster.node().injector().getInstance(PrivilegesEvaluator.class);
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_fullPrivileges() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator.createContext(
            FULL_PRIVILEGES_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivileges() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator.createContext(
            INDEX_A_READ_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithRegex() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator.createContext(
            INDEX_A_READ_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttr() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator.createContext(
            INDEX_A_READ_ATTR_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttrAndRegex() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator.createContext(
            INDEX_A_READ_ATTR_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(context);
        assertTrue(response.isAllowed());
    }

    static User user(TestSecurityConfig.User testUser) {
        User user = new User(testUser.getName());
        user.addSecurityRoles(testUser.getRoleNames());
        user.addAttributes(
            testUser.getAttributes()
                .entrySet()
                .stream()
                .map(e -> Map.entry("attr_internal_" + e.getKey(), e.getValue()))
                .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()))
        );
        return user;
    }

    static List<TestIndex> testIndices() {
        ArrayList<TestIndex> result = new ArrayList<>();

        for (char c : new char[] { 'a', 'b', 'c', 'd', 'e' }) {
            for (int i = 0; i < 90; i++) {
                result.add(new TestIndex("index_" + c + "_" + i, Settings.EMPTY));
            }
        }

        return result;
    }

}
