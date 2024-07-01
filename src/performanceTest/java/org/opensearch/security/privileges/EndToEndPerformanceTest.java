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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import com.github.noconnor.junitperf.JUnitPerfRule;
import com.github.noconnor.junitperf.JUnitPerfTest;
import com.github.noconnor.junitperf.JUnitPerfTestRequirement;
import com.github.noconnor.junitperf.reporting.providers.ConsoleReportGenerator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@Ignore
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class EndToEndPerformanceTest {

    final static TestSecurityConfig.User FULL_PRIVILEGES_USER = new TestSecurityConfig.User("full_privileges").roles(
        new TestSecurityConfig.Role("full_privileges_role").indexPermissions("*").on("*").clusterPermissions("*")
    );

    final static TestSecurityConfig.User INDEX_A_READ_USER = new TestSecurityConfig.User("index_a_read").roles(
        new TestSecurityConfig.Role("index_a_read_role").indexPermissions("read").on("index_a*").clusterPermissions("cluster_composite_ops")
    );

    final static TestSecurityConfig.User INDEX_A_READ_REGEX_USER = new TestSecurityConfig.User("index_a_read_regex").roles(
        new TestSecurityConfig.Role("index_a_read_regex_role").indexPermissions("read")
            .on("/^index_a.*/")
            .clusterPermissions("cluster_composite_ops")
    );

    final static TestSecurityConfig.User INDEX_A_READ_ATTR_USER = new TestSecurityConfig.User("index_a_read_attr").attr("attr_a", "a")
        .roles(
            new TestSecurityConfig.Role("index_a_read_attr_role").indexPermissions("read")
                .on("index_${attr_internal_attr_a}*")
                .clusterPermissions("cluster_composite_ops")
        );

    final static TestSecurityConfig.User INDEX_A_READ_ATTR_REGEX_USER = new TestSecurityConfig.User("index_a_read_attr").attr("attr_a", "a")
        .roles(
            new TestSecurityConfig.Role("index_a_read_attr_regex_role").indexPermissions("read")
                .on("/^index_${attr_internal_attr_a}.*/")
                .clusterPermissions("cluster_composite_ops")
        );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(FULL_PRIVILEGES_USER, INDEX_A_READ_USER, INDEX_A_READ_REGEX_USER, INDEX_A_READ_ATTR_USER, INDEX_A_READ_ATTR_REGEX_USER)
        .indices(testIndices())
        .build();

    @Rule
    public JUnitPerfRule perfTestRule = new JUnitPerfRule(new ConsoleReportGenerator());

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void search_fullPrivileges() {
        try (TestRestClient client = cluster.getRestClient(FULL_PRIVILEGES_USER)) {
            TestRestClient.HttpResponse response = client.get("index_a*/_search");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void search_limitedPrivileges() {
        try (TestRestClient client = cluster.getRestClient(INDEX_A_READ_USER)) {
            TestRestClient.HttpResponse response = client.get("index_a*/_search");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void search_limitedPrivilegesWithRegex() {
        try (TestRestClient client = cluster.getRestClient(INDEX_A_READ_REGEX_USER)) {
            TestRestClient.HttpResponse response = client.get("index_a*/_search");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void search_limitedPrivilegesWithUserAttr() {
        try (TestRestClient client = cluster.getRestClient(INDEX_A_READ_ATTR_USER)) {
            TestRestClient.HttpResponse response = client.get("index_a*/_search");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void search_limitedPrivilegesWithUserAttrAndRegex() {
        try (TestRestClient client = cluster.getRestClient(INDEX_A_READ_ATTR_REGEX_USER)) {
            TestRestClient.HttpResponse response = client.get("index_a*/_search");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
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
