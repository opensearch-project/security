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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
* This is a port for the test
* org.opensearch.security.privileges.PrivilegesEvaluatorTest to the new test
* framework for direct comparison
*/
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PrivilegesEvaluatorTest {

    protected final static TestSecurityConfig.User NEGATIVE_LOOKAHEAD = new TestSecurityConfig.User("negative_lookahead_user").roles(
        new Role("negative_lookahead_role").indexPermissions("read").on("/^(?!t.*).*/").clusterPermissions("cluster_composite_ops")
    );

    protected final static TestSecurityConfig.User NEGATED_REGEX = new TestSecurityConfig.User("negated_regex_user").roles(
        new Role("negated_regex_role").indexPermissions("read").on("/^[a-z].*/").clusterPermissions("cluster_composite_ops")
    );

    protected final static TestSecurityConfig.User SEARCH_TEMPLATE = new TestSecurityConfig.User("search_template_user").roles(
        new Role("search_template_role").indexPermissions("read").on("services")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(NEGATIVE_LOOKAHEAD, NEGATED_REGEX, SEARCH_TEMPLATE)
        .build();

    @Test
    public void testNegativeLookaheadPattern() throws Exception {

        try (TestRestClient client = cluster.getRestClient(NEGATIVE_LOOKAHEAD)) {
            assertThat(client.get("*/_search").getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            assertThat(client.get("r*/_search").getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
    }

    @Test
    public void testRegexPattern() throws Exception {

        try (TestRestClient client = cluster.getRestClient(NEGATED_REGEX)) {
            assertThat(client.get("*/_search").getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            assertThat(client.get("r*/_search").getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

    }

    @Test
    public void testSearchTemplateRequestSuccess() {
        try (TestRestClient client = cluster.getRestClient(SEARCH_TEMPLATE)) {
            assertThat(
                client.getWithJsonBody(
                    "services/_search/template",
                    "{\"source\":{\"query\":{\"match\":{\"service\":\"{{service_name}}\"}}},\"params\":{\"service_name\":\"Oracle\"}}"
                ).getStatusCode(),
                equalTo(HttpStatus.SC_OK)
            );
        }
    }

    @Test
    public void testSearchTemplateRequestUnauthorizedIndex() {
        try (TestRestClient client = cluster.getRestClient(SEARCH_TEMPLATE)) {
            assertThat(
                    client.getWithJsonBody(
                            "movies/_search/template",
                            "{\"source\":{\"query\":{\"match\":{\"service\":\"{{service_name}}\"}}},\"params\":{\"service_name\":\"Oracle\"}}"
                    ).getStatusCode(),
                    equalTo(HttpStatus.SC_FORBIDDEN)
            );
        }
    }

    @Test
    public void testSearchTemplateRequestUnauthorizedAllIndices() {
        try (TestRestClient client = cluster.getRestClient(SEARCH_TEMPLATE)) {
            assertThat(
                    client.getWithJsonBody(
                            "_search/template",
                            "{\"source\":{\"query\":{\"match\":{\"service\":\"{{service_name}}\"}}},\"params\":{\"service_name\":\"Oracle\"}}"
                    ).getStatusCode(),
                    equalTo(HttpStatus.SC_FORBIDDEN)
            );
        }
    }
}
