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

import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.script.mustache.MustacheModulePlugin;
import org.opensearch.script.mustache.RenderSearchTemplateAction;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestIndex;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

public class MiscPrivilegesIntTests {

    protected final static TestSecurityConfig.User NEGATIVE_LOOKAHEAD = new TestSecurityConfig.User("negative_lookahead_user").roles(
        new Role("negative_lookahead_role").indexPermissions("read").on("/^(?!t.*).*/").clusterPermissions("cluster_composite_ops")
    );

    protected final static TestSecurityConfig.User NEGATED_REGEX = new TestSecurityConfig.User("negated_regex_user").roles(
        new Role("negated_regex_role").indexPermissions("read").on("/^[a-r].*/").clusterPermissions("cluster_composite_ops")
    );

    protected final static TestSecurityConfig.User SEARCH_TEMPLATE = new TestSecurityConfig.User("search_template_user").roles(
        new Role("search_template_role").indexPermissions("read").on("services").clusterPermissions("cluster_composite_ops")
    );

    protected final static TestSecurityConfig.User RENDER_SEARCH_TEMPLATE = new TestSecurityConfig.User("render_search_template_user")
        .roles(
            new Role("render_search_template_role").indexPermissions("read")
                .on("services")
                .clusterPermissions(RenderSearchTemplateAction.NAME)
        );

    private final String TEST_RENDER_SEARCH_TEMPLATE_QUERY =
        """
            {"params":{"status":["pending","published"]},"source":"{\\"query\\": {\\"terms\\": {\\"status\\": [\\"{{#status}}\\",\\"{{.}}\\",\\"{{/status}}\\"]}}}"}""";

    final static TestIndex R = TestIndex.name("r").build();
    /**
     * This is necessary so that the testNegativeLookaheadPattern test has an forbidden index to match against
     */
    final static TestIndex T = TestIndex.name("t").build();

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(NEGATIVE_LOOKAHEAD, NEGATED_REGEX, SEARCH_TEMPLATE, RENDER_SEARCH_TEMPLATE, TestSecurityConfig.User.USER_ADMIN)
        .plugin(MustacheModulePlugin.class)
        .indices(R, T)
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
    public void testRenderSearchTemplateRequestFailure() {
        try (TestRestClient client = cluster.getRestClient(SEARCH_TEMPLATE)) {
            final String renderSearchTemplate = "_render/template";
            final TestRestClient.HttpResponse renderSearchTemplateResponse = client.postJson(
                renderSearchTemplate,
                TEST_RENDER_SEARCH_TEMPLATE_QUERY
            );
            assertThat(renderSearchTemplateResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }

    @Test
    public void testRenderSearchTemplateRequestSuccess() {
        try (TestRestClient client = cluster.getRestClient(RENDER_SEARCH_TEMPLATE)) {
            final String renderSearchTemplate = "_render/template";
            final TestRestClient.HttpResponse renderSearchTemplateResponse = client.postJson(
                renderSearchTemplate,
                TEST_RENDER_SEARCH_TEMPLATE_QUERY
            );
            assertThat(renderSearchTemplateResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
    }
}
