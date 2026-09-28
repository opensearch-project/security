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

package org.opensearch.security.api;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;
import static org.opensearch.test.framework.matcher.RestMatchers.isUnauthorized;

public class ViewVersionApiIntegrationTest extends AbstractApiIntegrationTest {

    @Rule
    public LocalCluster localCluster = clusterBuilder().users(new TestSecurityConfig.User("limitedUser").password("limitedPass"))
        .nodeSetting(EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED, true)
        .build();

    private static final TestSecurityConfig.User USER = new TestSecurityConfig.User("user");

    private String endpointPrefix() {
        return PLUGINS_PREFIX + "/api";
    }

    private String viewVersionBase() {
        return endpointPrefix() + "/versions";
    }

    private String viewVersion(String versionId) {
        return endpointPrefix() + "/version/" + versionId;
    }

    @Before
    public void setupIndexAndCerts() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            client.createUser(USER.getName(), USER).assertStatusCode(201);
        }
    }

    @Test
    public void testViewAllVersions() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            var response = client.get(viewVersionBase());
            assertThat(response, isOk());
            var json = response.bodyAsJsonNode();

            assertThat(json.has("versions"), is(true));
            var versions = json.get("versions");
            assertThat(versions.isArray(), is(true));
            assertThat(versions.size(), greaterThan(0));
        }
    }

    @Test
    public void testViewSpecificVersionFound() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            var response = client.get(viewVersion("v1"));
            assertThat(response, isOk());
            var json = response.bodyAsJsonNode();

            assertThat(json.has("versions"), is(true));
            var versions = json.get("versions");
            assertThat(versions.isArray(), is(true));
            assertThat(versions.size(), is(1));

            var ver = versions.get(0);
            assertThat(ver.get("version_id").asText(), equalTo("v1"));
        }
    }

    @Test
    public void testViewSpecificVersionNotFound() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            var response = client.get(viewVersion("does-not-exist"));
            assertThat(response, isNotFound());
            var json = response.bodyAsJsonNode();

            assertThat(json.has("status"), is(true));
            assertThat(json.get("status").asText(), equalTo("NOT_FOUND"));

            assertThat(json.has("message"), is(true));
            assertThat(json.get("message").asText(), containsString("not found"));
        }
    }

    @Test
    public void testViewAllVersions_forbiddenWithoutAdminCert() throws Exception {
        try (TestRestClient client = localCluster.getRestClient("limitedUser", "limitedPass")) {
            var response = client.get(viewVersionBase());
            assertThat(response, anyOf(isUnauthorized(), isForbidden()));
        }
    }
}
