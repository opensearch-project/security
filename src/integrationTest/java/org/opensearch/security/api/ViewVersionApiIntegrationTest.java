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

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isOneOf;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED;

public class ViewVersionApiIntegrationTest extends AbstractApiIntegrationTest {

    static {
        testSecurityConfig.user(new TestSecurityConfig.User("limitedUser").password("limitedPass"));
    }

    private String endpointPrefix() {
        return PLUGINS_PREFIX + "/api";
    }

    private String viewVersionBase() {
        return endpointPrefix() + "/versions";
    }

    private String viewVersion(String versionId) {
        return endpointPrefix() + "/version/" + versionId;
    }

    @Override
    protected Map<String, Object> getClusterSettings() {
        Map<String, Object> settings = super.getClusterSettings();
        settings.put(EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED, true);
        return settings;
    }

    @Before
    public void setupIndexAndCerts() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER_NAME, DEFAULT_PASSWORD)) {
            client.get("/_cluster/health?wait_for_status=yellow&timeout=30s");
            client.delete("/.opensearch_security_config_versions");
            client.put("/.opensearch_security_config_versions");
            client.post("/_refresh");
            client.get("/_cluster/health/.opensearch_security_config_versions?wait_for_status=yellow&timeout=5s");

            String bulkPayload = ""
                + "{ \"index\": { \"_index\": \".opensearch_security_config_versions\", \"_id\": \"opensearch_security_config_versions\" } }\n"
                + "{ \"versions\": [ {"
                + "  \"version_id\": \"v1\","
                + "  \"timestamp\": \"2025-04-03T00:00:00Z\","
                + "  \"modified_by\": \"admin\","
                + "  \"security_configs\": {"
                + "    \"config_type_1\": {"
                + "      \"lastUpdated\": \"2025-04-03T00:00:00Z\","
                + "      \"configData\": {"
                + "        \"key1\": { \"dummy\": \"value1\" }"
                + "      }"
                + "    }"
                + "  }"
                + "} ] }\n";

            var bulkResponse = client.postJson("/_bulk?refresh=true", bulkPayload);
            assertThat("Failed to insert config versions doc via bulk: " + bulkResponse.getBody(), bulkResponse.getStatusCode(), is(200));
        }
    }

    @Test
    public void testViewAllVersions() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            var response = ok(() -> client.get(viewVersionBase()));
            var json = response.bodyAsJsonNode();

            assertThat(json.has("versions"), is(true));
            var versions = json.get("versions");
            assertThat(versions.isArray(), is(true));
            assertThat(versions.size(), greaterThan(0));
        });
    }

    @Test
    public void testViewSpecificVersionFound() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            var response = ok(() -> client.get(viewVersion("v1")));
            var json = response.bodyAsJsonNode();

            assertThat(json.has("versions"), is(true));
            var versions = json.get("versions");
            assertThat(versions.isArray(), is(true));
            assertThat(versions.size(), is(1));

            var ver = versions.get(0);
            assertThat(ver.get("version_id").asText(), equalTo("v1"));
        });
    }

    @Test
    public void testViewSpecificVersionNotFound() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            var response = notFound(() -> client.get(viewVersion("does-not-exist")));
            var json = response.bodyAsJsonNode();

            assertThat(json.has("status"), is(true));
            assertThat(json.get("status").asText(), equalTo("NOT_FOUND"));

            assertThat(json.has("message"), is(true));
            assertThat(json.get("message").asText(), containsString("not found"));
        });
    }

    @Test
    public void testViewAllVersions_forbiddenWithoutAdminCert() throws Exception {
        withUser("limitedUser", "limitedPass", client -> {
            var response = client.get(viewVersionBase());
            assertThat(response.getStatusCode(), isOneOf(401, 403));
        });
    }
}
