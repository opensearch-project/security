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

import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isOneOf;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED;

public class RollbackVersionApiIntegrationTest extends AbstractApiIntegrationTest {

    private String endpointPrefix() {
        return PLUGINS_PREFIX + "/api";
    }

    private String RollbackBase() {
        return endpointPrefix() + "/rollback";
    }

    private String RollbackVersion(String versionId) {
        return RollbackBase() + "/version/" + versionId;
    }

    @Override
    protected Map<String, Object> getClusterSettings() {
        Map<String, Object> settings = super.getClusterSettings();
        settings.put(EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED, true);
        return settings;
    }

    @Before
    public void setupConfigVersionsIndex() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER_NAME, DEFAULT_PASSWORD)) {
            client.get("/_cluster/health?wait_for_status=yellow&timeout=30s");
            client.delete("/.opensearch_security_config_versions");
            client.put("/.opensearch_security_config_versions");
            client.post("/_refresh");
            client.get("/_cluster/health/.opensearch_security_config_versions?wait_for_status=yellow&timeout=5s");

            String bulkPayload =
                "{ \"index\": { \"_index\": \".opensearch_security_config_versions\", \"_id\": \"opensearch_security_config_versions\" } }\n"
                    + "{ \"versions\": ["
                    + "  {"
                    + "    \"version_id\": \"v1\","
                    + "    \"timestamp\": \"2025-04-03T00:00:00Z\","
                    + "    \"modified_by\": \"admin\","
                    + "    \"security_configs\": {"
                    + "      \"internalusers\": {"
                    + "        \"lastUpdated\": \"2025-04-03T00:00:00Z\","
                    + "        \"configData\": { \"admin\": { \"hash\": \"$2y$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" } }"
                    + "      }"
                    + "    }"
                    + "  },"
                    + "  {"
                    + "    \"version_id\": \"v2\","
                    + "    \"timestamp\": \"2025-04-04T00:00:00Z\","
                    + "    \"modified_by\": \"admin\","
                    + "    \"security_configs\": {"
                    + "      \"internalusers\": {"
                    + "        \"lastUpdated\": \"2025-04-04T00:00:00Z\","
                    + "        \"configData\": { \"admin\": { \"hash\": \"$2y$12$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\" } }"
                    + "      }"
                    + "    }"
                    + "  }"
                    + "] }\n";

            var response = client.postJson("/_bulk?refresh=true", bulkPayload);
            assertThat("Bulk insert failed", response.getStatusCode(), is(200));
        }
    }

    @Test
    public void testRollbackToPreviousVersion_success() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            var response = client.post(RollbackBase());
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getTextFromJsonBody("/status"), equalTo("OK"));
            assertThat(response.getTextFromJsonBody("/message"), containsString("config rolled back to version"));
        });
    }

    @Test
    public void testRollbackToSpecificVersion_success() throws Exception {
        String versionId = "v1";
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            var response = client.post(RollbackVersion(versionId));
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getTextFromJsonBody("/status"), equalTo("OK"));
            assertThat(response.getTextFromJsonBody("/message"), containsString("config rolled back to version " + versionId));
        });
    }

    @Test
    public void testRollbackWithNonAdmin_shouldBeUnauthorized() throws Exception {
        withUser(NEW_USER, DEFAULT_PASSWORD, client -> {
            var response = client.post(RollbackBase());
            assertThat(response.getStatusCode(), isOneOf(HttpStatus.SC_FORBIDDEN, HttpStatus.SC_UNAUTHORIZED));
        });
    }

    @Test
    public void testRollbackToInvalidVersion_shouldReturnNotFound() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            var response = client.post(RollbackVersion("does-not-exist"));
            assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));
            assertThat(response.getTextFromJsonBody("/message"), containsString("not found"));
        });
    }

    @Test
    public void testRollbackWhenOnlyOneVersion_shouldFail() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            client.delete("/.opensearch_security_config_versions");
            client.put("/.opensearch_security_config_versions");
            client.post("/_refresh");
            client.get("/_cluster/health/.opensearch_security_config_versions?wait_for_status=yellow&timeout=30s");

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
            assertThat("Bulk insert failed: " + bulkResponse.getBody(), bulkResponse.getStatusCode(), is(200));

            client.post("/_refresh");

            var response = client.post(RollbackBase());
            assertThat(response.getStatusCode(), is(404));
            assertThat(response.getBody(), containsString("No previous version available to rollback"));
        });
    }

}
