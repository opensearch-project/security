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

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isOneOf;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED;

public class RollbackVersionApiIntegrationTest extends AbstractApiIntegrationTest {

    private static final String ENDPOINT_PREFIX = PLUGINS_PREFIX + "/api";
    private static final String ROLLBACK_BASE = ENDPOINT_PREFIX + "/version/rollback";
    private static final TestSecurityConfig.User USER = new TestSecurityConfig.User("user");

    private String RollbackVersion(String versionId) {
        return ROLLBACK_BASE + "/" + versionId;
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
            client.createUser(USER.getName(), USER).assertStatusCode(201);
        }
    }

    @Test
    public void testRollbackToPreviousVersion_success() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            var response = client.post(ROLLBACK_BASE);
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
            var response = client.post(ROLLBACK_BASE);
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
            // To perform below test, delete all entries in .opensearch_security_config_versions index
            String deleteQuery = """
                    {
                        "query": {
                            "match_all": {}
                        }
                    }
                """;
            client.postJson("/.opensearch_security_config_versions/_delete_by_query", deleteQuery);

            // Insert 1 record in .opensearch_security_config_versions index
            String bulkPayload =
                """
                       {"index":{"_index":".opensearch_security_config_versions","_id":"opensearch_security_config_versions"}}
                       {"versions":[{"version_id":"v1","timestamp":"2025-04-03T00:00:00Z","modified_by":"admin","security_configs":{"config_type_1":{"lastUpdated":"2025-04-03T00:00:00Z","configData":{"key1":{"dummy":"value1"}}}}}]}
                    """;

            var bulkResponse = client.postJson("/_bulk?refresh=true", bulkPayload);
            assertThat("Bulk insert failed: " + bulkResponse.getBody(), bulkResponse.getStatusCode(), is(200));

            var response = client.post(ROLLBACK_BASE);
            assertThat(response.getStatusCode(), is(404));
            assertThat(response.getBody(), containsString("No previous version available to rollback"));
        });
    }

}
