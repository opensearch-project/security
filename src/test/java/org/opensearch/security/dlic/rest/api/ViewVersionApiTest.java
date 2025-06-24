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

package org.opensearch.security.dlic.rest.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isOneOf;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED;

public class ViewVersionApiTest extends AbstractRestApiUnitTest {

    private final String ENDPOINT = PLUGINS_PREFIX + "/api";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Before
    public void setupIndexAndCerts() throws Exception {
        Settings settings = Settings.builder().put(EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED, true).build();

        super.setup(settings);
        rh.sendAdminCertificate = true;

        String docPayload = """
                {
                "versions": [
                    {
                    "version_id": "v1",
                    "timestamp": "2025-04-03T00:00:00Z",
                    "modified_by": "admin",
                    "security_configs": {
                        "config_type_1": {
                        "lastUpdated": "2025-04-03T00:00:00Z",
                        "configData": {
                            "key1": {
                                "dummy": "value1"
                            }
                        }
                        }
                    }
                    }
                ]
                }
            """;

        HttpResponse createDoc = rh.executePutRequest(
            "/.opensearch_security_config_versions/_doc/opensearch_security_config_versions",
            docPayload
        );
        rh.executePostRequest("/.opensearch_security_config_versions/_refresh", "");

        assertThat("Failed to insert config versions doc", createDoc.getStatusCode(), is(oneOf(200, 201)));

    }

    @Test
    public void testGetAllVersions_returnsOkAndHasVersionsArray() throws Exception {
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/versions");

        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        JsonNode body = OBJECT_MAPPER.readTree(response.getBody());
        assertThat(body.has("versions"), is(true));

        JsonNode versions = body.get("versions");
        assertThat(versions.isArray(), is(true));
        assertThat("Should have at least 1 version", versions.size(), greaterThan(0));

        JsonNode version = versions.get(0);
        assertThat(version.has("version_id"), is(true));
        assertThat(version.has("timestamp"), is(true));
        assertThat(version.has("modified_by"), is(true));
        assertThat(version.has("security_configs"), is(true));
    }

    @Test
    public void testGetSpecificVersion_returnsCorrectVersion() throws Exception {
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/version/v1");

        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        JsonNode body = OBJECT_MAPPER.readTree(response.getBody());
        assertThat(body.has("versions"), is(true));
        JsonNode versions = body.get("versions");
        assertThat(versions.isArray(), is(true));
        assertThat(versions.size(), is(1));

        JsonNode version = versions.get(0);
        assertThat(version.get("version_id").asText(), equalTo("v1"));
    }

    @Test
    public void testGetSpecificVersionNotFound_returns404() throws Exception {
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/version/does-not-exist");

        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        JsonNode body = OBJECT_MAPPER.readTree(response.getBody());
        assertThat(body.has("status"), is(true));
        assertThat(body.get("status").asText(), equalTo("NOT_FOUND"));

        assertThat(body.has("message"), is(true));
        assertThat(body.get("message").asText(), containsString("not found"));
    }

    @Test
    public void testGetAllVersions_forbiddenWithoutAdminCert() throws Exception {
        rh.sendAdminCertificate = false;

        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/versions");

        assertThat(response.getStatusCode(), isOneOf(HttpStatus.SC_UNAUTHORIZED, HttpStatus.SC_FORBIDDEN));
    }
}
