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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isOneOf;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED;

public class RollbackVersionApiTest extends AbstractRestApiUnitTest {

    private final String ENDPOINT = getEndpointPrefix() + "/api";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Before
    public void startCluster() throws Exception {
        Settings settings = Settings.builder().put(EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED, true).build();

        super.setup(settings);
        rh.sendAdminCertificate = true;

        String docPayload = """
                {
                  "versions": [
                    {
                      "version_id": "v1",
                      "timestamp": "2025-04-01T00:00:00Z",
                      "modified_by": "admin",
                      "security_configs": {
                        "internalusers": {
                          "lastUpdated": "2025-04-01T00:00:00Z",
                          "configData": {
                            "testuser": {
                              "hash": "$2y$12$dummyHash"
                            }
                          }
                        }
                      }
                    },
                    {
                      "version_id": "v2",
                      "timestamp": "2025-04-05T00:00:00Z",
                      "modified_by": "admin",
                      "security_configs": {
                        "internalusers": {
                          "lastUpdated": "2025-04-05T00:00:00Z",
                          "configData": {
                            "testuser": {
                              "hash": "$2y$12$anotherHash"
                            }
                          }
                        }
                      }
                    }
                  ]
                }
            """;

        HttpResponse response = rh.executePutRequest(
            "/.opensearch_security_config_versions/_doc/opensearch_security_config_versions",
            docPayload
        );

        rh.executePostRequest("/.opensearch_security_config_versions/_refresh", "");

        assertThat("Failed to insert config versions doc", response.getStatusCode(), is(oneOf(200, 201)));
    }

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    @Test
    public void testRollbackToPreviousVersion_success() throws Exception {
        rh.sendAdminCertificate = true;

        HttpResponse response = rh.executePostRequest(ENDPOINT + "/rollback", "");

        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(response.getBody(), containsString("config rolled back to version v1"));
    }

    @Test
    public void testRollbackToSpecificVersion_success() throws Exception {
        rh.sendAdminCertificate = true;

        HttpResponse response = rh.executePostRequest(ENDPOINT + "/rollback/version/v1", "");

        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(response.getBody(), containsString("config rolled back to version v1"));
    }

    @Test
    public void testRollbackToInvalidVersion_shouldFail() throws Exception {
        rh.sendAdminCertificate = true;

        HttpResponse response = rh.executePostRequest(ENDPOINT + "/rollback/version/invalid", "");

        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));
        assertThat(response.getBody(), containsString("Version invalid not found"));
    }

    @Test
    public void testRollbackWithoutEnoughVersions_shouldFail() throws Exception {
        rh.sendAdminCertificate = true;

        // Overwrite with a single version
        String singleVersionDoc = """
                {
                  "versions": [
                    {
                      "version_id": "v1",
                      "timestamp": "2025-04-01T00:00:00Z",
                      "modified_by": "admin",
                      "security_configs": {
                        "internalusers": {
                          "lastUpdated": "2025-04-01T00:00:00Z",
                          "configData": {
                            "testuser": {
                              "hash": "$2y$12$dummyHash"
                            }
                          }
                        }
                      }
                    }
                  ]
                }
            """;

        HttpResponse overwrite = rh.executePutRequest(
            "/.opensearch_security_config_versions/_doc/opensearch_security_config_versions",
            singleVersionDoc
        );

        assertThat("Failed to insert single-version doc", overwrite.getStatusCode(), isOneOf(200, 201));

        HttpResponse rollback = rh.executePostRequest(ENDPOINT + "/rollback", "");
        assertThat(rollback.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));
        assertThat(rollback.getBody(), containsString("No previous version available to rollback"));
    }

    @Test
    public void testRollbackWithoutAdminCert_shouldFail() throws Exception {
        rh.sendAdminCertificate = false;

        HttpResponse response = rh.executePostRequest(ENDPOINT + "/rollback", "");

        assertThat(
            "Expected UNAUTHORIZED or FORBIDDEN when no admin cert is provided",
            response.getStatusCode(),
            isOneOf(HttpStatus.SC_UNAUTHORIZED, HttpStatus.SC_FORBIDDEN)
        );
    }
}
