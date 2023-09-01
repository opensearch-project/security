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

package org.opensearch.security.system_indices;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.junit.Assert.assertEquals;

public class SystemIndexPermissionDisabledTests extends SystemIndicesTests {

    @Before
    public void setup() throws Exception {
        setupWithSsl(true, false);
        createTestIndicesAndDocs();
    }

    @Test
    public void testSearchAsSuperAdmin() throws Exception {
        RestHelper restHelper = superAdminRestHelper();

        // search system indices
        for (String idx : SYSTEM_INDICES) {
            validateSearchResponse(restHelper.executePostRequest(idx + "/_search", matchAllQuery), 10);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchAsAdmin() {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
            MatcherAssert.assertThat(response.getBody(), Matchers.containsStringIgnoringCase("\"failed\":0"));
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchAsNormalUser() throws Exception {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery, normalUserHeader), 0);
        }

    }

    @Test
    public void testDeleteAsSuperAdmin() {
        RestHelper keyStoreRestHelper = superAdminRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseDoc = keyStoreRestHelper.executeDeleteRequest(index + "/_doc/document1");
            assertEquals(RestStatus.OK.getStatus(), responseDoc.getStatusCode());

            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executeDeleteRequest(index);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());
        }
    }

    @Test
    public void testDeleteAsAdmin() {
        RestHelper sslRestHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseDoc = sslRestHelper.executeDeleteRequest(index + "/_doc/document1", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseDoc.getStatusCode());
            MatcherAssert.assertThat(
                responseDoc.getBody(),
                Matchers.containsStringIgnoringCase(
                    "{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}]"
                )
            );

            RestHelper.HttpResponse responseIndex = sslRestHelper.executeDeleteRequest(index, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseIndex.getStatusCode());
            MatcherAssert.assertThat(
                responseDoc.getBody(),
                Matchers.containsStringIgnoringCase(
                    "{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}]"
                )
            );
        }
    }

    @Test
    public void testCloseOpenAsSuperAdmin() {
        RestHelper keyStoreRestHelper = superAdminRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseClose = keyStoreRestHelper.executePostRequest(index + "/_close", "");
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());
            MatcherAssert.assertThat(responseClose.getBody(), Matchers.containsStringIgnoringCase("{\"closed\":true}"));

            RestHelper.HttpResponse responseOpen = keyStoreRestHelper.executePostRequest(index + "/_open", "");
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }

    }

    @Test
    public void testCloseOpenAsAdmin() {
        RestHelper sslRestHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseClose = sslRestHelper.executePostRequest(index + "/_close", "", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseClose.getStatusCode());
            MatcherAssert.assertThat(
                responseClose.getBody(),
                Matchers.containsStringIgnoringCase(
                    "{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}"
                )
            );

            RestHelper.HttpResponse responseOpen = sslRestHelper.executePostRequest(index + "/_open", "", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseOpen.getStatusCode());
            MatcherAssert.assertThat(
                responseOpen.getBody(),
                Matchers.containsStringIgnoringCase(
                    "{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}"
                )
            );
        }
    }

    @Test
    public void testCloseOpenAsNormalUser() {
        RestHelper sslRestHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseClose = sslRestHelper.executePostRequest(index + "/_close", "", normalUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());

            RestHelper.HttpResponse responseOpen = sslRestHelper.executePostRequest(index + "/_open", "", normalUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }
    }

    @Test
    public void testUpdateAsSuperAdmin() {
        RestHelper keyStoreRestHelper = superAdminRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n" + "    \"index\" : {\n" + "        \"refresh_interval\" : null\n" + "    }\n" + "}";

        // as super-admin
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_settings", indexSettings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
        // as admin
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_settings", indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testUpdateMappingsAsSuperAdmin() {
        RestHelper keyStoreRestHelper = superAdminRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String newMappings = "{\"properties\": {" + "\"user_name\": {" + "\"type\": \"text\"" + "}}}";

        // as super-admin
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_mapping", newMappings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

        }
        // as admin
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_mapping", newMappings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testUpdateMappingsAsAdmin() {
        RestHelper keyStoreRestHelper = superAdminRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String newMappings = "{\"properties\": {" + "\"user_name\": {" + "\"type\": \"text\"" + "}}}";

        // as super-admin
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_mapping", newMappings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

        }
        // as admin
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_mapping", newMappings, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
            MatcherAssert.assertThat(response.getBody(), Matchers.containsStringIgnoringCase(generalErrorMessage));
        }
    }

    @Test
    public void testCreateIndexAsSuperAdmin() {
        RestHelper keyStoreRestHelper = superAdminRestHelper();

        String indexSettings = "{\n"
            + "    \"settings\" : {\n"
            + "        \"index\" : {\n"
            + "            \"number_of_shards\" : 3, \n"
            + "            \"number_of_replicas\" : 2 \n"
            + "        }\n"
            + "    }\n"
            + "}";

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executePutRequest(index, indexSettings);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = keyStoreRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}");
            assertEquals(RestStatus.CREATED.getStatus(), response.getStatusCode());
            MatcherAssert.assertThat(response.getBody(), Matchers.containsStringIgnoringCase("\"result\":\"created\""));

        }

    }

    @Test
    public void testCreateIndexAsAdmin() {
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n"
            + "    \"settings\" : {\n"
            + "        \"index\" : {\n"
            + "            \"number_of_shards\" : 3, \n"
            + "            \"number_of_replicas\" : 2 \n"
            + "        }\n"
            + "    }\n"
            + "}";

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseIndex = sslRestHelper.executePutRequest(index, indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseIndex.getStatusCode());
            MatcherAssert.assertThat(
                responseIndex.getBody(),
                Matchers.containsStringIgnoringCase(
                    "{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}"
                )
            );

            RestHelper.HttpResponse response = sslRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
            MatcherAssert.assertThat(
                responseIndex.getBody(),
                Matchers.containsStringIgnoringCase(
                    "{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}]"
                )
            );

        }
    }

    @Test
    public void testCreateIndexAsNormalUser() {
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n"
            + "    \"settings\" : {\n"
            + "        \"index\" : {\n"
            + "            \"number_of_shards\" : 3, \n"
            + "            \"number_of_replicas\" : 2 \n"
            + "        }\n"
            + "    }\n"

            + "}";
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseIndex = sslRestHelper.executePutRequest(index, indexSettings, normalUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = sslRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", normalUserHeader);
            assertEquals(RestStatus.CREATED.getStatus(), response.getStatusCode());
        }
    }
}
