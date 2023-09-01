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

import org.apache.hc.core5.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.opensearch.action.admin.indices.close.CloseIndexRequest;
import org.opensearch.client.Client;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Adds test for scenario when system index feature is disabled
 */
public class SystemIndexDisabledTests extends AbstractSystemIndicesTests {

    @Before
    public void setup() throws Exception {
        setupWithSsl(false, false);
        createTestIndicesAndDocs();
    }

    /**
     * SEARCH
     */
    @Test
    public void testSearchAsSuperAdmin() throws Exception {
        RestHelper restHelper = superAdminRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            int expectedHits = index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN) ? 10 : 1;
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery), expectedHits);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchAsAdmin() throws Exception {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            // security index remains accessible only by super-admin
            int expectedHits = index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN) ? 0 : 1;
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader), expectedHits);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        assertTrue(response.getBody().contains(SYSTEM_INDICES.get(0)));
        assertFalse(response.getBody().contains(ACCESSIBLE_ONLY_BY_SUPER_ADMIN));
    }

    @Test
    public void testSearchAsNormalUser() throws Exception {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            // security index is only accessible by super-admin
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", "", normalUserHeader);
            if (index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN)) {
                validateForbiddenResponse(response, "indices:data/read/search", normalUser);
            } else {
                validateSearchResponse(response, 1);
            }
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", "", normalUserHeader);
        assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
        validateForbiddenResponse(response, "indices:data/read/search", normalUser);
    }

    /**
     *  DELETE document + index
     */
    @Test
    public void testDeleteAsSuperAdmin() {
        RestHelper restHelper = superAdminRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseDoc = restHelper.executeDeleteRequest(index + "/_doc/document1");
            assertEquals(RestStatus.OK.getStatus(), responseDoc.getStatusCode());

            RestHelper.HttpResponse responseIndex = restHelper.executeDeleteRequest(index);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());
        }
    }

    @Test
    public void testDeleteAsAdmin() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executeDeleteRequest(index + "/_doc/document1", allAccessUserHeader);
            allowedExceptSecurityIndex(index, response, "", allAccessUser);

            response = restHelper.executeDeleteRequest(index, allAccessUserHeader);
            allowedExceptSecurityIndex(index, response, "", allAccessUser);
        }
    }

    @Test
    public void testDeleteAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executeDeleteRequest(index + "/_doc/document1", normalUserHeader);
            allowedExceptSecurityIndex(index, response, "", normalUser);

            response = restHelper.executeDeleteRequest(index, normalUserHeader);
            allowedExceptSecurityIndex(index, response, "", normalUser);
        }
    }

    /**
     * CLOSE-OPEN
     */
    @Test
    public void testCloseOpenAsSuperAdmin() {
        RestHelper restHelper = superAdminRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse responseClose = restHelper.executePostRequest(index + "/_close", "");
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());

            RestHelper.HttpResponse responseOpen = restHelper.executePostRequest(index + "/_open", "");
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }
    }

    @Test
    public void testCloseOpenAsAdmin() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_close", "", allAccessUserHeader);
            allowedExceptSecurityIndex(index, response, "", allAccessUser);

            // admin can open security index but cannot close it
            response = restHelper.executePostRequest(index + "/_open", "", allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testCloseOpenAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_close", "", normalUserHeader);
            allowedExceptSecurityIndex(index, response, "", normalUser);

            // normal user cannot open or close security index
            response = restHelper.executePostRequest(index + "/_open", "", normalUserHeader);
            allowedExceptSecurityIndex(index, response, "indices:admin/open", normalUser);
        }
    }

    /**
     * CREATE
     */
    @Test
    public void testCreateIndexAsSuperAdmin() {
        RestHelper restHelper = superAdminRestHelper();

        for (String index : INDICES_FOR_CREATE_REQUEST) {
            RestHelper.HttpResponse responseIndex = restHelper.executePutRequest(index, createIndexSettings);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}");
            assertEquals(RestStatus.CREATED.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testCreateIndexAsAdmin() {
        RestHelper restHelper = sslRestHelper();

        for (String index : INDICES_FOR_CREATE_REQUEST) {
            RestHelper.HttpResponse responseIndex = restHelper.executePutRequest(index, createIndexSettings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", allAccessUserHeader);
            assertEquals(RestStatus.CREATED.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testCreateIndexAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        for (String index : INDICES_FOR_CREATE_REQUEST) {
            RestHelper.HttpResponse response = restHelper.executePutRequest(index, createIndexSettings, normalUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

            response = restHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", normalUserHeader);
            assertEquals(RestStatus.CREATED.getStatus(), response.getStatusCode());
        }
    }

    /**
     * UPDATE settings + mappings
     */
    @Test
    public void testUpdateAsSuperAdmin() {
        RestHelper restHelper = superAdminRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePutRequest(index + "/_settings", updateIndexSettings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

            response = restHelper.executePutRequest(index + "/_mapping", newMappings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testUpdateMappingsAsAdmin() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePutRequest(index + "/_mapping", newMappings, allAccessUserHeader);
            allowedExceptSecurityIndex(index, response, "", allAccessUser);

            response = restHelper.executePutRequest(index + "/_settings", updateIndexSettings, allAccessUserHeader);
            allowedExceptSecurityIndex(index, response, "", allAccessUser);
        }
    }

    @Test
    public void testUpdateAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePutRequest(index + "/_mapping", newMappings, normalUserHeader);
            allowedExceptSecurityIndex(index, response, "", normalUser);

            response = restHelper.executePutRequest(index + "/_settings", updateIndexSettings, normalUserHeader);
            allowedExceptSecurityIndex(index, response, "", normalUser);
        }
    }

    /**
     * SNAPSHOT get + restore
     */
    @Test
    public void testSnapshotSystemIndicesAsSuperAdmin() {
        createSnapshots();

        RestHelper restHelper = superAdminRestHelper();
        try (Client tc = getClient()) {
            for (String index : SYSTEM_INDICES) {
                tc.admin().indices().close(new CloseIndexRequest(index)).actionGet();
            }
        }

        for (String index : SYSTEM_INDICES) {
            assertEquals(HttpStatus.SC_OK, restHelper.executeGetRequest("_snapshot/" + index + "/" + index + "_1").getStatusCode());
            assertEquals(
                HttpStatus.SC_OK,
                restHelper.executePostRequest(
                    "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                    "",
                    allAccessUserHeader
                ).getStatusCode()
            );
            assertEquals(
                HttpStatus.SC_OK,
                restHelper.executePostRequest(
                    "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                    "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                    allAccessUserHeader
                ).getStatusCode()
            );
        }
    }

    @Test
    public void testSnapshotSystemIndicesAsAdmin() {
        createSnapshots();

        RestHelper restHelper = sslRestHelper();
        try (Client tc = getClient()) {
            for (String index : SYSTEM_INDICES) {
                tc.admin().indices().close(new CloseIndexRequest(index)).actionGet();
            }
        }

        for (String index : SYSTEM_INDICES) {
            String snapshotRequest = "_snapshot/" + index + "/" + index + "_1";
            RestHelper.HttpResponse res = restHelper.executeGetRequest(snapshotRequest);
            assertEquals(HttpStatus.SC_UNAUTHORIZED, res.getStatusCode());

            res = restHelper.executePostRequest(snapshotRequest + "/_restore?wait_for_completion=true", "", allAccessUserHeader);
            allowedExceptSecurityIndex(index, res, "", allAccessUser);

            res = restHelper.executePostRequest(
                snapshotRequest + "/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                allAccessUserHeader
            );
            allowedExceptSecurityIndex(index, res, "", allAccessUser);
        }
    }

    @Test
    public void testSnapshotSystemIndicesAsNormalUser() {
        createSnapshots();

        try (Client tc = getClient()) {
            for (String index : SYSTEM_INDICES) {
                tc.admin().indices().close(new CloseIndexRequest(index)).actionGet();
            }
        }

        RestHelper restHelper = sslRestHelper();
        for (String index : SYSTEM_INDICES) {
            String snapshotRequest = "_snapshot/" + index + "/" + index + "_1";
            RestHelper.HttpResponse res = restHelper.executeGetRequest(snapshotRequest);
            assertEquals(HttpStatus.SC_UNAUTHORIZED, res.getStatusCode());

            res = restHelper.executePostRequest(snapshotRequest + "/_restore?wait_for_completion=true", "", normalUserHeader);
            allowedExceptSecurityIndex(index, res, "", normalUser);

            res = restHelper.executePostRequest(
                snapshotRequest + "/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                normalUserHeader
            );
            if (index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN)) {
                validateForbiddenResponse(res, "", normalUser);
            } else {
                validateForbiddenResponse(res, "indices:data/write/index, indices:admin/create", normalUser);
            }
        }
    }
}
