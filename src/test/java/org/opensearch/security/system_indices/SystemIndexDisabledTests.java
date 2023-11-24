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

import java.io.IOException;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
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
        testSearchWithUser(normalUser, normalUserHeader);
    }

    @Test
    public void testSearchAsNormalUserWithoutSystemIndexAccess() throws Exception {
        testSearchWithUser(normalUserWithoutSystemIndex, normalUserWithoutSystemIndexHeader);
    }

    private void testSearchWithUser(String user, Header header) throws IOException {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            // security index is only accessible by super-admin
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", "", header);
            if (index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN) || index.startsWith(SYSTEM_INDEX_WITH_NO_ASSOCIATED_ROLE_PERMISSIONS)) {
                validateForbiddenResponse(response, "indices:data/read/search", user);
            } else {
                validateSearchResponse(response, 1);
            }
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", "", header);
        assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
        validateForbiddenResponse(response, "indices:data/read/search", user);
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
        testDeleteWithUser(allAccessUser, allAccessUserHeader, "", "");
    }

    @Test
    public void testDeleteAsNormalUser() {
        testDeleteWithUser(normalUser, normalUserHeader, "indices:admin/delete", "indices:data/write/delete");
    }

    @Test
    public void testDeleteAsNormalUserWithoutSystemIndexAccess() {
        testDeleteWithUser(
            normalUserWithoutSystemIndex,
            normalUserWithoutSystemIndexHeader,
            "indices:admin/delete",
            "indices:data/write/delete"
        );
    }

    private void testDeleteWithUser(String user, Header header, String indexAction, String documentAction) {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executeDeleteRequest(index + "/_doc/document1", header);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, documentAction, user);

            response = restHelper.executeDeleteRequest(index, header);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, indexAction, user);
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
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "", allAccessUser);

            // User can open the index but cannot close it
            response = restHelper.executePostRequest(index + "/_open", "", allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testCloseOpenAsNormalUser() {
        testCloseOpenWithUser(normalUser, normalUserHeader);
    }

    @Test
    public void testCloseOpenAsNormalUserWithoutSystemIndexAccess() {
        testCloseOpenWithUser(normalUserWithoutSystemIndex, normalUserWithoutSystemIndexHeader);
    }

    private void testCloseOpenWithUser(String user, Header header) {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_close", "", header);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:admin/close", user);

            // User can open the index but cannot close it
            response = restHelper.executePostRequest(index + "/_open", "", header);
            if (index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN) || index.equals(SYSTEM_INDEX_WITH_NO_ASSOCIATED_ROLE_PERMISSIONS)) {
                validateForbiddenResponse(response, "indices:admin/open", user);
            } else {
                assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
            }
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
        testCreateIndexWithUser(allAccessUserHeader);
    }

    @Test
    public void testCreateIndexAsNormalUser() {
        testCreateIndexWithUser(normalUserHeader);
    }

    @Test
    public void testCreateIndexAsNormalUserWithoutSystemIndexAccess() {
        testCreateIndexWithUser(normalUserWithoutSystemIndexHeader);
    }

    private void testCreateIndexWithUser(Header header) {
        RestHelper restHelper = sslRestHelper();

        for (String index : INDICES_FOR_CREATE_REQUEST) {
            RestHelper.HttpResponse response = restHelper.executePutRequest(index, createIndexSettings, header);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

            response = restHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", header);
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
        testUpdateWithUser(allAccessUser, allAccessUserHeader);
    }

    @Test
    public void testUpdateAsNormalUser() {
        testUpdateWithUser(normalUser, normalUserHeader);
    }

    @Test
    public void testUpdateAsNormalUserWithoutSystemIndexAccess() {
        testUpdateWithUser(normalUserWithoutSystemIndex, normalUserWithoutSystemIndexHeader);
    }

    private void testUpdateWithUser(String user, Header header) {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePutRequest(index + "/_mapping", newMappings, header);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:admin/mapping/put", user);

            response = restHelper.executePutRequest(index + "/_settings", updateIndexSettings, header);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:admin/settings/update", user);
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
            shouldBeAllowedOnlyForAuthorizedIndices(index, res, "", allAccessUser);

            res = restHelper.executePostRequest(
                snapshotRequest + "/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                allAccessUserHeader
            );
            shouldBeAllowedOnlyForAuthorizedIndices(index, res, "", allAccessUser);
        }
    }

    @Test
    public void testSnapshotSystemIndicesAsNormalUser() {
        testSnapshotWithUser(normalUser, normalUserHeader);
    }

    @Test
    public void testSnapshotSystemIndicesAsNormalUserWithoutSystemIndexAccess() {
        testSnapshotWithUser(normalUserWithoutSystemIndex, normalUserWithoutSystemIndexHeader);
    }

    private void testSnapshotWithUser(String user, Header header) {
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

            String action = index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN) ? "" : "indices:data/write/index, indices:admin/create";

            res = restHelper.executePostRequest(snapshotRequest + "/_restore?wait_for_completion=true", "", header);
            shouldBeAllowedOnlyForAuthorizedIndices(index, res, action, user);

            res = restHelper.executePostRequest(
                snapshotRequest + "/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                header
            );
            validateForbiddenResponse(res, action, user);
        }
    }
}
