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

public class SystemIndexPermissionEnabledTests extends AbstractSystemIndicesTests {

    @Before
    public void setup() throws Exception {
        setupWithSsl(true, true);
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
    public void testSearchAsAdmin() {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader);
            // no system indices are searchable by admin
            validateForbiddenResponse(response, "", allAccessUser);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        assertFalse(response.getBody().contains(SYSTEM_INDICES.get(0)));
        assertFalse(response.getBody().contains(ACCESSIBLE_ONLY_BY_SUPER_ADMIN));
    }

    @Test
    public void testSearchAsNormalUser() throws Exception {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            // security index is only accessible by super-admin
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", "", normalUserHeader);
            if (index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN) || index.equals(SYSTEM_INDEX_WITH_NO_ASSOCIATED_ROLE_PERMISSIONS)) {
                validateForbiddenResponse(response, "", normalUser);
            } else {
                // got 1 hits because system index permissions are enabled
                validateSearchResponse(response, 1);
            }
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", "", normalUserHeader);
        assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
        validateForbiddenResponse(response, "indices:data/read/search", normalUser);
    }

    @Test
    public void testSearchAsNormalUserWithoutSystemIndexAccess() {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", "", normalUserWithoutSystemIndexHeader);
            validateForbiddenResponse(response, "", normalUserWithoutSystemIndex);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", "", normalUserWithoutSystemIndexHeader);
        assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
        validateForbiddenResponse(response, "indices:data/read/search", normalUserWithoutSystemIndex);
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
            validateForbiddenResponse(response, "", allAccessUser);

            response = restHelper.executeDeleteRequest(index, allAccessUserHeader);
            validateForbiddenResponse(response, "", allAccessUser);
        }
    }

    @Test
    public void testDeleteAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        // allows interacting with the index it has access to: `.system_index_1` with `.system*` pattern and `system:admin/system_index`
        // permission
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executeDeleteRequest(index + "/_doc/document1", normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "", normalUser);

            response = restHelper.executeDeleteRequest(index, normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "", normalUser);
        }
    }

    @Test
    public void testDeleteAsNormalUserWithoutSystemIndexAccess() {
        RestHelper restHelper = sslRestHelper();

        // does not allow interaction with any system index as it doesn't have the permission
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executeDeleteRequest(
                index + "/_doc/document1",
                normalUserWithoutSystemIndexHeader
            );
            validateForbiddenResponse(response, "", normalUserWithoutSystemIndex);

            response = restHelper.executeDeleteRequest(index, normalUserWithoutSystemIndexHeader);
            validateForbiddenResponse(response, "", normalUserWithoutSystemIndex);
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
        testCloseOpenWithUser(allAccessUser, allAccessUserHeader);
    }

    @Test
    public void testCloseOpenAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_close", "", normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "", normalUser);

            // normal user cannot open or close security index
            response = restHelper.executePostRequest(index + "/_open", "", normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "", normalUser);
        }
    }

    @Test
    public void testCloseOpenAsNormalUserWithoutSystemIndexAccess() {
        testCloseOpenWithUser(normalUserWithoutSystemIndex, normalUserWithoutSystemIndexHeader);
    }

    private void testCloseOpenWithUser(String user, Header header) {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_close", "", header);
            validateForbiddenResponse(response, "", user);

            // admin or normal user (without system index permission) cannot open or close any system index
            response = restHelper.executePostRequest(index + "/_open", "", header);
            validateForbiddenResponse(response, "", user);
        }
    }

    /**
     * CREATE
     * should be allowed as any user
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
    public void testUpdateAsAdmin() {
        testUpdateWithUser(allAccessUser, allAccessUserHeader);
    }

    @Test
    public void testUpdateAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePutRequest(index + "/_settings", updateIndexSettings, normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "", normalUser);

            response = restHelper.executePutRequest(index + "/_mapping", newMappings, normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "", normalUser);
        }
    }

    @Test
    public void testUpdateAsNormalUserWithoutSystemIndexAccess() {
        testUpdateWithUser(normalUserWithoutSystemIndex, normalUserWithoutSystemIndexHeader);
    }

    private void testUpdateWithUser(String user, Header header) {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePutRequest(index + "/_settings", updateIndexSettings, header);
            validateForbiddenResponse(response, "", user);

            response = restHelper.executePutRequest(index + "/_mapping", newMappings, header);
            validateForbiddenResponse(response, "", user);
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
            RestHelper.HttpResponse res = restHelper.executeGetRequest("_snapshot/" + index + "/" + index + "_1");
            assertEquals(HttpStatus.SC_UNAUTHORIZED, res.getStatusCode());

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "",
                allAccessUserHeader
            );
            validateForbiddenResponse(res, "", allAccessUser);

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                allAccessUserHeader
            );
            shouldBeAllowedOnlyForAuthorizedIndices(index, res, "", allAccessUser);
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
            RestHelper.HttpResponse res = restHelper.executeGetRequest("_snapshot/" + index + "/" + index + "_1");
            assertEquals(HttpStatus.SC_UNAUTHORIZED, res.getStatusCode());

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "",
                normalUserHeader
            );
            shouldBeAllowedOnlyForAuthorizedIndices(index, res, "", normalUser);

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                normalUserHeader
            );

            String action = index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN) ? "" : "indices:data/write/index, indices:admin/create";
            validateForbiddenResponse(res, action, normalUser);
        }
    }

    @Test
    public void testSnapshotSystemIndicesAsNormalUserWithoutSystemIndexAccess() {
        createSnapshots();

        try (Client tc = getClient()) {
            for (String index : SYSTEM_INDICES) {
                tc.admin().indices().close(new CloseIndexRequest(index)).actionGet();
            }
        }

        RestHelper restHelper = sslRestHelper();
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse res = restHelper.executeGetRequest("_snapshot/" + index + "/" + index + "_1");
            assertEquals(HttpStatus.SC_UNAUTHORIZED, res.getStatusCode());

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "",
                normalUserWithoutSystemIndexHeader
            );
            validateForbiddenResponse(res, "", normalUserWithoutSystemIndex);

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                normalUserWithoutSystemIndexHeader
            );
            String action = index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN) ? "" : "indices:data/write/index, indices:admin/create";
            validateForbiddenResponse(res, action, normalUserWithoutSystemIndex);
        }
    }
}
