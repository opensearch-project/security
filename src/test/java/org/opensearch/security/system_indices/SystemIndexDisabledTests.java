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

import org.apache.hc.core5.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.admin.indices.close.CloseIndexRequest;
import org.opensearch.client.Client;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
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
        assertThat(response.getStatusCode(), is(RestStatus.OK.getStatus()));
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
        assertThat(response.getStatusCode(), is(RestStatus.OK.getStatus()));
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
        assertThat(response.getStatusCode(), is(RestStatus.FORBIDDEN.getStatus()));
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
            assertThat(responseDoc.getStatusCode(), is(RestStatus.OK.getStatus()));

            RestHelper.HttpResponse responseIndex = restHelper.executeDeleteRequest(index);
            assertThat(responseIndex.getStatusCode(), is(RestStatus.OK.getStatus()));
        }
    }

    @Test
    public void testDeleteAsAdmin() {
        testDeleteWithUser(allAccessUser, allAccessUserHeader, "indices:admin/delete", "indices:data/write/delete");
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
            assertThat(responseClose.getStatusCode(), is(RestStatus.OK.getStatus()));

            RestHelper.HttpResponse responseOpen = restHelper.executePostRequest(index + "/_open", "");
            assertThat(responseOpen.getStatusCode(), is(RestStatus.OK.getStatus()));
        }
    }

    @Test
    public void testCloseOpenAsAdmin() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_close", "", allAccessUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:admin/close", allAccessUser);

            // User can open the index but cannot close it
            response = restHelper.executePostRequest(index + "/_open", "", allAccessUserHeader);
            assertThat(response.getStatusCode(), is(RestStatus.OK.getStatus()));
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
                assertThat(response.getStatusCode(), is(RestStatus.OK.getStatus()));
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
            assertThat(responseIndex.getStatusCode(), is(RestStatus.OK.getStatus()));

            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}");
            assertThat(response.getStatusCode(), is(RestStatus.CREATED.getStatus()));
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
            assertThat(response.getStatusCode(), is(RestStatus.OK.getStatus()));

            response = restHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", header);
            assertThat(response.getStatusCode(), is(RestStatus.CREATED.getStatus()));
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
            assertThat(response.getStatusCode(), is(RestStatus.OK.getStatus()));

            response = restHelper.executePutRequest(index + "/_mapping", newMappings);
            assertThat(response.getStatusCode(), is(RestStatus.OK.getStatus()));
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
            assertThat(restHelper.executeGetRequest("_snapshot/" + index + "/" + index + "_1").getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(
                restHelper.executePostRequest(
                    "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                    "",
                    allAccessUserHeader
                ).getStatusCode(),
                is(HttpStatus.SC_OK)
            );
            assertThat(
                restHelper.executePostRequest(
                    "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                    "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                    allAccessUserHeader
                ).getStatusCode(),
                is(HttpStatus.SC_OK)
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
            assertThat(res.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

            res = restHelper.executePostRequest(snapshotRequest + "/_restore?wait_for_completion=true", "", allAccessUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, res, "cluster:admin/snapshot/restore", allAccessUser);

            res = restHelper.executePostRequest(
                snapshotRequest + "/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                allAccessUserHeader
            );
            shouldBeAllowedOnlyForAuthorizedIndices(index, res, "cluster:admin/snapshot/restore", allAccessUser);
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
            assertThat(res.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

            String action = index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN)
                ? "cluster:admin/snapshot/restore"
                : "indices:data/write/index, indices:admin/create";

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
