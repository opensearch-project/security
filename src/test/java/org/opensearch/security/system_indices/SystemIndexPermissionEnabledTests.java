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
        assertThat(response.getStatusCode(), is(RestStatus.OK.getStatus()));
    }

    @Test
    public void testSearchAsAdmin() {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader);
            // no system indices are searchable by admin
            validateForbiddenResponse(response, "indices:data/read/search", allAccessUser);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertThat(response.getStatusCode(), is(RestStatus.OK.getStatus()));
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
                validateForbiddenResponse(response, "indices:data/read/search", normalUser);
            } else {
                // got 1 hits because system index permissions are enabled
                validateSearchResponse(response, 1);
            }
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", "", normalUserHeader);
        assertThat(response.getStatusCode(), is(RestStatus.FORBIDDEN.getStatus()));
        validateForbiddenResponse(response, "indices:data/read/search", normalUser);
    }

    @Test
    public void testSearchAsNormalUserWithoutSystemIndexAccess() {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", "", normalUserWithoutSystemIndexHeader);
            validateForbiddenResponse(response, "indices:data/read/search", normalUserWithoutSystemIndex);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", "", normalUserWithoutSystemIndexHeader);
        assertThat(response.getStatusCode(), is(RestStatus.FORBIDDEN.getStatus()));
        validateForbiddenResponse(response, "indices:data/read/search", normalUserWithoutSystemIndex);
    }

    @Test
    public void testNormalIndexShouldAlwaysBeSearchable() throws Exception {
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : NO_SYSTEM_INDICES) {
            RestHelper.HttpResponse responseWithoutSystemIndexPermission = restHelper.executeGetRequest(
                index + "/_search",
                "",
                normalUserWithoutSystemIndexHeader
            );
            validateSearchResponse(responseWithoutSystemIndexPermission, 1);

            RestHelper.HttpResponse responseWithSystemIndexPermission = restHelper.executeGetRequest(
                index + "/_search",
                "",
                normalUserHeader
            );
            validateSearchResponse(responseWithSystemIndexPermission, 1);
        }
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
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executeDeleteRequest(index + "/_doc/document1", allAccessUserHeader);
            validateForbiddenResponse(response, "indices:data/write/delete", allAccessUser);

            response = restHelper.executeDeleteRequest(index, allAccessUserHeader);
            validateForbiddenResponse(response, "indices:admin/delete", allAccessUser);
        }
    }

    @Test
    public void testDeleteAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        // allows interacting with the index it has access to: `.system_index_1` with `.system*` pattern and `system:admin/system_index`
        // permission
        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executeDeleteRequest(index + "/_doc/document1", normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:data/write/delete", normalUser);

            response = restHelper.executeDeleteRequest(index, normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:admin/delete", normalUser);
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
            validateForbiddenResponse(response, "indices:data/write/delete", normalUserWithoutSystemIndex);

            response = restHelper.executeDeleteRequest(index, normalUserWithoutSystemIndexHeader);
            validateForbiddenResponse(response, "indices:admin/delete", normalUserWithoutSystemIndex);
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
        testCloseOpenWithUser(allAccessUser, allAccessUserHeader);
    }

    @Test
    public void testCloseOpenAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_close", "", normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:admin/close", normalUser);

            // normal user cannot open or close security index
            response = restHelper.executePostRequest(index + "/_open", "", normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:admin/open", normalUser);
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
            validateForbiddenResponse(response, "indices:admin/close", user);

            // admin or normal user (without system index permission) cannot open or close any system index
            response = restHelper.executePostRequest(index + "/_open", "", header);
            validateForbiddenResponse(response, "indices:admin/open", user);
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
    public void testUpdateAsAdmin() {
        testUpdateWithUser(allAccessUser, allAccessUserHeader);
    }

    @Test
    public void testUpdateAsNormalUser() {
        RestHelper restHelper = sslRestHelper();

        for (String index : SYSTEM_INDICES) {
            RestHelper.HttpResponse response = restHelper.executePutRequest(index + "/_settings", updateIndexSettings, normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:admin/settings/update", normalUser);

            response = restHelper.executePutRequest(index + "/_mapping", newMappings, normalUserHeader);
            shouldBeAllowedOnlyForAuthorizedIndices(index, response, "indices:admin/mapping/put", normalUser);
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
            validateForbiddenResponse(response, "indices:admin/settings/update", user);

            response = restHelper.executePutRequest(index + "/_mapping", newMappings, header);
            validateForbiddenResponse(response, "indices:admin/mapping/put", user);
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
            RestHelper.HttpResponse res = restHelper.executeGetRequest("_snapshot/" + index + "/" + index + "_1");
            assertThat(res.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "",
                allAccessUserHeader
            );
            validateForbiddenResponse(res, "cluster:admin/snapshot/restore", allAccessUser);

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                allAccessUserHeader
            );
            shouldBeAllowedOnlyForAuthorizedIndices(index, res, "cluster:admin/snapshot/restore", allAccessUser);
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
            assertThat(res.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "",
                normalUserHeader
            );
            shouldBeAllowedOnlyForAuthorizedIndices(index, res, "cluster:admin/snapshot/restore", normalUser);

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                normalUserHeader
            );

            String action = index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN)
                ? "cluster:admin/snapshot/restore"
                : "indices:data/write/index, indices:admin/create";
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
            assertThat(res.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "",
                normalUserWithoutSystemIndexHeader
            );
            validateForbiddenResponse(res, "cluster:admin/snapshot/restore", normalUserWithoutSystemIndex);

            res = restHelper.executePostRequest(
                "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                normalUserWithoutSystemIndexHeader
            );
            String action = index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN)
                ? "cluster:admin/snapshot/restore"
                : "indices:data/write/index, indices:admin/create";
            validateForbiddenResponse(res, action, normalUserWithoutSystemIndex);
        }
    }
}
