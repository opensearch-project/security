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
import java.util.Arrays;
import java.util.List;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.opensearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.opensearch.action.admin.indices.close.CloseIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/**
 *  Test for opendistro system indices, to restrict configured indices access to adminDn
 *  Refer:    "plugins.security.system_indices.enabled"
 *            "plugins.security.system_indices.indices";
 */
public class SystemIndicesTests extends SingleClusterTest {

    private static final List<String> listOfIndexesToTest = Arrays.asList("system_index_a", "system_index_b");
    private static final String matchAllQuery = "{\n\"query\": {\"match_all\": {}}}";
    private static final String allAccessUser = "admin_all_access";
    private static final Header allAccessUserHeader = encodeBasicHeader(allAccessUser, allAccessUser);
    private static final String generalErrorMessage = String.format(
        "no permissions for [] and User [name=%s, backend_roles=[], requestedTenant=null]",
        allAccessUser
    );

    private static final String extensionUser = "extensions_user";
    private static final Header extensionUserHeader = encodeBasicHeader(extensionUser, allAccessUser);
    private static final String extensionUserC = "extensions_user_c";
    private static final Header extensionUserCHeader = encodeBasicHeader(extensionUserC, allAccessUser);

    private void setupSystemIndicesDisabledWithSsl() throws Exception {

        Settings systemIndexSettings = Settings.builder()
            .put(ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY, false)
            .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, listOfIndexesToTest)
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .put("path.repo", repositoryPath.getRoot().getAbsolutePath())
            .build();
        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setConfig("config_system_indices.yml")
                .setSecurityRoles("roles_system_indices.yml")
                .setSecurityInternalUsers("internal_users_system_indices.yml")
                .setSecurityRolesMapping("roles_mapping_system_indices.yml"),
            systemIndexSettings,
            true
        );
    }

    private void setupSystemIndicesEnabledWithSsl() throws Exception {

        Settings systemIndexSettings = Settings.builder()
            .put(ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY, true)
            .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, listOfIndexesToTest)
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .put("path.repo", repositoryPath.getRoot().getAbsolutePath())
            .build();
        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setConfig("config_system_indices.yml")
                .setSecurityRoles("roles_system_indices.yml")
                .setSecurityInternalUsers("internal_users_system_indices.yml")
                .setSecurityRolesMapping("roles_mapping_system_indices.yml"),
            systemIndexSettings,
            true
        );
    }

    /**
     * Creates a set of test indices and indexes one document into each index.
     *
     * @throws Exception
     */
    private void createTestIndicesAndDocs() {
        try (Client tc = getClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin().indices().create(new CreateIndexRequest(index)).actionGet();
                tc.index(
                    new IndexRequest(index).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .id("document1")
                        .source("{ \"foo\": \"bar\" }", XContentType.JSON)
                ).actionGet();
            }
        }
    }

    private void createSnapshots() {
        try (Client tc = getClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin()
                    .cluster()
                    .putRepository(
                        new PutRepositoryRequest(index).type("fs")
                            .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/" + index))
                    )
                    .actionGet();
                tc.admin()
                    .cluster()
                    .createSnapshot(
                        new CreateSnapshotRequest(index, index + "_1").indices(index).includeGlobalState(true).waitForCompletion(true)
                    )
                    .actionGet();
            }
        }
    }

    private RestHelper keyStoreRestHelper() {
        RestHelper restHelper = restHelper();
        restHelper.keystore = "kirk-keystore.jks";
        restHelper.enableHTTPClientSSL = true;
        restHelper.trustHTTPServerCertificate = true;
        restHelper.sendAdminCertificate = true;
        return restHelper;
    }

    private RestHelper sslRestHelper() {
        RestHelper restHelper = restHelper();
        restHelper.enableHTTPClientSSL = true;
        return restHelper;
    }

    /***************************************************************************************************************************
     * Search api tests. Search is a special case.
     ***************************************************************************************************************************/

    private void validateSearchResponse(RestHelper.HttpResponse response, int expectecdHits) throws IOException {
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

        XContentParser xcp = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
        assertEquals(RestStatus.OK, searchResponse.status());
        assertEquals(expectecdHits, searchResponse.getHits().getHits().length);
        assertEquals(0, searchResponse.getFailedShards());
        assertEquals(5, searchResponse.getSuccessfulShards());
    }

    @Test
    public void testSearchAsSuperAdmin() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper restHelper = keyStoreRestHelper();

        // search system indices
        for (String index : listOfIndexesToTest) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery), 1);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchAsAdmin() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : listOfIndexesToTest) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader), 1);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchWithSystemIndicesAsSuperAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper restHelper = keyStoreRestHelper();

        // search system indices
        for (String index : listOfIndexesToTest) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery), 1);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchWithSystemIndicesShouldFailAsAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
            assertTrue(response.getBody().contains(""));

        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        XContentParser xcp = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
        assertEquals(RestStatus.OK, searchResponse.status());
        assertEquals(0, searchResponse.getHits().getHits().length);
    }

    @Test
    public void testSearchInOwnSystemIndicesShouldSucceedAsExtensionUser() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper restHelper = sslRestHelper();

        for (String index : listOfIndexesToTest) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery, extensionUserHeader), 0);
        }

    }

    public void testSearchAllWithSystemIndicesShouldFailAsExtensionUser() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper restHelper = sslRestHelper();

        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, extensionUserHeader);
        assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
        assertTrue(response.getBody().contains(""));

        XContentParser xcp = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
        assertEquals(RestStatus.FORBIDDEN, searchResponse.status());
        assertEquals(0, searchResponse.getHits().getHits().length);
    }

    /***************************************************************************************************************************
     * Delete index and Delete doc
     ***************************************************************************************************************************/

    @Test
    public void testDeleteShouldSucceedAsSuperAdmin() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseDoc = keyStoreRestHelper.executeDeleteRequest(index + "/_doc/document1");
            assertEquals(RestStatus.OK.getStatus(), responseDoc.getStatusCode());

            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executeDeleteRequest(index);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());
        }
    }

    @Test
    public void testDeleteDocShouldSucceedAsAdmin() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper sslRestHelper = sslRestHelper();

        // as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseDoc = sslRestHelper.executeDeleteRequest(index + "/_doc/document1", allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseDoc.getStatusCode());

            RestHelper.HttpResponse responseIndex = sslRestHelper.executeDeleteRequest(index, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());
        }
    }

    @Test
    public void testDeleteDocWithSystemIndicesShouldSucceedAsSuperAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseDoc = keyStoreRestHelper.executeDeleteRequest(index + "/_doc/document1");
            assertEquals(RestStatus.OK.getStatus(), responseDoc.getStatusCode());

            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executeDeleteRequest(index);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());
        }
    }

    @Test
    public void testDeleteDocWithSystemIndicesShouldFailsAsAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();

        RestHelper sslRestHelper = sslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseDoc = sslRestHelper.executeDeleteRequest(index + "/_doc/document1", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseDoc.getStatusCode());
            assertTrue(
                responseDoc.getBody()
                    .contains(
                        "{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}]"
                    )
            );

            RestHelper.HttpResponse responseIndex = sslRestHelper.executeDeleteRequest(index, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseIndex.getStatusCode());
            assertTrue(
                responseDoc.getBody()
                    .contains(
                        "{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}]"
                    )
            );
        }
    }

    /***************************************************************************************************************************
     * open and close index
     ***************************************************************************************************************************/

    @Test
    public void testCloseOpen() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        // as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseClose = keyStoreRestHelper.executePostRequest(index + "/_close", "");
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());

            RestHelper.HttpResponse responseOpen = keyStoreRestHelper.executePostRequest(index + "/_open", "");
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }

        // as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseClose = sslRestHelper.executePostRequest(index + "/_close", "", allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());

            RestHelper.HttpResponse responseOpen = sslRestHelper.executePostRequest(index + "/_open", "", allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }
    }

    @Test
    public void testCloseOpenWithSystemIndicesShouldSucceedAsSuperAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseClose = keyStoreRestHelper.executePostRequest(index + "/_close", "");
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());
            assertTrue(responseClose.getBody().contains("{\"closed\":true}"));

            RestHelper.HttpResponse responseOpen = keyStoreRestHelper.executePostRequest(index + "/_open", "");
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }

    }

    @Test
    public void testCloseOpenIndexShouldFailWithSystemIndicesAsAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper sslRestHelper = sslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseClose = sslRestHelper.executePostRequest(index + "/_close", "", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseClose.getStatusCode());
            Assert.assertTrue(
                responseClose.getBody()
                    .contains(
                        "{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}"
                    )
            );

            RestHelper.HttpResponse responseOpen = sslRestHelper.executePostRequest(index + "/_open", "", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseOpen.getStatusCode());
            Assert.assertTrue(
                responseOpen.getBody()
                    .contains(
                        "{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}"
                    )
            );

        }
    }

    @Test
    public void testCloseIndexShouldFailAndOpenIndexShouldSucceedWithSystemIndicesAsExtensionUser() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper sslRestHelper = sslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseClose = sslRestHelper.executePostRequest(index + "/_close", "", extensionUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());

            RestHelper.HttpResponse responseOpen = sslRestHelper.executePostRequest(index + "/_open", "", extensionUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }
    }

    /***************************************************************************************************************************
     * Update Index Settings
     ***************************************************************************************************************************/

    @Test
    public void testUpdateIndexSettingsWithNormalIndicesShouldSucceed() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n" + "    \"index\" : {\n" + "        \"refresh_interval\" : null\n" + "    }\n" + "}";

        // as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_settings", indexSettings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
        // as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_settings", indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testUpdateIndexSettingsWithSystemIndicesShouldFailAsAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n" + "    \"index\" : {\n" + "        \"refresh_interval\" : null\n" + "    }\n" + "}";

        // as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_settings", indexSettings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
        // as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_settings", indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
            Assert.assertTrue(response.getBody().contains(""));

        }
    }

    /***************************************************************************************************************************
     * Index mappings. indices:admin/mapping/put
     ************************************************************************************************************************** */

    @Test
    public void testUpdateMappingsWithNormalIndicesShouldSucceed() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String newMappings = "{\"properties\": {" + "\"user_name\": {" + "\"type\": \"text\"" + "}}}";

        // as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_mapping", newMappings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

        }
        // as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_mapping", newMappings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testUpdateMappingsWithSystemIndicesShouldFailAsAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String newMappings = "{\"properties\": {" + "\"user_name\": {" + "\"type\": \"text\"" + "}}}";

        // as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_mapping", newMappings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

        }
        // as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_mapping", newMappings, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    /***************************************************************************************************************************
     * Create index and Create doc
     ***************************************************************************************************************************/

    @Test
    public void testCreateIndexWithNormalIndicesShouldSucceed() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n"
            + "    \"settings\" : {\n"
            + "        \"index\" : {\n"
            + "            \"number_of_shards\" : 3, \n"
            + "            \"number_of_replicas\" : 2 \n"
            + "        }\n"
            + "    }\n"
            + "}";

        // as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executePutRequest(index, indexSettings);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = keyStoreRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}");
            assertTrue(response.getStatusCode() == RestStatus.CREATED.getStatus());
        }

        for (String index : listOfIndexesToTest) {
            keyStoreRestHelper.executeDeleteRequest(index);
        }

        // as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseIndex = sslRestHelper.executePutRequest(index, indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = sslRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", allAccessUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.CREATED.getStatus());
        }
    }

    @Test
    public void testCreateIndexWithSystemIndicesShouldSucceedAsSuperAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();

        String indexSettings = "{\n"
            + "    \"settings\" : {\n"
            + "        \"index\" : {\n"
            + "            \"number_of_shards\" : 3, \n"
            + "            \"number_of_replicas\" : 2 \n"
            + "        }\n"
            + "    }\n"
            + "}";

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executePutRequest(index, indexSettings);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = keyStoreRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}");
            assertTrue(response.getStatusCode() == RestStatus.CREATED.getStatus());
            Assert.assertTrue(response.getBody().contains("\"result\":\"created\""));

        }

    }

    @Test
    public void testCreateIndexWithSystemIndicesShouldFailAsAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n"
            + "    \"settings\" : {\n"
            + "        \"index\" : {\n"
            + "            \"number_of_shards\" : 3, \n"
            + "            \"number_of_replicas\" : 2 \n"
            + "        }\n"
            + "    }\n"
            + "}";

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseIndex = sslRestHelper.executePutRequest(index, indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseIndex.getStatusCode());
            Assert.assertTrue(
                responseIndex.getBody()
                    .contains(
                        "{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}"
                    )
            );

            RestHelper.HttpResponse response = sslRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
            Assert.assertTrue(
                response.getBody()
                    .contains(
                        "{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}]"
                    )
            );

        }
    }

    @Test
    public void testCreateIndexWithSystemIndicesShouldSucceedWithExtensionRole() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n"
            + "    \"settings\" : {\n"
            + "        \"index\" : {\n"
            + "            \"number_of_shards\" : 3, \n"
            + "            \"number_of_replicas\" : 2 \n"
            + "        }\n"
            + "    }\n"

            + "}";
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseIndex = sslRestHelper.executePutRequest(index, indexSettings, extensionUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = sslRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", extensionUserHeader);
            assertEquals(RestStatus.CREATED.getStatus(), response.getStatusCode());
        }
    }

    /***************************************************************************************************************************
     * snapshot : since snapshot takes more time, we are testing only Enabled case.
     ***************************************************************************************************************************/
    @Test
    public void testSnapshotWithSystemIndices() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        createSnapshots();

        try (Client tc = getClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin().indices().close(new CloseIndexRequest(index)).actionGet();
            }
        }

        RestHelper sslRestHelper = sslRestHelper();
        // as admin
        for (String index : listOfIndexesToTest) {
            assertEquals(
                HttpStatus.SC_OK,
                sslRestHelper.executeGetRequest("_snapshot/" + index + "/" + index + "_1", allAccessUserHeader).getStatusCode()
            );
            assertEquals(
                HttpStatus.SC_FORBIDDEN,
                sslRestHelper.executePostRequest(
                    "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                    "",
                    allAccessUserHeader
                ).getStatusCode()
            );
            assertEquals(
                HttpStatus.SC_OK,
                sslRestHelper.executePostRequest(
                    "_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true",
                    "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                    allAccessUserHeader
                ).getStatusCode()
            );
        }
    }

    @Test
    public void testExtensionIndexAccessShouldSucceedForExtensionUser() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        RestHelper sslRestHelper = sslRestHelper();

        RestHelper.HttpResponse response = sslRestHelper.executePostRequest(
            "system_index_a" + "/_doc",
            "{\"foo\": \"bar\"}",
            extensionUserHeader
        );
        assertEquals(RestStatus.CREATED.getStatus(), response.getStatusCode());

        response = sslRestHelper.executeGetRequest("system_index_a", extensionUserHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"version\":{\"created\""));
    }

    @Test
    public void testExtensionIndexAccessShouldFailAsDifferentExtensionUser() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        RestHelper sslRestHelper = sslRestHelper();

        RestHelper.HttpResponse response = sslRestHelper.executePostRequest(
            "system_index_a" + "/_doc",
            "{\"foo\": \"bar\"}",
            extensionUserCHeader
        );
        assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());

        response = sslRestHelper.executeGetRequest("system_index_a", extensionUserCHeader);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertTrue(
            response.getBody()
                .contains(
                    "{\"error\":{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [indices:admin/get] and User [name=extensions_user_c, backend_roles=[], requestedTenant=null]\"}]"
                )
        );
    }

}
