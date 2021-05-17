/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.system_indices;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.opensearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.opensearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.opensearch.action.admin.indices.close.CloseIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.RestStatus;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/**
 *  Test for opendistro system indices, to restrict configured indices access to adminDn
 *  Refer:    "opendistro_security.system_indices.enabled"
 *            "opendistro_security.system_indices.indices";
 */
public class SystemIndicesTests extends SingleClusterTest {

    private static final List<String> listOfIndexesToTest = Arrays.asList("config1", "config2");
    private static final String matchAllQuery = "{\n\"query\": {\"match_all\": {}}}";
    private static final String allAccessUser = "admin_all_access";
    private static final Header allAccessUserHeader = encodeBasicHeader(allAccessUser, allAccessUser);
    private static final String generalErrorMessage = String.format("no permissions for [] and User [name=%s, backend_roles=[], requestedTenant=null]", allAccessUser);

    private void setupSystemIndicesDisabledWithSsl() throws Exception {

        Settings systemIndexSettings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_ENABLED_KEY, false)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_KEY, listOfIndexesToTest)
                .put("opendistro_security.ssl.http.enabled",true)
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .build();
        setup(Settings.EMPTY,
                new DynamicSecurityConfig()
                        .setConfig("config_system_indices.yml")
                        .setSecurityRoles("roles_system_indices.yml")
                        .setSecurityInternalUsers("internal_users_system_indices.yml")
                        .setSecurityRolesMapping("roles_mapping_system_indices.yml"),
                systemIndexSettings,
                true);
    }

    private void setupSystemIndicesEnabledWithSsl() throws Exception {

        Settings systemIndexSettings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_ENABLED_KEY, true)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_KEY, listOfIndexesToTest)
                .put("opendistro_security.ssl.http.enabled",true)
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .build();
        setup(Settings.EMPTY,
                new DynamicSecurityConfig()
                        .setConfig("config_system_indices.yml")
                        .setSecurityRoles("roles_system_indices.yml")
                        .setSecurityInternalUsers("internal_users_system_indices.yml")
                        .setSecurityRolesMapping("roles_mapping_system_indices.yml"),
                systemIndexSettings,
                true);
    }

    /**
     * Creates a set of test indices and indexes one document into each index.
     *
     * @throws Exception
     */
    private void createTestIndicesAndDocs() {
        try (TransportClient tc = getInternalTransportClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin().indices().create(new CreateIndexRequest(index)).actionGet();
                tc.index(new IndexRequest(index).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).id("document1").source("{ \"foo\": \"bar\" }", XContentType.JSON)).actionGet();
            }
        }
    }

    private void createSnapshots() {
        try (TransportClient tc = getInternalTransportClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin().cluster().putRepository(new PutRepositoryRequest(index).type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/" + index))).actionGet();
                tc.admin().cluster().createSnapshot(new CreateSnapshotRequest(index, index + "_1").indices(index).includeGlobalState(true).waitForCompletion(true)).actionGet();
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

        XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
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

        //search system indices
        for (String index : listOfIndexesToTest) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery), 1);
        }

        //search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchAsAdmin() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper restHelper = sslRestHelper();

        //search system indices
        for (String index : listOfIndexesToTest) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader), 1);
        }

        //search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchWithSystemIndicesAsSuperAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper restHelper = keyStoreRestHelper();

        //search system indices
        for (String index : listOfIndexesToTest) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery), 1);
        }

        //search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }


    @Test
    public void testSearchWithSystemIndicesAsAdmin() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper restHelper = sslRestHelper();

        for (String index : listOfIndexesToTest) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader), 0);
        }

        //search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
        assertEquals(RestStatus.OK, searchResponse.status());
        assertEquals(0, searchResponse.getHits().getHits().length);
    }

    /***************************************************************************************************************************
     * Delete index and Delete doc
     ***************************************************************************************************************************/

    @Test
    public void testDelete() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseDoc = keyStoreRestHelper.executeDeleteRequest(index + "/_doc/document1");
            assertEquals(RestStatus.OK.getStatus(), responseDoc.getStatusCode());

            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executeDeleteRequest(index);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());
        }
        createTestIndicesAndDocs();

        //as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseDoc = sslRestHelper.executeDeleteRequest(index + "/_doc/document1", allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseDoc.getStatusCode());

            RestHelper.HttpResponse responseIndex = sslRestHelper.executeDeleteRequest(index, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());
        }
    }

    @Test
    public void testDeleteWithSystemIndices() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseDoc = keyStoreRestHelper.executeDeleteRequest(index + "/_doc/document1");
            assertEquals(RestStatus.OK.getStatus(), responseDoc.getStatusCode());

            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executeDeleteRequest(index);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());
        }
        createTestIndicesAndDocs();

        //as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseDoc = sslRestHelper.executeDeleteRequest(index + "/_doc/document1", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseDoc.getStatusCode());

            RestHelper.HttpResponse responseIndex = sslRestHelper.executeDeleteRequest(index, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseIndex.getStatusCode());
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

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseClose = keyStoreRestHelper.executePostRequest(index + "/_close","");
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());

            RestHelper.HttpResponse responseOpen = keyStoreRestHelper.executePostRequest(index + "/_open", "");
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }

        //as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseClose = sslRestHelper.executePostRequest(index + "/_close","", allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());

            RestHelper.HttpResponse responseOpen = sslRestHelper.executePostRequest(index + "/_open", "", allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }
    }

    @Test
    public void testCloseOpenWithSystemIndices() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseClose = keyStoreRestHelper.executePostRequest(index + "/_close","");
            assertEquals(RestStatus.OK.getStatus(), responseClose.getStatusCode());

            RestHelper.HttpResponse responseOpen = keyStoreRestHelper.executePostRequest(index + "/_open", "");
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }

        //as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseClose = sslRestHelper.executePostRequest(index + "/_close","", allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), responseClose.getStatusCode());

            RestHelper.HttpResponse responseOpen = sslRestHelper.executePostRequest(index + "/_open", "", allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseOpen.getStatusCode());
        }
    }

    /***************************************************************************************************************************
     * Update Index Settings
     ***************************************************************************************************************************/

    @Test
    public void testUpdateIndexSettings() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n" +
                "    \"index\" : {\n" +
                "        \"refresh_interval\" : null\n" +
                "    }\n" +
                "}";

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_settings", indexSettings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
        //as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_settings", indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testUpdateIndexSettingsWithSystemIndices() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n" +
                "    \"index\" : {\n" +
                "        \"refresh_interval\" : null\n" +
                "    }\n" +
                "}";

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_settings", indexSettings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
        //as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_settings", indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
        }
    }
    /***************************************************************************************************************************
     * Index mappings. indices:admin/mapping/put
     ************************************************************************************************************************** */

    @Test
    public void testUpdateMappings() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String newMappings = "{\"properties\": {" +
                "\"user_name\": {" +
                "\"type\": \"text\"" +
                "}}}";

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_mapping", newMappings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

        }
        //as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = sslRestHelper.executePutRequest(index + "/_mapping", newMappings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

    @Test
    public void testUpdateMappingsWithSystemIndices() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        createTestIndicesAndDocs();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String newMappings = "{\"properties\": {" +
                "\"user_name\": {" +
                "\"type\": \"text\"" +
                "}}}";

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = keyStoreRestHelper.executePutRequest(index + "/_mapping", newMappings);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

        }
        //as admin
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
    public void testCreate() throws Exception {
        setupSystemIndicesDisabledWithSsl();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n" +
                "    \"settings\" : {\n" +
                "        \"index\" : {\n" +
                "            \"number_of_shards\" : 3, \n" +
                "            \"number_of_replicas\" : 2 \n" +
                "        }\n" +
                "    }\n" +
                "}";

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executePutRequest(index, indexSettings);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = keyStoreRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}");
            assertTrue(response.getStatusCode() == RestStatus.CREATED.getStatus());
        }

        for (String index : listOfIndexesToTest) {
            keyStoreRestHelper.executeDeleteRequest(index);
        }

        //as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseIndex = sslRestHelper.executePutRequest(index, indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = sslRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", allAccessUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.CREATED.getStatus());
        }
    }

    @Test
    public void testCreateWithSystemIndices() throws Exception {
        setupSystemIndicesEnabledWithSsl();
        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n" +
                "    \"settings\" : {\n" +
                "        \"index\" : {\n" +
                "            \"number_of_shards\" : 3, \n" +
                "            \"number_of_replicas\" : 2 \n" +
                "        }\n" +
                "    }\n" +
                "}";

        //as super-admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseIndex = keyStoreRestHelper.executePutRequest(index, indexSettings);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = keyStoreRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}");
            assertTrue(response.getStatusCode() == RestStatus.CREATED.getStatus());
        }

        for (String index : listOfIndexesToTest) {
            keyStoreRestHelper.executeDeleteRequest(index);
        }

        //as admin
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse responseIndex = sslRestHelper.executePutRequest(index, indexSettings, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), responseIndex.getStatusCode());

            RestHelper.HttpResponse response = sslRestHelper.executePostRequest(index + "/_doc", "{\"foo\": \"bar\"}", allAccessUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
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

        try (TransportClient tc = getInternalTransportClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin().indices().close(new CloseIndexRequest(index)).actionGet();
            }
        }

        RestHelper sslRestHelper = sslRestHelper();
        // as admin
        for (String index : listOfIndexesToTest) {
            assertEquals(HttpStatus.SC_OK,        sslRestHelper.executeGetRequest("_snapshot/" + index + "/" + index + "_1", allAccessUserHeader).getStatusCode());
            assertEquals(HttpStatus.SC_OK,        sslRestHelper.executePostRequest("_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }", allAccessUserHeader).getStatusCode());
            assertEquals(HttpStatus.SC_FORBIDDEN, sslRestHelper.executePostRequest("_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true", "", allAccessUserHeader).getStatusCode());
        }
    }
}
