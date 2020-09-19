/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */
/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.amazon.opendistroforelasticsearch.security.protected_indices;

import java.util.Arrays;
import java.util.List;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.elasticsearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.close.CloseIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestStatus;
import org.junit.Test;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

public class ProtectedIndicesTests extends SingleClusterTest {

    private static final List<String> listOfIndexesToTest = Arrays.asList("logs1", "logs2", "logs3", "no_match");
    private static final List<String> listOfIndexPatternsToTest = Arrays.asList("*logs*", "logs*", "*lo*");
    private static final List<String> protectedIndexRoles = Arrays.asList("protected_index_role1", "protected_index_role2");
    private static final String matchAllQuery = "{\n\"query\": {\"match_all\": {}}}";
    // This user is mapped to all_access, but is not mapped to any protectedIndexRoles
    private static final String indexAccessNoRoleUser = "indexAccessNoRoleUser";
    private static final Header indexAccessNoRoleUserHeader = encodeBasicHeader(indexAccessNoRoleUser, indexAccessNoRoleUser);
    private static final String generalErrorMessage = String.format("no permissions for [] and User [name=%s, backend_roles=[], requestedTenant=null]", indexAccessNoRoleUser);
    // This user is mapped to all_access and protected_index_role1
    private static final String protectedIndexUser = "protectedIndexUser";
    private static final Header protectedIndexUserHeader = encodeBasicHeader(protectedIndexUser, protectedIndexUser);

    /**
     * Setup settings loading custom config, users, roles and mappings.
     * Set the protected indices and protected indices roles.
     * Enable protected indices.
     *
     * @throws Exception
     */
    public void setupSettingsEnabled() throws Exception {
        // Setup settings
        Settings protectedIndexSettings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_KEY, true)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_KEY, listOfIndexesToTest)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_KEY, protectedIndexRoles)
                .build();
        setup(Settings.EMPTY,
                new DynamicSecurityConfig()
                        .setConfig("config_protected_indices.yml")
                        .setSecurityRoles("roles_protected_indices.yml")
                        .setSecurityInternalUsers("internal_users_protected_indices.yml")
                        .setSecurityRolesMapping("roles_mapping_protected_indices.yml"),
                protectedIndexSettings,
                true);
    }

    public void setupSettingsIndexPatterns() throws Exception {
        // Setup settings
        Settings protectedIndexSettings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_KEY, true)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_KEY, listOfIndexPatternsToTest)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_KEY, protectedIndexRoles)
                .build();
        setup(Settings.EMPTY,
                new DynamicSecurityConfig()
                        .setConfig("config_protected_indices.yml")
                        .setSecurityRoles("roles_protected_indices.yml")
                        .setSecurityInternalUsers("internal_users_protected_indices.yml")
                        .setSecurityRolesMapping("roles_mapping_protected_indices.yml"),
                protectedIndexSettings,
                true);
    }

    /**
     * Setup settings loading custom config, users, roles and mappings.
     * Set the protected indices and protected indices roles.
     * Disable protected indices.
     *
     * @throws Exception
     */
    public void setupSettingsDisabled() throws Exception {
        // Setup settings
        Settings protectedIndexSettings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_KEY, false)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_KEY, listOfIndexesToTest)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_KEY, protectedIndexRoles)
                .build();
        setup(Settings.EMPTY,
                new DynamicSecurityConfig()
                        .setConfig("config_protected_indices.yml")
                        .setSecurityRoles("roles_protected_indices.yml")
                        .setSecurityInternalUsers("internal_users_protected_indices.yml")
                        .setSecurityRolesMapping("roles_mapping_protected_indices.yml"),
                protectedIndexSettings,
                true);
    }

    public void setupSettingsEnabledSnapshot() throws Exception {
        final Settings settings = Settings.builder()
                .putList("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .put(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_KEY, true)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_KEY, listOfIndexesToTest)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_KEY, protectedIndexRoles)
                .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig()
                .setConfig("config_protected_indices.yml")
                .setSecurityRoles("roles_protected_indices.yml")
                .setSecurityInternalUsers("internal_users_protected_indices.yml")
                .setSecurityRolesMapping("roles_mapping_protected_indices.yml"),
                settings,
                true);
    }

    /**
     * Creates a set of test indices and indexes one document into each index.
     *
     * @throws Exception
     */
    public void createTestIndicesAndDocs() {
        try (TransportClient tc = getInternalTransportClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin().indices().create(new CreateIndexRequest(index)).actionGet();
                tc.index(new IndexRequest(index).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).id("document1").source("{ \"foo\": \"bar\" }", XContentType.JSON)).actionGet();
            }
        }
    }

    public void createSnapshots() {
        try (TransportClient tc = getInternalTransportClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin().cluster().putRepository(new PutRepositoryRequest(index).type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/" + index))).actionGet();
                tc.admin().cluster().createSnapshot(new CreateSnapshotRequest(index, index + "_1").indices(index).includeGlobalState(true).waitForCompletion(true)).actionGet();
            }
        }
    }

    /************************************************************************************************
     * Tests with a user who has all index permissions but is not member of the protectedIndexRoles
     ***********************************************************************************************/

    // Test data search
    @Test
    public void testNoSearchResults() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        // Test direct index query.
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_search", matchAllQuery, indexAccessNoRoleUserHeader);
            XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
            SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
            // confirm good response.
            assertTrue(searchResponse.status() == RestStatus.OK);
            // confirm no search hits.
            assertTrue(searchResponse.getHits().getHits().length == 0);
            // confirm no failed shards.
            assertTrue(searchResponse.getFailedShards() == 0);
            // confirm data was actually queried
            assertTrue(searchResponse.getSuccessfulShards() == 5);
        }

        // Test index pattern
        for (String indexPattern : listOfIndexPatternsToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(indexPattern + "/_search", matchAllQuery, indexAccessNoRoleUserHeader);
            XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
            SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
            // confirm good response.
            assertTrue(searchResponse.status() == RestStatus.OK);
            // confirm no search hits.
            assertTrue(searchResponse.getHits().getHits().length == 0);
            // confirm no failed shards.
            assertTrue(searchResponse.getFailedShards() == 0);
            // confirm data was actually queried
            assertTrue(searchResponse.getSuccessfulShards() == 15);
        }
    }

    @Test
    public void testSearchWithSettingDisabled() throws Exception {
        setupSettingsDisabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        // Test direct index query.
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_search", matchAllQuery, protectedIndexUserHeader);
            XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
            SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
            // confirm good response.
            assertTrue(searchResponse.status() == RestStatus.OK);
            // confirm search hits.
            assertTrue(searchResponse.getHits().getHits().length == 1);
            // confirm no failed shards.
            assertTrue(searchResponse.getFailedShards() == 0);
            // confirm data was actually queried
            assertTrue(searchResponse.getSuccessfulShards() == 5);
        }

        // Test index pattern
        for (String indexPattern : listOfIndexPatternsToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(indexPattern + "/_search", matchAllQuery, protectedIndexUserHeader);
            XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
            SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
            // confirm good response.
            assertTrue(searchResponse.status() == RestStatus.OK);
            // confirm search hits.
            assertTrue(searchResponse.getHits().getHits().length == 3);
            // confirm no failed shards.
            assertTrue(searchResponse.getFailedShards() == 0);
            // confirm data was actually queried
            assertTrue(searchResponse.getSuccessfulShards() == 15);
        }
    }

    @Test
    public void testNoResultsAlias() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        int i = 0;
        try (TransportClient tc = getInternalTransportClient()) {
            for (String index : listOfIndexesToTest) {
                IndicesAliasesRequest request = new IndicesAliasesRequest();
                IndicesAliasesRequest.AliasActions aliasAction =
                        new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                                .index(index)
                                .alias("alias" + i);
                request.addAliasAction(aliasAction);
                tc.admin().indices().aliases(request).actionGet();
                i++;
            }
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (int aliasNumber = 0; aliasNumber < i; aliasNumber++) {
            RestHelper.HttpResponse response = rh.executePostRequest("alias" + aliasNumber + "/_search", matchAllQuery, indexAccessNoRoleUserHeader);
            XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
            SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
            // confirm good response.
            assertTrue(searchResponse.status() == RestStatus.OK);
            // confirm no search hits.
            assertTrue(searchResponse.getHits().getHits().length == 0);
            // confirm no failed shards.
            assertTrue(searchResponse.getFailedShards() == 0);
            // confirm data was actually queried
            assertTrue(searchResponse.getSuccessfulShards() == 5);
        }
    }

    // Test indices:admin/create
    @Test
    public void testNoAccessCreateIndexDisabled() throws Exception {
        setupSettingsDisabled();
        // Create rest client
        RestHelper rh = nonSslRestHelper();

        String indexSettings = "{\n" +
                "    \"settings\" : {\n" +
                "        \"index\" : {\n" +
                "            \"number_of_shards\" : 3, \n" +
                "            \"number_of_replicas\" : 2 \n" +
                "        }\n" +
                "    }\n" +
                "}";
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePutRequest(index, indexSettings, indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Test indices:data/write
    @Test
    public void testNonAccessCreateDocument() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            // Try to create documents
            String doc = "{\"foo\": \"bar\"}";
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_doc", doc, indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    @Test
    public void testNonAccessCreateDocumentPatternSetting() throws Exception {
        setupSettingsIndexPatterns();

        try (TransportClient tc = getInternalTransportClient()) {
            for (String pattern : listOfIndexPatternsToTest) {
                String index = pattern.replace("*", "1");
                tc.admin().indices().create(new CreateIndexRequest(index)).actionGet();
            }
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String pattern : listOfIndexPatternsToTest) {
            // Try to create documents
            String doc = "{\"foo\": \"bar\"}";
            String index = pattern.replace("*", "1");
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_doc", doc, indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    // Test indices:data/write
    @Test
    public void testNonAccessCreateDocumentDisabled() throws Exception {
        setupSettingsDisabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            // Try to create documents
            String doc = "{\"foo\": \"bar\"}";
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_doc", doc, indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.CREATED.getStatus());
        }
    }

    @Test
    public void testNonAccessDeleteDocument() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            // Try to delete documents
            RestHelper.HttpResponse response = rh.executeDeleteRequest(index + "/_doc/document1", indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    @Test
    public void testNonAccessDeleteDocumentDisabled() throws Exception {
        setupSettingsDisabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            // Try to delete documents
            RestHelper.HttpResponse response = rh.executeDeleteRequest(index + "/_doc/document1", indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Test indices:admin/delete
    @Test
    public void testNonAccessDeleteIndex() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            // Try to delete documents
            RestHelper.HttpResponse response = rh.executeDeleteRequest(index, indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    // Test indices:admin/delete
    @Test
    public void testNonAccessDeleteIndexDisabled() throws Exception {
        setupSettingsDisabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            // Try to delete documents
            RestHelper.HttpResponse response = rh.executeDeleteRequest(index, indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Tests indices:admin/mapping/put
    @Test
    public void testNonAccessUpdateMappings() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        String newMappings = "{\"properties\": {" +
                "\"user_name\": {" +
                "\"type\": \"text\"" +
                "}}}";
        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePutRequest(index + "/_mapping", newMappings, indexAccessNoRoleUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    // Tests indices:admin/mapping/put
    @Test
    public void testNonAccessUpdateMappingsDisabled() throws Exception {
        setupSettingsDisabled();
        createTestIndicesAndDocs();

        String newMappings = "{\"properties\": {" +
                "\"user_name\": {" +
                "\"type\": \"text\"" +
                "}}}";
        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePutRequest(index + "/_mapping", newMappings, indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Tests indices:admin/close
    @Test
    public void testNonAccessCloseIndex() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_close", "", indexAccessNoRoleUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    // Tests indices:admin/aliases
    @Test
    public void testNonAccessAliasOperations() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        // Test create alias
        String aliasTemplate = "{\"actions\" : [{ \"add\" : { \"index\" : \"%s\", \"alias\" : \"foobar\" } }]}";
        for (String index : listOfIndexesToTest) {

            RestHelper.HttpResponse response = rh.executePostRequest("_aliases", String.format(aliasTemplate, index), indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }

        // Test remove alias
        aliasTemplate = "{\"actions\" : [{ \"remove\" : { \"index\" : \"%s\", \"alias\" : \"foobar\" } }]}";
        for (String index : listOfIndexesToTest) {

            RestHelper.HttpResponse response = rh.executePostRequest("_aliases", String.format(aliasTemplate, index), indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }

        // Test remove index
        aliasTemplate = "{\"actions\" : [{ \"remove_index\" : { \"index\" : \"%s\"} }]}";
        for (String index : listOfIndexesToTest) {

            RestHelper.HttpResponse response = rh.executePostRequest("_aliases", String.format(aliasTemplate, index), indexAccessNoRoleUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    // Tests indicies:admin/settings/update permission
    @Test
    public void testNonAccessUpdateIndexSettings() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        String indexSettings = "{\n" +
                "    \"settings\" : {\n" +
                "        \"index\" : {\n" +
                "            \"number_of_shards\" : 30, \n" +
                "            \"number_of_replicas\" : 20 \n" +
                "        }\n" +
                "    }\n" +
                "}";
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePutRequest(index + "/_settings", indexSettings, indexAccessNoRoleUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    /************************************************************************************************
     * Tests with a user who has all index permissions and is a member of the protectedIndexRoles
     ***********************************************************************************************/

    // Test data search
    @Test
    public void testSearchResults() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        // Test direct index query.
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_search", matchAllQuery, protectedIndexUserHeader);
            XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
            SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
            // confirm good response.
            assertTrue(searchResponse.status() == RestStatus.OK);
            // confirm search hits.
            assertTrue(searchResponse.getHits().getHits().length == 1);
            // confirm no failed shards.
            assertTrue(searchResponse.getFailedShards() == 0);
            // confirm data was actually queried
            assertTrue(searchResponse.getSuccessfulShards() == 5);
        }

        // Test index pattern
        for (String indexPattern : listOfIndexPatternsToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(indexPattern + "/_search", matchAllQuery, protectedIndexUserHeader);
            XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
            SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
            // confirm good response.
            assertTrue(searchResponse.status() == RestStatus.OK);
            // confirm search hits.
            assertTrue(searchResponse.getHits().getHits().length == 3);
            // confirm no failed shards.
            assertTrue(searchResponse.getFailedShards() == 0);
            // confirm data was actually queried
            assertTrue(searchResponse.getSuccessfulShards() == 15);
        }
    }

    @Test
    public void testResultsAlias() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        int i = 0;
        try (TransportClient tc = getInternalTransportClient()) {
            for (String index : listOfIndexesToTest) {
                IndicesAliasesRequest request = new IndicesAliasesRequest();
                IndicesAliasesRequest.AliasActions aliasAction =
                        new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                                .index(index)
                                .alias("alias" + i);
                request.addAliasAction(aliasAction);
                tc.admin().indices().aliases(request).actionGet();
                i++;
            }
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (int aliasNumber = 0; aliasNumber < i; aliasNumber++) {
            RestHelper.HttpResponse response = rh.executePostRequest("alias" + aliasNumber + "/_search", matchAllQuery, protectedIndexUserHeader);

            XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
            SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
            // confirm good response.
            assertTrue(searchResponse.status() == RestStatus.OK);
            // confirm search hits.
            assertTrue(searchResponse.getHits().getHits().length == 1);
            // confirm no failed shards.
            assertTrue(searchResponse.getFailedShards() == 0);
            // confirm data was actually queried
            assertTrue(searchResponse.getSuccessfulShards() == 5);
        }
    }

    // Test indices:admin/create
    @Test
    public void testCreateIndex() throws Exception {
        setupSettingsEnabled();
        // Create rest client
        RestHelper rh = nonSslRestHelper();

        String indexSettings = "{\n" +
                "    \"settings\" : {\n" +
                "        \"index\" : {\n" +
                "            \"number_of_shards\" : 3, \n" +
                "            \"number_of_replicas\" : 2 \n" +
                "        }\n" +
                "    }\n" +
                "}";
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePutRequest(index, indexSettings, protectedIndexUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Test indices:data/write
    @Test
    public void testCreateDocument() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            // Try to create documents
            String doc = "{\"foo\": \"bar\"}";
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_doc", doc, protectedIndexUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.CREATED.getStatus());
        }
    }

    @Test
    public void testDeleteDocument() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            // Try to delete documents
            RestHelper.HttpResponse response = rh.executeDeleteRequest(index + "/_doc/document1", protectedIndexUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Test indices:admin/delete
    @Test
    public void testDeleteIndex() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            // Try to delete documents
            RestHelper.HttpResponse response = rh.executeDeleteRequest(index, protectedIndexUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Tests indices:admin/mapping/put
    @Test
    public void testUpdateMappings() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        String newMappings = "{\"properties\": {" +
                "\"user_name\": {" +
                "\"type\": \"text\"" +
                "}}}";
        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePutRequest(index + "/_mapping", newMappings, protectedIndexUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Tests indices:admin/close
    @Test
    public void testCloseIndex() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_close", "", protectedIndexUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Tests indices:admin/open
    @Test
    public void testOpenIndex() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_open", "", protectedIndexUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Tests indices:admin/aliases
    @Test
    public void testAliasOperations() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        // Test create alias
        String aliasTemplate = "{\"actions\" : [{ \"add\" : { \"index\" : \"%s\", \"alias\" : \"foobar\" } }]}";
        for (String index : listOfIndexesToTest) {

            RestHelper.HttpResponse response = rh.executePostRequest("_aliases", String.format(aliasTemplate, index), protectedIndexUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }

        // Test remove alias
        aliasTemplate = "{\"actions\" : [{ \"remove\" : { \"index\" : \"%s\", \"alias\" : \"foobar\" } }]}";
        for (String index : listOfIndexesToTest) {

            RestHelper.HttpResponse response = rh.executePostRequest("_aliases", String.format(aliasTemplate, index), protectedIndexUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }

        // Test remove index
        aliasTemplate = "{\"actions\" : [{ \"remove_index\" : { \"index\" : \"%s\"} }]}";
        for (String index : listOfIndexesToTest) {

            RestHelper.HttpResponse response = rh.executePostRequest("_aliases", String.format(aliasTemplate, index), protectedIndexUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    // Tests indicies:admin/settings/update permission
    @Test
    public void testUpdateIndexSettings() throws Exception {
        setupSettingsEnabled();
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        String indexSettings = "{\n" +
                "    \"index\" : {\n" +
                "        \"refresh_interval\" : null\n" +
                "    }\n" +
                "}";

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePutRequest(index + "/_settings", indexSettings, protectedIndexUserHeader);
            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
        }
    }

    /************************************************************************************************
     * Test snapshot operations
     ***********************************************************************************************/

    @Test
    public void testAccessSnapshot() throws Exception {
        setupSettingsEnabledSnapshot();
        createTestIndicesAndDocs();
        createSnapshots();

        try (TransportClient tc = getInternalTransportClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin().indices().close(new CloseIndexRequest(index)).actionGet();
            }
        }

        String putSnapshot = "{"+
                "\"indices\": \"%s\"," +
                "\"ignore_unavailable\": false," +
                "\"include_global_state\": false" +
                "}";

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/" + index + "/" + index + "_1", protectedIndexUserHeader).getStatusCode());
            assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }", protectedIndexUserHeader).getStatusCode());
            assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true", "", protectedIndexUserHeader).getStatusCode());
            assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/" + index + "/" + index + "_1/_restore?wait_for_completion=true","{ \"indices\": \"" + index + "\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"" + index + "_1\" }", protectedIndexUserHeader).getStatusCode());
            assertEquals(HttpStatus.SC_OK, rh.executePutRequest("_snapshot/" + index + "/" + index + "_2?wait_for_completion=true", String.format(putSnapshot, index), protectedIndexUserHeader).getStatusCode());
        }
    }
}
