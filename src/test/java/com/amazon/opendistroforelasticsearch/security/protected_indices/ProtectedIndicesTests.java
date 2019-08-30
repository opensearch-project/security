package com.amazon.opendistroforelasticsearch.security.protected_indices;

import java.util.Arrays;
import java.util.List;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.apache.http.Header;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
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
import org.junit.Before;
import org.junit.Test;

import static junit.framework.TestCase.assertTrue;

public class ProtectedIndicesTests extends SingleClusterTest {

    private static final List<String> listOfIndexesToTest = Arrays.asList("logs1", "logs2", "logs3", "no_match");
    private static final List<String> listOfIndexPatternsToTest = Arrays.asList("*logs*", "logs*", "*lo*");
    private static final List<String> protectedIndexRoles = Arrays.asList("protected_index_role1", "protected_index_role2");
    private static final String matchAllQuery = "{\n\"query\": {\"match_all\": {}}}";
    // This user is mapped to all_access, but is not mapped to any protectedIndexRoles
    private static final String indexAccessNoRoleUser = "indexAccessNoRoleUser";
    private static final Header indexAccessNoRoleUserHeader = encodeBasicHeader(indexAccessNoRoleUser, indexAccessNoRoleUser);
    private static final String generalErrorMessage = String.format("no permissions for [] and User [name=%s, roles=[], requestedTenant=null]", indexAccessNoRoleUser);
    // This user is mapped to all_access and protected_index_role1
    private static final String protectedIndexUser = "protectedIndexUser";
    private static final Header protectedIndexUserHeader = encodeBasicHeader(protectedIndexUser, protectedIndexUser);

    /**
     * Setup settings loading custom config, users, roles and mappings.
     * Set the protected indices and protected indices roles.
     *
     * @throws Exception
     */
    @Before
    public void setupSettings() throws Exception {
        // Setup settings
        Settings adminOnlyIndexSettings = Settings.builder()
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
                adminOnlyIndexSettings,
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

    /************************************************************************************************
     * Tests with a user who has all index permissions but is not member of the protectedIndexRoles
     ***********************************************************************************************/

    // Test data search
    @Test
    public void testNoSearchResults() throws Exception {
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
    public void testNoResultsAlias() throws Exception {
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
            }
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (int aliasNumber = 0; aliasNumber < i; aliasNumber++) {
            RestHelper.HttpResponse response = rh.executePostRequest("alias" + aliasNumber + "/_search", matchAllQuery, indexAccessNoRoleUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    // Test indices:admin/create
    @Test
    public void testNoAccessCreateIndex() throws Exception {
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
            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    // Test indices:data/write
    @Test
    public void testNonAccessCreateDocument() throws Exception {
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
    public void testNonAccessDeleteDocument() throws Exception {
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

    // Test indices:admin/delete
    @Test
    public void testNonAccessDeleteIndex() throws Exception {
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

    // Tests indices:admin/mapping/put
    @Test
    public void testNonAccessUpdateMappings() throws Exception {
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

    // Tests indices:admin/close
    @Test
    public void testNonAccessCloseIndex() throws Exception {
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_close", "", indexAccessNoRoleUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    // Tests indices:admin/open
    @Test
    public void testNonAccessOpenIndex() throws Exception {
        createTestIndicesAndDocs();

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = rh.executePostRequest(index + "/_open", "", indexAccessNoRoleUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
            assertTrue(response.getBody().contains(generalErrorMessage));
        }
    }

    // Tests indices:admin/aliases
    @Test
    public void testNonAccessAliasOperations() throws Exception {
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
            }
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        for (int aliasNumber = 0; aliasNumber < i; aliasNumber++) {
            RestHelper.HttpResponse response = rh.executePostRequest("alias" + aliasNumber + "/_search", matchAllQuery, protectedIndexUserHeader);

            assertTrue(response.getStatusCode() == RestStatus.OK.getStatus());
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

    // Test indices:admin/create
    @Test
    public void testCreateIndex() throws Exception {
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
}
