package com.amazon.opendistroforelasticsearch.security.alerting;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.rest.RestStatus;
import org.junit.Assert;
import org.junit.Test;

public class BlockedIndexIntegrationTests extends SingleClusterTest {

    /**********************************************************
     * Test index access with no index created
     **********************************************************/

    // Tests indicies:admin/create permission
    @Test
    public void testNonAccessCreateIndex() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        // Try to create index
        String indexSettings = "{\n" +
                "    \"settings\" : {\n" +
                "        \"index\" : {\n" +
                "            \"number_of_shards\" : 3, \n" +
                "            \"number_of_replicas\" : 2 \n" +
                "        }\n" +
                "    }\n" +
                "}";
        RestHelper.HttpResponse response = rh.executePutRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0), indexSettings, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    @Test
    public void testNonAccessCreateIndexInPattern() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        // Try to create index
        String indexSettings = "{\n" +
                "    \"settings\" : {\n" +
                "        \"index\" : {\n" +
                "            \"number_of_shards\" : 3, \n" +
                "            \"number_of_replicas\" : 2 \n" +
                "        }\n" +
                "    }\n" +
                "}";

        String indexName = ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDEX_PATTERN_DEFAULT.get(0).substring(0, ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDEX_PATTERN_DEFAULT.get(0).length() - 1);

        RestHelper.HttpResponse response = rh.executePutRequest(indexName + "foobar", indexSettings, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    // Tests indices:data/write permission
    @Test
    public void testNonAccessCreateDocument() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        // Try to create index
        String doc = "{\"foo\": \"bar\"}";
        RestHelper.HttpResponse response = rh.executePostRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0) + "/_doc", doc, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    // Tests indices:data/read permission
    @Test
    public void testNonAccessQueryNoIndex() throws Exception {
         // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        String query = QueryBuilders.matchAllQuery().toString();

        RestHelper.HttpResponse response = rh.executePostRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0) + "/_doc", query, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    /**********************************************************
     * Test index access with index created
     **********************************************************/
    // Tests indices:data/write permission
    @Test
    public void testNonAccessGetWithIndex() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0))).actionGet();
            tc.index(new IndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0)).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).id("document1").source("{ \"foo\": \"bar\" }", XContentType.JSON)).actionGet();
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        RestHelper.HttpResponse response = rh.executeGetRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0) + "/_doc/document1", encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    // Tests indices:admin/delete permission
    @Test
    public void testNonAccessDeleteWithIndex() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0))).actionGet();
            tc.index(new IndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0)).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).id("document1").source("{ \"foo\": \"bar\" }", XContentType.JSON)).actionGet();
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        // Try to delete document
        RestHelper.HttpResponse deleteDocResponse = rh.executeDeleteRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0) + "/_doc/document1", encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(deleteDocResponse.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(deleteDocResponse.getBody().contains("This index is reserved for members of [all_access] role only."));

        // Try to delete index
        RestHelper.HttpResponse deleteIndexResponse = rh.executeDeleteRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0), encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(deleteIndexResponse.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(deleteIndexResponse.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    // Tests indices:admin/mapping/put
    @Test
    public void testNonAccessUpdateMappingsWithIndex() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        try (TransportClient tc = getInternalTransportClient()) {

            String mappings = "\"properties\": {" +
                    "\"user_name\": {" +
                    "\"type\": \"text\"" +
                    "}}";
            tc.admin().indices().create(new CreateIndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0)).mapping("_doc", mappings, XContentType.JSON)).actionGet();
            tc.index(new IndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0)).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).id("document1").source("{ \"username\": \"foobar\" }", XContentType.JSON)).actionGet();
        }

        String newMappings = "{\"properties\": {" +
                "\"user_name\": {" +
                "\"type\": \"text\"" +
                "}}}";
        // Create rest client
        RestHelper rh = nonSslRestHelper();

        RestHelper.HttpResponse response = rh.executePutRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0) + "/_mapping", newMappings, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    // Tests indices:admin/settings/update
    @Test
    public void testNonAccessUpdateIndexSettingsWithIndex() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        try (TransportClient tc = getInternalTransportClient()) {

            String indexSettings = "{\n" +
                    "        \"index\" : {\n" +
                    "            \"number_of_shards\" : 3, \n" +
                    "            \"number_of_replicas\" : 2 \n" +
                    "        }\n" +
                    "}";
            tc.admin().indices().create(new CreateIndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0)).settings(indexSettings, XContentType.JSON)).actionGet();
            tc.index(new IndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0)).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).id("document1").source("{ \"username\": \"foobar\" }", XContentType.JSON)).actionGet();
        }

        String newIndexSettings = "{\n" +
                "    \"index\" : {\n" +
                "        \"number_of_replicas\" : 10\n" +
                "    }\n" +
                "}";
        // Create rest client
        RestHelper rh = nonSslRestHelper();

        RestHelper.HttpResponse response = rh.executePutRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0) + "/_settings", newIndexSettings, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    // Tests indices:admin/close*
    @Test
    public void testNonAccessCloseIndexWithIndex() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0))).actionGet();
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        RestHelper.HttpResponse response = rh.executePostRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0) + "/_close", "", encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    // Tests indices:admin/aliases
    @Test
    public void testNonAccessAliasWithIndex() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0))).actionGet();
        }

        String alias = "{\"actions\" : [\n" +
                "{ \"add\" : { \"index\" : \"" + ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0) + "\", \"alias\" : \"foobar\" } }\n" +
                "]}";
        // Create rest client
        RestHelper rh = nonSslRestHelper();

        RestHelper.HttpResponse response = rh.executePostRequest("_aliases", alias, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    // Tests indices:data/read permission
    @Test
    public void testNonAccessQueryWithIndex() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0))).actionGet();
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        String query = QueryBuilders.matchAllQuery().toString();

        RestHelper.HttpResponse response = rh.executePostRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0) + "/_doc", query, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    // Tests indices:data/read permission
    @Test
    public void testNonAccessQueryWithIndexPattern() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        try (TransportClient tc = getInternalTransportClient()) {
            String indexName = ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDEX_PATTERN_DEFAULT.get(0).substring(0, ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDEX_PATTERN_DEFAULT.get(0).length() - 1);
            tc.admin().indices().create(new CreateIndexRequest(indexName + "foobar")).actionGet();
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        String query = QueryBuilders.matchAllQuery().toString();

        RestHelper.HttpResponse response = rh.executePostRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDEX_PATTERN_DEFAULT.get(0) + "/_doc", query, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

    @Test
    public void testNonAccessQueryAlias() throws Exception {
        // Setup settings
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config.yml").setSecurityRoles("roles.yml").setSecurityInternalUsers("internal_users.yml"), Settings.EMPTY, true);

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(IndicesAliasesRequest.AliasActions.add().index(ConfigConstants.OPENDISTRO_SECURITY_ROLE_BLOCKED_INDICES_DEFAULT.get(0)).alias("foobar"))).actionGet();
        }

        // Create rest client
        RestHelper rh = nonSslRestHelper();

        String query = QueryBuilders.matchAllQuery().toString();

        RestHelper.HttpResponse response = rh.executePostRequest("foobar/_doc", query, encodeBasicHeader("alertinguser", "alertinguser"));

        Assert.assertTrue(response.getStatusCode() == RestStatus.FORBIDDEN.getStatus());
        Assert.assertTrue(response.getBody().contains("This index is reserved for members of [all_access] role only."));
    }

}
