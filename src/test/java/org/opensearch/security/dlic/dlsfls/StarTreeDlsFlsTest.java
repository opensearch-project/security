/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlic.dlsfls;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.forcemerge.ForceMergeRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * Integration tests for star tree functionality with DLS/FLS restrictions.
 * Tests that star tree queries are disabled when DLS/FLS is applied.
 */
public class StarTreeDlsFlsTest extends AbstractDlsFlsTest {

    private static final String STARTREE_INDEX_NAME = "startree_sales";
    private static final String REGULAR_INDEX_NAME = "regular_sales";

    protected void setupStarTreeTest() throws Exception {
        final Settings settings = Settings.EMPTY;
        final DynamicSecurityConfig dynamicSecurityConfig = new DynamicSecurityConfig().setSecurityRoles("roles_startree.yml")
            .setSecurityRolesMapping("roles_mapping_startree.yml")
            .setSecurityInternalUsers("internal_users_startree.yml");

        setup(settings, dynamicSecurityConfig);
    }

    @Override
    protected void populateData(Client tc) {
        // Create star tree index with composite mapping
        try {
            tc.admin()
                .indices()
                .create(
                    new CreateIndexRequest(STARTREE_INDEX_NAME).settings(
                        Settings.builder()
                            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                            .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
                            .put("index.composite_index", true)
                            .put("index.append_only.enabled", true)
                            .put("index.search.star_tree_index.enabled", true)
                            .build()
                    )
                        .mapping(
                            XContentFactory.jsonBuilder()
                                .startObject()
                                .startObject("composite")
                                .startObject("sales_star_tree")
                                .field("type", "star_tree")
                                .startObject("config")
                                .startArray("ordered_dimensions")
                                .startObject()
                                .field("name", "department")
                                .endObject()
                                .startObject()
                                .field("name", "region")
                                .endObject()
                                .endArray()
                                .startArray("metrics")
                                .startObject()
                                .field("name", "sales_amount")
                                .field("stats", new String[] { "sum", "value_count" })
                                .endObject()
                                .endArray()
                                .endObject()
                                .endObject()
                                .endObject()
                                .startObject("properties")
                                .startObject("department")
                                .field("type", "keyword")
                                .endObject()
                                .startObject("region")
                                .field("type", "keyword")
                                .endObject()
                                .startObject("sales_amount")
                                .field("type", "double")
                                .endObject()
                                .startObject("employee_id")
                                .field("type", "keyword")
                                .endObject()
                                .startObject("sensitive_data")
                                .field("type", "text")
                                .endObject()
                                .endObject()
                                .endObject()
                                .toString()
                        )
                )
                .actionGet();

            // Create regular index for comparison
            tc.admin()
                .indices()
                .create(
                    new CreateIndexRequest(REGULAR_INDEX_NAME).settings(
                        Settings.builder()
                            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                            .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
                            .build()
                    )
                        .mapping(
                            XContentFactory.jsonBuilder()
                                .startObject()
                                .startObject("properties")
                                .startObject("department")
                                .field("type", "keyword")
                                .endObject()
                                .startObject("region")
                                .field("type", "keyword")
                                .endObject()
                                .startObject("sales_amount")
                                .field("type", "double")
                                .endObject()
                                .startObject("employee_id")
                                .field("type", "keyword")
                                .endObject()
                                .startObject("sensitive_data")
                                .field("type", "text")
                                .endObject()
                                .endObject()
                                .endObject()
                                .toString()
                        )
                )
                .actionGet();

        } catch (Exception e) {
            throw new RuntimeException("Failed to create indices", e);
        }

        // Populate star tree index with test data
        tc.index(
            new IndexRequest(STARTREE_INDEX_NAME).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"department\": \"engineering\", \"region\": \"us-west\", \"sales_amount\": 1000.0, \"employee_id\": \"emp1\", \"sensitive_data\": \"confidential info 1\"}",
                    XContentType.JSON
                )
        ).actionGet();

        tc.index(
            new IndexRequest(STARTREE_INDEX_NAME).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"department\": \"engineering\", \"region\": \"us-east\", \"sales_amount\": 1500.0, \"employee_id\": \"emp2\", \"sensitive_data\": \"confidential info 2\"}",
                    XContentType.JSON
                )
        ).actionGet();

        tc.index(
            new IndexRequest(STARTREE_INDEX_NAME).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"department\": \"sales\", \"region\": \"us-west\", \"sales_amount\": 2000.0, \"employee_id\": \"emp3\", \"sensitive_data\": \"confidential info 3\"}",
                    XContentType.JSON
                )
        ).actionGet();

        tc.index(
            new IndexRequest(STARTREE_INDEX_NAME).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"department\": \"sales\", \"region\": \"us-east\", \"sales_amount\": 2500.0, \"employee_id\": \"emp4\", \"sensitive_data\": \"confidential info 4\"}",
                    XContentType.JSON
                )
        ).actionGet();

        // Populate regular index with same data
        tc.index(
            new IndexRequest(REGULAR_INDEX_NAME).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"department\": \"engineering\", \"region\": \"us-west\", \"sales_amount\": 1000.0, \"employee_id\": \"emp1\", \"sensitive_data\": \"confidential info 1\"}",
                    XContentType.JSON
                )
        ).actionGet();

        tc.index(
            new IndexRequest(REGULAR_INDEX_NAME).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"department\": \"engineering\", \"region\": \"us-east\", \"sales_amount\": 1500.0, \"employee_id\": \"emp2\", \"sensitive_data\": \"confidential info 2\"}",
                    XContentType.JSON
                )
        ).actionGet();

        tc.index(
            new IndexRequest(REGULAR_INDEX_NAME).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"department\": \"sales\", \"region\": \"us-west\", \"sales_amount\": 2000.0, \"employee_id\": \"emp3\", \"sensitive_data\": \"confidential info 3\"}",
                    XContentType.JSON
                )
        ).actionGet();

        tc.index(
            new IndexRequest(REGULAR_INDEX_NAME).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"department\": \"sales\", \"region\": \"us-east\", \"sales_amount\": 2500.0, \"employee_id\": \"emp4\", \"sensitive_data\": \"confidential info 4\"}",
                    XContentType.JSON
                )
        ).actionGet();

        // Force merge to create star tree segments
        tc.admin().indices().forceMerge(new ForceMergeRequest(STARTREE_INDEX_NAME).maxNumSegments(1)).actionGet();
        tc.admin().indices().forceMerge(new ForceMergeRequest(REGULAR_INDEX_NAME).maxNumSegments(1)).actionGet();

        try {
            Thread.sleep(2000); // Allow time for indexing and merging
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Test
    public void testStarTreeWithoutDlsFls() throws Exception {
        setupStarTreeTest();

        // Test aggregation query that should use star tree (no DLS/FLS restrictions)
        String aggregationQuery = "{"
            + "\"size\": 0,"
            + "\"aggs\": {"
            + "  \"departments\": {"
            + "    \"terms\": {"
            + "      \"field\": \"department\""
            + "    },"
            + "    \"aggs\": {"
            + "      \"total_sales\": {"
            + "        \"sum\": {"
            + "          \"field\": \"sales_amount\""
            + "        }"
            + "      }"
            + "    }"
            + "  }"
            + "}"
            + "}";

        // Execute query as admin (no restrictions)
        HttpResponse response = rh.executePostRequest(
            "/" + STARTREE_INDEX_NAME + "/_search?pretty",
            aggregationQuery,
            encodeBasicHeader("startree_admin", "password")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        /**
         * "aggregations" : {
         *     "departments" : {
         *       "doc_count_error_upper_bound" : 0,
         *       "sum_other_doc_count" : 0,
         *       "buckets" : [
         *         {
         *           "key" : "engineering",
         *           "doc_count" : 2,
         *           "total_sales" : {
         *             "value" : 2500.0
         *           }
         *         },
         *         {
         *           "key" : "sales",
         *           "doc_count" : 2,
         *           "total_sales" : {
         *             "value" : 4500.0
         *           }
         *         }
         *       ]
         *     }
         *   }
         */
        Assert.assertTrue(
            "Should contain correct sales total",
            response.getBody().contains("2500.0") && response.getBody().contains("4500.0")
        );

        // Check star tree stats - should show star tree queries were used
        HttpResponse statsResponse = rh.executeGetRequest(
            "/" + STARTREE_INDEX_NAME + "/_stats/search?pretty",
            encodeBasicHeader("startree_admin", "password")
        );
        assertThat(statsResponse.getStatusCode(), is(HttpStatus.SC_OK));

        Assert.assertTrue(
            "Star tree query total should be 1 since there are no restrictions",
            statsResponse.getBody().contains("\"startree_query_total\" : 1")
        );

        Assert.assertTrue(
            "Regular query total should be > 0",
            statsResponse.getBody().contains("\"query_total\" : 1")
                || statsResponse.getBody().matches(".*\"query_total\"\\s*:\\s*[1-9]\\d*.*")
        );

    }

    @Test
    public void testStarTreeWithDlsRestriction() throws Exception {
        setupStarTreeTest();

        String aggregationQuery = "{"
            + "\"size\": 0,"
            + "\"aggs\": {"
            + "  \"departments\": {"
            + "    \"terms\": {"
            + "      \"field\": \"department\""
            + "    },"
            + "    \"aggs\": {"
            + "      \"total_sales\": {"
            + "        \"sum\": {"
            + "          \"field\": \"sales_amount\""
            + "        }"
            + "      }"
            + "    }"
            + "  }"
            + "}"
            + "}";

        HttpResponse response = rh.executePostRequest(
            "/" + STARTREE_INDEX_NAME + "/_search?pretty",
            aggregationQuery,
            encodeBasicHeader("startree_dls_user", "password")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        HttpResponse statsResponse = rh.executeGetRequest(
            "/" + STARTREE_INDEX_NAME + "/_stats/search?pretty",
            encodeBasicHeader("startree_admin", "password")
        );
        assertThat(statsResponse.getStatusCode(), is(HttpStatus.SC_OK));
        String statsBody = statsResponse.getBody();
        // Assert that star tree queries are 0 (disabled due to FLS)
        Assert.assertTrue("Star tree query total should be 0 when FLS is applied", statsBody.contains("\"startree_query_total\" : 0"));

        Assert.assertTrue(
            "Regular query total should be > 0",
            statsBody.contains("\"query_total\" : 1") || statsBody.matches(".*\"query_total\"\\s*:\\s*[1-9]\\d*.*")
        );
    }

    @Test
    public void testStarTreeWithDlsRestrictionForDFSThenFetchQuery() throws Exception {
        setupStarTreeTest();

        String aggregationQuery = "{"
            + "\"size\": 0,"
            + "\"aggs\": {"
            + "  \"departments\": {"
            + "    \"terms\": {"
            + "      \"field\": \"department\""
            + "    },"
            + "    \"aggs\": {"
            + "      \"total_sales\": {"
            + "        \"sum\": {"
            + "          \"field\": \"sales_amount\""
            + "        }"
            + "      }"
            + "    }"
            + "  }"
            + "}"
            + "}";

        HttpResponse response = rh.executePostRequest(
            "/" + STARTREE_INDEX_NAME + "/_search?search_type=dfs_query_then_fetch",
            aggregationQuery,
            encodeBasicHeader("startree_dls_user", "password")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        HttpResponse statsResponse = rh.executeGetRequest(
            "/" + STARTREE_INDEX_NAME + "/_stats/search?pretty",
            encodeBasicHeader("startree_admin", "password")
        );
        assertThat(statsResponse.getStatusCode(), is(HttpStatus.SC_OK));
        String statsBody = statsResponse.getBody();
        // Assert that star tree queries are 0 (disabled due to FLS)
        Assert.assertTrue("Star tree query total should be 0 when FLS is applied", statsBody.contains("\"startree_query_total\" : 0"));

        Assert.assertTrue(
            "Regular query total should be > 0",
            statsBody.contains("\"query_total\" : 1") || statsBody.matches(".*\"query_total\"\\s*:\\s*[1-9]\\d*.*")
        );
    }

    @Test
    public void testStarTreeWithFlsRestriction() throws Exception {
        setupStarTreeTest();

        // Test aggregation query with FLS restriction
        String aggregationQuery = "{"
            + "\"size\": 0,"
            + "\"aggs\": {"
            + "  \"departments\": {"
            + "    \"terms\": {"
            + "      \"field\": \"department\""
            + "    },"
            + "    \"aggs\": {"
            + "      \"total_sales\": {"
            + "        \"sum\": {"
            + "          \"field\": \"sales_amount\""
            + "        }"
            + "      }"
            + "    }"
            + "  }"
            + "}"
            + "}";

        HttpResponse response = rh.executePostRequest(
            "/" + STARTREE_INDEX_NAME + "/_search?pretty",
            aggregationQuery,
            encodeBasicHeader("startree_fls_user", "password")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        HttpResponse statsResponse = rh.executeGetRequest(
            "/" + STARTREE_INDEX_NAME + "/_stats/search?pretty",
            encodeBasicHeader("startree_admin", "password")
        );
        assertThat(statsResponse.getStatusCode(), is(HttpStatus.SC_OK));

        String statsBody = statsResponse.getBody();
        // Assert that star tree queries are 0 (disabled due to FLS)
        Assert.assertTrue("Star tree query total should be 0 when FLS is applied", statsBody.contains("\"startree_query_total\" : 0"));

        Assert.assertTrue(
            "Regular query total should be > 0",
            statsBody.contains("\"query_total\" : 1") || statsBody.matches(".*\"query_total\"\\s*:\\s*[1-9]\\d*.*")
        );
    }

    @Test
    public void testStarTreeWithFieldMasking() throws Exception {
        setupStarTreeTest();

        // Test query with field masking
        String searchQuery = "{"
            + "\"query\": {"
            + "  \"match_all\": {}"
            + "},"
            + "\"_source\": [\"department\", \"sales_amount\", \"sensitive_data\"]"
            + "}";

        // Execute query as user with field masking
        HttpResponse response = rh.executePostRequest(
            "/" + STARTREE_INDEX_NAME + "/_search?pretty",
            searchQuery,
            encodeBasicHeader("startree_masked_user", "password")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // Check star tree stats - should show NO star tree queries were used due to field masking
        HttpResponse statsResponse = rh.executeGetRequest(
            "/" + STARTREE_INDEX_NAME + "/_stats/search?pretty",
            encodeBasicHeader("startree_admin", "password")
        );
        assertThat(statsResponse.getStatusCode(), is(HttpStatus.SC_OK));

        String statsBody = statsResponse.getBody();
        // Assert that star tree queries are 0 (disabled due to FLS)
        Assert.assertTrue("Star tree query total should be 0 when FLS is applied", statsBody.contains("\"startree_query_total\" : 0"));

        Assert.assertTrue(
            "Regular query total should be > 0",
            statsBody.contains("\"query_total\" : 1") || statsBody.matches(".*\"query_total\"\\s*:\\s*[1-9]\\d*.*")
        );

    }
}
