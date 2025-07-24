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
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
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

    // Test data for consistent use across indices
    private static final String[] TEST_DOCUMENTS = { """
        {
          "department": "engineering",
          "region": "us-west",
          "sales_amount": 1000.0,
          "employee_id": "emp1",
          "sensitive_data": "confidential info 1"
        }
        """, """
        {
          "department": "engineering",
          "region": "us-east",
          "sales_amount": 1500.0,
          "employee_id": "emp2",
          "sensitive_data": "confidential info 2"
        }
        """, """
        {
          "department": "sales",
          "region": "us-west",
          "sales_amount": 2000.0,
          "employee_id": "emp3",
          "sensitive_data": "confidential info 3"
        }
        """, """
        {
          "department": "sales",
          "region": "us-east",
          "sales_amount": 2500.0,
          "employee_id": "emp4",
          "sensitive_data": "confidential info 4"
        }
        """ };

    /**
     * Helper method to bulk index documents to multiple indices efficiently
     */
    private void bulkIndexDocuments(Client tc, String[] documents, String... indexNames) {
        BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(RefreshPolicy.IMMEDIATE);

        for (String document : documents) {
            for (String indexName : indexNames) {
                bulkRequest.add(new IndexRequest(indexName).source(document, XContentType.JSON));
            }
        }

        BulkResponse bulkResponse = tc.bulk(bulkRequest).actionGet();

        // Check for failures
        if (bulkResponse.hasFailures()) {
            throw new RuntimeException("Bulk indexing failed: " + bulkResponse.buildFailureMessage());
        }
    }

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
            String starTreeMapping = """
                {
                  "composite": {
                    "sales_star_tree": {
                      "type": "star_tree",
                      "config": {
                        "ordered_dimensions": [
                          {"name": "department"},
                          {"name": "region"},
                          {"name": "sensitive_data"}
                        ],
                        "metrics": [
                          {"name": "sales_amount", "stats": ["sum", "value_count"]}
                        ]
                      }
                    }
                  },
                  "properties": {
                    "department": {"type": "keyword"},
                    "region": {"type": "keyword"},
                    "sales_amount": {"type": "double"},
                    "employee_id": {"type": "keyword"},
                    "sensitive_data": {"type": "keyword"}
                  }
                }
                """;

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
                    ).mapping(starTreeMapping)
                )
                .actionGet();

            // Create regular index for comparison
            String regularMapping = """
                {
                  "properties": {
                    "department": {"type": "keyword"},
                    "region": {"type": "keyword"},
                    "sales_amount": {"type": "double"},
                    "employee_id": {"type": "keyword"},
                    "sensitive_data": {"type": "keyword"}
                  }
                }
                """;

            tc.admin()
                .indices()
                .create(
                    new CreateIndexRequest(REGULAR_INDEX_NAME).settings(
                        Settings.builder()
                            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                            .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
                            .build()
                    ).mapping(regularMapping)
                )
                .actionGet();

        } catch (Exception e) {
            throw new RuntimeException("Failed to create indices", e);
        }

        // Define test data once to avoid duplication
        String[] testDocuments = TEST_DOCUMENTS;

        // Populate both indices with the same test data using a single bulk request
        bulkIndexDocuments(tc, testDocuments, STARTREE_INDEX_NAME, REGULAR_INDEX_NAME);

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
        String aggregationQuery = """
            {
              "size": 0,
              "aggs": {
                "departments": {
                  "terms": {
                    "field": "department"
                  },
                  "aggs": {
                    "total_sales": {
                      "sum": {
                        "field": "sales_amount"
                      }
                    }
                  }
                }
              }
            }
            """;

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

        String aggregationQuery = """
            {
              "size": 0,
              "aggs": {
                "departments": {
                  "terms": {
                    "field": "department"
                  },
                  "aggs": {
                    "total_sales": {
                      "sum": {
                        "field": "sales_amount"
                      }
                    }
                  }
                }
              }
            }
            """;

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
        Assert.assertTrue("Should contain correct sales total", response.getBody().contains("2500.0"));
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

        String aggregationQuery = """
            {
              "size": 0,
              "aggs": {
                "departments": {
                  "terms": {
                    "field": "department"
                  },
                  "aggs": {
                    "total_sales": {
                      "sum": {
                        "field": "sales_amount"
                      }
                    }
                  }
                }
              }
            }
            """;

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
        Assert.assertTrue("Should contain correct sales total", response.getBody().contains("2500.0"));
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
        String aggregationQuery = """
            {
              "size": 0,
              "aggs": {
                "departments": {
                  "terms": {
                    "field": "department"
                  },
                  "aggs": {
                    "total_sales": {
                      "sum": {
                        "field": "sales_amount"
                      }
                    }
                  }
                }
              }
            }
            """;

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
        Assert.assertTrue(
            "Should contain correct sales total",
            response.getBody().contains("2500.0") && response.getBody().contains("4500.0")
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
        String searchQuery = """
            {
              "query": {
                "match_all": {}
              },
              "aggs": {
                "departments": {
                  "terms": {
                    "field": "sensitive_data"
                  }
                }
              }
            }
            """;

        // Execute query as user with field masking
        HttpResponse response = rh.executePostRequest(
            "/" + STARTREE_INDEX_NAME + "/_search?pretty",
            searchQuery,
            encodeBasicHeader("startree_masked_user", "password")
        );
        /**
         * {
         *   "took" : 74,
         *   "timed_out" : false,
         *   "_shards" : {
         *     "total" : 1,
         *     "successful" : 1,
         *     "skipped" : 0,
         *     "failed" : 0
         *   },
         *   "hits" : {
         *     "total" : {
         *       "value" : 4,
         *       "relation" : "eq"
         *     },
         *   },
         *   "aggregations" : {
         *     "departments" : {
         *       "doc_count_error_upper_bound" : 0,
         *       "sum_other_doc_count" : 0,
         *       "buckets" : [
         *         {
         *           "key" : "5e08a7aba0e2e1620a3f2bc533dbde2a132d7fec92e1d5bcf093addd99da51e8",
         *           "doc_count" : 1
         *         },
         *         {
         *           "key" : "aef40b3afd324a3124d3ba026f124ee2d745cbc833866a711db976f6a728d4f4",
         *           "doc_count" : 1
         *         },
         *         {
         *           "key" : "bc95c2aa20960646cd245b07ff5c369d69786bf6fec08d3e7d37ce620f86720b",
         *           "doc_count" : 1
         *         },
         *         {
         *           "key" : "dfdb4f84a0dc572ec9e3f8fa61b60a64710a66edddb8c78b584759ac73099eb1",
         *           "doc_count" : 1
         *         }
         *       ]
         *     }
         *   }
         * }
         */
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response.getBody().contains("dfdb4f84a0dc572ec9e3f8fa61b60a64710a66edddb8c78b584759ac73099eb1"));
        Assert.assertTrue(response.getBody().contains("\"value\" : 4"));
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
