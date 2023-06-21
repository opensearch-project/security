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
package org.opensearch.security;

import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

/**
 * Integration tests to test point in time APIs permission model
 */
public class PitIntegrationTests extends SingleClusterTest {

    @Test
    public void testPitExplicitAPIAccess() throws Exception {
        setup();
        RestHelper rh = nonSslRestHelper();
        try (Client tc = getClient()) {
            // create alias
            tc.admin().indices().create(new CreateIndexRequest("pit_1").alias(new Alias("alias"))).actionGet();
            // create index
            tc.index(
                new IndexRequest("pit_2").id("2")
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source("{\"content\":2}", XContentType.JSON)
            ).actionGet();

        }

        RestHelper.HttpResponse resc;

        // Create point in time in index should be successful since the user has permission for index
        resc = rh.executePostRequest("/alias/_search/point_in_time?keep_alive=100m", "", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        String pitId1 = resc.findValueInJson("pit_id");

        // Create point in time in index for which the user does not have permission
        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Create point in time in index for which the user has permission for
        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "", encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        String pitId2 = resc.findValueInJson("pit_id");
        resc = rh.executePostRequest("/pit*/_search/point_in_time?keep_alive=100m", "", encodeBasicHeader("all-pit", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // PIT segments should work since there is atleast one PIT for which user has access for
        resc = rh.executeGetRequest("/_cat/pit_segments", "{\"pit_id\":\"" + pitId1 + "\"}", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // PIT segments should work since there is atleast one PIT for which user has access for
        resc = rh.executeGetRequest("/_cat/pit_segments", "{\"pit_id\":\"" + pitId1 + "\"}", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // Should throw error since user does not have access for pitId2
        resc = rh.executeGetRequest("/_cat/pit_segments", "{\"pit_id\":\"" + pitId2 + "\"}", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Should throw error since user does not have access for pitId2
        resc = rh.executeGetRequest(
            "/_cat/pit_segments",
            "{\"pit_id\":[\"" + pitId1 + "\",\"" + pitId2 + "\"]}",
            encodeBasicHeader("pit-1", "nagilum")
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Delete explicit PITs should work for PIT for which user has access for
        resc = rh.executeDeleteRequest("/_search/point_in_time", "{\"pit_id\":\"" + pitId1 + "\"}", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertEquals(pitId1, resc.findValueInJson("pits[0].pit_id"));
        Assert.assertEquals("true", resc.findValueInJson("pits[0].successful"));

        // Should throw error since user does not have access for pitId2
        resc = rh.executeDeleteRequest("/_search/point_in_time", "{\"pit_id\":\"" + pitId2 + "\"}", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Should throw error since user does not have access for pitId2
        resc = rh.executeDeleteRequest(
            "/_search/point_in_time",
            "{\"pit_id\":[\"" + pitId1 + "\",\"" + pitId2 + "\"]}",
            encodeBasicHeader("pit-1", "nagilum")
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Delete explicit PITs should work for PIT for which user has access for
        resc = rh.executeDeleteRequest("/_search/point_in_time", "{\"pit_id\":\"" + pitId2 + "\"}", encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertEquals(pitId2, resc.findValueInJson("pits[0].pit_id"));
        Assert.assertEquals("true", resc.findValueInJson("pits[0].successful"));

    }

    @Test
    public void testPitAllAPIAccess() throws Exception {
        setup();
        RestHelper rh = nonSslRestHelper();

        // Create two indices
        try (Client tc = getClient()) {
            tc.index(
                new IndexRequest("pit_1").id("1")
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
            tc.index(
                new IndexRequest("pit_2").id("2")
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source("{\"content\":2}", XContentType.JSON)
            ).actionGet();
        }

        RestHelper.HttpResponse resc;

        // Create point in time in index should be successful since the user has permission for index
        resc = rh.executePostRequest("/pit_1/_search/point_in_time?keep_alive=100m", "", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        String pitId1 = resc.findValueInJson("pit_id");

        // Create point in time in index for which the user does not have permission
        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Create point in time in index for which the user has permission for
        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "", encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        String pitId2 = resc.findValueInJson("pit_id");

        // Throw security error if user does not have all index permission
        resc = rh.executeGetRequest("/_search/point_in_time/_all", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // List all PITs should work for user with all index access
        resc = rh.executeGetRequest("/_search/point_in_time/_all", encodeBasicHeader("all-pit", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        List<String> pitList = new ArrayList<>();
        pitList.add(pitId1);
        pitList.add(pitId2);
        pitList.contains(resc.findValueInJson("pits[0].pit_id"));
        pitList.contains(resc.findValueInJson("pits[1].pit_id"));

        // Throw security error if user does not have all index permission
        resc = rh.executeGetRequest("/_cat/pit_segments/_all", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // PIT segments should work for user with all index access
        resc = rh.executeGetRequest("/_cat/pit_segments/_all", encodeBasicHeader("all-pit", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // Throw security error if user does not have all index permission
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Delete all PITs should work for user with all index access
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all", encodeBasicHeader("all-pit", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        pitList.contains(resc.findValueInJson("pits[0].pit_id"));
        pitList.contains(resc.findValueInJson("pits[1].pit_id"));
        Assert.assertEquals("true", resc.findValueInJson("pits[0].successful"));
        Assert.assertEquals("true", resc.findValueInJson("pits[1].successful"));

    }

    @Test
    public void testDataStreamWithPits() throws Exception {
        setup();
        RestHelper rh = nonSslRestHelper();
        String indexTemplate = "{\"index_patterns\": [ \"my-data-stream*\" ], \"data_stream\": { }, \"priority\": 200, "
            + "\"template\": {\"settings\": { } } }";

        rh.executePutRequest("/_index_template/my-data-stream-template", indexTemplate, encodeBasicHeader("ds1", "nagilum"));

        rh.executePutRequest("/_data_stream/my-data-stream11", indexTemplate, encodeBasicHeader("ds3", "nagilum"));
        rh.executePutRequest("/_data_stream/my-data-stream21", indexTemplate, encodeBasicHeader("ds3", "nagilum"));

        RestHelper.HttpResponse resc;
        // create pit should work since user has permission on data stream
        resc = rh.executePostRequest("/my-data-stream11/_search/point_in_time?keep_alive=100m", "", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        String pitId1 = resc.findValueInJson("pit_id");

        // PIT segments works since the user has access for backing indices
        resc = rh.executeGetRequest("/_cat/pit_segments", "{\"pit_id\":\"" + pitId1 + "\"}", encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // create pit should work since user has permission on data stream
        resc = rh.executePostRequest("/my-data-stream21/_search/point_in_time?keep_alive=100m", "", encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        String pitId2 = resc.findValueInJson("pit_id");

        // since pit-3 doesn't have permission to backing data stream indices, throw security error
        resc = rh.executeGetRequest("/_cat/pit_segments", "{\"pit_id\":\"" + pitId2 + "\"}", encodeBasicHeader("pit-3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Delete all PITs should work for user with all index access
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all", encodeBasicHeader("all-pit", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
    }
}
