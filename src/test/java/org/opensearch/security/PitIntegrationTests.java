package org.opensearch.security;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

public class PitIntegrationTests  extends SingleClusterTest {

//    @Test
//    public void pitCreate() throws Exception {
//        setup();
//        RestHelper rh = nonSslRestHelper();
//
//        // Create two indices
//        try (Client tc = getClient()) {
//            tc.index(new IndexRequest("pit_1").id("1").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).
//                    source("{\"content\":1}", XContentType.JSON)).actionGet();
//            tc.index(new IndexRequest("pit_2").id("2").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).
//                    source("{\"content\":2}", XContentType.JSON)).actionGet();
//        }
//
//        RestHelper.HttpResponse resc;
//
//        // Create point in time in index should be successful since the user has permission for index
//        resc = rh.executePostRequest("/pit_1/_search/point_in_time?keep_alive=100m", "",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
//
//        // Create point in time in index for which the user does not have permission
//        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
//
//        // Create point in time in index for which the user has permission for
//        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "",
//                encodeBasicHeader("pit-2", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
//
//        // List all PITs should work since there is atleast one PIT for which user has access for
//        resc = rh.executeGetRequest("/_search/point_in_time/_all",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
//
//        // PIT segments should work since there is atleast one PIT for which user has access for
//        resc = rh.executeGetRequest("/_cat/pit_segments/_all",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
//
//        // Delete all PITs should work since there is atleast one PIT for which user has access for
//        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
//
//        // List all PITs should throw error since there are no PITs for which the user has access for
//        resc = rh.executeGetRequest("/_search/point_in_time/_all",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
//
//        // Delete all PITs should throw error since there are no PITs for which the user has access for
//        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
//
//        // PIT segments should work since there is atleast one PIT for which user has access for
//        resc = rh.executeGetRequest("/_cat/pit_segments/_all",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
//
//        // List all PITs should work since there is atleast one PIT for which user has access for
//        resc = rh.executeGetRequest("/_search/point_in_time/_all",
//                encodeBasicHeader("pit-2", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
//
//        // PIT segments should work since there is atleast one PIT for which user has access for
//        resc = rh.executeGetRequest("/_cat/pit_segments/_all",
//                encodeBasicHeader("pit-2", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
//
//        // Delete all PITs should work since there is atleast one PIT for which user has access for
//        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
//                encodeBasicHeader("pit-2", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
//
//        // List all PITs should work since there are no PITs in the cluster
//        resc = rh.executeGetRequest("/_search/point_in_time/_all",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, resc.getStatusCode());
//
//        // Delete all PITs should work since there are no PITs in the cluster
//        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
//                encodeBasicHeader("pit-1", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, resc.getStatusCode());
//
//        // PIT segments should work since there is atleast one PIT for which user has access for
//        resc = rh.executeGetRequest("/_cat/pit_segments/_all",
//                encodeBasicHeader("pit-2", "nagilum"));
//        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
//    }

    @Test
    public void pitCreateWithDeleteAll() throws Exception {
        setup();
        RestHelper rh = nonSslRestHelper();

        // Create two indices
        try (Client tc = getClient()) {
            tc.index(new IndexRequest("pit_1").id("1").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).
                    source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("pit_2").id("2").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).
                    source("{\"content\":2}", XContentType.JSON)).actionGet();
        }

        RestHelper.HttpResponse resc;

        // Create point in time in index should be successful since the user has permission for index
        resc = rh.executePostRequest("/pit_1/_search/point_in_time?keep_alive=100m", "",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // Create point in time in index for which the user does not have permission
        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Create point in time in index for which the user has permission for
        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "",
                encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // Delete all PITs should work since there is atleast one PIT for which user has access for
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // Delete all PITs should throw error since there are no PITs for which the user has access for
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Delete all PITs should work since there is atleast one PIT for which user has access for
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // Delete all PITs should work since there are no PITs in the cluster
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, resc.getStatusCode());
    }

    @Test
    public void pitCreateWithGetAll() throws Exception {
        setup();
        RestHelper rh = nonSslRestHelper();

        // Create two indices
        try (Client tc = getClient()) {
            tc.index(new IndexRequest("pit_1").id("1").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).
                    source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("pit_2").id("2").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).
                    source("{\"content\":2}", XContentType.JSON)).actionGet();
        }

        RestHelper.HttpResponse resc;

        // List all PITs should work since there are no PITs in the cluster
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // List all PITs should work since there are no PITs in the cluster
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Create point in time in index should be successful since the user has permission for index
        resc = rh.executePostRequest("/pit_1/_search/point_in_time?keep_alive=100m", "",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // List all PITs should work since there are no PITs in the cluster
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-index-perm-no-get-permission", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Create point in time in index for which the user does not have permission
        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // Create point in time in index for which the user has permission for
        resc = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "",
                encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // List all PITs should work since there is atleast one PIT for which user has access for
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // PIT segments should work since there is atleast one PIT for which user has access for
        resc = rh.executeGetRequest("/_cat/pit_segments/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        Thread.sleep(500);

        // Delete all PITs should work since there is atleast one PIT for which user has access for
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());


        // List all PITs should throw error since there are no PITs for which the user has access for
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // PIT segments should throw error since there are PITs in system but no PIT for which user has access for
        resc = rh.executeGetRequest("/_cat/pit_segments/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // List all PITs should work since there is atleast one PIT for which user has access for
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // PIT segments should work since there is atleast one PIT for which user has access for
        resc = rh.executeGetRequest("/_cat/pit_segments/_all",
                encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // Delete all PITs should work since there is atleast one PIT for which user has access for
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // List all PITs should work since there are no PITs in the cluster
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
    }
}
