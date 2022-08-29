package org.opensearch.security;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

public class PitIntegrationTests  extends SingleClusterTest {

    @Test
    public void createPit() throws Exception {
        setup();
        RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse response;

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("pit_1").id("1").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("pit_2").id("2").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("pit_3").id("3").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":3}", XContentType.JSON)).actionGet();
        }

        RestHelper.HttpResponse resc = rh.executePostRequest("/pit_1/_search/point_in_time?keep_alive=100m", "",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        RestHelper.HttpResponse resc1 = rh.executePostRequest("/pit_2/_search/point_in_time?keep_alive=100m", "",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc1.getStatusCode());

        RestHelper.HttpResponse resc2 = rh.executeDeleteRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc2.getStatusCode());

    }
}
