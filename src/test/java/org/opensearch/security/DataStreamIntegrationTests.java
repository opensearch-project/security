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

import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;


public class DataStreamIntegrationTests extends SingleClusterTest {

    public String getIndexTemplateBody() {
        return  "{\"index_patterns\": [ \"my-data-stream*\" ], \"data_stream\": { }, \"priority\": 200, \"template\": {\"settings\": { } } }";
    }

    public void createSampleDataStreams(RestHelper rh) throws Exception{
        // Valid index-template is required to create data-streams
        rh.executePutRequest("/_index_template/my-data-stream-template", getIndexTemplateBody(), encodeBasicHeader("ds1", "nagilum"));

        rh.executePutRequest("/_data_stream/my-data-stream11", getIndexTemplateBody(), encodeBasicHeader("ds3", "nagilum"));
        rh.executePutRequest("/_data_stream/my-data-stream21", getIndexTemplateBody(), encodeBasicHeader("ds3", "nagilum"));
        rh.executePutRequest("/_data_stream/my-data-stream22", getIndexTemplateBody(), encodeBasicHeader("ds3", "nagilum"));
        rh.executePutRequest("/_data_stream/my-data-stream23", getIndexTemplateBody(), encodeBasicHeader("ds3", "nagilum"));
        rh.executePutRequest("/_data_stream/my-data-stream33", getIndexTemplateBody(), encodeBasicHeader("ds3", "nagilum"));
    }

    @Test
    public void testCreateDataStream() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();
        HttpResponse response;

        response = rh.executePutRequest("/_index_template/my-data-stream-template", getIndexTemplateBody(), encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePutRequest("/_index_template/my-data-stream-template", getIndexTemplateBody(), encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest("/_data_stream/my-data-stream11", getIndexTemplateBody(), encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePutRequest("/_data_stream/my-data-stream11", getIndexTemplateBody(), encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest("/_data_stream/my-data-stream22", getIndexTemplateBody(), encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest("/_data_stream/my-data-stream33", getIndexTemplateBody(), encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePutRequest("/_data_stream/my-data-stream33", getIndexTemplateBody(), encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testGetDataStream() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();
        createSampleDataStreams(rh);
        HttpResponse response;

        response = rh.executeGetRequest("/_data_stream/my-data-stream11", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream11", encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream11", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream22", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream33", encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream*", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream21,my-data-stream22", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream*", encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream2*", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream21,my-data-stream22", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream*", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream*", encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testDeleteDataStream() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();
        createSampleDataStreams(rh);
        HttpResponse response;

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream11", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream11", encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream11", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream22", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream33", encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream*", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream21,my-data-stream22", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream*", encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream21,my-data-stream22", encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream2*", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream21,my-data-stream22", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream*", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream*", encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testDataStreamStats() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();
        createSampleDataStreams(rh);
        HttpResponse response;

        response = rh.executeGetRequest("/_data_stream/my-data-stream11/_stats", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream11/_stats", encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream11/_stats", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream22/_stats", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream22/_stats", encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream33/_stats", encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream*/_stats", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream21,my-data-stream22/_stats", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream*/_stats", encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream2*/_stats", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream21,my-data-stream22/_stats", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream*/_stats", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("/_data_stream/my-data-stream*/_stats", encodeBasicHeader("ds3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testBackingIndicesOfDataStream() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();
        createSampleDataStreams(rh);
        HttpResponse response;

        response = rh.executeGetRequest("my-data-stream11", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("my-data-stream22", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream11-000001", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream22-000001", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream21-000001,.ds-my-data-stream22-000001", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream2*", encodeBasicHeader("ds0", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("my-data-stream11", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest("my-data-stream22", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream11-000001", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream22-000001", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream21-000001,.ds-my-data-stream22-000001", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream2*", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }
}
