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

package org.opensearch.security;

import org.apache.http.HttpStatus;
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
        rh.executePutRequest("/_data_stream/my-data-stream22", getIndexTemplateBody(), encodeBasicHeader("ds3", "nagilum"));
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
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream11", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream22", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream22", encodeBasicHeader("ds1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeDeleteRequest("/_data_stream/my-data-stream33", encodeBasicHeader("ds3", "nagilum"));
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
    }
}
