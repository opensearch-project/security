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

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DataStreamIntegrationTests extends SingleClusterTest {

    final String bulkDocsBody = "{ \"create\" : {} }"
        + System.lineSeparator()
        + "{ \"@timestamp\" : \"2099-03-08T11:04:05.000Z\", \"user\" : { \"id\" : \"vlb44hny\", \"name\": \"Sam\"}, \"message\" : \"Login attempt failed\" }"
        + System.lineSeparator()
        + "{ \"create\" : {} }"
        + System.lineSeparator()
        + "{ \"@timestamp\" : \"2099-03-08T11:04:05.000Z\", \"user\" : { \"id\" : \"8a4f500d\", \"name\": \"Dam\"}, \"message\" : \"Login successful\" }"
        + System.lineSeparator()
        + "{ \"create\" : {} }"
        + System.lineSeparator()
        + "{ \"@timestamp\" : \"2099-03-08T11:04:05.000Z\", \"user\" : { \"id\" : \"l7gk7f82\", \"name\": \"Pam\"}, \"message\" : \"Login attempt failed\" }"
        + System.lineSeparator();

    final String searchQuery1 = "{ \"seq_no_primary_term\" : true, \"query\": { \"match\": { \"user.id\": \"8a4f500d\"}}}";
    final String searchQuery2 = "{ \"seq_no_primary_term\" : true, \"query\": { \"match\": { \"user.id\": \"l7gk7f82\"}}}";

    public String getIndexTemplateBody() {
        return "{\"index_patterns\": [ \"my-data-stream*\" ], \"data_stream\": { }, \"priority\": 200, \"template\": {\"settings\": { } } }";
    }

    public void createSampleDataStreams(RestHelper rh) throws Exception {
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

        response = rh.executePutRequest(
            "/_index_template/my-data-stream-template",
            getIndexTemplateBody(),
            encodeBasicHeader("ds0", "nagilum")
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePutRequest(
            "/_index_template/my-data-stream-template",
            getIndexTemplateBody(),
            encodeBasicHeader("ds1", "nagilum")
        );
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
    public void testGetIndexOnBackingIndicesOfDataStream() throws Exception {

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
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream21-000001,.ds-my-data-stream22-000001", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(".ds-my-data-stream2*", encodeBasicHeader("ds2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testDocumentLevelSecurityOnDataStream() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();
        createSampleDataStreams(rh);
        HttpResponse response;

        rh.executePutRequest("/my-data-stream11/_bulk?refresh=true", bulkDocsBody, encodeBasicHeader("ds_admin", "nagilum"));
        rh.executePutRequest("/my-data-stream21/_bulk?refresh=true", bulkDocsBody, encodeBasicHeader("ds_admin", "nagilum"));

        response = rh.executePostRequest("/my-data-stream11/_search", searchQuery1, encodeBasicHeader("ds_dls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("8a4f500d"));
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));

        response = rh.executePostRequest("/my-data-stream22/_search", searchQuery1, encodeBasicHeader("ds_dls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/.ds-my-data-stream11-000001/_search", searchQuery1, encodeBasicHeader("ds_dls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("8a4f500d"));
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));

        response = rh.executePostRequest("/.ds-my-data-stream11-000001/_search", searchQuery2, encodeBasicHeader("ds_dls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("l7gk7f82"));
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"}"));

        response = rh.executePostRequest("/.ds-my-data-stream22-000001/_search", searchQuery2, encodeBasicHeader("ds_dls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/my-data-stream2*/_search", searchQuery1, encodeBasicHeader("ds_dls2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("8a4f500d"));
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));

        response = rh.executePostRequest("/my-data-stream1*/_search", searchQuery1, encodeBasicHeader("ds_dls2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/.ds-my-data-stream2*/_search", searchQuery1, encodeBasicHeader("ds_dls2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("8a4f500d"));
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));

        response = rh.executePostRequest("/.ds-my-data-stream1*/_search", searchQuery1, encodeBasicHeader("ds_dls2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/my-*/_search", searchQuery1, encodeBasicHeader("ds_dls3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("8a4f500d"));
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":2,\"relation\":\"eq\"}"));

        response = rh.executePostRequest("/.ds-my-*/_search", searchQuery1, encodeBasicHeader("ds_dls3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("8a4f500d"));
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":2,\"relation\":\"eq\"}"));

        response = rh.executePostRequest("/my-*/_search", searchQuery2, encodeBasicHeader("ds_dls3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("l7gk7f82"));
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"}"));

        response = rh.executePostRequest("/.ds-my-*/_search", searchQuery2, encodeBasicHeader("ds_dls3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("l7gk7f82"));
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"}"));
    }

    @Test
    public void testFLSOnBackingIndicesOfDataStream() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();
        createSampleDataStreams(rh);
        HttpResponse response;

        rh.executePutRequest("/my-data-stream11/_bulk?refresh=true", bulkDocsBody, encodeBasicHeader("ds_admin", "nagilum"));
        rh.executePutRequest("/my-data-stream21/_bulk?refresh=true", bulkDocsBody, encodeBasicHeader("ds_admin", "nagilum"));

        response = rh.executePostRequest("/my-data-stream11/_search", searchQuery1, encodeBasicHeader("ds_fls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertFalse(response.getBody().contains("\"name\":\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\"Login successful\""));

        response = rh.executePostRequest("/.ds-my-data-stream11-000001/_search", searchQuery1, encodeBasicHeader("ds_fls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertFalse(response.getBody().contains("\"name\":\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\"Login successful\""));

        response = rh.executePostRequest("/.ds-my-data-stream11-000001/_search", searchQuery2, encodeBasicHeader("ds_fls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"l7gk7f82\""));
        Assert.assertFalse(response.getBody().contains("\"name\":\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\"Login attempt failed\""));

        response = rh.executePostRequest("/my-data-stream22/_search", searchQuery1, encodeBasicHeader("ds_fls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/.ds-my-data-stream22-000001/_search", searchQuery2, encodeBasicHeader("ds_fls1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/my-data-stream2*/_search", searchQuery1, encodeBasicHeader("ds_fls2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/.ds-my-data-stream2*/_search", searchQuery1, encodeBasicHeader("ds_fls2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/my-data-stream1*/_search", searchQuery1, encodeBasicHeader("ds_fls2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/.ds-my-data-stream1*/_search", searchQuery1, encodeBasicHeader("ds_fls2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/my-*/_search", searchQuery1, encodeBasicHeader("ds_fls3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":2,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/.ds-my-*/_search", searchQuery1, encodeBasicHeader("ds_fls3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/my-*/_search", searchQuery2, encodeBasicHeader("ds_fls3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"id\":\"l7gk7f82\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Pam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\""));
    }

    @Test
    public void testFieldMaskingOnDataStream() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();
        createSampleDataStreams(rh);
        HttpResponse response;

        rh.executePutRequest("/my-data-stream11/_bulk?refresh=true", bulkDocsBody, encodeBasicHeader("ds_admin", "nagilum"));
        rh.executePutRequest("/my-data-stream21/_bulk?refresh=true", bulkDocsBody, encodeBasicHeader("ds_admin", "nagilum"));

        response = rh.executePostRequest("/my-data-stream11/_search", searchQuery1, encodeBasicHeader("ds_fm1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\"Login successful\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/.ds-my-data-stream11-000001/_search", searchQuery1, encodeBasicHeader("ds_fm1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\"Login successful\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/.ds-my-data-stream11-000001/_search", searchQuery2, encodeBasicHeader("ds_fm1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"l7gk7f82\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Pam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\"Login attempt failed\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/my-data-stream22/_search", searchQuery1, encodeBasicHeader("ds_fm1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/.ds-my-data-stream22-000001/_search", searchQuery2, encodeBasicHeader("ds_fm1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/my-data-stream2*/_search", searchQuery1, encodeBasicHeader("ds_fm2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\"Login successful\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/.ds-my-data-stream2*/_search", searchQuery1, encodeBasicHeader("ds_fm2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\"Login successful\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/my-data-stream1*/_search", searchQuery1, encodeBasicHeader("ds_fm2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/.ds-my-data-stream1*/_search", searchQuery1, encodeBasicHeader("ds_fm2", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePostRequest("/my-*/_search", searchQuery1, encodeBasicHeader("ds_fm3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hits\":{\"total\":{\"value\":2,\"relation\":\"eq\"}"));
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertFalse(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\"Login successful\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/.ds-my-*/_search", searchQuery1, encodeBasicHeader("ds_fm3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"id\":\"8a4f500d\""));
        Assert.assertFalse(response.getBody().contains("\"name\":\"Dam\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\"Login successful\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\""));

        response = rh.executePostRequest("/my-*/_search", searchQuery2, encodeBasicHeader("ds_fm3", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"id\":\"l7gk7f82\""));
        Assert.assertFalse(response.getBody().contains("\"name\":\"Pam\""));
        Assert.assertTrue(response.getBody().contains("\"name\":\""));
        Assert.assertFalse(response.getBody().contains("\"message\":\"Login attempt failed\""));
        Assert.assertTrue(response.getBody().contains("\"message\":\""));
    }
}
