/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

/**
 * Integration tests to test point in time APIs permission model
 */
public class PitIntegrationTests  extends SingleClusterTest {

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

        // Delete all PITs throws forbidden error since there are no PITs in the cluster
        resc = rh.executeDeleteRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
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

        // List all PITs should work since there is atleast one PIT for which user has access for
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        // PIT segments should work since there is atleast one PIT for which user has access for
        resc = rh.executeGetRequest("/_cat/pit_segments/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

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

        // List all PITs throws forbidden error since there are no PITs in the cluster
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());

        // PIT segments API throws forbidden error since there are no PITs in the cluster
        resc = rh.executeGetRequest("/_search/point_in_time/_all",
                encodeBasicHeader("pit-1", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
    }
}