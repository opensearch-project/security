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
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class IndexTemplateClusterPermissionsCheckTest extends SingleClusterTest {
    private RestHelper rh;

    final static String indexTemplateBody =
        "{ \"index_patterns\": [\"sem1234*\"], \"template\": { \"settings\": { \"number_of_shards\": 2, \"number_of_replicas\": 1 }, \"mappings\": { \"properties\": { \"timestamp\": { \"type\": \"date\", \"format\": \"yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis\" }, \"value\": { \"type\": \"double\" } } } } }";

    private String getFailureResponseReason(String user) {
        return "no permissions for [indices:admin/index_template/put] and User [name=" + user + ", backend_roles=[], requestedTenant=null]";
    }

    @Before
    public void setupRestHelper() throws Exception {
        setup();
        rh = nonSslRestHelper();
    }

    @Test
    public void testPutIndexTemplateByNonPrivilegedUser() throws Exception {
        String expectedFailureResponse = getFailureResponseReason("ds4");

        // should fail, as user `ds3` doesn't have correct permissions
        HttpResponse response = rh.executePutRequest("/_index_template/sem1234", indexTemplateBody, encodeBasicHeader("ds4", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertEquals(expectedFailureResponse, response.findValueInJson("error.root_cause[0].reason"));
    }

    @Test
    public void testPutIndexTemplateByPrivilegedUser() throws Exception {
        // should pass, as user `sem-user` has correct permissions
        HttpResponse response = rh.executePutRequest(
            "/_index_template/sem1234",
            indexTemplateBody,
            encodeBasicHeader("sem-user", "nagilum")
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testPutIndexTemplateAsIndexLevelPermission() throws Exception {
        String expectedFailureResponse = getFailureResponseReason("sem-user2");

        // should fail, as user `sem-user2` is assigned `put-template` permission as index-level, not cluster-level
        HttpResponse response = rh.executePutRequest(
            "/_index_template/sem1234",
            indexTemplateBody,
            encodeBasicHeader("sem-user2", "nagilum")
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertEquals(expectedFailureResponse, response.findValueInJson("error.root_cause[0].reason"));
    }

}
