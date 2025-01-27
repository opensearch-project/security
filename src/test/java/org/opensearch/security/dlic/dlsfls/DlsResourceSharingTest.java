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

package org.opensearch.security.dlic.dlsfls;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.resources.ResourceSharingConstants;
import org.opensearch.security.spi.resources.ResourceAccessScope;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * These tests are flaky for some reason, but pass on retries all the time
 */
public class DlsResourceSharingTest extends AbstractDlsFlsTest {

    @Override
    protected void populateData(Client tc) {

        tc.index(
            new IndexRequest("resources").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"name\": \"A\"}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("resources").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"name\": \"B\"}", XContentType.JSON)
        ).actionGet();

        // create a resource-sharing entry
        tc.index(
            new IndexRequest(ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX).id("0")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(jsonPayload("0", "share_user"), XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest(ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX).id("1")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(jsonPayload("1", "non_share_user"), XContentType.JSON)
        ).actionGet();

        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
        }
        tc.search(new SearchRequest().indices(".opendistro_security")).actionGet();
        tc.search(new SearchRequest().indices(ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX)).actionGet();
        tc.search(new SearchRequest().indices("resources")).actionGet();

        OpenSearchSecurityPlugin.getResourceIndicesMutable().add("resources");
    }

    private String jsonPayload(String resourceId, String shareWithUser) {
        ;

        return String.format(
            "{"
                + "  \"source_idx\": \"resources\","
                + "  \"resource_id\": \"%s\","
                + "  \"created_by\": {"
                + "    \"user\": \"admin\""
                + "  },"
                + "\"share_with\":{"
                + "\""
                + ResourceAccessScope.PUBLIC
                + "\":{"
                + "\"users\": [\"%s\"]"
                + "}"
                + "}"
                + "}",
            resourceId,
            shareWithUser
        );
    }

    @Test
    public void testDLSForResourceSharingWithShareUser() throws Exception {
        final Settings settings = Settings.builder().put(ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED, true).build();
        setup(settings);

        HttpResponse res;

        // Verify that share_user can see exactly 1 document in the resources index
        // and that it is the one with name "A" (doc _id=0)
        res = rh.executeGetRequest("/resources/_search?pretty&size=10", encodeBasicHeader("share_user", "password"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        // Should see exactly 1 hit
        Assert.assertTrue("share_user should see only 1 document", res.getBody().contains("\"value\" : 1"));
        // That document should be "A"
        Assert.assertTrue("share_user should see 'A'", res.getBody().contains("\"name\" : \"A\""));
        // Should NOT see "B"
        Assert.assertFalse("share_user should NOT see 'B'", res.getBody().contains("\"name\" : \"B\""));
    }

    @Test
    public void testNonDls() throws Exception {
        setup();

        HttpResponse res;

        // Verify that share_user can see both documents
        res = rh.executeGetRequest("/resources/_search?pretty&size=10", encodeBasicHeader("share_user", "password"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        // Should see exactly 2 hit
        Assert.assertTrue("share_user should see 2 documents", res.getBody().contains("\"value\" : 2"));
        Assert.assertTrue("share_user should see 'A'", res.getBody().contains("\"name\" : \"A\""));
        Assert.assertTrue("share_user should see 'B'", res.getBody().contains("\"name\" : \"B\""));
    }

}
