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

package org.opensearch.security.dlic.rest.api;

import org.apache.hc.core5.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class FlushCacheApiTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public FlushCacheApiTest() {
        ENDPOINT = getEndpointPrefix() + "/api/cache";
    }

    @Test
    public void testFlushCache() throws Exception {

        setup();

        // Only DELETE is allowed for flush cache
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // Username to test cache invalidation
        String username = "testuser";

        // GET
        HttpResponse response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_NOT_IMPLEMENTED, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("message"), "Method GET not supported for this action.");

        // PUT
        response = rh.executePutRequest(ENDPOINT, "{}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_IMPLEMENTED, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("message"), "Method PUT not supported for this action.");

        // POST
        response = rh.executePostRequest(ENDPOINT, "{}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_IMPLEMENTED, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("message"), "Method POST not supported for this action.");

        // DELETE
        response = rh.executeDeleteRequest(ENDPOINT, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("message"), "Cache flushed successfully.");

        // DELETE request for a specific user's cache
        String userEndpoint = ENDPOINT + "/user/" + username;
        response = rh.executeDeleteRequest(userEndpoint, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("message"), "Cache invalidated for user: " + username);

    }
}
