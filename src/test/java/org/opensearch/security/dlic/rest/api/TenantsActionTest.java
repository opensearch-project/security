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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class TenantsActionTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public TenantsActionTest() {
        ENDPOINT = getEndpointPrefix() + "/api/tenants";
    }

    @Test
    public void testParallelPutRequests() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String[] caseOneRequests = { ENDPOINT + "/tenant1", ENDPOINT + "/tenant1" };
        String[] caseOneBodies = { "{\"description\":\"create tenant 1\"}", "{\"description\":\"create tenant 2\"}" };
        HttpResponse[] caseOneResponses = executeMultipleAsyncPutRequest(caseOneRequests, caseOneBodies);
        boolean created = false;
        for (HttpResponse response : caseOneResponses) {
            int sc = response.getStatusCode();
            switch (sc) {
                case HttpStatus.SC_CREATED:
                    Assert.assertFalse(created);
                    created = true;
                    break;
                case HttpStatus.SC_OK:
                    break;
                default:
                    Assert.assertEquals(HttpStatus.SC_CONFLICT, sc);
                    break;
            }
        }

        String[] caseTwoRequests = { ENDPOINT + "/tenant1", ENDPOINT + "/tenant1", ENDPOINT + "/tenant1",
                ENDPOINT + "/tenant1", ENDPOINT + "/tenant1" };
        String[] caseTwoBodies = { "{\"description\":\"create tenant 1\"}", "{\"description\":\"create tenant 2\"}",
                "{\"description\":\"create tenant 3\"}", "{\"description\":\"create tenant 4\"}",
                "{\"description\":\"create tenant 5\"}" };
        HttpResponse[] caseTwoResponses = executeMultipleAsyncPutRequest(caseTwoRequests, caseTwoBodies);
        created = false;
        for (HttpResponse response : caseTwoResponses) {
            int sc = response.getStatusCode();
            switch (sc) {
                case HttpStatus.SC_CREATED:
                    Assert.assertFalse(created);
                    created = true;
                    break;
                case HttpStatus.SC_OK:
                    break;
                default:
                    Assert.assertEquals(HttpStatus.SC_CONFLICT, sc);
                    break;
            }
        }

        String[] caseThreeRequests = { ENDPOINT + "/tenant1", ENDPOINT + "/tenant1", ENDPOINT + "/tenant1",
                ENDPOINT + "/tenant1", ENDPOINT + "/tenant1", ENDPOINT + "/tenant1", ENDPOINT + "/tenant1",
                ENDPOINT + "/tenant1", ENDPOINT + "/tenant1", ENDPOINT + "/tenant1" };
        String[] caseThreeBodies = { "{\"description\":\"create tenant 1\"}", "{\"description\":\"create tenant 2\"}",
                "{\"description\":\"create tenant 3\"}", "{\"description\":\"create tenant 4\"}",
                "{\"description\":\"create tenant 5\"}", "{\"description\":\"create tenant 6\"}",
                "{\"description\":\"create tenant 7\"}", "{\"description\":\"create tenant 8\"}",
                "{\"description\":\"create tenant 9\"}", "{\"description\":\"create tenant 10\"}" };
        HttpResponse[] caseThreeResponses = executeMultipleAsyncPutRequest(caseThreeRequests, caseThreeBodies);
        created = false;
        for (HttpResponse response : caseThreeResponses) {
            int sc = response.getStatusCode();
            switch (sc) {
                case HttpStatus.SC_CREATED:
                    Assert.assertFalse(created);
                    created = true;
                    break;
                case HttpStatus.SC_OK:
                    break;
                default:
                    Assert.assertEquals(HttpStatus.SC_CONFLICT, sc);
                    break;
            }
        }
    }

    private HttpResponse[] executeMultipleAsyncPutRequest(final String[] requests,
            final String[] bodies) throws Exception {
        final int numOfRequests = Math.min(requests.length, bodies.length);
        final ExecutorService executorService = Executors.newFixedThreadPool(numOfRequests);
        try {
            List<Future<HttpResponse>> futures = new ArrayList<>(numOfRequests);
            for (int i_ = 0; i_ < numOfRequests; i_++) {
                final int i = i_;
                futures.add(executorService.submit(() -> rh.executePutRequest(requests[i], bodies[i])));
            }
            return futures.stream().map(this::from).toArray(HttpResponse[]::new);
        } finally {
            executorService.shutdown();
        }
    }

    private HttpResponse from(Future<HttpResponse> future) {
        try {
            return future.get();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
