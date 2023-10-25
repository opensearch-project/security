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
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class TenantInfoActionTest extends AbstractRestApiUnitTest {
    private String payload = "{\"hosts\":[],\"users\":[\"sarek\"],"
            + "\"backend_roles\":[\"starfleet*\",\"ambassador\"],\"and_backend_roles\":[],\"description\":\"Migrated "
            + "from v6\"}";
    private final String BASE_ENDPOINT;
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public TenantInfoActionTest() {
        BASE_ENDPOINT = getEndpointPrefix();
        ENDPOINT = getEndpointPrefix() + "/tenantinfo";
    }

    @Test
    public void testTenantInfoAPIAccess() throws Exception {
        Settings settings = Settings.builder()
                .put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
                .build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        rh.sendHTTPClientCredentials = true;
        response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    @Test
    public void testTenantInfoAPIUpdate() throws Exception {
        Settings settings = Settings.builder()
                .put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
                .build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCredentials = true;
        rh.sendAdminCertificate = true;

        // update security config
        RestHelper.HttpResponse response = rh.executePatchRequest(
                BASE_ENDPOINT + "/api/securityconfig",
                "[{\"op\": \"add\",\"path\": \"/config/dynamic/kibana/opendistro_role\","
                        + "\"value\": \"opendistro_security_internal\"}]",
                new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(BASE_ENDPOINT + "/api/rolesmapping/opendistro_security_internal", payload,
                new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testParallelPutRequests() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String[] tenantNames = { "tenant_1", "tenant_2" };
        String[] descriptions = { "create tenant 1", "create tenant 2" };
        HttpResponse[] responses = executeMultipleAsyncPutRequest(tenantNames, descriptions);
        int numCreatedResponses = 0;
        int numConflictResponses = 0;
        Integer requestIndexCreated = null;
        for (int i = 0; i < responses.length; i++) {
            HttpResponse response = responses[i];
            if (response.getStatusCode() == HttpStatus.SC_CREATED) {
                numCreatedResponses++;
                requestIndexCreated = i;
            } else if (response.getStatusCode() == HttpStatus.SC_CONFLICT) {
                numConflictResponses++;
            }
        }
        Assert.assertEquals(1, numCreatedResponses); // check that no more than 1 created status is read
        Assert.assertEquals(1, numConflictResponses); // check that no more than 1 conflict status is read
        Assert.assertNotNull(requestIndexCreated); // check that a created status is read

        HttpResponse response = rh
                .executeGetRequest(BASE_ENDPOINT + "/api/tenants/" + tenantNames[requestIndexCreated]);
        Assert.assertEquals(descriptions[requestIndexCreated],
                response.findValueInJson(tenantNames[requestIndexCreated] + ".description"));
    }

    private HttpResponse[] executeMultipleAsyncPutRequest(final String[] names,
            final String[] descriptions) throws Exception {
        final int numOfRequests = Math.min(names.length, descriptions.length);
        final String TENANTS_ENDPOINT = BASE_ENDPOINT + "/api/tenants/";
        final ExecutorService executorService = Executors.newFixedThreadPool(numOfRequests);
        try {
            List<Future<HttpResponse>> futures = new ArrayList<>(numOfRequests);
            for (int i_ = 0; i_ < numOfRequests; i_++) {
                final int i = i_;
                final String request = TENANTS_ENDPOINT + names[i];
                final String body = String.format("{\"description\":\"%s\"}", descriptions[i]);
                futures.add(executorService.submit(() -> rh.executePutRequest(request, body)));
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
