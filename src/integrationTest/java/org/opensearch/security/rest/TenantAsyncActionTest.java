package org.opensearch.security.rest;



import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.http.HttpStatus;
import org.junit.Test;
import org.opensearch.security.dlic.rest.api.AbstractRestApiUnitTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.test.framework.AsyncActions;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.anyOf;

public class TenantAsyncActionTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public TenantAsyncActionTest() {
        ENDPOINT = getEndpointPrefix() + "/api/tenants/tenant1";
    }

    @Test
    public void testParallelPutRequests() throws Exception {
        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        final String TENANTS_ENDPOINT = ENDPOINT;
        final String TENANTS_BODY = "{\"description\":\"create new tenant\"}";

        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final List<CompletableFuture<RestHelper.HttpResponse>> conflictingRequests = AsyncActions.generate(() -> {
            return rh.executePutRequest(TENANTS_ENDPOINT, TENANTS_BODY);
        }, 2, 4);

        // Make sure all requests start at the same time
        countDownLatch.countDown();

        AtomicInteger numCreatedResponses = new AtomicInteger();
        AsyncActions.getAll(conflictingRequests, 1, TimeUnit.SECONDS).forEach((response) -> {
            assertThat(response.getStatusCode(), anyOf(equalTo(HttpStatus.SC_CREATED), equalTo(HttpStatus.SC_CONFLICT)));
            if (response.getStatusCode() == HttpStatus.SC_CREATED) numCreatedResponses.getAndIncrement();
        });
        assertThat(numCreatedResponses.get(), equalTo(1)); // should only be one 201

        RestHelper.HttpResponse getResponse = rh.executeGetRequest(TENANTS_ENDPOINT); // make sure the one 201 works
        assertThat(getResponse.findValueInJson("tenant1" + ".description"), equalTo("create new tenant"));
    }
}