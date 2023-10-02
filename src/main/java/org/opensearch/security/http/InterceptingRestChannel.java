package org.opensearch.security.http;

import org.opensearch.rest.AbstractRestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;

public class InterceptingRestChannel extends AbstractRestChannel {
    private RestResponse interceptedResponse;

    public InterceptingRestChannel(RestRequest request, boolean detailedErrorsEnabled) {
        super(request, detailedErrorsEnabled);
    }

    public RestResponse getInterceptedResponse() {
        return this.interceptedResponse;
    }

    public void sendResponse(RestResponse response) {
        this.interceptedResponse = response;
    }
}
