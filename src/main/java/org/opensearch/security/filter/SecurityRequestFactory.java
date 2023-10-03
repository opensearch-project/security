package org.opensearch.security.filter;

import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

public class SecurityRequestFactory {

    public static SecurityRequestChannel from() {
        return null;
    }

    public static SecurityRequest from(final RestRequest request) {
        return new OpenSearchRequest(request);
    }

    public static SecurityRequestChannel from(final RestRequest request, final RestChannel channel) {
        return new OpenSearchRequestChannel(request, channel);
    }
}
