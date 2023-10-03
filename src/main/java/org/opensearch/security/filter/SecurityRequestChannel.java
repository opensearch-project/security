package org.opensearch.security.filter;

import java.util.Map;

/**
 * When a request is recieved by the security plugin this governs getting information about the request as well as a way to complet
 */
public interface SecurityRequestChannel extends SecurityRequest {

    public boolean hasCompleted();

    public boolean completeWithResponse(final int statusCode, final Map<String, String> headers, final String body);
}
