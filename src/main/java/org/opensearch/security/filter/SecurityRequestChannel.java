package org.opensearch.security.filter;

/**
 * When a request is recieved by the security plugin this governs getting information about the request as well as a way to complet
 */
public interface SecurityRequestChannel extends SecurityRequest {

    /**
     * If this channel has been been used to send a response
     */
    public boolean hasCompleted();

    /** Use this channel to send a response */
    public boolean completeWithResponse(final SecurityResponse response);
}
