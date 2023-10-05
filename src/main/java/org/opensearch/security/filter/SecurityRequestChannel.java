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

package org.opensearch.security.filter;

import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestResponse;

/**
 * When a request is recieved by the security plugin this governs getting information about the request and complete with with a response
 */
public interface SecurityRequestChannel extends SecurityRequest {

    /**
     * If this channel has been used to send a response
     */
    boolean hasResponse();

    /**
     * Gets the captured response
     */
    RestResponse getCapturedResponse();

    /** Use this channel to capture a response */
    boolean captureResponse(final SecurityResponse response);

    /** Use this channel to send the captured response */
    void sendResponseToChannel(RestChannel channel);
}
