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

import java.util.Optional;

/**
 * When a request is recieved by the security plugin this governs getting information about the request and complete with with a response
 */
public interface SecurityRequestChannel extends SecurityRequest {

    /** Associate a response with this channel */
    public void queueForSending(final SecurityResponse response);

    /** Acess the queued response */
    public Optional<SecurityResponse> getQueuedResponse();
}
