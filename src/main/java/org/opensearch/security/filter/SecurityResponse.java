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

import java.util.Map;

import org.apache.http.HttpHeaders;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestResponse;

public class SecurityResponse {

    public static final Map<String, String> CONTENT_TYPE_APP_JSON = Map.of(HttpHeaders.CONTENT_TYPE, "application/json");

    private final int status;
    private final Map<String, String> headers;
    private final String body;

    public SecurityResponse(final int status, final Map<String, String> headers, final String body) {
        this.status = status;
        this.headers = headers;
        this.body = body;
    }

    public int getStatus() {
        return status;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public RestResponse asRestResponse() {
        final RestResponse restResponse = new BytesRestResponse(RestStatus.fromCode(getStatus()), getBody());
        getHeaders().forEach(restResponse::addHeader);
        return restResponse;
    }

}
