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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpHeaders;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestResponse;

public class SecurityResponse {

    public static final Map<String, String> CONTENT_TYPE_APP_JSON = Map.of(HttpHeaders.CONTENT_TYPE, "application/json");

    private final int status;
    private Map<String, List<String>> headers;
    private final String body;
    private final String contentType;

    public SecurityResponse(final int status, final Exception e) {
        this.status = status;
        this.body = generateFailureMessage(e);
        this.contentType = XContentType.JSON.mediaType();
    }

    public SecurityResponse(final int status, String body) {
        this.status = status;
        this.body = body;
        this.contentType = null;
    }

    public SecurityResponse(final int status, final Map<String, String> headers, final String body) {
        this.status = status;
        populateHeaders(headers);
        this.body = body;
        this.contentType = null;
    }

    public SecurityResponse(final int status, final Map<String, String> headers, final String body, String contentType) {
        this.status = status;
        this.body = body;
        this.contentType = contentType;
        populateHeaders(headers);
    }

    private void populateHeaders(Map<String, String> headers) {
        if (headers != null) {
            headers.entrySet().forEach(entry -> addHeader(entry.getKey(), entry.getValue()));
        }
    }

    /**
     * Add a custom header.
     */
    public void addHeader(String name, String value) {
        if (headers == null) {
            headers = new HashMap<>(2);
        }
        List<String> header = headers.get(name);
        if (header == null) {
            header = new ArrayList<>();
            headers.put(name, header);
        }
        header.add(value);
    }

    public int getStatus() {
        return status;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public RestResponse asRestResponse() {
        final RestResponse restResponse;
        if (this.contentType != null) {
            restResponse = new BytesRestResponse(RestStatus.fromCode(getStatus()), this.contentType, getBody());
        } else {
            restResponse = new BytesRestResponse(RestStatus.fromCode(getStatus()), getBody());
        }
        if (getHeaders() != null) {
            getHeaders().entrySet().forEach(entry -> { entry.getValue().forEach(value -> restResponse.addHeader(entry.getKey(), value)); });
        }
        return restResponse;
    }

    protected String generateFailureMessage(final Exception e) {
        try {
            return XContentFactory.jsonBuilder()
                .startObject()
                .startObject("error")
                .field("status", "error")
                .field("reason", e.getMessage())
                .endObject()
                .endObject()
                .toString();
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }
}
