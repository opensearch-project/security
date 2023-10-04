package org.opensearch.security.filter;

import java.util.Map;

public class SecurityResponse {
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

}
