package org.opensearch.security.filter;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.opensearch.core.rest.RestStatus;

public class SecurityResponse {
    private final int code;
    final Exception ex;
    protected SecurityResponse(final int code, final Exception ex){
        this.code = code;
        this.ex = ex;
    }

    public int getCode() {
        return code;
    }

    public Exception getException() {
        return ex;
    }

    public static class Builder {
        private int code;
        private Map<String, String> headers;
        private String body;
        public Builder() {
            code = -1;
            headers = new HashMap<>();
            body = "";
        }

        public Builder code(final int code) {
            this.code = code;
            return this;
        }

        public Builder code(final RestStatus code) {
            this.code = code.getStatus();
            return this;
        }

        public Builder header(final String key, final String value) {
            this.headers.put(key, value);
            return this;
        }

        public Builder body(final String body) {
            this.body = body;
            return this;
        }

        public SecurityResponse build() {
            if (code == -1) {
                throw new IllegalArgumentException("No response code set");
            }

            return new SecurityResponse(code, null);
        }

        public Optional<SecurityResponse> buildAsOptional() {
            return Optional.of(build());
        }
    }
}