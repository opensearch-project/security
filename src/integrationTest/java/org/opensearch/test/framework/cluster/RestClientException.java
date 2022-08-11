package org.opensearch.test.framework.cluster;

class RestClientException extends RuntimeException {
    public RestClientException(String message, Throwable cause) {
        super(message, cause);
    }
}
