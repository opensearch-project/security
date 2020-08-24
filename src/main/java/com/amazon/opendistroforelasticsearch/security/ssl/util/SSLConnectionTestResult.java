package com.amazon.opendistroforelasticsearch.security.ssl.util;

/**
 * Return codes for SSLConnectionTestUtil.testConnection()
 */
public enum SSLConnectionTestResult {
    /**
     * ES Ping to the server failed.
     */
    ES_PING_FAILED,
    /**
     * Server does not support SSL.
     */
    SSL_NOT_AVAILABLE,
    /**
     * Server supports SSL.
     */
    SSL_AVAILABLE
}
