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

package org.opensearch.security.securityconf.impl;

public enum HttpRequestMethods {
    GET("GET"),
    POST("POST"),
    PUT("PUT"),
    DELETE("DELETE"),
    OPTIONS("OPTIONS"),
    HEAD("HEAD"),
    PATCH("PATCH"),
    TRACE("TRACE"),
    CONNECT("CONNECT");

    private String requestMethod;

    HttpRequestMethods(String method) {
        this.requestMethod = method;
    }

    public String getRequestMethod() {
        return requestMethod;
    }
}
