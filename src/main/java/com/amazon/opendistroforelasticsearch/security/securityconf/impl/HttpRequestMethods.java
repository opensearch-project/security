package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

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

