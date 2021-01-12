package com.amazon.opendistroforelasticsearch.security.authtoken.validation;

import org.elasticsearch.rest.RestStatus;

public class TokenCreationException extends Exception {
    private static final long serialVersionUID = -47600121877964762L;

    private RestStatus restStatus;

    public TokenCreationException(String message, RestStatus restStatus, Throwable cause) {
        super(message, cause);
        this.restStatus = restStatus;
    }

    public TokenCreationException(String message, RestStatus restStatus) {
        super(message);
        this.restStatus = restStatus;
    }


    public RestStatus getRestStatus() {
        return restStatus;
    }

    public void setRestStatus(RestStatus restStatus) {
        this.restStatus = restStatus;
    }

}
