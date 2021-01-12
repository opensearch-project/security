package com.amazon.opendistroforelasticsearch.security.authtoken.validation;

public class NoSuchAuthTokenException extends Exception {

    private static final long serialVersionUID = -343178809366694796L;

    public NoSuchAuthTokenException(String id) {
        super("No such auth token: " + id);
    }

    public NoSuchAuthTokenException(String id, Throwable cause) {
        super("No such auth token: " + id, cause);
    }

}
