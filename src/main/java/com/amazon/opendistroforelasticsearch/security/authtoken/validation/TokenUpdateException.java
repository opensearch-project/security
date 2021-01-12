package com.amazon.opendistroforelasticsearch.security.authtoken.validation;

public class TokenUpdateException extends Exception {

    private static final long serialVersionUID = -8909316128729638749L;

    public TokenUpdateException() {
        super();
    }

    public TokenUpdateException(String message, Throwable cause) {
        super(message, cause);
    }

    public TokenUpdateException(String message) {
        super(message);
    }

    public TokenUpdateException(Throwable cause) {
        super(cause);
    }

}

