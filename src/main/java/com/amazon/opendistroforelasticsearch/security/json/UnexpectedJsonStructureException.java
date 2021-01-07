package com.amazon.opendistroforelasticsearch.security.json;

import com.fasterxml.jackson.core.JsonProcessingException;

public class UnexpectedJsonStructureException extends JsonProcessingException {

    private static final long serialVersionUID = 4969591600760212956L;

    public UnexpectedJsonStructureException(String msg) {
        super(msg);
    }

}
