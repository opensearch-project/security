package com.amazon.dlic.auth.http.jwt.authtoken.api.validation;

import com.fasterxml.jackson.databind.JsonNode;

@FunctionalInterface
public interface JsonNodeParser<ValueType> {
    ValueType parse(JsonNode jsonNode) throws ConfigValidationException;

    default String getExpectedValue() {
        return null;
    }

}


