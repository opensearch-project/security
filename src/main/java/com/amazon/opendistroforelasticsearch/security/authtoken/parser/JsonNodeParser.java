package com.amazon.opendistroforelasticsearch.security.authtoken.parser;

import com.amazon.opendistroforelasticsearch.security.authtoken.validation.ConfigValidationException;
import com.fasterxml.jackson.databind.JsonNode;

@FunctionalInterface
public interface JsonNodeParser<ValueType> {
    ValueType parse(JsonNode jsonNode) throws ConfigValidationException;

    default String getExpectedValue() {
        return null;
    }

}
