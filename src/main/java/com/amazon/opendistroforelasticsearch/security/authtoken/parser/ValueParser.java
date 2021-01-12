package com.amazon.opendistroforelasticsearch.security.authtoken.parser;

import com.amazon.opendistroforelasticsearch.security.authtoken.validation.ConfigValidationException;

public interface ValueParser<ValueType> {
    ValueType parse(String string) throws ConfigValidationException;

    String getExpectedValue();
}
