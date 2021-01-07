package com.amazon.dlic.auth.http.jwt.authtoken.api.validation;

public interface ValueParser<ValueType> {
    ValueType parse(String string) throws ConfigValidationException;

    String getExpectedValue();
}
