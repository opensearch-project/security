package com.amazon.dlic.auth.http.jwt.authtoken.api.temporal;

import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.ConfigValidationException;

import java.time.Duration;

public interface DurationExpression {
    Duration getActualDuration(int iteration);

    public static DurationExpression parse(String string) throws ConfigValidationException {
        if (string == null) {
            return null;
        }

        DurationExpression result = ExpontentialDurationExpression.tryParse(string);

        if (result != null) {
            return result;
        } else {
            return new ConstantDurationExpression(DurationFormat.INSTANCE.parse(string));
        }
    }
}

