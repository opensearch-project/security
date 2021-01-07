package com.amazon.dlic.auth.http.jwt.authtoken.api.temporal;

import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.ConfigValidationException;
import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.InvalidAttributeValue;

import java.time.Duration;
import java.time.Period;
import java.time.temporal.TemporalAmount;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class TemporalAmountFormat {
    public static final TemporalAmountFormat INSTANCE = new TemporalAmountFormat();

    private final Pattern pattern = Pattern.compile("((?<period>" //
            + PeriodFormat.PATTERN_STRING //
            + ")" //
            + "|" //
            + "(?<duration>" //
            + DurationFormat.PATTERN_STRING //
            + "))");

    public TemporalAmount parse(String temporalAmountString) throws ConfigValidationException {
        if (temporalAmountString == null) {
            return null;
        }

        if (temporalAmountString.equals("0")) {
            return Duration.ZERO;
        }

        Matcher matcher = pattern.matcher(temporalAmountString);

        if (!matcher.matches()) {
            throw new ConfigValidationException(new InvalidAttributeValue(null, temporalAmountString,
                    "<Years>y? <Months>M? <Weeks>w? <Days>d?  |  <Days>d? <Hours>h? <Minutes>m? <Seconds>s? <Milliseconds>ms?"));
        }

        if (matcher.group("period") != null) {
            return PeriodFormat.INSTANCE.parse(matcher);
        } else {
            return DurationFormat.INSTANCE.parse(matcher);
        }

    }

    public String format(TemporalAmount temporalAmount) {
        if (temporalAmount == null) {
            return null;
        }

        if (temporalAmount instanceof Duration) {
            return DurationFormat.INSTANCE.format((Duration) temporalAmount);
        } else if (temporalAmount instanceof Period) {
            return PeriodFormat.INSTANCE.format((Period) temporalAmount);
        } else {
            throw new IllegalArgumentException("Unknown temporalAmount value: " + temporalAmount);
        }
    }

    static Long getNumericMatch(Matcher matcher, String name) {
        String group = matcher.group(name);

        if (group != null) {
            return Long.parseLong(group);
        } else {
            return null;
        }
    }
}


