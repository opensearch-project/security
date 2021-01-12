package com.amazon.opendistroforelasticsearch.security.util.temporal;

import com.amazon.opendistroforelasticsearch.security.authtoken.validation.ConfigValidationException;
import com.amazon.opendistroforelasticsearch.security.authtoken.validation.InvalidAttributeValueError;

import static com.amazon.opendistroforelasticsearch.security.util.temporal.TemporalAmountFormat.getNumericMatch;

import java.time.Period;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class PeriodFormat {

    public static final PeriodFormat INSTANCE = new PeriodFormat();

    static final String PATTERN_STRING = "((?<y>[0-9]+)y)?\\s*" //
            + "((?<M>[0-9]+)M)?\\s*" //
            + "((?<pw>[0-9]+)w)?\\s*" //
            + "((?<pd>[0-9]+)d)?\\s*";

    private final Pattern pattern = Pattern.compile(PATTERN_STRING);

    public Period parse(String periodString) throws ConfigValidationException {
        if (periodString == null) {
            return null;
        }

        if (periodString.equals("0")) {
            return Period.ZERO;
        }

        Matcher matcher = pattern.matcher(periodString);

        if (!matcher.matches()) {
            throw new ConfigValidationException(new InvalidAttributeValueError(null, periodString, "<Years>y? <Months>M? <Weeks>w? <Days>d? "));
        }

        return parse(matcher);
    }

    Period parse(Matcher matcher) {
        Period result = Period.ZERO;

        Long y = getNumericMatch(matcher, "y");

        if (y != null) {
            result = result.plusYears(y);
        }

        Long m = getNumericMatch(matcher, "M");

        if (m != null) {
            result = result.plusMonths(m);
        }

        Long w = getNumericMatch(matcher, "pw");

        if (w != null) {
            result = result.plusDays(w * 7);
        }

        Long d = getNumericMatch(matcher, "pd");

        if (d != null) {
            result = result.plusDays(d);
        }

        return result;
    }

    public String format(Period period) {
        if (period == null) {
            return null;
        }

        if (period.isZero()) {
            return "0";
        }

        if (period.isNegative()) {
            throw new IllegalArgumentException("Negative periods are not supported");
        }

        StringBuilder result = new StringBuilder();

        int years = period.getYears();

        if (years != 0) {
            result.append(years).append("y");
        }

        int months = period.getMonths();

        if (months != 0) {
            result.append(months).append("M");
        }

        int days = period.getDays();

        if (days != 0) {
            result.append(days).append("d");
        }

        return result.toString();
    }

}
