package com.amazon.dlic.auth.http.jwt.authtoken.api.validation;

import java.io.IOException;

import org.elasticsearch.common.xcontent.XContentBuilder;

import com.fasterxml.jackson.databind.JsonNode;

public class InvalidAttributeValue extends ValidationError {
    private final Object expected;
    private final Object value;

    public InvalidAttributeValue(String attribute, Object value, Object expected, JsonNode jsonNode) {
        super(attribute, "Invalid value", jsonNode);
        this.expected = expected;
        this.value = value;
    }

    public InvalidAttributeValue(String attribute, Object value, Object expected, ValidatingJsonNode jsonNode) {
        this(attribute, value, expected, jsonNode.getDelegate());
    }

    public InvalidAttributeValue(String attribute, Object value, Object expected) {
        this(attribute, value, expected, (JsonNode) null);
    }

    public Object getExpected() {
        return expected;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("error", getMessage());

        builder.field("value", value);

        if (expected != null) {
            builder.field("expected", expectedToString(expected));
        }

        builder.endObject();
        return builder;
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private static String expectedToString(Object expected) {
        if (expected == null) {
            return null;
        } else if (expected instanceof Class<?> && ((Class<?>) expected).isEnum()) {
            return getEnumValues((Class<Enum>) expected);
        } else {
            return expected.toString();
        }
    }

    private static <E extends Enum<E>> String getEnumValues(Class<E> enumClass) {
        StringBuilder result = new StringBuilder();

        for (E e : enumClass.getEnumConstants()) {
            if (result.length() > 0) {
                result.append("|");
            }

            result.append(e.name());
        }

        return result.toString();
    }

    @Override
    public String toString() {
        return "InvalidAttributeValue [expected=" + expected + ", value=" + value + ", attribute=" + getAttribute() + "]";
    }
}

