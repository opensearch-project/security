package com.amazon.dlic.auth.http.jwt.authtoken.api.validation;


import java.io.IOException;

import org.elasticsearch.common.xcontent.XContentBuilder;

import com.fasterxml.jackson.databind.JsonNode;

public class UnsupportedAttribute extends ValidationError {
    private final Object value;

    public UnsupportedAttribute(String attribute, Object value, JsonNode jsonNode) {
        super(attribute, "Unsupported attribute", jsonNode);
        this.value = value;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("error", getMessage());
        builder.field("value", value);
        builder.endObject();
        return builder;
    }
}


