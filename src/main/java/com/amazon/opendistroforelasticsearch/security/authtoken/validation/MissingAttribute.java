package com.amazon.opendistroforelasticsearch.security.authtoken.validation;

import java.io.IOException;

import org.elasticsearch.common.xcontent.XContentBuilder;

import com.fasterxml.jackson.databind.JsonNode;

public class MissingAttribute extends ValidationError {
    public MissingAttribute(String attribute, JsonNode jsonNode) {
        super(attribute, "Required attribute is missing", jsonNode);
    }

    public MissingAttribute(String attribute, ValidatingJsonNode jsonNode) {
        this(attribute, jsonNode.getDelegate());
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("error", getMessage());
        builder.endObject();
        return builder;
    }
}
