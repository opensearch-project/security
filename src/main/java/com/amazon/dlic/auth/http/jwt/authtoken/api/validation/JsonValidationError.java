package com.amazon.dlic.auth.http.jwt.authtoken.api.validation;

import java.io.IOException;

import org.elasticsearch.common.xcontent.XContentBuilder;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParseException;

public class JsonValidationError extends ValidationError {
    private JsonLocation jsonLocation;
    private String context;

    JsonValidationError(String attribute, JsonParseException jsonParseException) {
        super(attribute, "Error while parsing JSON document: " + jsonParseException.getOriginalMessage());
        cause(jsonParseException);
        this.jsonLocation = jsonParseException.getLocation();
        this.context = jsonParseException.getRequestPayloadAsString();
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("error", getMessage());

        if (jsonLocation != null) {
            builder.field("line", jsonLocation.getLineNr());
        }

        if (jsonLocation != null) {
            builder.field("column", jsonLocation.getColumnNr());
        }

        if (context != null) {
            builder.field("context", context);
        }

        builder.endObject();
        return builder;
    }

}


