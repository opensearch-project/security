package com.amazon.dlic.auth.http.jwt.authtoken.api;

import java.io.ByteArrayInputStream;

import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.ConfigValidationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestStatus;

import com.google.common.base.Charsets;

public class Responses {
    private static final Logger log = LogManager.getLogger(Responses.class);

    public static void sendError(RestChannel channel, RestStatus status, String error) {
        sendError(channel, status, error, (String) null);
    }

    public static void sendError(RestChannel channel, RestStatus status, String error, String detailJsonDocument) {

        try {
            final XContentBuilder builder = channel.newBuilder();
            builder.prettyPrint();
            builder.humanReadable(true);
            builder.startObject();
            builder.field("status", status.getStatus());

            if (error != null) {
                builder.field("error", error);
            }

            if (detailJsonDocument != null) {
                builder.rawField("detail", new ByteArrayInputStream(detailJsonDocument.getBytes(Charsets.UTF_8)), XContentType.JSON);
            }
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(status, builder));
        } catch (Exception e) {
            log.error(e.toString(), e);
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

    public static void sendError(RestChannel channel, RestStatus status, String error, ToXContent detailDocument) {

        try {
            final XContentBuilder builder = channel.newBuilder();
            builder.prettyPrint();
            builder.humanReadable(true);
            builder.startObject();
            builder.field("status", status.getStatus());

            if (error != null) {
                builder.field("error", error);
            }

            if (detailDocument != null) {
                builder.field("detail", detailDocument);
            }
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(status, builder));
        } catch (Exception e) {
            log.error(e.toString(), e);
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

    public static void sendError(RestChannel channel, Exception e) {
        if (e instanceof ConfigValidationException) {
            sendError(channel, RestStatus.BAD_REQUEST, e.getMessage(), ((ConfigValidationException) e).getValidationErrors());
        } else {
            sendError(channel, ExceptionsHelper.status(e), e.getMessage());
        }
    }

    public static void send(RestChannel channel, RestStatus status) {
        try {
            final XContentBuilder builder = channel.newBuilder();
            builder.prettyPrint();
            builder.humanReadable(true);
            builder.startObject();
            builder.field("status", status.getStatus());

            builder.endObject();
            channel.sendResponse(new BytesRestResponse(status, builder));
        } catch (Exception e) {
            log.error(e.toString(), e);
            throw ExceptionsHelper.convertToElastic(e);
        }
    }
}

