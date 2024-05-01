/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;

import org.opensearch.ExceptionsHelper;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

public class Responses {

    public static void ok(final RestChannel channel, final String message) {
        response(channel, RestStatus.OK, message);
    }

    public static void ok(final RestChannel channel, final ToXContent toXContent) {
        response(channel, RestStatus.OK, toXContent);
    }

    public static void created(final RestChannel channel, final String message) {
        response(channel, RestStatus.CREATED, message);
    }

    public static void methodNotImplemented(final RestChannel channel, final RestRequest.Method method) {
        notImplemented(channel, "Method " + method.name() + " not supported for this action.");
    }

    public static void notImplemented(final RestChannel channel, final String message) {
        response(channel, RestStatus.NOT_IMPLEMENTED, message);
    }

    public static void notFound(final RestChannel channel, final String message) {
        response(channel, RestStatus.NOT_FOUND, message);
    }

    public static void conflict(final RestChannel channel, final String message) {
        response(channel, RestStatus.CONFLICT, message);
    }

    public static void internalServerError(final RestChannel channel, final String message) {
        response(channel, RestStatus.INTERNAL_SERVER_ERROR, message);
    }

    public static void forbidden(final RestChannel channel, final String message) {
        response(channel, RestStatus.FORBIDDEN, message);
    }

    public static void badRequest(final RestChannel channel, final String message) {
        response(channel, RestStatus.BAD_REQUEST, message);
    }

    public static void unauthorized(final RestChannel channel) {
        response(channel, RestStatus.UNAUTHORIZED, "Unauthorized");
    }

    public static void response(RestChannel channel, RestStatus status, String message) {
        response(channel, status, payload(status, message));
    }

    public static void response(final RestChannel channel, final RestStatus status, final ToXContent toXContent) {
        try (final var builder = channel.newBuilder()) {
            toXContent.toXContent(builder, ToXContent.EMPTY_PARAMS);
            channel.sendResponse(new BytesRestResponse(status, builder));
        } catch (final IOException ioe) {
            throw ExceptionsHelper.convertToOpenSearchException(ioe);
        }
    }

    public static ToXContent forbiddenMessage(final String message) {
        return payload(RestStatus.FORBIDDEN, message);
    }

    public static ToXContent badRequestMessage(final String message) {
        return payload(RestStatus.BAD_REQUEST, message);
    }

    public static ToXContent methodNotImplementedMessage(final RestRequest.Method method) {
        return payload(RestStatus.NOT_FOUND, "Method " + method.name() + " not supported for this action.");
    }

    public static ToXContent notFoundMessage(final String message) {
        return payload(RestStatus.NOT_FOUND, message);
    }

    public static ToXContent conflictMessage(final String message) {
        return payload(RestStatus.CONFLICT, message);
    }

    public static ToXContent payload(final RestStatus status, final String message) {
        return (builder, params) -> builder.startObject().field("status", status.name()).field("message", message).endObject();
    }

}
