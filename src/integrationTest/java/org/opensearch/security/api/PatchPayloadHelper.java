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

package org.opensearch.security.api;

import java.util.Locale;

import org.opensearch.core.xcontent.ToXContentObject;

interface PatchPayloadHelper extends ToXContentObject {

    enum Op {
        ADD,
        REPLACE,
        REMOVE;
    }

    static <T> ToXContentObject addOp(final String path, final T value) {
        return operation(Op.ADD, path, value);
    }

    static <T> ToXContentObject replaceOp(final String path, final T value) {
        return operation(Op.REPLACE, path, value);
    }

    static ToXContentObject removeOp(final String path) {
        return operation(Op.REMOVE, path, null);
    }

    private static <T> ToXContentObject operation(final Op op, final String path, final T value) {
        return (builder, params) -> {
            final var opPath = path.startsWith("/") ? path : "/" + path;
            builder.startObject().field("op", op.name().toLowerCase(Locale.ROOT)).field("path", opPath);
            if (value != null) {
                if (value instanceof ToXContentObject) {
                    builder.field("value", (ToXContentObject) value);
                } else if (value instanceof String) {
                    builder.field("value", (String) value);
                } else if (value instanceof Boolean) {
                    builder.field("value", (Boolean) value);
                } else {
                    throw new IllegalArgumentException("Unsupported java type " + value.getClass());
                }
            }
            return builder.endObject();
        };
    }

    static ToXContentObject patch(final ToXContentObject... operations) {
        return (builder, params) -> {
            builder.startArray();
            for (final var o : operations)
                o.toXContent(builder, EMPTY_PARAMS);
            return builder.endArray();
        };
    }

}
