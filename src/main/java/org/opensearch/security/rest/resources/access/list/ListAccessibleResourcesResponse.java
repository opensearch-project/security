/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.list;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Set;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.spi.resources.Resource;

/**
 * Response to a ListAccessibleResourcesRequest
 */
public class ListAccessibleResourcesResponse extends ActionResponse implements ToXContentObject {
    private final Set<Resource> resources;
    private final String resourceClass;

    public ListAccessibleResourcesResponse(String resourceClass, Set<Resource> resources) {
        this.resourceClass = resourceClass;
        this.resources = resources;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(resourceClass);
        out.writeCollection(resources);
    }

    public ListAccessibleResourcesResponse(StreamInput in) throws IOException {
        this.resourceClass = in.readString();
        this.resources = readResourcesFromStream(in);
    }

    private Set<Resource> readResourcesFromStream(StreamInput in) {
        try {
            // TODO check if there is a better way to handle this
            Class<?> clazz = Class.forName(this.resourceClass);
            @SuppressWarnings("unchecked")
            Class<? extends Resource> resourceClass = (Class<? extends Resource>) clazz;
            return in.readSet(i -> {
                try {
                    return resourceClass.getDeclaredConstructor(StreamInput.class).newInstance(i);
                } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (ClassNotFoundException | IOException e) {
            return Set.of();
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resources", resources);
        builder.endObject();
        return builder;
    }
}
