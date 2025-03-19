/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.spi.resources.Resource;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;

/**
 * This class is used to represent the response of a resource access request.
 * It contains the response type and the response data.
 *
 * @opensearch.experimental
 */
public class ResourceAccessResponse extends ActionResponse implements ToXContentObject {
    public enum ResponseType {
        RESOURCES,
        RESOURCE_SHARING,
        BOOLEAN
    }

    private final ResponseType responseType;
    private final Object responseData;

    public ResourceAccessResponse(final StreamInput in) throws IOException {
        this.responseType = in.readEnum(ResponseType.class);
        this.responseData = null;
    }

    public ResourceAccessResponse(Set<Resource> resources) {
        this.responseType = ResponseType.RESOURCES;
        this.responseData = resources;
    }

    public ResourceAccessResponse(ResourceSharing resourceSharing) {
        this.responseType = ResponseType.RESOURCE_SHARING;
        this.responseData = resourceSharing;
    }

    public ResourceAccessResponse(boolean hasPermission) {
        this.responseType = ResponseType.BOOLEAN;
        this.responseData = hasPermission;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(responseType);
        switch (responseType) {
            case RESOURCES -> out.writeCollection((Set<Resource>) responseData);
            case RESOURCE_SHARING -> ((ResourceSharing) responseData).writeTo(out);
            case BOOLEAN -> out.writeBoolean((Boolean) responseData);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        switch (responseType) {
            case RESOURCES -> builder.field("resources", responseData);
            case RESOURCE_SHARING -> builder.field("sharing_info", responseData);
            case BOOLEAN -> builder.field("has_permission", responseData);
        }
        return builder.endObject();
    }

    @SuppressWarnings("unchecked")
    public Set<Resource> getResources() {
        return responseType == ResponseType.RESOURCES ? (Set<Resource>) responseData : Collections.emptySet();
    }

    public ResourceSharing getResourceSharing() {
        return responseType == ResponseType.RESOURCE_SHARING ? (ResourceSharing) responseData : null;
    }

    public Boolean getHasPermission() {
        return responseType == ResponseType.BOOLEAN ? (Boolean) responseData : null;
    }

    @Override
    public String toString() {
        return "ResourceAccessResponse [responseType=" + responseType + ", responseData=" + responseData + "]";
    }
}
