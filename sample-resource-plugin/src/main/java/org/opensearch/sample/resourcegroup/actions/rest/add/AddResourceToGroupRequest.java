/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.add;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;

/**
 * Request object for AddResourceToGroupRequest transport action
 */
public class AddResourceToGroupRequest extends ActionRequest implements DocRequest.ParentReferencing {

    private final String groupId;
    private final String resourceId;

    /**
     * Default constructor
     */
    public AddResourceToGroupRequest(String groupId, String resourceId) {
        this.groupId = groupId;
        this.resourceId = resourceId;
    }

    public AddResourceToGroupRequest(StreamInput in) throws IOException {
        this.groupId = in.readString();
        this.resourceId = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(groupId);
        out.writeString(resourceId);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return this.resourceId;
    }

    public String getGroupId() {
        return this.groupId;
    }

    @Override
    public String type() {
        return RESOURCE_TYPE;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public String id() {
        return resourceId;
    }

    @Override
    public String parentType() {
        return RESOURCE_GROUP_TYPE;
    }

    @Override
    public String parentId() {
        return groupId;
    }
}
