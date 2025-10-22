/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.add;

import org.opensearch.action.ActionType;

/**
 * Action to add a sample resource to a resource group
 */
public class AddResourceToGroupAction extends ActionType<AddResourceToGroupResponse> {
    /**
     * Add sample resource to group action instance
     */
    public static final AddResourceToGroupAction INSTANCE = new AddResourceToGroupAction();
    /**
     * Add sample resource to group action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/group/add";

    private AddResourceToGroupAction() {
        super(NAME, AddResourceToGroupResponse::new);
    }
}
