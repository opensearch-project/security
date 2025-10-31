/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.create;

import org.opensearch.action.ActionType;

/**
 * Action to update a sample resource group
 */
public class UpdateResourceGroupAction extends ActionType<CreateResourceGroupResponse> {
    /**
     * Update sample resource group action instance
     */
    public static final UpdateResourceGroupAction INSTANCE = new UpdateResourceGroupAction();
    /**
     * Update sample resource group action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/group/update";

    private UpdateResourceGroupAction() {
        super(NAME, CreateResourceGroupResponse::new);
    }
}
