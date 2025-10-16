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
 * Action to create a sample resource
 */
public class CreateResourceGroupAction extends ActionType<CreateResourceGroupResponse> {
    /**
     * Create sample resource action instance
     */
    public static final CreateResourceGroupAction INSTANCE = new CreateResourceGroupAction();
    /**
     * Create sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/group/create";

    private CreateResourceGroupAction() {
        super(NAME, CreateResourceGroupResponse::new);
    }
}
