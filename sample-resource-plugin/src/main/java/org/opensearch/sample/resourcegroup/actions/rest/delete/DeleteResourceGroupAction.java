/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.delete;

import org.opensearch.action.ActionType;

/**
 * Action to delete a sample resource
 */
public class DeleteResourceGroupAction extends ActionType<DeleteResourceGroupResponse> {
    /**
     * Delete sample resource action instance
     */
    public static final DeleteResourceGroupAction INSTANCE = new DeleteResourceGroupAction();
    /**
     * Delete sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/group/delete";

    private DeleteResourceGroupAction() {
        super(NAME, DeleteResourceGroupResponse::new);
    }
}
