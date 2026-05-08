/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.delete;

import org.opensearch.action.ActionType;
import org.opensearch.sample.resourcegroup.actions.transport.DeleteResourceGroupTransportAction;

/**
 * Action to delete a sample resource group
 */
public class DeleteResourceGroupAction extends ActionType<DeleteResourceGroupTransportAction.Response> {
    public static final DeleteResourceGroupAction INSTANCE = new DeleteResourceGroupAction();
    public static final String NAME = "sampleresourcegroup:delete";

    private DeleteResourceGroupAction() {
        super(NAME, DeleteResourceGroupTransportAction.Response::new);
    }
}
