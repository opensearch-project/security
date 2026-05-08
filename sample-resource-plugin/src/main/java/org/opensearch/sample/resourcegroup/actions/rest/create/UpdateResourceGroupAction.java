/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.create;

import org.opensearch.action.ActionType;
import org.opensearch.sample.resourcegroup.actions.transport.CreateResourceGroupTransportAction;

/**
 * Action to update a sample resource group
 */
public class UpdateResourceGroupAction extends ActionType<CreateResourceGroupTransportAction.Response> {
    public static final UpdateResourceGroupAction INSTANCE = new UpdateResourceGroupAction();
    public static final String NAME = "sampleresourcegroup:update";

    private UpdateResourceGroupAction() {
        super(NAME, CreateResourceGroupTransportAction.Response::new);
    }
}
