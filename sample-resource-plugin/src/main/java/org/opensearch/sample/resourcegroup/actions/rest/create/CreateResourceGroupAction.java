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
 * Action to create a sample resource group
 */
public class CreateResourceGroupAction extends ActionType<CreateResourceGroupTransportAction.Response> {
    public static final CreateResourceGroupAction INSTANCE = new CreateResourceGroupAction();
    public static final String NAME = "sampleresourcegroup:create";

    private CreateResourceGroupAction() {
        super(NAME, CreateResourceGroupTransportAction.Response::new);
    }
}
