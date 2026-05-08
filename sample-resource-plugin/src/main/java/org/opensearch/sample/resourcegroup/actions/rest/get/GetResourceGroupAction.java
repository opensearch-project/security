/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.get;

import org.opensearch.action.ActionType;
import org.opensearch.sample.resourcegroup.actions.transport.GetResourceGroupTransportAction;

/**
 * Action to get a sample resource group
 */
public class GetResourceGroupAction extends ActionType<GetResourceGroupTransportAction.Response> {
    public static final GetResourceGroupAction INSTANCE = new GetResourceGroupAction();
    public static final String NAME = "sampleresourcegroup:get";

    private GetResourceGroupAction() {
        super(NAME, GetResourceGroupTransportAction.Response::new);
    }
}
