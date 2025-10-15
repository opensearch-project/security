/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.get;

import org.opensearch.action.ActionType;

/**
 * Action to get a sample resource
 */
public class GetResourceGroupAction extends ActionType<GetResourceGroupResponse> {
    /**
     * Get sample resource action instance
     */
    public static final GetResourceGroupAction INSTANCE = new GetResourceGroupAction();
    /**
     * Get sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/group/get";

    private GetResourceGroupAction() {
        super(NAME, GetResourceGroupResponse::new);
    }
}
