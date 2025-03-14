/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.get;

import org.opensearch.action.ActionType;

/**
 * Action to get a sample resource
 */
public class GetResourceAction extends ActionType<GetResourceResponse> {
    /**
     * Get sample resource action instance
     */
    public static final GetResourceAction INSTANCE = new GetResourceAction();
    /**
     * Get sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/get";

    private GetResourceAction() {
        super(NAME, GetResourceResponse::new);
    }
}
