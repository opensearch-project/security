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
 * Action to get a sample resource by its name
 */
public class GetResourceByNameAction extends ActionType<GetResourceResponse> {
    /**
     * Get sample resource by name action instance
     */
    public static final GetResourceByNameAction INSTANCE = new GetResourceByNameAction();
    /**
     * Get sample resource by name action name
     */
    public static final String NAME = "sampleresource:get_by_name";

    private GetResourceByNameAction() {
        super(NAME, GetResourceResponse::new);
    }
}
