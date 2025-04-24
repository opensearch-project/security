/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.create;

import org.opensearch.action.ActionType;

/**
 * Action to create a sample resource
 */
public class CreateResourceAction extends ActionType<CreateResourceResponse> {
    /**
     * Create sample resource action instance
     */
    public static final CreateResourceAction INSTANCE = new CreateResourceAction();
    /**
     * Create sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/create";

    private CreateResourceAction() {
        super(NAME, CreateResourceResponse::new);
    }
}
