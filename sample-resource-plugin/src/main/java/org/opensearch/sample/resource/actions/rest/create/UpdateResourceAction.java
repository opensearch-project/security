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
 * Action to update a sample resource
 */
public class UpdateResourceAction extends ActionType<CreateResourceResponse> {
    /**
     * Update sample resource action instance
     */
    public static final UpdateResourceAction INSTANCE = new UpdateResourceAction();
    /**
     * Update sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/update";

    private UpdateResourceAction() {
        super(NAME, CreateResourceResponse::new);
    }
}
