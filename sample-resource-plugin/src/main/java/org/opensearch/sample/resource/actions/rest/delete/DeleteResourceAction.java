/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.delete;

import org.opensearch.action.ActionType;

/**
 * Action to delete a sample resource
 */
public class DeleteResourceAction extends ActionType<DeleteResourceResponse> {
    /**
     * Delete sample resource action instance
     */
    public static final DeleteResourceAction INSTANCE = new DeleteResourceAction();
    /**
     * Delete sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/delete";

    private DeleteResourceAction() {
        super(NAME, DeleteResourceResponse::new);
    }
}
