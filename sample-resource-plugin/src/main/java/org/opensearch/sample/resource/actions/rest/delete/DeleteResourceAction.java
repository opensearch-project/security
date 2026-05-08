/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.delete;

import org.opensearch.action.ActionType;
import org.opensearch.sample.resource.actions.transport.DeleteResourceTransportAction;

/**
 * Action to delete a sample resource
 */
public class DeleteResourceAction extends ActionType<DeleteResourceTransportAction.Response> {
    public static final DeleteResourceAction INSTANCE = new DeleteResourceAction();
    public static final String NAME = "sampleresource:delete";

    private DeleteResourceAction() {
        super(NAME, DeleteResourceTransportAction.Response::new);
    }
}
