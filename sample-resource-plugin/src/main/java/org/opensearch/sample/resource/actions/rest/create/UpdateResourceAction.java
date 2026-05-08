/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.create;

import org.opensearch.action.ActionType;
import org.opensearch.sample.resource.actions.transport.CreateResourceTransportAction;

/**
 * Action to update a sample resource
 */
public class UpdateResourceAction extends ActionType<CreateResourceTransportAction.Response> {
    public static final UpdateResourceAction INSTANCE = new UpdateResourceAction();
    public static final String NAME = "sampleresource:update";

    private UpdateResourceAction() {
        super(NAME, CreateResourceTransportAction.Response::new);
    }
}
