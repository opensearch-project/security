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
 * Action to create a sample resource
 */
public class CreateResourceAction extends ActionType<CreateResourceTransportAction.Response> {
    public static final CreateResourceAction INSTANCE = new CreateResourceAction();
    public static final String NAME = "sampleresource:create";

    private CreateResourceAction() {
        super(NAME, CreateResourceTransportAction.Response::new);
    }
}
