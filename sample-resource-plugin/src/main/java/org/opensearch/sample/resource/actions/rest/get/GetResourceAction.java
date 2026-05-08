/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.get;

import org.opensearch.action.ActionType;
import org.opensearch.sample.resource.actions.transport.GetResourceTransportAction;

/**
 * Action to get a sample resource
 */
public class GetResourceAction extends ActionType<GetResourceTransportAction.Response> {
    public static final GetResourceAction INSTANCE = new GetResourceAction();
    public static final String NAME = "sampleresource:get";

    private GetResourceAction() {
        super(NAME, GetResourceTransportAction.Response::new);
    }
}
