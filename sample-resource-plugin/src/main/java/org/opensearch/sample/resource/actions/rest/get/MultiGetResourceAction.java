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
 * Action to get several sample resources in one request
 */
public class MultiGetResourceAction extends ActionType<GetResourceResponse> {
    /**
     * Multi-get sample resource action instance
     */
    public static final MultiGetResourceAction INSTANCE = new MultiGetResourceAction();
    /**
     * Multi-get sample resource action name
     */
    public static final String NAME = "sampleresource:mget";

    private MultiGetResourceAction() {
        super(NAME, GetResourceResponse::new);
    }
}
