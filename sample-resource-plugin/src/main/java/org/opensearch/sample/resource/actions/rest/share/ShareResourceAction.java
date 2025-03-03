/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.share;

import org.opensearch.action.ActionType;

/**
 * Action to share a sample resource
 */
public class ShareResourceAction extends ActionType<ShareResourceResponse> {
    /**
     * Share sample resource action instance
     */
    public static final ShareResourceAction INSTANCE = new ShareResourceAction();
    /**
     * Share sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/share";

    private ShareResourceAction() {
        super(NAME, ShareResourceResponse::new);
    }
}
