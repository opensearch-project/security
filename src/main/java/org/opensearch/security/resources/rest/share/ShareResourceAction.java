/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.share;

import org.opensearch.action.ActionType;

/**
 * This class represents the action type for sharing resource.
 *
 * @opensearch.experimental
 */
public class ShareResourceAction extends ActionType<ShareResourceResponse> {

    public static final ShareResourceAction INSTANCE = new ShareResourceAction();

    public static final String NAME = "cluster:admin/security/resource_access/share";

    private ShareResourceAction() {
        super(NAME, ShareResourceResponse::new);
    }
}
