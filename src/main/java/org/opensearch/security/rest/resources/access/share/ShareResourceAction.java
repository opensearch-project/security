/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.share;

import org.opensearch.action.ActionType;

/**
 * Share resource
 */
public class ShareResourceAction extends ActionType<ShareResourceResponse> {

    public static final ShareResourceAction INSTANCE = new ShareResourceAction();

    public static final String NAME = "cluster:admin/security/resources/share";

    private ShareResourceAction() {
        super(NAME, ShareResourceResponse::new);
    }
}
