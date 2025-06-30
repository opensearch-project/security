/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import org.opensearch.action.ActionType;

/**
 * This class represents the action type for sharing resource.
 *
 */
public class ShareAction extends ActionType<ShareResponse> {

    public static final ShareAction INSTANCE = new ShareAction();

    public static final String NAME = "cluster:admin/security/resource/share";

    private ShareAction() {
        super(NAME, ShareResponse::new);
    }
}
