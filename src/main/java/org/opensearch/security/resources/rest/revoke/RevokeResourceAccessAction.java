/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.revoke;

import org.opensearch.action.ActionType;

/**
 * This class represents the action type for revoking resource access.
 *
 * @opensearch.experimental
 */
public class RevokeResourceAccessAction extends ActionType<RevokeResourceAccessResponse> {

    public static final RevokeResourceAccessAction INSTANCE = new RevokeResourceAccessAction();

    public static final String NAME = "cluster:admin/security/resource_access/revoke";

    private RevokeResourceAccessAction() {
        super(NAME, RevokeResourceAccessResponse::new);
    }
}
