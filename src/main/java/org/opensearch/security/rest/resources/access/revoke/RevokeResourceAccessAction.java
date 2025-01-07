/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.revoke;

import org.opensearch.action.ActionType;

public class RevokeResourceAccessAction extends ActionType<RevokeResourceAccessResponse> {
    public static final RevokeResourceAccessAction INSTANCE = new RevokeResourceAccessAction();

    public static final String NAME = "cluster:admin/security/resources/revoke";

    private RevokeResourceAccessAction() {
        super(NAME, RevokeResourceAccessResponse::new);
    }
}
