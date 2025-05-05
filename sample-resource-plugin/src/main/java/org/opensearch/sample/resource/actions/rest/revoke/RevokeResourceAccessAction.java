/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.revoke;

import org.opensearch.action.ActionType;

/**
 * Action to revoke a sample resource
 */
public class RevokeResourceAccessAction extends ActionType<RevokeResourceAccessResponse> {
    /**
     * Revoke sample resource action instance
     */
    public static final RevokeResourceAccessAction INSTANCE = new RevokeResourceAccessAction();
    /**
     * Revoke sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/revoke";

    private RevokeResourceAccessAction() {
        super(NAME, RevokeResourceAccessResponse::new);
    }
}
