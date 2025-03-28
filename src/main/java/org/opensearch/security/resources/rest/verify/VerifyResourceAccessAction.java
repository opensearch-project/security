/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.verify;

import org.opensearch.action.ActionType;

/**
 * This class represents the action type for verifying resource access.
 *
 * @opensearch.experimental
 */
public class VerifyResourceAccessAction extends ActionType<VerifyResourceAccessResponse> {

    public static final VerifyResourceAccessAction INSTANCE = new VerifyResourceAccessAction();

    public static final String NAME = "cluster:admin/security/resource_access/verify";

    private VerifyResourceAccessAction() {
        super(NAME, VerifyResourceAccessResponse::new);
    }
}
