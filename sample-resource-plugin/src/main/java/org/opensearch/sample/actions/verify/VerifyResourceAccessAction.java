/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.verify;

import org.opensearch.action.ActionType;

/**
 * Action to verify resource access for current user
 */
public class VerifyResourceAccessAction extends ActionType<VerifyResourceAccessResponse> {

    public static final VerifyResourceAccessAction INSTANCE = new VerifyResourceAccessAction();

    public static final String NAME = "cluster:admin/sampleresource/verify/resource_access";

    private VerifyResourceAccessAction() {
        super(NAME, VerifyResourceAccessResponse::new);
    }
}
