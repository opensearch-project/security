/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.common.resources.rest;

import org.opensearch.action.ActionType;

public class ResourceAccessAction extends ActionType<ResourceAccessResponse> {

    public static final ResourceAccessAction INSTANCE = new ResourceAccessAction();

    public static final String NAME = "cluster:admin/security/resource_access";

    private ResourceAccessAction() {
        super(NAME, ResourceAccessResponse::new);
    }
}
