/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest;

import org.opensearch.action.ActionType;

/**
 * This class represents the action type for resource access.
 * It is used to execute the resource access request and retrieve the response.
 *
 * @opensearch.experimental
 */
public class ResourceAccessAction extends ActionType<ResourceAccessResponse> {

    public static final ResourceAccessAction INSTANCE = new ResourceAccessAction();

    public static final String NAME = "cluster:admin/security/resource_access";

    private ResourceAccessAction() {
        super(NAME, ResourceAccessResponse::new);
    }
}
