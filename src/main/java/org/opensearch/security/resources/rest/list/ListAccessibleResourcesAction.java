/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.list;

import org.opensearch.action.ActionType;

/**
 * This class represents the action type for listing accessible resources.
 *
 * @opensearch.experimental
 */
public class ListAccessibleResourcesAction extends ActionType<ListAccessibleResourcesResponse> {

    public static final ListAccessibleResourcesAction INSTANCE = new ListAccessibleResourcesAction();

    public static final String NAME = "cluster:admin/security/resource_access/list";

    private ListAccessibleResourcesAction() {
        super(NAME, ListAccessibleResourcesResponse::new);
    }
}
