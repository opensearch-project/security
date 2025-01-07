/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.list;

import org.opensearch.action.ActionType;

/**
 * Action to list resources
 */
public class ListAccessibleResourcesAction extends ActionType<ListAccessibleResourcesResponse> {

    public static final ListAccessibleResourcesAction INSTANCE = new ListAccessibleResourcesAction();

    public static final String NAME = "cluster:admin/security/resources/list";

    private ListAccessibleResourcesAction() {
        super(NAME, ListAccessibleResourcesResponse::new);
    }
}
