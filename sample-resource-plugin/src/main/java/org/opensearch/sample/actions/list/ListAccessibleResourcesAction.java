/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.list;

import org.opensearch.action.ActionType;

/**
 * Action to list sample resources
 */
public class ListAccessibleResourcesAction extends ActionType<ListAccessibleResourcesResponse> {
    /**
     * List sample resource action instance
     */
    public static final ListAccessibleResourcesAction INSTANCE = new ListAccessibleResourcesAction();
    /**
     * List sample resource action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/list";

    private ListAccessibleResourcesAction() {
        super(NAME, ListAccessibleResourcesResponse::new);
    }
}
