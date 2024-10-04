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
public class ListSampleResourceAction extends ActionType<ListSampleResourceResponse> {
    /**
     * List sample resource action instance
     */
    public static final ListSampleResourceAction INSTANCE = new ListSampleResourceAction();
    /**
     * List sample resource action name
     */
    public static final String NAME = "cluster:admin/sampleresource/list";

    private ListSampleResourceAction() {
        super(NAME, ListSampleResourceResponse::new);
    }
}
