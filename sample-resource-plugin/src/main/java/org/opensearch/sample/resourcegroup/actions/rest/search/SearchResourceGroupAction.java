/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.search;

import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchResponse;

/**
 * Action to search sample resource groups
 */
public class SearchResourceGroupAction extends ActionType<SearchResponse> {

    public static final SearchResourceGroupAction INSTANCE = new SearchResourceGroupAction();

    public static final String NAME = "cluster:admin/sample-resource-plugin/group/search";

    private SearchResourceGroupAction() {
        super(NAME, SearchResponse::new);
    }
}
