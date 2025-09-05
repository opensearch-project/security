/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.search;

import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchResponse;

/**
 * Action to search sample resources
 */
public class SearchResourceAction extends ActionType<SearchResponse> {

    public static final SearchResourceAction INSTANCE = new SearchResourceAction();

    public static final String NAME = "cluster:admin/sample-resource-plugin/search";

    private SearchResourceAction() {
        super(NAME, SearchResponse::new);
    }
}
