/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.configuration;

import org.junit.Test;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DlsFlsValveImplTest {

    @Test
    public void usesFilterLevelDlsForTopLevelHybridQueryInAdaptiveMode() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(searchRequest, true, false);

        assertThat(result, is(true));
    }

    @Test
    public void usesFilterLevelDlsForTermLookupQueryInAdaptiveMode() {
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(QueryBuilders.matchAllQuery()));

        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(searchRequest, true, true);

        assertThat(result, is(true));
    }

    @Test
    public void usesLuceneLevelDlsForRegularQueryInAdaptiveMode() {
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(QueryBuilders.matchAllQuery()));

        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(searchRequest, true, false);

        assertThat(result, is(false));
    }

    @Test
    public void usesLuceneLevelDlsWhenSearchHasNoSourceInAdaptiveMode() {
        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(new SearchRequest(), true, false);

        assertThat(result, is(false));
    }

    @Test
    public void usesLuceneLevelDlsForNonSearchRequestInAdaptiveMode() {
        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(mock(ActionRequest.class), true, false);

        assertThat(result, is(false));
    }

    @Test
    public void doesNotSelectDlsModeForHybridQueryWithoutDlsRestrictions() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(searchRequest, false, false);

        assertThat(result, is(false));
    }
}
